//! Deadline-bounded clients for policy-custody authority endpoints.
//!
//! Every transport wait uses an absolute `CLOCK_BOOTTIME` timerfd. Endpoint
//! acceptance joins the socket peer to a retained pidfd, process start time,
//! executable identity, IMA evidence, fs-verity evidence, and the signed
//! current-key authorization checkpoint.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "policy-custody endpoint clients require Linux openat2, getrandom, epoll, pidfd, SOCK_SEQPACKET, IMA, fs-verity, and CLOCK_BOOTTIME"
);

use super::boottime::{
    boottime_now_nanos, poll_until, BoottimeDeadline, BoottimeDomain,
    BoottimeError, DeadlineOperationError, PollInterest, PollTarget,
    ProgressFd, WaitOutcome,
};
use super::protocol::{
    domain_separated_signature_preimage,
    endpoint_receipt_statement_sha256, endpoint_request_sha256,
    endpoint_response_sha256, pidfd_stat_identity_sha256,
    require_nonzero_digest, CleanupAuthorizationConsumptionStatement,
    CleanupConsumptionCasReply, CleanupConsumptionCommand,
    CleanupConsumptionCompareAndSwap, CleanupConsumptionQuery,
    CleanupConsumptionQueryReply, DurableConsumeAtomicityModel,
    DurableConsumeRequestV3, DurableConsumeStatement,
    DurableSettlementRecord,
    EndpointProcessIdentity, EndpointRequestEnvelope, EndpointRequestKind,
    IndependentDurableConsumeEvidence, PolicyCustodyEndpointRole,
    PersistedCleanupAuthorizationConsumptionV3,
    PersistedDurableConsumeReceiptV3,
    ProtocolBoottimeDeadline, ProtocolError,
    SignedCleanupConsumptionCursorV3,
    SettlementCasReply, SettlementCommand, SettlementCompareAndSwap,
    SettlementIdentity, SettlementQuery, SettlementQueryReply,
    SettlementStateReference, SignedCleanupAuthorizationV3,
    SignedDurableConsumeReceiptEnvelope,
    SignedEndpointKeyAuthorizationCheckpoint,
    SignedEndpointResponseEnvelope, SignedWatchdogOwnershipAckV3,
    SignedTrustedHostNoTeeCurrentHeadWire,
    SignedTrustedHostNoTeeConsumeHeadWire,
    TrustedHostNoTeeAcceptedFloorWire,
    TrustedHostNoTeeCheckpointPredecessorPathWire,
    TrustedHostNoTeeDurableConsumeInclusionPathWire,
    TrustedHostNoTeeEndpointConsumeCursorWire,
    TrustedHostNoTeeSignedFloorEvidenceWire,
    TrustedHostNoTeeTrustOperationWire,
    TrustedHostNoTeeTrustRequestWire,
    TrustedHostNoTeeTrustResponseWire,
    WatchdogOwnershipQueryReplyV3, WatchdogOwnershipQueryV3,
    WatchdogRegistrationV3,
    MAX_ENDPOINT_FRAME_BYTES,
    POLICY_CUSTODY_PROTOCOL_VERSION,
};
use super::super::{canonical_json_bytes, Sha256Digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROC_STAT_BYTES: usize = 4096;
const MAX_IMA_XATTR_BYTES: usize = 4096;
const MAX_SYSTEMD_CREDENTIAL_BYTES: usize = 1024 * 1024;
const TRUSTED_HOST_NO_TEE_MODE: &str = "trusted-host-no-tee";
const TRUSTED_HOST_LOCAL_SCOPE: &str = "co-located-host-local";
const TRUSTED_HOST_EPOLL_TOKEN: u64 = 1;
const FS_IOC_MEASURE_VERITY: libc::Ioctl = 0xc004_6686u32 as libc::Ioctl;
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;
const SO_PEERPIDFD_OPT: libc::c_int = 77;
const OPENAT2_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const OPENAT2_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const OPENAT2_RESOLVE_BENEATH: u64 = 0x08;
const GETRANDOM_NONBLOCK: libc::c_uint = 0x0001;

#[derive(Debug)]
pub(super) enum EndpointClientError {
    Io(io::Error),
    Boottime(BoottimeError),
    DeadlineExpired,
    Protocol(ProtocolError),
    Invalid(&'static str),
    InvalidOwned(String),
}

impl fmt::Display for EndpointClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Boottime(error) => write!(formatter, "{error}"),
            Self::DeadlineExpired => {
                formatter.write_str("absolute BOOTTIME deadline expired")
            }
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidOwned(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for EndpointClientError {}

impl From<io::Error> for EndpointClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<BoottimeError> for EndpointClientError {
    fn from(error: BoottimeError) -> Self {
        Self::Boottime(error)
    }
}

impl From<ProtocolError> for EndpointClientError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug, Clone)]
pub(super) struct CurrentKeyAuthorizationPin {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) exact_endpoint_generation: u64,
    pub(super) signing_key_id: Sha256Digest,
    pub(super) signing_key_spki_sha256: Sha256Digest,
    pub(super) verifying_key: VerifyingKey,
    pub(super) signed_current_key_authorization:
        SignedEndpointKeyAuthorizationCheckpoint,
    pub(super) exact_checkpoint_sha256: Sha256Digest,
    pub(super) exact_predecessor_checkpoint_sha256: Sha256Digest,
    pub(super) exact_checkpoint_sequence: u64,
    pub(super) exact_revocation_generation_high_water: u64,
    pub(super) exact_revocation_root_sha256: Sha256Digest,
    pub(super) rollback_floor_checkpoint_sequence: u64,
    pub(super) rollback_floor_endpoint_generation: u64,
    pub(super) rollback_floor_consumer_sequence: u64,
    pub(super) checkpoint_authority_key_id: Sha256Digest,
    pub(super) checkpoint_authority_key_spki_sha256: Sha256Digest,
    pub(super) checkpoint_authority_verifying_key: VerifyingKey,
}

impl CurrentKeyAuthorizationPin {
    fn validate_at(
        &self,
        expected_domain: BoottimeDomain,
        observed_at_boottime_nanos: u64,
    ) -> Result<(), EndpointClientError> {
        require_nonzero_digest(
            "currentKey.processIdentitySha256",
            &self.endpoint_process_identity_sha256,
        )?;
        require_nonzero_digest(
            "currentKey.signingKeyId",
            &self.signing_key_id,
        )?;
        require_nonzero_digest(
            "currentKey.signingKeySpkiSha256",
            &self.signing_key_spki_sha256,
        )?;
        require_nonzero_digest(
            "currentKey.checkpointSha256",
            &self.exact_checkpoint_sha256,
        )?;
        require_nonzero_digest(
            "currentKey.predecessorCheckpointSha256",
            &self.exact_predecessor_checkpoint_sha256,
        )?;
        require_nonzero_digest(
            "currentKey.revocationRootSha256",
            &self.exact_revocation_root_sha256,
        )?;
        require_nonzero_digest(
            "currentKey.checkpointAuthorityKeyId",
            &self.checkpoint_authority_key_id,
        )?;
        require_nonzero_digest(
            "currentKey.checkpointAuthorityKeySpkiSha256",
            &self.checkpoint_authority_key_spki_sha256,
        )?;
        self.signed_current_key_authorization.validate_shape()?;
        let signing_spki = self
            .verifying_key
            .to_public_key_der()
            .map_err(|_| {
                EndpointClientError::Invalid(
                    "current endpoint key cannot be encoded as SPKI DER",
                )
            })?;
        let authority_spki = self
            .checkpoint_authority_verifying_key
            .to_public_key_der()
            .map_err(|_| {
                EndpointClientError::Invalid(
                    "checkpoint authority key cannot be encoded as SPKI DER",
                )
            })?;
        let checkpoint = &self.signed_current_key_authorization;
        let payload = &checkpoint.payload;
        let valid_from = payload.valid_from_boottime.to_runtime()?;
        let valid_until = payload.valid_until_boottime.to_runtime()?;
        valid_from.require_expected_domain(expected_domain)?;
        valid_until.require_expected_domain(expected_domain)?;
        if self.exact_endpoint_generation == 0
            || self.exact_checkpoint_sequence == 0
            || self.exact_revocation_generation_high_water == 0
            || self.rollback_floor_checkpoint_sequence == 0
            || self.rollback_floor_endpoint_generation == 0
            || self.rollback_floor_consumer_sequence == 0
            || Sha256Digest::compute(signing_spki.as_bytes())
                != self.signing_key_spki_sha256
            || Sha256Digest::compute(authority_spki.as_bytes())
                != self.checkpoint_authority_key_spki_sha256
            || checkpoint.checkpoint_sha256
                != self.exact_checkpoint_sha256
            || payload.predecessor_checkpoint_sha256
                != self.exact_predecessor_checkpoint_sha256
            || checkpoint.authority_key_id
                != self.checkpoint_authority_key_id
            || checkpoint.authority_key_spki_sha256
                != self.checkpoint_authority_key_spki_sha256
            || payload.endpoint_role != self.endpoint_role
            || payload.endpoint_process_identity_sha256
                != self.endpoint_process_identity_sha256
            || payload.exact_endpoint_generation
                != self.exact_endpoint_generation
            || payload.authorized_signing_key_id
                != self.signing_key_id
            || payload.authorized_signing_key_spki_sha256
                != self.signing_key_spki_sha256
            || payload.checkpoint_sequence
                != self.exact_checkpoint_sequence
            || payload.revocation_generation_high_water
                != self.exact_revocation_generation_high_water
            || payload.revocation_root_sha256
                != self.exact_revocation_root_sha256
            || payload.rollback_floor_checkpoint_sequence
                != self.rollback_floor_checkpoint_sequence
            || payload.rollback_floor_endpoint_generation
                != self.rollback_floor_endpoint_generation
            || payload.rollback_floor_consumer_sequence
                != self.rollback_floor_consumer_sequence
            || self.exact_endpoint_generation
                < payload.rollback_floor_endpoint_generation
            || observed_at_boottime_nanos
                < payload
                    .valid_from_boottime
                    .absolute_boottime_nanos()
            || observed_at_boottime_nanos
                >= payload
                    .valid_until_boottime
                    .absolute_boottime_nanos()
        {
            return Err(EndpointClientError::Invalid(
                "current endpoint signing key authorization, revocation checkpoint, validity, or rollback floor mismatch",
            ));
        }
        verify_preimage_signature(
            &self.checkpoint_authority_verifying_key,
            &checkpoint.authority_signature_preimage()?,
            &checkpoint.authority_signature_base64,
        )
    }

    fn verify_claim(
        &self,
        expected_domain: BoottimeDomain,
        endpoint_role: PolicyCustodyEndpointRole,
        process_identity_sha256: &Sha256Digest,
        endpoint_generation: u64,
        checkpoint_sha256: &Sha256Digest,
        revocation_generation: u64,
        revocation_root_sha256: &Sha256Digest,
        signing_key_id: &Sha256Digest,
        signing_key_spki_sha256: &Sha256Digest,
        observed_at_boottime_nanos: u64,
    ) -> Result<(), EndpointClientError> {
        self.validate_at(
            expected_domain,
            observed_at_boottime_nanos,
        )?;
        if endpoint_role != self.endpoint_role
            || process_identity_sha256
                != &self.endpoint_process_identity_sha256
            || endpoint_generation != self.exact_endpoint_generation
            || checkpoint_sha256 != &self.exact_checkpoint_sha256
            || revocation_generation
                != self.exact_revocation_generation_high_water
            || revocation_root_sha256
                != &self.exact_revocation_root_sha256
            || signing_key_id != &self.signing_key_id
            || signing_key_spki_sha256
                != &self.signing_key_spki_sha256
        {
            return Err(EndpointClientError::Invalid(
                "endpoint signature does not use the exact currently authorized non-revoked key",
            ));
        }
        Ok(())
    }

    fn exact_checkpoint_matches(&self, other: &Self) -> bool {
        self.endpoint_role == other.endpoint_role
            && self.endpoint_process_identity_sha256
                == other.endpoint_process_identity_sha256
            && self.exact_endpoint_generation
                == other.exact_endpoint_generation
            && self.signing_key_id == other.signing_key_id
            && self.signing_key_spki_sha256
                == other.signing_key_spki_sha256
            && self.exact_checkpoint_sha256
                == other.exact_checkpoint_sha256
            && self.exact_checkpoint_sequence
                == other.exact_checkpoint_sequence
            && self.exact_revocation_generation_high_water
                == other.exact_revocation_generation_high_water
            && self.exact_revocation_root_sha256
                == other.exact_revocation_root_sha256
            && self.rollback_floor_checkpoint_sequence
                == other.rollback_floor_checkpoint_sequence
            && self.rollback_floor_endpoint_generation
                == other.rollback_floor_endpoint_generation
            && self.rollback_floor_consumer_sequence
                == other.rollback_floor_consumer_sequence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EndpointConsumeCursor {
    pub(super) sequence_high_water: u64,
    pub(super) expected_next_sequence: u64,
    pub(super) expected_predecessor_receipt_sha256: Sha256Digest,
}

impl EndpointConsumeCursor {
    fn validate(
        &self,
        rollback_floor_consumer_sequence: u64,
    ) -> Result<(), EndpointClientError> {
        require_nonzero_digest(
            "consumeCursor.predecessorReceiptSha256",
            &self.expected_predecessor_receipt_sha256,
        )?;
        if self.expected_next_sequence
                != self.sequence_high_water.checked_add(1).ok_or(
                    EndpointClientError::Invalid(
                        "endpoint consume sequence overflow",
                    ),
                )?
            || self.expected_next_sequence
                < rollback_floor_consumer_sequence
        {
            return Err(EndpointClientError::Invalid(
                "endpoint consume sequence high-water or rollback floor is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct EndpointTrustPin {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) socket_path: PathBuf,
    pub(super) endpoint_uid: u32,
    pub(super) endpoint_gid: u32,
    pub(super) endpoint_process_identity:
        EndpointProcessIdentity,
    pub(super) endpoint_process_identity_sha256: Sha256Digest,
    pub(super) exact_endpoint_generation: u64,
    pub(super) boottime_domain: BoottimeDomain,
    pub(super) current_key_authorization:
        CurrentKeyAuthorizationPin,
    pub(super) consume_cursor: EndpointConsumeCursor,
    pub(super) consume_head_observed_at_boottime_nanos: u64,
}

impl EndpointTrustPin {
    pub(super) fn validate(&self) -> Result<(), EndpointClientError> {
        self.boottime_domain.require_current()?;
        self.endpoint_process_identity.validate_shape()?;
        require_nonzero_digest(
            "endpointPin.processIdentitySha256",
            &self.endpoint_process_identity_sha256,
        )?;
        self.current_key_authorization.validate_at(
            self.boottime_domain,
            boottime_now_nanos()?,
        )?;
        self.consume_cursor.validate(
            self.current_key_authorization
                .rollback_floor_consumer_sequence,
        )?;
        if !self.socket_path.is_absolute()
            || self.socket_path.as_os_str().as_bytes().contains(&0)
            || self.exact_endpoint_generation == 0
            || self.endpoint_process_identity.endpoint_role
                != self.endpoint_role
            || self.endpoint_process_identity.endpoint_uid
                != self.endpoint_uid
            || self.endpoint_process_identity.endpoint_gid
                != self.endpoint_gid
            || self.endpoint_process_identity.identity_sha256
                != self.endpoint_process_identity_sha256
            || self.current_key_authorization.endpoint_role
                != self.endpoint_role
            || self
                .current_key_authorization
                .endpoint_process_identity_sha256
                != self.endpoint_process_identity_sha256
            || self.current_key_authorization.exact_endpoint_generation
                != self.exact_endpoint_generation
            || self.consume_head_observed_at_boottime_nanos == 0
            || self.consume_head_observed_at_boottime_nanos
                > boottime_now_nanos()?
        {
            return Err(EndpointClientError::Invalid(
                "endpoint trust pin is incomplete or internally inconsistent",
            ));
        }
        Ok(())
    }
}

pub(super) trait CurrentEndpointTrustProvider {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    /// Return a freshly verified current endpoint identity, key authorization,
    /// revocation checkpoint, and durable-consume cursor, or `None` when the
    /// progress descriptor must be polled.
    fn try_current_endpoint_trust_nonblocking(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<EndpointTrustPin>, EndpointClientError>;

    /// Verify the exact historical receipt, its signing checkpoint, and its
    /// inclusion in the current non-rolled-back durable-consume head.
    fn try_verify_historical_durable_consume_nonblocking(
        &mut self,
        request: HistoricalDurableConsumeVerification<'_>,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, EndpointClientError>;
}

#[derive(Clone, Copy)]
pub(super) struct HistoricalDurableConsumeVerification<'a> {
    pub(super) endpoint_role: PolicyCustodyEndpointRole,
    pub(super) persisted:
        &'a PersistedDurableConsumeReceiptV3,
    pub(super) identity: &'a SettlementIdentity,
    pub(super) current_head: &'a EndpointConsumeCursor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedHostNoTeeEndpointConfigCredential {
    api_version: String,
    attestation_mode: String,
    co_located: bool,
    hardware_proof: bool,
    maximum_frame_bytes: usize,
    endpoints: Vec<TrustedHostNoTeeEndpointBindingCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedHostNoTeeEndpointBindingCredential {
    endpoint_role: PolicyCustodyEndpointRole,
    socket_path: PathBuf,
    endpoint_uid: u32,
    endpoint_gid: u32,
    signed_floor_evidence_credential: String,
    checkpoint_authority_public_key_credential: String,
    checkpoint_authority_key_id: Sha256Digest,
    checkpoint_authority_key_spki_sha256: Sha256Digest,
    minimum_checkpoint_sequence: u64,
    minimum_endpoint_generation: u64,
    minimum_revocation_generation: u64,
    minimum_consumer_sequence: u64,
}

#[derive(Debug, Clone)]
struct TrustedHostNoTeeEndpointBinding {
    credential: TrustedHostNoTeeEndpointBindingCredential,
    checkpoint_authority_verifying_key: VerifyingKey,
    signed_floor: TrustedHostNoTeeAcceptedFloor,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TrustedHostNoTeeEndpointTrustReport {
    api_version: String,
    attestation_mode: String,
    authority_scope: String,
    co_located: bool,
    hardware_proof: bool,
    external_witness_count: u32,
    configuration_sha256: Sha256Digest,
}

impl TrustedHostNoTeeEndpointTrustReport {
    pub(super) fn attestation_mode(&self) -> &str {
        &self.attestation_mode
    }

    pub(super) fn authority_scope(&self) -> &str {
        &self.authority_scope
    }

    pub(super) fn co_located(&self) -> bool {
        self.co_located
    }

    pub(super) fn hardware_proof(&self) -> bool {
        self.hardware_proof
    }

    pub(super) fn configuration_sha256(&self) -> &Sha256Digest {
        &self.configuration_sha256
    }
}

impl From<&EndpointConsumeCursor>
    for TrustedHostNoTeeEndpointConsumeCursorWire
{
    fn from(cursor: &EndpointConsumeCursor) -> Self {
        Self {
            sequence_high_water: cursor.sequence_high_water,
            expected_next_sequence: cursor.expected_next_sequence,
            expected_predecessor_receipt_sha256: cursor
                .expected_predecessor_receipt_sha256
                .clone(),
        }
    }
}

impl From<TrustedHostNoTeeEndpointConsumeCursorWire>
    for EndpointConsumeCursor
{
    fn from(cursor: TrustedHostNoTeeEndpointConsumeCursorWire) -> Self {
        Self {
            sequence_high_water: cursor.sequence_high_water,
            expected_next_sequence: cursor.expected_next_sequence,
            expected_predecessor_receipt_sha256: cursor
                .expected_predecessor_receipt_sha256,
        }
    }
}

#[derive(Debug, Clone)]
struct TrustedHostNoTeeAcceptedFloor {
    current_key_authorization: CurrentKeyAuthorizationPin,
    consume_cursor: EndpointConsumeCursor,
    consume_head_observed_at_boottime_nanos: u64,
}

enum PendingTrustedHostRequest {
    Current {
        accepted_floor: TrustedHostNoTeeAcceptedFloor,
    },
    Historical {
        persisted: PersistedDurableConsumeReceiptV3,
        identity: SettlementIdentity,
        current_head: EndpointConsumeCursor,
        current_pin: EndpointTrustPin,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSocketStage {
    Connecting,
    Sending,
    Receiving,
}

struct PendingTrustedHostExchange {
    endpoint_role: PolicyCustodyEndpointRole,
    deadline: BoottimeDeadline,
    request_nonce_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    requested_at_boottime_nanos: u64,
    request_frame: Vec<u8>,
    maximum_frame_bytes: usize,
    endpoint_uid: u32,
    endpoint_gid: u32,
    socket: OwnedFd,
    stage: PendingSocketStage,
    attempt_now: bool,
    live_peer: Option<LiveEndpointProcess>,
    expected: PendingTrustedHostRequest,
}

pub(super) struct TrustedHostNoTeeEndpointTrustProvider {
    credential_directory: OwnedFd,
    bindings:
        BTreeMap<PolicyCustodyEndpointRole, TrustedHostNoTeeEndpointBinding>,
    maximum_frame_bytes: usize,
    progress_epoll: OwnedFd,
    pending: Option<PendingTrustedHostExchange>,
    accepted_current:
        BTreeMap<PolicyCustodyEndpointRole, EndpointTrustPin>,
    trust_report: TrustedHostNoTeeEndpointTrustReport,
}

impl TrustedHostNoTeeEndpointTrustProvider {
    pub(super) fn from_systemd_credentials(
        configuration_credential_name: &str,
        initialization_deadline: BoottimeDeadline,
    ) -> Result<Self, EndpointClientError> {
        initialization_deadline.require_live()?;
        let mut getrandom_capability_probe = [0_u8; 1];
        fill_getrandom_exact(&mut getrandom_capability_probe)?;
        let credential_directory = systemd_credentials_directory()?;
        let configuration_bytes = read_systemd_credential(
            &credential_directory,
            configuration_credential_name,
            MAX_SYSTEMD_CREDENTIAL_BYTES,
            initialization_deadline,
        )?;
        let configuration: TrustedHostNoTeeEndpointConfigCredential =
            decode_exact_canonical_json(&configuration_bytes)?;
        validate_trusted_host_configuration(&configuration)?;
        let configuration_sha256 =
            Sha256Digest::compute(&configuration_bytes);
        let mut bindings = BTreeMap::new();
        for credential in configuration.endpoints.iter().cloned() {
            initialization_deadline.require_live()?;
            let checkpoint_authority_verifying_key =
                read_systemd_verifying_key(
                    &credential_directory,
                    &credential
                        .checkpoint_authority_public_key_credential,
                    initialization_deadline,
                )?;
            validate_configured_verifying_key(
                &checkpoint_authority_verifying_key,
                &credential
                    .checkpoint_authority_key_spki_sha256,
                "checkpoint authority",
            )?;
            let signed_floor_bytes = read_systemd_credential(
                &credential_directory,
                &credential.signed_floor_evidence_credential,
                MAX_SYSTEMD_CREDENTIAL_BYTES,
                initialization_deadline,
            )?;
            let signed_floor_evidence:
                TrustedHostNoTeeSignedFloorEvidenceWire =
                decode_exact_canonical_json(&signed_floor_bytes)?;
            let signed_floor = validate_signed_floor_evidence(
                &credential,
                checkpoint_authority_verifying_key.clone(),
                signed_floor_evidence,
                initialization_deadline,
            )?;
            if signed_floor
                    .current_key_authorization
                    .verifying_key
                == checkpoint_authority_verifying_key
                || bindings
                    .insert(
                        credential.endpoint_role,
                        TrustedHostNoTeeEndpointBinding {
                            credential,
                            checkpoint_authority_verifying_key,
                            signed_floor,
                        },
                    )
                    .is_some()
            {
                return Err(EndpointClientError::Invalid(
                    "trusted-host endpoint role or verification key is duplicated",
                ));
            }
        }
        require_independent_signer_and_store_bindings(&bindings)?;
        initialization_deadline.require_live()?;
        Ok(Self {
            credential_directory,
            bindings,
            maximum_frame_bytes: configuration.maximum_frame_bytes,
            progress_epoll: create_progress_epoll()?,
            pending: None,
            accepted_current: BTreeMap::new(),
            trust_report: TrustedHostNoTeeEndpointTrustReport {
                api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_owned(),
                attestation_mode:
                    TRUSTED_HOST_NO_TEE_MODE.to_owned(),
                authority_scope:
                    TRUSTED_HOST_LOCAL_SCOPE.to_owned(),
                co_located: true,
                hardware_proof: false,
                external_witness_count: 0,
                configuration_sha256,
            },
        })
    }

    pub(super) fn trust_report(
        &self,
    ) -> &TrustedHostNoTeeEndpointTrustReport {
        &self.trust_report
    }

    pub(super) fn signed_endpoint_client_until(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        deadline: BoottimeDeadline,
    ) -> Result<PolicyCustodyEndpointClient, EndpointClientError> {
        let pin =
            current_endpoint_trust_until(self, endpoint_role, deadline)?;
        PolicyCustodyEndpointClient::new(
            pin,
            self.maximum_frame_bytes,
        )
    }

    pub(super) fn signed_signer_hsm_client_until(
        &mut self,
        deadline: BoottimeDeadline,
    ) -> Result<PolicyCustodyEndpointClient, EndpointClientError> {
        self.signed_endpoint_client_until(
            PolicyCustodyEndpointRole::SignerHsm,
            deadline,
        )
    }

    pub(super) fn signed_settlement_store_client_until(
        &mut self,
        deadline: BoottimeDeadline,
    ) -> Result<PolicyCustodyEndpointClient, EndpointClientError> {
        self.signed_endpoint_client_until(
            PolicyCustodyEndpointRole::SettlementStore,
            deadline,
        )
    }
}

pub(super) fn current_endpoint_trust_until<
    P: CurrentEndpointTrustProvider + ?Sized,
>(
    provider: &mut P,
    endpoint_role: PolicyCustodyEndpointRole,
    verification_deadline: BoottimeDeadline,
) -> Result<EndpointTrustPin, EndpointClientError> {
    let progress_fd = provider.progress_fd().as_raw_fd();
    loop {
        let token = verification_deadline.mutation_token()?;
        let attempted = token
            .execute_nonblocking(|| {
                provider.try_current_endpoint_trust_nonblocking(
                    endpoint_role,
                    &verification_deadline,
                )
            })
            .map_err(|error| match error {
                DeadlineOperationError::Authority(error) => {
                    EndpointClientError::Boottime(error)
                }
                DeadlineOperationError::Action(error) => error,
            })?;
        if !attempted.completed_before_deadline() {
            return Err(EndpointClientError::DeadlineExpired);
        }
        if let Some(pin) = attempted.into_value() {
            verification_deadline.require_live()?;
            return Ok(pin);
        }
        let descriptor =
            unsafe { BorrowedFd::borrow_raw(progress_fd) };
        match poll_until(
            verification_deadline,
            &[PollTarget::eventfd(descriptor)],
        )? {
            WaitOutcome::Progress(events)
                if events.iter().any(|event| {
                    event.readable()
                        || event.hung_up()
                        || event.errored()
                }) => {}
            WaitOutcome::Progress(_) => {
                return Err(EndpointClientError::Invalid(
                    "current-key progress descriptor woke without progress",
                ));
            }
            WaitOutcome::DeadlineExpired => {
                return Err(EndpointClientError::DeadlineExpired);
            }
        }
    }
}

fn verify_historical_durable_consume_until<
    P: CurrentEndpointTrustProvider + ?Sized,
>(
    provider: &mut P,
    request: HistoricalDurableConsumeVerification<'_>,
    verification_deadline: BoottimeDeadline,
) -> Result<(), EndpointClientError> {
    let progress_fd = provider.progress_fd().as_raw_fd();
    loop {
        let token = verification_deadline.mutation_token()?;
        let attempted = token
            .execute_nonblocking(|| {
                provider
                    .try_verify_historical_durable_consume_nonblocking(
                        request,
                        &verification_deadline,
                    )
            })
            .map_err(|error| match error {
                DeadlineOperationError::Authority(error) => {
                    EndpointClientError::Boottime(error)
                }
                DeadlineOperationError::Action(error) => error,
            })?;
        if !attempted.completed_before_deadline() {
            return Err(EndpointClientError::DeadlineExpired);
        }
        if attempted.into_value().is_some() {
            verification_deadline.require_live()?;
            return Ok(());
        }
        let descriptor =
            unsafe { BorrowedFd::borrow_raw(progress_fd) };
        match poll_until(
            verification_deadline,
            &[PollTarget::eventfd(descriptor)],
        )? {
            WaitOutcome::Progress(events)
                if events.iter().any(|event| {
                    event.readable()
                        || event.hung_up()
                        || event.errored()
                }) => {}
            WaitOutcome::Progress(_) => {
                return Err(EndpointClientError::Invalid(
                    "historical-consume verifier woke without progress",
                ));
            }
            WaitOutcome::DeadlineExpired => {
                return Err(EndpointClientError::DeadlineExpired);
            }
        }
    }
}

impl TrustedHostNoTeeEndpointTrustProvider {
    fn start_exchange(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        deadline: BoottimeDeadline,
        operation: TrustedHostNoTeeTrustOperationWire,
        expected: PendingTrustedHostRequest,
    ) -> Result<(), EndpointClientError> {
        if self.pending.is_some() {
            return Err(EndpointClientError::Invalid(
                "trusted-host endpoint provider already has an in-flight request",
            ));
        }
        let credential_directory_stat =
            descriptor_stat(self.credential_directory.as_raw_fd())?;
        if credential_directory_stat.mode & libc::S_IFMT as u32
            != libc::S_IFDIR as u32
        {
            return Err(EndpointClientError::Invalid(
                "retained CREDENTIALS_DIRECTORY descriptor is no longer a directory",
            ));
        }
        deadline.require_live()?;
        let binding = self.bindings.get(&endpoint_role).ok_or(
            EndpointClientError::Invalid(
                "trusted-host endpoint role is not configured",
            ),
        )?;
        let requested_at_boottime_nanos = boottime_now_nanos()?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(deadline);
        let mut request_entropy = [0_u8; 32];
        fill_getrandom_exact(&mut request_entropy)?;
        let request_entropy_base64 =
            URL_SAFE_NO_PAD.encode(request_entropy);
        let nonce_preimage = canonical_json_bytes(&(
            POLICY_CUSTODY_PROTOCOL_VERSION,
            endpoint_role,
            &request_entropy_base64,
            requested_at_boottime_nanos,
            &protocol_deadline,
            &operation,
        ))
        .map_err(|_| {
            EndpointClientError::Invalid(
                "trusted-host endpoint request nonce preimage is not canonical",
            )
        })?;
        let request_nonce_sha256 =
            Sha256Digest::compute(&nonce_preimage);
        require_nonzero_digest(
            "trustedHostRequest.requestNonceSha256",
            &request_nonce_sha256,
        )?;
        let request = TrustedHostNoTeeTrustRequestWire {
            api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_owned(),
            endpoint_role,
            request_nonce_sha256: request_nonce_sha256.clone(),
            request_entropy_base64,
            requested_at_boottime_nanos,
            deadline: protocol_deadline,
            operation,
        };
        request.validate_shape()?;
        let request_frame =
            canonical_json_bytes(&request).map_err(|_| {
                EndpointClientError::Invalid(
                    "trusted-host endpoint request is not canonical",
                )
            })?;
        if request_frame.is_empty()
            || request_frame.len() > self.maximum_frame_bytes
        {
            return Err(EndpointClientError::Invalid(
                "trusted-host endpoint request exceeds its configured frame bound",
            ));
        }
        let request_sha256 =
            endpoint_request_sha256(&request_frame);
        let (socket, connected) = start_seqpacket_nonblocking(
            &binding.credential.socket_path,
        )?;
        let stage = if connected {
            PendingSocketStage::Sending
        } else {
            PendingSocketStage::Connecting
        };
        register_progress_socket(
            self.progress_epoll.as_raw_fd(),
            socket.as_raw_fd(),
            PendingSocketStage::Sending,
        )?;
        self.pending = Some(PendingTrustedHostExchange {
            endpoint_role,
            deadline,
            request_nonce_sha256,
            request_sha256,
            requested_at_boottime_nanos,
            request_frame,
            maximum_frame_bytes: self.maximum_frame_bytes,
            endpoint_uid: binding.credential.endpoint_uid,
            endpoint_gid: binding.credential.endpoint_gid,
            socket,
            stage,
            attempt_now: connected,
            live_peer: None,
            expected,
        });
        Ok(())
    }

    fn ensure_current_exchange(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        deadline: BoottimeDeadline,
    ) -> Result<(), EndpointClientError> {
        if let Some(pending) = self.pending.as_ref() {
            if pending.endpoint_role == endpoint_role
                && pending.deadline == deadline
                && matches!(
                    &pending.expected,
                    PendingTrustedHostRequest::Current { .. }
                )
            {
                return Ok(());
            }
            return Err(EndpointClientError::Invalid(
                "trusted-host endpoint provider request changed while an exchange was pending",
            ));
        }
        let accepted_floor = if let Some(current) =
            self.accepted_current.get(&endpoint_role)
        {
            TrustedHostNoTeeAcceptedFloor {
                current_key_authorization:
                    current.current_key_authorization.clone(),
                consume_cursor: current.consume_cursor.clone(),
                consume_head_observed_at_boottime_nanos:
                    current.consume_head_observed_at_boottime_nanos,
            }
        } else {
            self.bindings
                .get(&endpoint_role)
                .ok_or(EndpointClientError::Invalid(
                    "trusted-host endpoint role has no signed startup floor",
                ))?
                .signed_floor
                .clone()
        };
        let accepted_floor_wire = TrustedHostNoTeeAcceptedFloorWire {
            checkpoint_sequence: accepted_floor
                .current_key_authorization
                .exact_checkpoint_sequence,
            checkpoint_sha256: accepted_floor
                .current_key_authorization
                .exact_checkpoint_sha256
                .clone(),
            consume_cursor:
                TrustedHostNoTeeEndpointConsumeCursorWire::from(
                    &accepted_floor.consume_cursor,
                ),
        };
        accepted_floor_wire.validate_shape()?;
        self.start_exchange(
            endpoint_role,
            deadline,
            TrustedHostNoTeeTrustOperationWire::CurrentEndpointTrust {
                accepted_floor: accepted_floor_wire,
            },
            PendingTrustedHostRequest::Current { accepted_floor },
        )
    }

    fn ensure_historical_exchange(
        &mut self,
        request: HistoricalDurableConsumeVerification<'_>,
        deadline: BoottimeDeadline,
    ) -> Result<(), EndpointClientError> {
        if let Some(pending) = self.pending.as_ref() {
            let matches_pending = match &pending.expected {
                PendingTrustedHostRequest::Historical {
                    persisted,
                    identity,
                    current_head,
                    ..
                } => {
                    persisted == request.persisted
                        && identity == request.identity
                        && current_head == request.current_head
                }
                PendingTrustedHostRequest::Current { .. } => false,
            };
            if pending.endpoint_role == request.endpoint_role
                && pending.deadline == deadline
                && matches_pending
            {
                return Ok(());
            }
            return Err(EndpointClientError::Invalid(
                "trusted-host historical verification changed while an exchange was pending",
            ));
        }
        request.current_head.validate(1)?;
        let current_pin = self
            .accepted_current
            .get(&request.endpoint_role)
            .cloned()
            .ok_or(EndpointClientError::Invalid(
                "historical verification requires a freshly accepted current endpoint head",
            ))?;
        if &current_pin.consume_cursor != request.current_head {
            return Err(EndpointClientError::Invalid(
                "historical verification current head is not the provider's accepted head",
            ));
        }
        self.start_exchange(
            request.endpoint_role,
            deadline,
            TrustedHostNoTeeTrustOperationWire::
                VerifyHistoricalDurableConsume {
                    persisted: request.persisted.clone(),
                    identity: request.identity.clone(),
                    expected_current_head:
                        TrustedHostNoTeeEndpointConsumeCursorWire::from(
                            request.current_head,
                        ),
                },
            PendingTrustedHostRequest::Historical {
                persisted: request.persisted.clone(),
                identity: request.identity.clone(),
                current_head: request.current_head.clone(),
                current_pin,
            },
        )
    }

    fn try_drive_exchange(
        &mut self,
    ) -> Result<
        Option<(PendingTrustedHostExchange, Vec<u8>)>,
        EndpointClientError,
    > {
        let epoll_fd = self.progress_epoll.as_raw_fd();
        let result = (|| {
            loop {
                let pending = self.pending.as_mut().ok_or(
                    EndpointClientError::Invalid(
                        "trusted-host endpoint exchange is absent",
                    ),
                )?;
                pending.deadline.require_live()?;
                let ready_events = if pending.attempt_now {
                    pending.attempt_now = false;
                    None
                } else {
                    match take_progress_socket_event(epoll_fd)? {
                        Some(events) => Some(events),
                        None => return Ok(None),
                    }
                };
                match pending.stage {
                    PendingSocketStage::Connecting => {
                        if ready_events.is_some_and(|events| {
                            events
                                & (libc::EPOLLERR as u32
                                    | libc::EPOLLHUP as u32)
                                != 0
                        }) {
                            return Err(EndpointClientError::Invalid(
                                "trusted-host endpoint connection failed",
                            ));
                        }
                        if ready_events.is_some_and(|events| {
                            events & libc::EPOLLOUT as u32 == 0
                        }) {
                            return Ok(None);
                        }
                        let socket_error = socket_pending_error(
                            pending.socket.as_raw_fd(),
                        )?;
                        if socket_error != 0 {
                            return Err(io::Error::from_raw_os_error(
                                socket_error,
                            )
                            .into());
                        }
                        validate_trusted_host_peer_credentials(
                            pending.socket.as_raw_fd(),
                            pending.endpoint_uid,
                            pending.endpoint_gid,
                        )?;
                        if let PendingTrustedHostRequest::Historical {
                            current_pin,
                            ..
                        } = &pending.expected
                        {
                            pending.live_peer = Some(
                                LiveEndpointProcess::observe(
                                    pending.socket.as_raw_fd(),
                                    current_pin,
                                )?,
                            );
                        }
                        pending.stage = PendingSocketStage::Sending;
                        pending.attempt_now = true;
                        modify_progress_socket(
                            epoll_fd,
                            pending.socket.as_raw_fd(),
                            PendingSocketStage::Sending,
                        )?;
                    }
                    PendingSocketStage::Sending => {
                        if ready_events.is_some_and(|events| {
                            events
                                & (libc::EPOLLERR as u32
                                    | libc::EPOLLHUP as u32)
                                != 0
                        }) {
                            return Err(EndpointClientError::Invalid(
                                "trusted-host endpoint closed before request send",
                            ));
                        }
                        if ready_events.is_some_and(|events| {
                            events & libc::EPOLLOUT as u32 == 0
                        }) {
                            return Ok(None);
                        }
                        validate_trusted_host_peer_credentials(
                            pending.socket.as_raw_fd(),
                            pending.endpoint_uid,
                            pending.endpoint_gid,
                        )?;
                        if pending.live_peer.is_none() {
                            if let PendingTrustedHostRequest::Historical {
                                current_pin,
                                ..
                            } = &pending.expected
                            {
                                pending.live_peer = Some(
                                    LiveEndpointProcess::observe(
                                        pending.socket.as_raw_fd(),
                                        current_pin,
                                    )?,
                                );
                            }
                        }
                        if !try_send_seqpacket_nonblocking(
                            pending.socket.as_raw_fd(),
                            &pending.request_frame,
                        )? {
                            return Ok(None);
                        }
                        pending.stage = PendingSocketStage::Receiving;
                        pending.attempt_now = true;
                        modify_progress_socket(
                            epoll_fd,
                            pending.socket.as_raw_fd(),
                            PendingSocketStage::Receiving,
                        )?;
                    }
                    PendingSocketStage::Receiving => {
                        if ready_events.is_some_and(|events| {
                            events & libc::EPOLLIN as u32 == 0
                                && events
                                    & (libc::EPOLLERR as u32
                                        | libc::EPOLLHUP as u32
                                        | libc::EPOLLRDHUP as u32)
                                    == 0
                        }) {
                            return Ok(None);
                        }
                        let frame =
                            match try_receive_seqpacket_nonblocking(
                                pending.socket.as_raw_fd(),
                                pending.maximum_frame_bytes,
                            )? {
                                Some(frame) => frame,
                                None => {
                                    if ready_events.is_some_and(
                                        |events| {
                                            events
                                                & (libc::EPOLLERR
                                                    as u32
                                                    | libc::EPOLLHUP
                                                        as u32
                                                    | libc::EPOLLRDHUP
                                                        as u32)
                                                != 0
                                        },
                                    ) {
                                        return Err(
                                            EndpointClientError::Invalid(
                                                "trusted-host endpoint closed without a response",
                                            ),
                                        );
                                    }
                                    return Ok(None);
                                }
                            };
                        let socket_fd =
                            pending.socket.as_raw_fd();
                        unregister_progress_socket(epoll_fd, socket_fd)?;
                        let completed = self.pending.take().ok_or(
                            EndpointClientError::Invalid(
                                "trusted-host endpoint exchange disappeared",
                            ),
                        )?;
                        return Ok(Some((completed, frame)));
                    }
                }
            }
        })();
        if result.is_err() {
            self.discard_pending_exchange();
        }
        result
    }

    fn discard_pending_exchange(&mut self) {
        if let Some(pending) = self.pending.take() {
            let _ = unregister_progress_socket(
                self.progress_epoll.as_raw_fd(),
                pending.socket.as_raw_fd(),
            );
        }
    }

    fn accept_current_pin(
        &mut self,
        pin: EndpointTrustPin,
    ) -> Result<EndpointTrustPin, EndpointClientError> {
        pin.validate()?;
        if let Some(previous) =
            self.accepted_current.get(&pin.endpoint_role)
        {
            require_monotonic_accepted_current(previous, &pin)?;
            let previous_authority =
                &previous.current_key_authorization;
            let next_authority =
                &pin.current_key_authorization;
            if (previous_authority.exact_checkpoint_sequence
                    == next_authority.exact_checkpoint_sequence
                && (!previous_authority
                    .exact_checkpoint_matches(next_authority)
                    || previous_authority
                        .exact_revocation_root_sha256
                        != next_authority
                            .exact_revocation_root_sha256))
                || (previous_authority
                    .exact_revocation_generation_high_water
                    == next_authority
                        .exact_revocation_generation_high_water
                    && previous_authority
                        .exact_revocation_root_sha256
                        != next_authority
                            .exact_revocation_root_sha256)
                || (previous.consume_cursor.sequence_high_water
                    == pin.consume_cursor.sequence_high_water
                    && previous
                        .consume_cursor
                        .expected_predecessor_receipt_sha256
                        != pin
                            .consume_cursor
                            .expected_predecessor_receipt_sha256)
            {
                return Err(EndpointClientError::Invalid(
                    "trusted-host endpoint checkpoint, revocation root, or consume receipt equivocated",
                ));
            }
        }
        self.accepted_current
            .insert(pin.endpoint_role, pin.clone());
        Ok(pin)
    }
}

impl CurrentEndpointTrustProvider
    for TrustedHostNoTeeEndpointTrustProvider
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_epoll.as_fd()
    }

    fn try_current_endpoint_trust_nonblocking(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<EndpointTrustPin>, EndpointClientError> {
        verification_deadline.require_live()?;
        self.ensure_current_exchange(
            endpoint_role,
            *verification_deadline,
        )?;
        let Some((pending, frame)) = self.try_drive_exchange()? else {
            return Ok(None);
        };
        let binding = self.bindings.get(&endpoint_role).ok_or(
            EndpointClientError::Invalid(
                "trusted-host endpoint binding disappeared",
            ),
        )?;
        let pin = verify_trusted_host_current_response(
            binding,
            &pending,
            &frame,
        )?;
        verification_deadline.require_live()?;
        Ok(Some(self.accept_current_pin(pin)?))
    }

    fn try_verify_historical_durable_consume_nonblocking(
        &mut self,
        request: HistoricalDurableConsumeVerification<'_>,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, EndpointClientError> {
        verification_deadline.require_live()?;
        self.ensure_historical_exchange(
            request,
            *verification_deadline,
        )?;
        let Some((mut pending, frame)) =
            self.try_drive_exchange()?
        else {
            return Ok(None);
        };
        let binding = self
            .bindings
            .get(&request.endpoint_role)
            .ok_or(EndpointClientError::Invalid(
                "trusted-host historical endpoint binding disappeared",
            ))?;
        verify_trusted_host_historical_response(
            binding,
            &mut pending,
            &frame,
        )?;
        verification_deadline.require_live()?;
        Ok(Some(()))
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedEndpointResponse<R> {
    response: R,
    signed_envelope: SignedEndpointResponseEnvelope,
    exact_signed_envelope_bytes: Vec<u8>,
    exact_canonical_response_bytes: Vec<u8>,
    exact_signature_payload_bytes: Vec<u8>,
}

impl<R> VerifiedEndpointResponse<R> {
    pub(super) fn response(&self) -> &R {
        &self.response
    }

    pub(super) fn signed_envelope(
        &self,
    ) -> &SignedEndpointResponseEnvelope {
        &self.signed_envelope
    }

    pub(super) fn exact_signed_envelope_bytes(&self) -> &[u8] {
        &self.exact_signed_envelope_bytes
    }

    pub(super) fn exact_canonical_response_bytes(&self) -> &[u8] {
        &self.exact_canonical_response_bytes
    }

    pub(super) fn exact_signature_payload_bytes(&self) -> &[u8] {
        &self.exact_signature_payload_bytes
    }

    pub(super) fn authorize_exact_binding_with_current_provider<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        provider: &mut P,
        exact_binding_sha256: &Sha256Digest,
        verification_deadline: BoottimeDeadline,
    ) -> Result<
        VerifiedCurrentKeyEndpointAuthorization,
        EndpointClientError,
    > {
        if &self.signed_envelope.response_sha256
            != exact_binding_sha256
        {
            return Err(EndpointClientError::Invalid(
                "signed current-key endpoint response does not authorize the exact binding",
            ));
        }
        let before = current_endpoint_trust_until(
            provider,
            self.signed_envelope.endpoint_role,
            verification_deadline,
        )?;
        before.current_key_authorization.verify_claim(
            before.boottime_domain,
            self.signed_envelope.endpoint_role,
            &self
                .signed_envelope
                .endpoint_process_identity_sha256,
            self.signed_envelope.endpoint_generation,
            &self
                .signed_envelope
                .current_key_authorization_checkpoint_sha256,
            self.signed_envelope.revocation_generation,
            &self.signed_envelope.revocation_root_sha256,
            &self.signed_envelope.signing_key_id,
            &self.signed_envelope.signing_key_spki_sha256,
            boottime_now_nanos()?,
        )?;
        let verified = VerifiedCurrentKeyEndpointAuthorization {
            endpoint_role: self.signed_envelope.endpoint_role,
            endpoint_process_identity_sha256: self
                .signed_envelope
                .endpoint_process_identity_sha256
                .clone(),
            endpoint_generation: self.signed_envelope.endpoint_generation,
            current_key_authorization_checkpoint_sha256: self
                .signed_envelope
                .current_key_authorization_checkpoint_sha256
                .clone(),
            revocation_generation: self
                .signed_envelope
                .revocation_generation,
            revocation_root_sha256: self
                .signed_envelope
                .revocation_root_sha256
                .clone(),
            signing_key_id: self.signed_envelope.signing_key_id.clone(),
            signing_key_spki_sha256: self
                .signed_envelope
                .signing_key_spki_sha256
                .clone(),
            exact_binding_sha256: exact_binding_sha256.clone(),
            exact_signed_envelope_bytes: self
                .exact_signed_envelope_bytes
                .clone(),
        };
        verification_deadline.require_live()?;
        let after = current_endpoint_trust_until(
            provider,
            self.signed_envelope.endpoint_role,
            verification_deadline,
        )?;
        require_same_current_checkpoint(&before, &after)?;
        after.current_key_authorization.verify_claim(
            after.boottime_domain,
            self.signed_envelope.endpoint_role,
            &self
                .signed_envelope
                .endpoint_process_identity_sha256,
            self.signed_envelope.endpoint_generation,
            &self
                .signed_envelope
                .current_key_authorization_checkpoint_sha256,
            self.signed_envelope.revocation_generation,
            &self.signed_envelope.revocation_root_sha256,
            &self.signed_envelope.signing_key_id,
            &self.signed_envelope.signing_key_spki_sha256,
            boottime_now_nanos()?,
        )?;
        verification_deadline.require_live()?;
        Ok(verified)
    }
}

/// This capability cannot be constructed outside endpoint verification. It
/// proves that a named binding was signed by the exact currently authorized,
/// non-revoked endpoint key.
#[derive(Debug, Clone)]
pub(super) struct VerifiedCurrentKeyEndpointAuthorization {
    endpoint_role: PolicyCustodyEndpointRole,
    endpoint_process_identity_sha256: Sha256Digest,
    endpoint_generation: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    exact_binding_sha256: Sha256Digest,
    exact_signed_envelope_bytes: Vec<u8>,
}

impl VerifiedCurrentKeyEndpointAuthorization {
    pub(super) fn endpoint_role(&self) -> PolicyCustodyEndpointRole {
        self.endpoint_role
    }

    pub(super) fn exact_binding_sha256(&self) -> &Sha256Digest {
        &self.exact_binding_sha256
    }

    pub(super) fn authority_key_id(&self) -> &Sha256Digest {
        &self.signing_key_id
    }

    pub(super) fn checkpoint_sha256(&self) -> &Sha256Digest {
        &self.current_key_authorization_checkpoint_sha256
    }

    pub(super) fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    pub(super) fn revocation_root_sha256(&self) -> &Sha256Digest {
        &self.revocation_root_sha256
    }

    pub(super) fn exact_signed_envelope_bytes(&self) -> &[u8] {
        &self.exact_signed_envelope_bytes
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedDurableConsumeReceipt {
    statement: DurableConsumeStatement,
    signed_envelope: SignedDurableConsumeReceiptEnvelope,
    exact_signed_envelope_bytes: Vec<u8>,
    exact_canonical_statement_bytes: Vec<u8>,
    exact_signature_payload_bytes: Vec<u8>,
}

impl VerifiedDurableConsumeReceipt {
    pub(super) fn statement(&self) -> &DurableConsumeStatement {
        &self.statement
    }

    pub(super) fn signed_envelope(
        &self,
    ) -> &SignedDurableConsumeReceiptEnvelope {
        &self.signed_envelope
    }

    pub(super) fn exact_signed_envelope_bytes(&self) -> &[u8] {
        &self.exact_signed_envelope_bytes
    }

    pub(super) fn exact_canonical_statement_bytes(&self) -> &[u8] {
        &self.exact_canonical_statement_bytes
    }

    pub(super) fn exact_signature_payload_bytes(&self) -> &[u8] {
        &self.exact_signature_payload_bytes
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedIndependentDurableConsumes {
    atomicity_model: DurableConsumeAtomicityModel,
    signer_hsm: VerifiedDurableConsumeReceipt,
    settlement_store: VerifiedDurableConsumeReceipt,
}

impl VerifiedIndependentDurableConsumes {
    pub(super) fn atomicity_model(
        &self,
    ) -> DurableConsumeAtomicityModel {
        self.atomicity_model
    }

    pub(super) fn signer_hsm(
        &self,
    ) -> &VerifiedDurableConsumeReceipt {
        &self.signer_hsm
    }

    pub(super) fn settlement_store(
        &self,
    ) -> &VerifiedDurableConsumeReceipt {
        &self.settlement_store
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettlementRecoveryDisposition {
    Applied,
    AlreadyApplied,
    Conflict,
}

#[derive(Debug, Clone)]
pub(super) struct SettlementRecoveryTrace {
    pub(super) disposition: SettlementRecoveryDisposition,
    pub(super) before:
        VerifiedEndpointResponse<SettlementQueryReply>,
    pub(super) compare_and_swap:
        VerifiedEndpointResponse<SettlementCasReply>,
    pub(super) after:
        VerifiedEndpointResponse<SettlementQueryReply>,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedSignedCleanupAuthorization {
    authorization: SignedCleanupAuthorizationV3,
    exact_signed_authorization_bytes: Vec<u8>,
    exact_canonical_signature_payload_bytes: Vec<u8>,
    exact_signature_preimage_bytes: Vec<u8>,
}

impl VerifiedSignedCleanupAuthorization {
    pub(super) fn authorization(
        &self,
    ) -> &SignedCleanupAuthorizationV3 {
        &self.authorization
    }

    pub(super) fn exact_signed_authorization_bytes(&self) -> &[u8] {
        &self.exact_signed_authorization_bytes
    }

    pub(super) fn exact_canonical_signature_payload_bytes(
        &self,
    ) -> &[u8] {
        &self.exact_canonical_signature_payload_bytes
    }

    pub(super) fn exact_signature_preimage_bytes(&self) -> &[u8] {
        &self.exact_signature_preimage_bytes
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedCleanupConsumption {
    persisted: PersistedCleanupAuthorizationConsumptionV3,
    exact_signature_payload_bytes: Vec<u8>,
}

impl VerifiedCleanupConsumption {
    pub(super) fn statement(
        &self,
    ) -> &CleanupAuthorizationConsumptionStatement {
        &self.persisted.statement
    }

    pub(super) fn signed_envelope(
        &self,
    ) -> &SignedDurableConsumeReceiptEnvelope {
        &self.persisted.signed_envelope
    }

    pub(super) fn exact_signed_consumption_bytes(&self) -> &[u8] {
        &self.persisted.exact_signed_envelope_bytes
    }

    pub(super) fn exact_canonical_statement_bytes(&self) -> &[u8] {
        &self.persisted.exact_canonical_statement_bytes
    }

    pub(super) fn exact_signature_payload_bytes(&self) -> &[u8] {
        &self.exact_signature_payload_bytes
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedCleanupQueryResponse {
    pub(super) endpoint_response:
        VerifiedEndpointResponse<CleanupConsumptionQueryReply>,
    authoritative_consumption: Option<VerifiedCleanupConsumption>,
    authoritative_cursor: VerifiedCleanupCursor,
}

impl VerifiedCleanupQueryResponse {
    pub(super) fn authoritative_consumption(
        &self,
    ) -> Option<&VerifiedCleanupConsumption> {
        self.authoritative_consumption.as_ref()
    }

    pub(super) fn authoritative_cursor(&self) -> &VerifiedCleanupCursor {
        &self.authoritative_cursor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CleanupRecoveryDisposition {
    Applied,
    AlreadyApplied,
    Conflict,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedCleanupCasResponse {
    pub(super) endpoint_response:
        VerifiedEndpointResponse<CleanupConsumptionCasReply>,
    pub(super) disposition: CleanupRecoveryDisposition,
    consumption: Option<VerifiedCleanupConsumption>,
    authoritative_cursor: VerifiedCleanupCursor,
}

impl VerifiedCleanupCasResponse {
    pub(super) fn consumption(
        &self,
    ) -> Option<&VerifiedCleanupConsumption> {
        self.consumption.as_ref()
    }

    pub(super) fn authoritative_cursor(&self) -> &VerifiedCleanupCursor {
        &self.authoritative_cursor
    }
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedCleanupCursor {
    signed_cursor: SignedCleanupConsumptionCursorV3,
    exact_signature_payload_bytes: Vec<u8>,
}

impl VerifiedCleanupCursor {
    pub(super) fn signed_cursor(
        &self,
    ) -> &SignedCleanupConsumptionCursorV3 {
        &self.signed_cursor
    }

    pub(super) fn sequence_high_water(&self) -> u64 {
        self.signed_cursor.cursor.sequence_high_water
    }

    pub(super) fn predecessor_receipt_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.signed_cursor.cursor.predecessor_receipt_sha256
    }
}

#[derive(Debug, Clone)]
pub(super) struct CleanupConsumptionRecoveryTrace {
    pub(super) before: VerifiedCleanupQueryResponse,
    pub(super) compare_and_swap: VerifiedCleanupCasResponse,
    pub(super) after: VerifiedCleanupQueryResponse,
}

pub(super) struct PolicyCustodyEndpointClient {
    pin: EndpointTrustPin,
    maximum_frame_bytes: usize,
}

impl PolicyCustodyEndpointClient {
    pub(super) fn new(
        pin: EndpointTrustPin,
        maximum_frame_bytes: usize,
    ) -> Result<Self, EndpointClientError> {
        pin.validate()?;
        if maximum_frame_bytes == 0
            || maximum_frame_bytes > MAX_ENDPOINT_FRAME_BYTES
        {
            return Err(EndpointClientError::Invalid(
                "endpoint frame bound is invalid",
            ));
        }
        Ok(Self {
            pin,
            maximum_frame_bytes,
        })
    }

    pub(super) fn pin(&self) -> &EndpointTrustPin {
        &self.pin
    }

    fn require_role(
        &self,
        expected_role: PolicyCustodyEndpointRole,
    ) -> Result<(), EndpointClientError> {
        if self.pin.endpoint_role != expected_role {
            return Err(EndpointClientError::Invalid(
                "endpoint client role does not authorize this operation",
            ));
        }
        Ok(())
    }

    pub(super) fn current_durable_consume_request<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        identity: SettlementIdentity,
        consume_nonce_sha256: Sha256Digest,
        issued_at_boottime_nanos: u64,
    ) -> Result<DurableConsumeRequestV3, EndpointClientError> {
        if !matches!(
            self.pin.endpoint_role,
            PolicyCustodyEndpointRole::SignerHsm
                | PolicyCustodyEndpointRole::SettlementStore
        ) {
            return Err(EndpointClientError::Invalid(
                "durable-consume request producer requires a SignerHsm or SettlementStore client",
            ));
        }
        identity.validate()?;
        let runtime_deadline =
            identity.operation_deadline.to_runtime()?;
        let current = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(&self.pin, &current)?;
        let request = DurableConsumeRequestV3 {
            api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_owned(),
            identity,
            consumer_role: self.pin.endpoint_role,
            consume_nonce_sha256,
            expected_consumer_generation:
                current.exact_endpoint_generation,
            expected_consumer_sequence:
                current.consume_cursor.expected_next_sequence,
            expected_predecessor_receipt_sha256: current
                .consume_cursor
                .expected_predecessor_receipt_sha256,
            issued_at_boottime_nanos,
            deadline: ProtocolBoottimeDeadline::from_runtime(
                runtime_deadline,
            ),
        };
        request.validate()?;
        Ok(request)
    }

    pub(super) fn durably_consume<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        request: &DurableConsumeRequestV3,
    ) -> Result<VerifiedDurableConsumeReceipt, EndpointClientError> {
        request.validate()?;
        self.require_role(request.consumer_role)?;
        if !matches!(
            request.consumer_role,
            PolicyCustodyEndpointRole::SignerHsm
                | PolicyCustodyEndpointRole::SettlementStore
        ) {
            return Err(EndpointClientError::Invalid(
                "durable consume is forbidden for this endpoint role",
            ));
        }
        let runtime_deadline = request.deadline.to_runtime()?;
        let current_before = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(&self.pin, &current_before)?;
        if request.expected_consumer_generation
                != current_before.exact_endpoint_generation
            || request.expected_consumer_sequence
                != current_before
                    .consume_cursor
                    .expected_next_sequence
            || request.expected_predecessor_receipt_sha256
                != current_before
                    .consume_cursor
                    .expected_predecessor_receipt_sha256
        {
            return Err(EndpointClientError::Invalid(
                "durable-consume request does not bind the fresh current generation and consume cursor",
            ));
        }
        let response: VerifiedEndpointResponse<
            PersistedDurableConsumeReceiptV3,
        > = self.round_trip(
            current_trust,
            EndpointRequestKind::DurableConsume,
            &request.consume_nonce_sha256,
            request,
            &request.deadline,
        )?;
        let persisted = response.response();
        let statement = &persisted.statement;
        if statement.consumer_role != request.consumer_role
            || statement.consume_nonce_sha256
                != request.consume_nonce_sha256
            || statement.consumer_generation
                != request.expected_consumer_generation
            || statement.consumer_sequence
                != request.expected_consumer_sequence
            || statement.predecessor_receipt_sha256
                != request.expected_predecessor_receipt_sha256
            || statement.consumed_at_boottime_nanos
                < request.issued_at_boottime_nanos
            || statement.consumed_at_boottime_nanos
                > response
                    .signed_envelope()
                    .observed_at_boottime_nanos
        {
            return Err(EndpointClientError::Invalid(
                "durable-consume receipt changed the exact request, current cursor, or BOOTTIME ordering",
            ));
        }
        verify_durable_consume_receipt(
            persisted,
            &request.identity,
            &current_before,
            &request.deadline,
        )
    }

    pub(super) fn verify_cleanup_authorization(
        authority: &CurrentKeyAuthorizationPin,
        exact_signed_authorization_bytes: &[u8],
        predecessor: &DurableSettlementRecord,
    ) -> Result<
        VerifiedSignedCleanupAuthorization,
        EndpointClientError,
    > {
        let authorization: SignedCleanupAuthorizationV3 =
            decode_exact_canonical_json(exact_signed_authorization_bytes)?;
        authorization.validate_shape()?;
        authorization.payload.validate_against(predecessor)?;
        let runtime_deadline = authorization
            .payload
            .absolute_boottime_deadline
            .to_runtime()?;
        let expected_domain = runtime_deadline.domain();
        let now = boottime_now_nanos()?;
        authority.verify_claim(
            expected_domain,
            PolicyCustodyEndpointRole::CleanupWatchdog,
            &authority.endpoint_process_identity_sha256,
            authority.exact_endpoint_generation,
            &authorization
                .current_key_authorization_checkpoint_sha256,
            authorization.revocation_generation,
            &authorization.revocation_root_sha256,
            &authorization.authority_key_id,
            &authorization.authority_key_spki_sha256,
            now,
        )?;
        if authorization.payload.executor_role
                != PolicyCustodyEndpointRole::CleanupWatchdog
            || authority.endpoint_role
                != PolicyCustodyEndpointRole::CleanupWatchdog
        {
            return Err(EndpointClientError::Invalid(
                "cleanup authorization was not issued by the cleanup watchdog role",
            ));
        }
        let signature_payload =
            authorization.canonical_signature_payload()?;
        let signature_preimage =
            authorization.authority_signature_preimage()?;
        verify_preimage_signature(
            &authority.verifying_key,
            &signature_preimage,
            &authorization.authority_signature_base64,
        )?;
        runtime_deadline.require_expected_domain(expected_domain)?;
        runtime_deadline.require_live()?;
        authority.validate_at(expected_domain, boottime_now_nanos()?)?;
        Ok(VerifiedSignedCleanupAuthorization {
            authorization,
            exact_signed_authorization_bytes:
                exact_signed_authorization_bytes.to_vec(),
            exact_canonical_signature_payload_bytes: signature_payload,
            exact_signature_preimage_bytes: signature_preimage,
        })
    }

    pub(super) fn query_settlement<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        query: &SettlementQuery,
    ) -> Result<
        VerifiedEndpointResponse<SettlementQueryReply>,
        EndpointClientError,
    > {
        query.validate()?;
        self.require_role(PolicyCustodyEndpointRole::SettlementStore)?;
        let command = SettlementCommand::Query(query.clone());
        let response: VerifiedEndpointResponse<SettlementQueryReply> =
            self.round_trip(
            current_trust,
            EndpointRequestKind::SettlementQuery,
            &query.query_nonce_sha256,
            &command,
            &query.deadline,
        )?;
        response.response.validate(&query.identity)?;
        self.recheck_local_deadline(&query.deadline)?;
        Ok(response)
    }

    fn compare_and_swap_settlement<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        request: &SettlementCompareAndSwap,
    ) -> Result<
        VerifiedEndpointResponse<SettlementCasReply>,
        EndpointClientError,
    > {
        request.validate_shape()?;
        self.require_role(PolicyCustodyEndpointRole::SettlementStore)?;
        let command =
            SettlementCommand::CompareAndSwap(request.clone());
        let response = self.round_trip(
            current_trust,
            EndpointRequestKind::SettlementCompareAndSwap,
            &request.transition.transition_nonce_sha256,
            &command,
            &request.deadline,
        )?;
        validate_compare_and_swap_reply(request, &response.response)?;
        self.recheck_local_deadline(&request.deadline)?;
        Ok(response)
    }

    pub(super) fn query_compare_and_swap_query<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        before_query: &SettlementQuery,
        request: &SettlementCompareAndSwap,
        after_query: &SettlementQuery,
    ) -> Result<SettlementRecoveryTrace, EndpointClientError> {
        self.require_role(PolicyCustodyEndpointRole::SettlementStore)?;
        let runtime_deadline = request.deadline.to_runtime()?;
        let operation_before = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(&self.pin, &operation_before)?;
        if before_query.identity != request.identity
            || after_query.identity != request.identity
            || before_query.deadline != request.deadline
            || after_query.deadline != request.deadline
            || before_query.query_nonce_sha256
                == after_query.query_nonce_sha256
            || before_query.query_nonce_sha256
                == request.transition.transition_nonce_sha256
            || after_query.query_nonce_sha256
                == request.transition.transition_nonce_sha256
        {
            return Err(EndpointClientError::Invalid(
                "query/CAS/query identity, deadline, or one-use nonce mismatch",
            ));
        }
        let before =
            self.query_settlement(current_trust, before_query)?;
        let predecessor = before
            .response
            .canonical_state_chain
            .iter()
            .find(|state| {
                SettlementStateReference::from_record(state)
                    == request.expected
            })
            .ok_or(EndpointClientError::Invalid(
                "pre-CAS canonical state chain omits the exact predecessor",
            ))?;
        request.validate(predecessor)?;
        let compare_and_swap = self.compare_and_swap_settlement(
            current_trust,
            request,
        )?;
        let disposition = match &compare_and_swap.response {
            SettlementCasReply::Applied { .. } => {
                SettlementRecoveryDisposition::Applied
            }
            SettlementCasReply::AlreadyApplied { .. } => {
                SettlementRecoveryDisposition::AlreadyApplied
            }
            SettlementCasReply::Conflict { .. } => {
                SettlementRecoveryDisposition::Conflict
            }
        };
        let after =
            self.query_settlement(current_trust, after_query)?;
        validate_recovery_observation(
            request,
            &compare_and_swap.response,
            &after.response,
        )?;
        let operation_after = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(
            &operation_before,
            &operation_after,
        )?;
        self.recheck_local_deadline(&request.deadline)?;
        Ok(SettlementRecoveryTrace {
            disposition,
            before,
            compare_and_swap,
            after,
        })
    }

    pub(super) fn consume_cleanup_authorization<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        verified_authorization:
            &VerifiedSignedCleanupAuthorization,
        before_query: &CleanupConsumptionQuery,
        compare_and_swap: &CleanupConsumptionCompareAndSwap,
        after_query: &CleanupConsumptionQuery,
    ) -> Result<
        CleanupConsumptionRecoveryTrace,
        EndpointClientError,
    > {
        let authorization = verified_authorization.authorization();
        if !matches!(
            self.pin.endpoint_role,
            PolicyCustodyEndpointRole::FenceAuthority
                | PolicyCustodyEndpointRole::CgroupExecutor
                | PolicyCustodyEndpointRole::SettlementStore
                | PolicyCustodyEndpointRole::TerminationLedger
        ) {
            return Err(EndpointClientError::Invalid(
                "cleanup consumption client role is not authorized for cleanup Query/CAS",
            ));
        }
        let runtime_deadline =
            compare_and_swap.deadline.to_runtime()?;
        let current_before = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        before_query.validate()?;
        compare_and_swap.validate_shape()?;
        after_query.validate()?;
        if self.pin.endpoint_role
                != authorization.payload.endpoint_role
            || &compare_and_swap.authorization != authorization
            || compare_and_swap.expected_consumer_sequence_high_water
                != current_before.consume_cursor.sequence_high_water
            || compare_and_swap.expected_predecessor_receipt_sha256
                != current_before
                    .consume_cursor
                    .expected_predecessor_receipt_sha256
            || before_query.authorization_nonce_sha256
                != authorization.payload.authorization_nonce_sha256
            || after_query.authorization_nonce_sha256
                != authorization.payload.authorization_nonce_sha256
            || before_query.deadline != compare_and_swap.deadline
            || after_query.deadline != compare_and_swap.deadline
            || before_query.query_nonce_sha256
                == after_query.query_nonce_sha256
            || before_query.query_nonce_sha256
                == compare_and_swap.cas_nonce_sha256
            || after_query.query_nonce_sha256
                == compare_and_swap.cas_nonce_sha256
        {
            return Err(EndpointClientError::Invalid(
                "cleanup Query/CAS/Query binding, cursor, role, or nonce mismatch",
            ));
        }
        let before = self.query_cleanup_consumption(
            current_trust,
            before_query,
            Some(&current_before.consume_cursor),
        )?;
        let cas = self.compare_and_swap_cleanup_consumption(
            current_trust,
            verified_authorization,
            compare_and_swap,
        )?;
        validate_cleanup_retry_semantics(
            before.authoritative_consumption(),
            &cas,
            authorization,
        )?;
        let after = self.query_cleanup_consumption(
            current_trust,
            after_query,
            None,
        )?;
        if after.authoritative_cursor().signed_cursor
            != cas.authoritative_cursor().signed_cursor
        {
            return Err(EndpointClientError::Invalid(
                "post-CAS cleanup query did not return the exact signed authoritative cursor",
            ));
        }
        match (after.authoritative_consumption(), cas.consumption()) {
            (Some(after_consumption), Some(cas_consumption))
                if after_consumption.exact_signed_consumption_bytes()
                    == cas_consumption
                        .exact_signed_consumption_bytes() => {}
            (None, None)
                if cas.disposition
                    == CleanupRecoveryDisposition::Conflict => {}
            _ => {
                return Err(EndpointClientError::Invalid(
                    "post-CAS cleanup query did not preserve the exact optional durable consumption",
                ));
            }
        }
        let current_after = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_monotonic_current_head(
            &current_before,
            &current_after,
        )?;
        require_same_current_authority(
            &current_before,
            &current_after,
        )?;
        if current_after.consume_cursor.sequence_high_water
                != after
                    .authoritative_cursor()
                    .sequence_high_water()
            || current_after
                .consume_cursor
                .expected_predecessor_receipt_sha256
                != *after
                    .authoritative_cursor()
                    .predecessor_receipt_sha256()
        {
            return Err(EndpointClientError::Invalid(
                "post-CAS current durable-consume head does not match the signed authoritative cursor",
            ));
        }
        self.recheck_local_deadline(&compare_and_swap.deadline)?;
        Ok(CleanupConsumptionRecoveryTrace {
            before,
            compare_and_swap: cas,
            after,
        })
    }

    fn query_cleanup_consumption<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        query: &CleanupConsumptionQuery,
        expected_cursor: Option<&EndpointConsumeCursor>,
    ) -> Result<VerifiedCleanupQueryResponse, EndpointClientError> {
        query.validate()?;
        let command = CleanupConsumptionCommand::Query(query.clone());
        let endpoint_response: VerifiedEndpointResponse<
            CleanupConsumptionQueryReply,
        > = self.round_trip(
            current_trust,
            EndpointRequestKind::CleanupAuthorizationQuery,
            &query.query_nonce_sha256,
            &command,
            &query.deadline,
        )?;
        let authoritative_consumption = endpoint_response
            .response
            .authoritative_consumption
            .as_ref()
            .map(|consumption| {
                self.verify_cleanup_consumption(
                    consumption,
                    None,
                    &query.authorization_nonce_sha256,
                    &query.deadline,
                )
            })
            .transpose()?;
        let authoritative_cursor = self.verify_cleanup_cursor(
            &endpoint_response.response.authoritative_cursor,
            &query.deadline,
        )?;
        if let Some(expected_cursor) = expected_cursor {
            if authoritative_cursor.sequence_high_water()
                    != expected_cursor.sequence_high_water
                || authoritative_cursor.predecessor_receipt_sha256()
                    != &expected_cursor
                        .expected_predecessor_receipt_sha256
            {
                return Err(EndpointClientError::Invalid(
                    "queried cleanup cursor does not match the pre-operation current head",
                ));
            }
        }
        self.recheck_local_deadline(&query.deadline)?;
        Ok(VerifiedCleanupQueryResponse {
            endpoint_response,
            authoritative_consumption,
            authoritative_cursor,
        })
    }

    fn compare_and_swap_cleanup_consumption<
        P: CurrentEndpointTrustProvider + ?Sized,
    >(
        &self,
        current_trust: &mut P,
        verified_authorization:
            &VerifiedSignedCleanupAuthorization,
        request: &CleanupConsumptionCompareAndSwap,
    ) -> Result<VerifiedCleanupCasResponse, EndpointClientError> {
        request.validate_shape()?;
        if &request.authorization
            != verified_authorization.authorization()
        {
            return Err(EndpointClientError::Invalid(
                "cleanup CAS authorization differs from verified bytes",
            ));
        }
        let command =
            CleanupConsumptionCommand::CompareAndSwap(request.clone());
        let endpoint_response: VerifiedEndpointResponse<
            CleanupConsumptionCasReply,
        > = self.round_trip(
            current_trust,
            EndpointRequestKind::CleanupAuthorizationCompareAndSwap,
            &request.cas_nonce_sha256,
            &command,
            &request.deadline,
        )?;
        let (disposition, expected_authorization) =
            match &endpoint_response.response {
                CleanupConsumptionCasReply::Applied { .. } => (
                    CleanupRecoveryDisposition::Applied,
                    Some(verified_authorization.authorization()),
                ),
                CleanupConsumptionCasReply::AlreadyApplied { .. } => (
                    CleanupRecoveryDisposition::AlreadyApplied,
                    Some(verified_authorization.authorization()),
                ),
                CleanupConsumptionCasReply::Conflict { .. } => (
                    CleanupRecoveryDisposition::Conflict,
                    None,
                ),
            };
        let consumption = endpoint_response
            .response
            .consumption()
            .map(|signed| {
                self.verify_cleanup_consumption(
                    signed,
                    expected_authorization,
                    &request
                        .authorization
                        .payload
                        .authorization_nonce_sha256,
                    &request.deadline,
                )
            })
            .transpose()?;
        let authoritative_cursor = self.verify_cleanup_cursor(
            endpoint_response.response.authoritative_cursor(),
            &request.deadline,
        )?;
        if authoritative_cursor.sequence_high_water()
                < request.expected_consumer_sequence_high_water
            || (disposition != CleanupRecoveryDisposition::Conflict
                && authoritative_cursor.sequence_high_water()
                    != request
                        .expected_consumer_sequence_high_water
                        .checked_add(1)
                        .ok_or(EndpointClientError::Invalid(
                            "cleanup cursor high-water overflow",
                        ))?)
        {
            return Err(EndpointClientError::Invalid(
                "cleanup CAS returned a rolled-back or non-adjacent authoritative cursor",
            ));
        }
        if let Some(consumption) = &consumption {
            if consumption.statement().consumer_sequence
                    != authoritative_cursor.sequence_high_water()
                || consumption
                    .statement()
                    .predecessor_receipt_sha256
                    != request.expected_predecessor_receipt_sha256
                || (disposition
                        != CleanupRecoveryDisposition::Conflict
                    && *authoritative_cursor
                        .predecessor_receipt_sha256()
                        != consumption
                            .signed_envelope()
                            .envelope_sha256)
                || (disposition == CleanupRecoveryDisposition::Conflict
                    && consumption
                        .statement()
                        .authorization_sha256
                        == request.authorization.authorization_sha256)
            {
                return Err(EndpointClientError::Invalid(
                    "cleanup consumption does not bind the authoritative cursor or conflict",
                ));
            }
        } else if disposition != CleanupRecoveryDisposition::Conflict {
            return Err(EndpointClientError::Invalid(
                "successful cleanup CAS omitted durable consumption",
            ));
        }
        self.recheck_local_deadline(&request.deadline)?;
        Ok(VerifiedCleanupCasResponse {
            endpoint_response,
            disposition,
            consumption,
            authoritative_cursor,
        })
    }

    fn verify_cleanup_cursor(
        &self,
        signed: &SignedCleanupConsumptionCursorV3,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<VerifiedCleanupCursor, EndpointClientError> {
        signed.validate_shape()?;
        let payload = signed.canonical_signature_payload()?;
        self.pin.current_key_authorization.verify_claim(
            self.pin.boottime_domain,
            signed.cursor.endpoint_role,
            &signed.endpoint_process_identity_sha256,
            signed.cursor.endpoint_generation,
            &signed.current_key_authorization_checkpoint_sha256,
            signed.revocation_generation,
            &signed.revocation_root_sha256,
            &signed.signing_key_id,
            &signed.signing_key_spki_sha256,
            signed.cursor.observed_at_boottime_nanos,
        )?;
        if signed.cursor.endpoint_role != self.pin.endpoint_role
            || signed.cursor.deadline != *deadline
        {
            return Err(EndpointClientError::Invalid(
                "cleanup cursor role or deadline mismatch",
            ));
        }
        verify_signature(
            &self.pin.current_key_authorization.verifying_key,
            self.pin.endpoint_role.receipt_signature_domain(),
            &payload,
            &signed.signature_base64,
        )?;
        self.recheck_local_deadline(deadline)?;
        Ok(VerifiedCleanupCursor {
            signed_cursor: signed.clone(),
            exact_signature_payload_bytes: payload,
        })
    }

    fn verify_cleanup_consumption(
        &self,
        persisted: &PersistedCleanupAuthorizationConsumptionV3,
        expected_authorization: Option<&SignedCleanupAuthorizationV3>,
        expected_authorization_nonce: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<VerifiedCleanupConsumption, EndpointClientError> {
        persisted.validate_cleanup_exact_bytes(
            self.pin.endpoint_role,
            expected_authorization,
        )?;
        let signed = &persisted.signed_envelope;
        signed.validate_shape()?;
        self.pin.current_key_authorization.verify_claim(
            self.pin.boottime_domain,
            signed.endpoint_role,
            &signed.endpoint_process_identity_sha256,
            signed.endpoint_generation,
            &signed.current_key_authorization_checkpoint_sha256,
            signed.revocation_generation,
            &signed.revocation_root_sha256,
            &signed.signing_key_id,
            &signed.signing_key_spki_sha256,
            boottime_now_nanos()?,
        )?;
        if signed.endpoint_role != self.pin.endpoint_role {
            return Err(EndpointClientError::Invalid(
                "cleanup consumption was signed by the wrong endpoint role",
            ));
        }
        let canonical_statement =
            &persisted.exact_canonical_statement_bytes;
        if canonical_statement.len() > self.maximum_frame_bytes
            || signed.statement_sha256
                != endpoint_receipt_statement_sha256(
                    canonical_statement,
                )
        {
            return Err(EndpointClientError::Invalid(
                "cleanup consumption statement digest or bound is invalid",
            ));
        }
        let statement = &persisted.statement;
        if statement.authorization_nonce_sha256
                != *expected_authorization_nonce
            || statement.endpoint_role != self.pin.endpoint_role
        {
            return Err(EndpointClientError::Invalid(
                "cleanup consumption nonce or endpoint role mismatch",
            ));
        }
        if let Some(authorization) = expected_authorization {
            statement.validate_against(authorization)?;
        }
        let signature_payload =
            signed.canonical_signature_payload()?;
        verify_signature(
            &self.pin.current_key_authorization.verifying_key,
            self.pin.endpoint_role.receipt_signature_domain(),
            &signature_payload,
            &signed.signature_base64,
        )?;
        let runtime_deadline = deadline.to_runtime()?;
        runtime_deadline
            .require_expected_domain(self.pin.boottime_domain)?;
        runtime_deadline.require_live()?;
        self.pin.current_key_authorization.validate_at(
            self.pin.boottime_domain,
            boottime_now_nanos()?,
        )?;
        self.recheck_local_deadline(deadline)?;
        Ok(VerifiedCleanupConsumption {
            persisted: persisted.clone(),
            exact_signature_payload_bytes: signature_payload,
        })
    }

    fn recheck_local_deadline(
        &self,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), EndpointClientError> {
        let runtime_deadline = deadline.to_runtime()?;
        runtime_deadline
            .require_expected_domain(self.pin.boottime_domain)?;
        runtime_deadline.require_live()?;
        self.pin.current_key_authorization.validate_at(
            self.pin.boottime_domain,
            boottime_now_nanos()?,
        )
    }

    fn round_trip<
        P: CurrentEndpointTrustProvider + ?Sized,
        Q,
        R,
    >(
        &self,
        current_trust: &mut P,
        request_kind: EndpointRequestKind,
        request_nonce_sha256: &Sha256Digest,
        request: &Q,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<VerifiedEndpointResponse<R>, EndpointClientError>
    where
        Q: Serialize,
        R: Serialize + DeserializeOwned,
    {
        self.pin.validate()?;
        if !request_kind.permits_role(self.pin.endpoint_role) {
            return Err(EndpointClientError::Invalid(
                "endpoint request kind is forbidden for the constructed client role",
            ));
        }
        require_nonzero_digest(
            "endpointRequest.requestNonceSha256",
            request_nonce_sha256,
        )?;
        let runtime_deadline = deadline.to_runtime()?;
        runtime_deadline
            .require_expected_domain(self.pin.boottime_domain)?;
        runtime_deadline.require_live()?;
        let current_before = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(&self.pin, &current_before)?;
        let canonical_request =
            canonical_json_bytes(request).map_err(|_| {
                EndpointClientError::Invalid(
                    "endpoint request is not canonical",
                )
            })?;
        if canonical_request.len() > self.maximum_frame_bytes {
            return Err(EndpointClientError::Invalid(
                "endpoint request exceeds the configured frame bound",
            ));
        }
        let request_sha256 =
            endpoint_request_sha256(&canonical_request);
        require_nonzero_digest(
            "endpointRequest.requestSha256",
            &request_sha256,
        )?;
        let mut envelope = EndpointRequestEnvelope {
            api_version: POLICY_CUSTODY_PROTOCOL_VERSION.to_string(),
            endpoint_role: self.pin.endpoint_role,
            request_kind,
            request_nonce_sha256: request_nonce_sha256.clone(),
            canonical_request_base64:
                URL_SAFE_NO_PAD.encode(&canonical_request),
            request_sha256: request_sha256.clone(),
            deadline: deadline.clone(),
            envelope_sha256: Sha256Digest::compute(
                b"temporary-nonzero-endpoint-envelope",
            ),
        };
        envelope.envelope_sha256 =
            envelope.computed_envelope_sha256()?;
        envelope.validate_shape()?;
        let request_frame =
            canonical_json_bytes(&envelope).map_err(|_| {
                EndpointClientError::Invalid(
                    "endpoint request envelope is not canonical",
                )
            })?;
        if request_frame.len() > self.maximum_frame_bytes {
            return Err(EndpointClientError::Invalid(
                "endpoint request envelope exceeds the frame bound",
            ));
        }
        let socket = connect_seqpacket(
            &self.pin.socket_path,
            runtime_deadline,
        )?;
        let live_peer =
            LiveEndpointProcess::observe(socket.as_raw_fd(), &self.pin)?;
        live_peer.revalidate(socket.as_raw_fd(), &self.pin)?;
        send_seqpacket(
            socket.as_raw_fd(),
            &request_frame,
            runtime_deadline,
        )?;
        let response_frame = receive_seqpacket(
            socket.as_raw_fd(),
            self.maximum_frame_bytes,
            runtime_deadline,
        )?;
        let signed: SignedEndpointResponseEnvelope =
            decode_exact_canonical_json(&response_frame)?;
        let verified = self.verify_response_envelope::<R>(
            signed,
            response_frame,
            request_nonce_sha256,
            &request_sha256,
            deadline,
        )?;
        runtime_deadline
            .require_expected_domain(self.pin.boottime_domain)?;
        runtime_deadline.require_live()?;
        live_peer.revalidate(socket.as_raw_fd(), &self.pin)?;
        self.pin.current_key_authorization.validate_at(
            self.pin.boottime_domain,
            boottime_now_nanos()?,
        )?;
        let current_after = current_endpoint_trust_until(
            current_trust,
            self.pin.endpoint_role,
            runtime_deadline,
        )?;
        require_same_current_authority(
            &current_before,
            &current_after,
        )?;
        current_after.current_key_authorization.verify_claim(
            current_after.boottime_domain,
            verified.signed_envelope.endpoint_role,
            &verified
                .signed_envelope
                .endpoint_process_identity_sha256,
            verified.signed_envelope.endpoint_generation,
            &verified
                .signed_envelope
                .current_key_authorization_checkpoint_sha256,
            verified.signed_envelope.revocation_generation,
            &verified.signed_envelope.revocation_root_sha256,
            &verified.signed_envelope.signing_key_id,
            &verified.signed_envelope.signing_key_spki_sha256,
            verified.signed_envelope.observed_at_boottime_nanos,
        )?;
        runtime_deadline.require_live()?;
        Ok(verified)
    }

    fn verify_response_envelope<R>(
        &self,
        signed: SignedEndpointResponseEnvelope,
        exact_signed_envelope_bytes: Vec<u8>,
        expected_nonce_sha256: &Sha256Digest,
        expected_request_sha256: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<VerifiedEndpointResponse<R>, EndpointClientError>
    where
        R: Serialize + DeserializeOwned,
    {
        signed.validate_shape()?;
        self.pin.current_key_authorization.verify_claim(
            self.pin.boottime_domain,
            signed.endpoint_role,
            &signed.endpoint_process_identity_sha256,
            signed.endpoint_generation,
            &signed.current_key_authorization_checkpoint_sha256,
            signed.revocation_generation,
            &signed.revocation_root_sha256,
            &signed.signing_key_id,
            &signed.signing_key_spki_sha256,
            signed.observed_at_boottime_nanos,
        )?;
        if signed.endpoint_role != self.pin.endpoint_role
            || signed.endpoint_process_identity
                != self.pin.endpoint_process_identity
            || signed.endpoint_process_identity_sha256
                != self.pin.endpoint_process_identity_sha256
            || signed.request_nonce_sha256 != *expected_nonce_sha256
            || signed.request_sha256 != *expected_request_sha256
            || signed.observed_at_boottime_nanos
                >= deadline.absolute_boottime_nanos()
        {
            return Err(EndpointClientError::Invalid(
                "signed endpoint response binding mismatch",
            ));
        }
        let canonical_response = URL_SAFE_NO_PAD
            .decode(&signed.canonical_response_base64)
            .map_err(|_| {
                EndpointClientError::Invalid(
                    "endpoint response base64 is invalid",
                )
            })?;
        if canonical_response.len() > self.maximum_frame_bytes
            || signed.response_sha256
                != endpoint_response_sha256(&canonical_response)
        {
            return Err(EndpointClientError::Invalid(
                "endpoint response digest or bound is invalid",
            ));
        }
        let response: R =
            decode_exact_canonical_json(&canonical_response)?;
        let signature_payload =
            signed.canonical_signature_payload()?;
        verify_signature(
            &self.pin.current_key_authorization.verifying_key,
            self.pin.endpoint_role.response_signature_domain(),
            &signature_payload,
            &signed.signature_base64,
        )?;
        let runtime_deadline = deadline.to_runtime()?;
        runtime_deadline
            .require_expected_domain(self.pin.boottime_domain)?;
        runtime_deadline.require_live()?;
        self.pin.current_key_authorization.validate_at(
            self.pin.boottime_domain,
            boottime_now_nanos()?,
        )?;
        Ok(VerifiedEndpointResponse {
            response,
            signed_envelope: signed,
            exact_signed_envelope_bytes,
            exact_canonical_response_bytes: canonical_response,
            exact_signature_payload_bytes: signature_payload,
        })
    }
}

pub(super) fn verify_independent_durable_consumes(
    evidence: &IndependentDurableConsumeEvidence,
    identity: &SettlementIdentity,
    signer_hsm_pin: &EndpointTrustPin,
    settlement_store_pin: &EndpointTrustPin,
    verification_deadline: &ProtocolBoottimeDeadline,
) -> Result<VerifiedIndependentDurableConsumes, EndpointClientError> {
    evidence.validate_envelope_shape()?;
    signer_hsm_pin.validate()?;
    settlement_store_pin.validate()?;
    let runtime_verification_deadline =
        verification_deadline.to_runtime()?;
    runtime_verification_deadline.require_expected_domain(
        signer_hsm_pin.boottime_domain,
    )?;
    runtime_verification_deadline.require_expected_domain(
        settlement_store_pin.boottime_domain,
    )?;
    runtime_verification_deadline.require_live()?;
    if signer_hsm_pin.endpoint_role
            != PolicyCustodyEndpointRole::SignerHsm
        || settlement_store_pin.endpoint_role
            != PolicyCustodyEndpointRole::SettlementStore
        || signer_hsm_pin.endpoint_process_identity_sha256
            == settlement_store_pin.endpoint_process_identity_sha256
        || signer_hsm_pin
                .current_key_authorization
                .signing_key_id
            == settlement_store_pin
                .current_key_authorization
                .signing_key_id
        || signer_hsm_pin
                .current_key_authorization
                .signing_key_spki_sha256
            == settlement_store_pin
                .current_key_authorization
                .signing_key_spki_sha256
    {
        return Err(EndpointClientError::Invalid(
            "HSM and store trust pins are not independent",
        ));
    }
    let signer_hsm = verify_durable_consume_receipt(
        &evidence.signer_hsm,
        identity,
        signer_hsm_pin,
        verification_deadline,
    )?;
    let settlement_store = verify_durable_consume_receipt(
        &evidence.settlement_store,
        identity,
        settlement_store_pin,
        verification_deadline,
    )?;
    if signer_hsm.statement.consume_nonce_sha256
            == settlement_store.statement.consume_nonce_sha256
        || signer_hsm.statement.consume_binding_sha256
            != settlement_store.statement.consume_binding_sha256
    {
        return Err(EndpointClientError::Invalid(
            "independent durable consumes lack distinct nonces or a common operation binding",
        ));
    }
    Ok(VerifiedIndependentDurableConsumes {
        atomicity_model:
            DurableConsumeAtomicityModel::
                IndependentDurableConsumesNoDistributedAtomicity,
        signer_hsm,
        settlement_store,
    })
}

pub(super) fn verify_independent_durable_consumes_with_current_provider<
    P: CurrentEndpointTrustProvider + ?Sized,
>(
    provider: &mut P,
    evidence: &IndependentDurableConsumeEvidence,
    identity: &SettlementIdentity,
    verification_deadline: &ProtocolBoottimeDeadline,
) -> Result<VerifiedIndependentDurableConsumes, EndpointClientError> {
    let runtime_deadline = verification_deadline.to_runtime()?;
    runtime_deadline.require_live()?;
    evidence.validate_envelope_shape()?;
    evidence.signer_hsm.validate_exact_bytes(
        PolicyCustodyEndpointRole::SignerHsm,
        identity,
    )?;
    evidence.settlement_store.validate_exact_bytes(
        PolicyCustodyEndpointRole::SettlementStore,
        identity,
    )?;
    let signer_before = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::SignerHsm,
        runtime_deadline,
    )?;
    let store_before = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::SettlementStore,
        runtime_deadline,
    )?;
    verify_historical_durable_consume_until(
        provider,
        HistoricalDurableConsumeVerification {
            endpoint_role: PolicyCustodyEndpointRole::SignerHsm,
            persisted: &evidence.signer_hsm,
            identity,
            current_head: &signer_before.consume_cursor,
        },
        runtime_deadline,
    )?;
    verify_historical_durable_consume_until(
        provider,
        HistoricalDurableConsumeVerification {
            endpoint_role:
                PolicyCustodyEndpointRole::SettlementStore,
            persisted: &evidence.settlement_store,
            identity,
            current_head: &store_before.consume_cursor,
        },
        runtime_deadline,
    )?;
    runtime_deadline.require_live()?;
    let signer_after = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::SignerHsm,
        runtime_deadline,
    )?;
    let store_after = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::SettlementStore,
        runtime_deadline,
    )?;
    require_monotonic_current_head(&signer_before, &signer_after)?;
    require_monotonic_current_head(&store_before, &store_after)?;
    verify_historical_durable_consume_until(
        provider,
        HistoricalDurableConsumeVerification {
            endpoint_role: PolicyCustodyEndpointRole::SignerHsm,
            persisted: &evidence.signer_hsm,
            identity,
            current_head: &signer_after.consume_cursor,
        },
        runtime_deadline,
    )?;
    verify_historical_durable_consume_until(
        provider,
        HistoricalDurableConsumeVerification {
            endpoint_role:
                PolicyCustodyEndpointRole::SettlementStore,
            persisted: &evidence.settlement_store,
            identity,
            current_head: &store_after.consume_cursor,
        },
        runtime_deadline,
    )?;
    let signer_hsm = materialize_historical_verified_receipt(
        &evidence.signer_hsm,
        PolicyCustodyEndpointRole::SignerHsm,
        identity,
        &signer_after.consume_cursor,
    )?;
    let settlement_store = materialize_historical_verified_receipt(
        &evidence.settlement_store,
        PolicyCustodyEndpointRole::SettlementStore,
        identity,
        &store_after.consume_cursor,
    )?;
    runtime_deadline.require_live()?;
    Ok(VerifiedIndependentDurableConsumes {
        atomicity_model:
            DurableConsumeAtomicityModel::
                IndependentDurableConsumesNoDistributedAtomicity,
        signer_hsm,
        settlement_store,
    })
}

fn materialize_historical_verified_receipt(
    persisted: &PersistedDurableConsumeReceiptV3,
    endpoint_role: PolicyCustodyEndpointRole,
    identity: &SettlementIdentity,
    current_head: &EndpointConsumeCursor,
) -> Result<VerifiedDurableConsumeReceipt, EndpointClientError> {
    persisted.validate_exact_bytes(endpoint_role, identity)?;
    let statement = &persisted.statement;
    if !statement.occurred_before_operation_deadline
        || statement.occurred_before_operation_deadline
            != (statement.consumed_at_boottime_nanos
                < identity
                    .operation_deadline
                    .absolute_boottime_nanos())
        || statement.consumer_sequence
            > current_head.sequence_high_water
    {
        return Err(EndpointClientError::Invalid(
            "historical durable consume is not included in the current head or did not occur before the operation deadline",
        ));
    }
    Ok(VerifiedDurableConsumeReceipt {
        statement: statement.clone(),
        signed_envelope: persisted.signed_envelope.clone(),
        exact_signed_envelope_bytes:
            persisted.exact_signed_envelope_bytes.clone(),
        exact_canonical_statement_bytes:
            persisted.exact_canonical_statement_bytes.clone(),
        exact_signature_payload_bytes:
            persisted.signed_envelope.canonical_signature_payload()?,
    })
}

fn verify_durable_consume_receipt(
    persisted: &PersistedDurableConsumeReceiptV3,
    identity: &SettlementIdentity,
    pin: &EndpointTrustPin,
    verification_deadline: &ProtocolBoottimeDeadline,
) -> Result<VerifiedDurableConsumeReceipt, EndpointClientError> {
    persisted.validate_exact_bytes(pin.endpoint_role, identity)?;
    let signed = &persisted.signed_envelope;
    pin.validate()?;
    signed.validate_shape()?;
    pin.current_key_authorization.verify_claim(
        pin.boottime_domain,
        signed.endpoint_role,
        &signed.endpoint_process_identity_sha256,
        signed.endpoint_generation,
        &signed.current_key_authorization_checkpoint_sha256,
        signed.revocation_generation,
        &signed.revocation_root_sha256,
        &signed.signing_key_id,
        &signed.signing_key_spki_sha256,
        boottime_now_nanos()?,
    )?;
    if signed.endpoint_role != pin.endpoint_role {
        return Err(EndpointClientError::Invalid(
            "signed durable consume role mismatch",
        ));
    }
    let canonical_statement =
        persisted.exact_canonical_statement_bytes.clone();
    if canonical_statement.len() > MAX_ENDPOINT_FRAME_BYTES
        || signed.statement_sha256
            != endpoint_receipt_statement_sha256(
                &canonical_statement,
            )
    {
        return Err(EndpointClientError::Invalid(
            "durable consume statement digest or bound is invalid",
        ));
    }
    let statement = persisted.statement.clone();
    statement.validate(pin.endpoint_role, identity)?;
    if statement.consumer_generation != signed.endpoint_generation
        || statement.consumer_generation != pin.exact_endpoint_generation
        || statement.consumer_sequence
            != pin.consume_cursor.expected_next_sequence
        || statement.consumer_sequence
            <= pin.consume_cursor.sequence_high_water
        || statement.predecessor_receipt_sha256
            != pin
                .consume_cursor
                .expected_predecessor_receipt_sha256
        || statement.consumed_at_boottime_nanos
            >= identity.operation_deadline.absolute_boottime_nanos()
    {
        return Err(EndpointClientError::Invalid(
            "durable consume generation, sequence high-water, predecessor receipt, or deadline is invalid",
        ));
    }
    let signature_payload = signed.canonical_signature_payload()?;
    verify_signature(
        &pin.current_key_authorization.verifying_key,
        pin.endpoint_role.receipt_signature_domain(),
        &signature_payload,
        &signed.signature_base64,
    )?;
    let runtime_deadline = verification_deadline.to_runtime()?;
    runtime_deadline.require_expected_domain(pin.boottime_domain)?;
    runtime_deadline.require_live()?;
    pin.current_key_authorization.validate_at(
        pin.boottime_domain,
        boottime_now_nanos()?,
    )?;
    let exact_signed_envelope_bytes =
        persisted.exact_signed_envelope_bytes.clone();
    runtime_deadline.require_expected_domain(pin.boottime_domain)?;
    runtime_deadline.require_live()?;
    pin.current_key_authorization.validate_at(
        pin.boottime_domain,
        boottime_now_nanos()?,
    )?;
    Ok(VerifiedDurableConsumeReceipt {
        statement,
        signed_envelope: signed.clone(),
        exact_signed_envelope_bytes,
        exact_canonical_statement_bytes: canonical_statement,
        exact_signature_payload_bytes: signature_payload,
    })
}

fn require_same_current_authority(
    before: &EndpointTrustPin,
    after: &EndpointTrustPin,
) -> Result<(), EndpointClientError> {
    before.validate()?;
    after.validate()?;
    if before.endpoint_role != after.endpoint_role
        || before.endpoint_process_identity
            != after.endpoint_process_identity
        || !before
            .current_key_authorization
            .exact_checkpoint_matches(&after.current_key_authorization)
    {
        return Err(EndpointClientError::Invalid(
            "current endpoint identity, signing checkpoint, or revocation authority changed during the privileged operation",
        ));
    }
    Ok(())
}

pub(super) fn require_same_current_checkpoint(
    before: &EndpointTrustPin,
    after: &EndpointTrustPin,
) -> Result<(), EndpointClientError> {
    require_same_current_authority(before, after)?;
    if before.consume_cursor != after.consume_cursor {
        return Err(EndpointClientError::Invalid(
            "current endpoint identity, revocation checkpoint, or consume cursor changed during verification",
        ));
    }
    Ok(())
}

fn require_monotonic_current_head(
    before: &EndpointTrustPin,
    after: &EndpointTrustPin,
) -> Result<(), EndpointClientError> {
    before.validate()?;
    after.validate()?;
    if before.endpoint_role != after.endpoint_role
        || before.endpoint_process_identity
            != after.endpoint_process_identity
        || before.exact_endpoint_generation
            != after.exact_endpoint_generation
        || after
            .current_key_authorization
            .exact_checkpoint_sequence
            < before
                .current_key_authorization
                .exact_checkpoint_sequence
        || after
            .current_key_authorization
            .exact_revocation_generation_high_water
            < before
                .current_key_authorization
                .exact_revocation_generation_high_water
        || after.consume_cursor.sequence_high_water
            < before.consume_cursor.sequence_high_water
        || after
            .current_key_authorization
            .rollback_floor_consumer_sequence
            < before
                .current_key_authorization
                .rollback_floor_consumer_sequence
    {
        return Err(EndpointClientError::Invalid(
            "current endpoint key, revocation, or durable-consume head rolled back during verification",
        ));
    }
    Ok(())
}

fn require_monotonic_accepted_current(
    before: &EndpointTrustPin,
    after: &EndpointTrustPin,
) -> Result<(), EndpointClientError> {
    before
        .current_key_authorization
        .signed_current_key_authorization
        .validate_shape()?;
    before.consume_cursor.validate(
        before
            .current_key_authorization
            .rollback_floor_consumer_sequence,
    )?;
    after.validate()?;
    let before_authority = &before.current_key_authorization;
    let after_authority = &after.current_key_authorization;
    if before.endpoint_role != after.endpoint_role
        || before_authority.checkpoint_authority_key_id
            != after_authority.checkpoint_authority_key_id
        || before_authority.checkpoint_authority_key_spki_sha256
            != after_authority.checkpoint_authority_key_spki_sha256
        || after_authority.exact_checkpoint_sequence
            < before_authority.exact_checkpoint_sequence
        || after_authority.exact_endpoint_generation
            < before_authority.exact_endpoint_generation
        || after_authority.exact_revocation_generation_high_water
            < before_authority.exact_revocation_generation_high_water
        || after_authority.rollback_floor_checkpoint_sequence
            < before_authority.rollback_floor_checkpoint_sequence
        || after_authority.rollback_floor_endpoint_generation
            < before_authority.rollback_floor_endpoint_generation
        || after_authority.rollback_floor_consumer_sequence
            < before_authority.rollback_floor_consumer_sequence
        || after.consume_cursor.sequence_high_water
            < before.consume_cursor.sequence_high_water
    {
        return Err(EndpointClientError::Invalid(
            "accepted endpoint trust successor rolled back its authority, generation, revocation, or durable-consume floor",
        ));
    }
    Ok(())
}

fn recheck_verified_consume_current(
    verified: &VerifiedDurableConsumeReceipt,
    pin: &EndpointTrustPin,
    verification_deadline: BoottimeDeadline,
) -> Result<(), EndpointClientError> {
    verification_deadline.require_live()?;
    let signed = verified.signed_envelope();
    pin.current_key_authorization.verify_claim(
        pin.boottime_domain,
        signed.endpoint_role,
        &signed.endpoint_process_identity_sha256,
        signed.endpoint_generation,
        &signed.current_key_authorization_checkpoint_sha256,
        signed.revocation_generation,
        &signed.revocation_root_sha256,
        &signed.signing_key_id,
        &signed.signing_key_spki_sha256,
        boottime_now_nanos()?,
    )?;
    verification_deadline.require_live()?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedWatchdogOwnershipAck {
    acknowledgement: SignedWatchdogOwnershipAckV3,
    exact_signed_acknowledgement_bytes: Vec<u8>,
    exact_signature_payload_bytes: Vec<u8>,
}

impl VerifiedWatchdogOwnershipAck {
    pub(super) fn acknowledgement(
        &self,
    ) -> &SignedWatchdogOwnershipAckV3 {
        &self.acknowledgement
    }

    pub(super) fn exact_signed_acknowledgement_bytes(&self) -> &[u8] {
        &self.exact_signed_acknowledgement_bytes
    }
}

pub(super) fn verify_watchdog_ownership_ack_with_current_provider<
    P: CurrentEndpointTrustProvider + ?Sized,
>(
    provider: &mut P,
    registration: &WatchdogRegistrationV3,
    acknowledgement: &SignedWatchdogOwnershipAckV3,
    verification_deadline: &ProtocolBoottimeDeadline,
) -> Result<VerifiedWatchdogOwnershipAck, EndpointClientError> {
    registration.validate()?;
    acknowledgement.validate_shape()?;
    acknowledgement
        .ownership
        .validate_against_registration(registration)?;
    let runtime_deadline = verification_deadline.to_runtime()?;
    runtime_deadline.require_live()?;
    let before = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::CleanupWatchdog,
        runtime_deadline,
    )?;
    before.validate()?;
    let signature_payload =
        acknowledgement.canonical_signature_payload()?;
    before.current_key_authorization.verify_claim(
        before.boottime_domain,
        acknowledgement.endpoint_role,
        &acknowledgement.endpoint_process_identity_sha256,
        acknowledgement.endpoint_generation,
        &acknowledgement
            .current_key_authorization_checkpoint_sha256,
        acknowledgement.revocation_generation,
        &acknowledgement.revocation_root_sha256,
        &acknowledgement.signing_key_id,
        &acknowledgement.signing_key_spki_sha256,
        boottime_now_nanos()?,
    )?;
    verify_signature(
        &before.current_key_authorization.verifying_key,
        PolicyCustodyEndpointRole::CleanupWatchdog
            .response_signature_domain(),
        &signature_payload,
        &acknowledgement.signature_base64,
    )?;
    let exact_signed_acknowledgement_bytes =
        canonical_json_bytes(acknowledgement).map_err(|_| {
            EndpointClientError::Invalid(
                "watchdog ownership acknowledgement is not canonical",
            )
        })?;
    runtime_deadline.require_live()?;
    let after = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::CleanupWatchdog,
        runtime_deadline,
    )?;
    require_same_current_checkpoint(&before, &after)?;
    after.current_key_authorization.verify_claim(
        after.boottime_domain,
        acknowledgement.endpoint_role,
        &acknowledgement.endpoint_process_identity_sha256,
        acknowledgement.endpoint_generation,
        &acknowledgement
            .current_key_authorization_checkpoint_sha256,
        acknowledgement.revocation_generation,
        &acknowledgement.revocation_root_sha256,
        &acknowledgement.signing_key_id,
        &acknowledgement.signing_key_spki_sha256,
        boottime_now_nanos()?,
    )?;
    runtime_deadline.require_live()?;
    Ok(VerifiedWatchdogOwnershipAck {
        acknowledgement: acknowledgement.clone(),
        exact_signed_acknowledgement_bytes,
        exact_signature_payload_bytes: signature_payload,
    })
}

pub(super) fn verify_watchdog_ownership_query_confirmation<
    P: CurrentEndpointTrustProvider + ?Sized,
>(
    provider: &mut P,
    registration: &WatchdogRegistrationV3,
    initially_verified: &VerifiedWatchdogOwnershipAck,
    query: &WatchdogOwnershipQueryV3,
    reply: &WatchdogOwnershipQueryReplyV3,
    verification_deadline: &ProtocolBoottimeDeadline,
) -> Result<VerifiedWatchdogOwnershipAck, EndpointClientError> {
    query.validate()?;
    reply.validate_exact_fresh_binding(query)?;
    if query.registration_sha256 != registration.registration_sha256
        || query.ownership_id_sha256
            != initially_verified
                .acknowledgement
                .ownership
                .ownership_id_sha256
        || query.expected_state_sha256
            != initially_verified
                .acknowledgement
                .ownership
                .state_sha256
        || query.deadline != *verification_deadline
    {
        return Err(EndpointClientError::Invalid(
            "watchdog ownership Query does not bind the exact verified registration and state",
        ));
    }
    reply.signed_envelope.validate_shape()?;
    let canonical_request = canonical_json_bytes(query).map_err(|_| {
        EndpointClientError::Invalid(
            "watchdog ownership Query is not canonical",
        )
    })?;
    let canonical_response =
        canonical_json_bytes(&reply.response).map_err(|_| {
            EndpointClientError::Invalid(
                "watchdog ownership Query response is not canonical",
            )
        })?;
    let canonical_envelope =
        canonical_json_bytes(&reply.signed_envelope).map_err(|_| {
            EndpointClientError::Invalid(
                "watchdog ownership Query envelope is not canonical",
            )
        })?;
    let envelope = &reply.signed_envelope;
    if reply.exact_canonical_response_bytes != canonical_response
        || reply.exact_signed_envelope_bytes != canonical_envelope
        || envelope.endpoint_role
            != PolicyCustodyEndpointRole::CleanupWatchdog
        || envelope.request_nonce_sha256 != query.query_nonce_sha256
        || envelope.request_sha256
            != endpoint_request_sha256(&canonical_request)
        || envelope.response_sha256
            != endpoint_response_sha256(&canonical_response)
        || envelope.canonical_response_base64
            != URL_SAFE_NO_PAD.encode(&canonical_response)
        || envelope.observed_at_boottime_nanos == 0
        || envelope.observed_at_boottime_nanos
            >= verification_deadline.absolute_boottime_nanos()
    {
        return Err(EndpointClientError::Invalid(
            "watchdog ownership Query response lacks a fresh exact signed request/response binding",
        ));
    }
    let runtime_deadline = verification_deadline.to_runtime()?;
    runtime_deadline.require_live()?;
    let before = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::CleanupWatchdog,
        runtime_deadline,
    )?;
    let signature_payload = envelope.canonical_signature_payload()?;
    before.current_key_authorization.verify_claim(
        before.boottime_domain,
        envelope.endpoint_role,
        &envelope.endpoint_process_identity_sha256,
        envelope.endpoint_generation,
        &envelope.current_key_authorization_checkpoint_sha256,
        envelope.revocation_generation,
        &envelope.revocation_root_sha256,
        &envelope.signing_key_id,
        &envelope.signing_key_spki_sha256,
        envelope.observed_at_boottime_nanos,
    )?;
    verify_signature(
        &before.current_key_authorization.verifying_key,
        PolicyCustodyEndpointRole::CleanupWatchdog
            .response_signature_domain(),
        &signature_payload,
        &envelope.signature_base64,
    )?;
    runtime_deadline.require_live()?;
    let after = current_endpoint_trust_until(
        provider,
        PolicyCustodyEndpointRole::CleanupWatchdog,
        runtime_deadline,
    )?;
    require_same_current_checkpoint(&before, &after)?;
    after.current_key_authorization.verify_claim(
        after.boottime_domain,
        envelope.endpoint_role,
        &envelope.endpoint_process_identity_sha256,
        envelope.endpoint_generation,
        &envelope.current_key_authorization_checkpoint_sha256,
        envelope.revocation_generation,
        &envelope.revocation_root_sha256,
        &envelope.signing_key_id,
        &envelope.signing_key_spki_sha256,
        envelope.observed_at_boottime_nanos,
    )?;
    runtime_deadline.require_live()?;
    let authoritative = reply
        .response
        .authoritative_ownership
        .as_ref()
        .ok_or(EndpointClientError::Invalid(
            "watchdog ownership Query omitted authoritative state",
        ))?;
    let verified = verify_watchdog_ownership_ack_with_current_provider(
        provider,
        registration,
        authoritative,
        verification_deadline,
    )?;
    if verified.acknowledgement
        != initially_verified.acknowledgement
    {
        return Err(EndpointClientError::Invalid(
            "watchdog ownership Query did not confirm the exact durable acknowledgement",
        ));
    }
    Ok(verified)
}

fn validate_compare_and_swap_reply(
    request: &SettlementCompareAndSwap,
    reply: &SettlementCasReply,
) -> Result<(), EndpointClientError> {
    match reply {
        SettlementCasReply::Applied {
            transition_id_sha256,
            authoritative_state,
        }
        | SettlementCasReply::AlreadyApplied {
            transition_id_sha256,
            authoritative_state,
        } => {
            require_nonzero_digest(
                "settlementCas.transitionIdSha256",
                transition_id_sha256,
            )?;
            authoritative_state.validate_shape()?;
            if *transition_id_sha256
                    != request.transition.transition_id_sha256
                || *authoritative_state != request.candidate
            {
                return Err(EndpointClientError::Invalid(
                    "CAS success does not return the exact requested transition",
                ));
            }
        }
        SettlementCasReply::Conflict {
            authoritative_state,
        } => {
            authoritative_state.validate_shape()?;
            let authoritative_reference =
                SettlementStateReference::from_record(
                    authoritative_state,
                );
            if authoritative_state.identity != request.identity
                || authoritative_reference == request.expected
                || *authoritative_state == request.candidate
                || authoritative_state.state_revision
                    < request.expected.state_revision
            {
                return Err(EndpointClientError::Invalid(
                    "CAS conflict equals the predecessor/candidate, rolls back state, or belongs to another operation",
                ));
            }
        }
    }
    Ok(())
}

fn validate_recovery_observation(
    request: &SettlementCompareAndSwap,
    compare_and_swap: &SettlementCasReply,
    after: &SettlementQueryReply,
) -> Result<(), EndpointClientError> {
    after.validate(&request.identity)?;
    let expected = compare_and_swap.authoritative_state();
    let authoritative = after.authoritative_state.as_ref().ok_or(
        EndpointClientError::Invalid(
            "post-CAS query omitted authoritative settlement state",
        ),
    )?;
    if authoritative == expected {
        return Ok(());
    }
    let expected_position = after
        .canonical_state_chain
        .iter()
        .position(|state| state == expected)
        .ok_or(EndpointClientError::Invalid(
            "post-CAS chain does not contain the exact signed CAS state",
        ))?;
    let tail = &after.canonical_state_chain[expected_position..];
    if tail.first() != Some(expected)
        || tail.last() != Some(authoritative)
    {
        return Err(EndpointClientError::Invalid(
            "post-CAS state is neither exact nor a complete successor chain",
        ));
    }
    for states in tail.windows(2) {
        states[1].validate_successor(&states[0])?;
    }
    if matches!(
        compare_and_swap,
        SettlementCasReply::Applied { .. }
            | SettlementCasReply::AlreadyApplied { .. }
    ) && tail.first() != Some(&request.candidate)
    {
        return Err(EndpointClientError::Invalid(
            "post-CAS chain does not preserve the exact applied candidate",
        ));
    }
    Ok(())
}

fn validate_cleanup_retry_semantics(
    before: Option<&VerifiedCleanupConsumption>,
    cas: &VerifiedCleanupCasResponse,
    requested: &SignedCleanupAuthorizationV3,
) -> Result<(), EndpointClientError> {
    match (before, cas.disposition) {
        (Some(existing), CleanupRecoveryDisposition::AlreadyApplied)
            if existing.statement().authorization_sha256
                == requested.authorization_sha256
                && existing.exact_signed_consumption_bytes()
                    == cas
                        .consumption()
                        .ok_or(EndpointClientError::Invalid(
                            "cleanup already-applied result omitted consumption",
                        ))?
                        .exact_signed_consumption_bytes() =>
        {
            Ok(())
        }
        (Some(existing), CleanupRecoveryDisposition::Conflict)
            if existing.statement().authorization_nonce_sha256
                == requested.payload.authorization_nonce_sha256
                && existing.statement().authorization_sha256
                    != requested.authorization_sha256
                && existing.exact_signed_consumption_bytes()
                    == cas
                        .consumption()
                        .ok_or(EndpointClientError::Invalid(
                            "cleanup conflict changed an existing consumption without returning it",
                        ))?
                        .exact_signed_consumption_bytes() =>
        {
            Ok(())
        }
        (None, CleanupRecoveryDisposition::Applied) => Ok(()),
        (None, CleanupRecoveryDisposition::AlreadyApplied)
        | (None, CleanupRecoveryDisposition::Conflict) => {
            match cas.consumption() {
                Some(consumption)
                    if consumption
                        .statement()
                        .authorization_nonce_sha256
                        == requested
                            .payload
                            .authorization_nonce_sha256 =>
                {
                    Ok(())
                }
                None
                    if cas.disposition
                        == CleanupRecoveryDisposition::Conflict
                        && cas.authoritative_cursor().sequence_high_water()
                            > 0 =>
                {
                    Ok(())
                }
                _ => Err(EndpointClientError::Invalid(
                    "cleanup CAS race returned neither the requested nonce nor a signed authoritative conflict cursor",
                )),
            }
        }
        _ => Err(EndpointClientError::Invalid(
            "cleanup retry did not return the same signed consumption or a changed-reuse conflict",
        )),
    }
}

fn verify_signature(
    key: &VerifyingKey,
    domain: &[u8],
    canonical_payload: &[u8],
    signature_base64: &str,
) -> Result<(), EndpointClientError> {
    let preimage =
        domain_separated_signature_preimage(domain, canonical_payload)?;
    verify_preimage_signature(key, &preimage, signature_base64)
}

fn verify_preimage_signature(
    key: &VerifyingKey,
    preimage: &[u8],
    signature_base64: &str,
) -> Result<(), EndpointClientError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| {
            EndpointClientError::Invalid(
                "endpoint signature encoding is invalid",
            )
        })?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| {
            EndpointClientError::Invalid(
                "endpoint signature length is invalid",
            )
        })?;
    key.verify_strict(preimage, &signature).map_err(|_| {
        EndpointClientError::Invalid(
            "endpoint signature verification failed",
        )
    })
}

fn decode_exact_canonical_json<T>(
    bytes: &[u8],
) -> Result<T, EndpointClientError>
where
    T: Serialize + DeserializeOwned,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| {
        EndpointClientError::Invalid(
            "endpoint frame JSON shape is invalid",
        )
    })?;
    let canonical = canonical_json_bytes(&value).map_err(|_| {
        EndpointClientError::Invalid(
            "endpoint frame cannot be canonicalized",
        )
    })?;
    if canonical != bytes {
        return Err(EndpointClientError::Invalid(
            "noncanonical endpoint frame rejected",
        ));
    }
    Ok(value)
}

fn decode_trusted_host_response(
    pending: &PendingTrustedHostExchange,
    frame: &[u8],
) -> Result<
    (
        SignedEndpointResponseEnvelope,
        TrustedHostNoTeeTrustResponseWire,
        Vec<u8>,
        Vec<u8>,
    ),
    EndpointClientError,
> {
    if frame.is_empty() || frame.len() > pending.maximum_frame_bytes {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint response exceeds its frame bound",
        ));
    }
    let signed: SignedEndpointResponseEnvelope =
        decode_exact_canonical_json(frame)?;
    signed.validate_shape()?;
    let now = boottime_now_nanos()?;
    if signed.endpoint_role != pending.endpoint_role
        || signed.request_nonce_sha256
            != pending.request_nonce_sha256
        || signed.request_sha256 != pending.request_sha256
        || signed.observed_at_boottime_nanos
            < pending.requested_at_boottime_nanos
        || signed.observed_at_boottime_nanos > now
        || signed.observed_at_boottime_nanos
            >= pending.deadline.absolute_nanos()
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint response request, freshness, or BOOTTIME binding mismatch",
        ));
    }
    pending.deadline.require_live()?;
    let canonical_response = URL_SAFE_NO_PAD
        .decode(&signed.canonical_response_base64)
        .map_err(|_| {
            EndpointClientError::Invalid(
                "trusted-host endpoint response base64 is invalid",
            )
        })?;
    if canonical_response.is_empty()
        || canonical_response.len() > pending.maximum_frame_bytes
        || signed.response_sha256
            != endpoint_response_sha256(&canonical_response)
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint response digest or bound is invalid",
        ));
    }
    let response: TrustedHostNoTeeTrustResponseWire =
        decode_exact_canonical_json(&canonical_response)?;
    response.validate_shape()?;
    let signature_payload =
        signed.canonical_signature_payload()?;
    Ok((
        signed,
        response,
        canonical_response,
        signature_payload,
    ))
}

fn authorization_pin_from_checkpoint(
    endpoint_role: PolicyCustodyEndpointRole,
    endpoint_process_identity_sha256: &Sha256Digest,
    signing_key: VerifyingKey,
    checkpoint_authority_key: VerifyingKey,
    checkpoint: SignedEndpointKeyAuthorizationCheckpoint,
) -> Result<CurrentKeyAuthorizationPin, EndpointClientError> {
    let signing_spki = signing_key.to_public_key_der().map_err(|_| {
        EndpointClientError::Invalid(
            "endpoint signing key cannot be encoded as SPKI DER",
        )
    })?;
    let authority_spki = checkpoint_authority_key
        .to_public_key_der()
        .map_err(|_| {
            EndpointClientError::Invalid(
                "checkpoint authority key cannot be encoded as SPKI DER",
            )
        })?;
    let payload = &checkpoint.payload;
    if payload.endpoint_role != endpoint_role
        || &payload.endpoint_process_identity_sha256
            != endpoint_process_identity_sha256
        || payload.authorized_signing_key_spki_sha256
            != Sha256Digest::compute(signing_spki.as_bytes())
        || checkpoint.authority_key_spki_sha256
            != Sha256Digest::compute(authority_spki.as_bytes())
    {
        return Err(EndpointClientError::Invalid(
            "endpoint checkpoint does not authorize the supplied role, process, or verification keys",
        ));
    }
    Ok(CurrentKeyAuthorizationPin {
        endpoint_role,
        endpoint_process_identity_sha256:
            endpoint_process_identity_sha256.clone(),
        exact_endpoint_generation:
            payload.exact_endpoint_generation,
        signing_key_id:
            payload.authorized_signing_key_id.clone(),
        signing_key_spki_sha256:
            payload.authorized_signing_key_spki_sha256.clone(),
        verifying_key: signing_key,
        signed_current_key_authorization: checkpoint.clone(),
        exact_checkpoint_sha256:
            checkpoint.checkpoint_sha256.clone(),
        exact_predecessor_checkpoint_sha256:
            payload.predecessor_checkpoint_sha256.clone(),
        exact_checkpoint_sequence: payload.checkpoint_sequence,
        exact_revocation_generation_high_water:
            payload.revocation_generation_high_water,
        exact_revocation_root_sha256:
            payload.revocation_root_sha256.clone(),
        rollback_floor_checkpoint_sequence:
            payload.rollback_floor_checkpoint_sequence,
        rollback_floor_endpoint_generation:
            payload.rollback_floor_endpoint_generation,
        rollback_floor_consumer_sequence:
            payload.rollback_floor_consumer_sequence,
        checkpoint_authority_key_id:
            checkpoint.authority_key_id.clone(),
        checkpoint_authority_key_spki_sha256:
            checkpoint.authority_key_spki_sha256.clone(),
        checkpoint_authority_verifying_key:
            checkpoint_authority_key,
    })
}

fn decode_ed25519_spki_base64(
    encoded: &str,
    label: &'static str,
) -> Result<VerifyingKey, EndpointClientError> {
    let spki = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        EndpointClientError::InvalidOwned(format!(
            "{label} is not canonical base64url"
        ))
    })?;
    VerifyingKey::from_public_key_der(&spki).map_err(|_| {
        EndpointClientError::InvalidOwned(format!(
            "{label} is not an Ed25519 SPKI"
        ))
    })
}

fn verify_checkpoint_authority_signature(
    binding: &TrustedHostNoTeeEndpointBinding,
    checkpoint: &SignedEndpointKeyAuthorizationCheckpoint,
) -> Result<(), EndpointClientError> {
    checkpoint.validate_shape()?;
    if checkpoint.authority_key_id
            != binding.credential.checkpoint_authority_key_id
        || checkpoint.authority_key_spki_sha256
            != binding
                .credential
                .checkpoint_authority_key_spki_sha256
        || checkpoint.payload.endpoint_role
            != binding.credential.endpoint_role
    {
        return Err(EndpointClientError::Invalid(
            "endpoint checkpoint is outside the configured role or checkpoint authority",
        ));
    }
    verify_preimage_signature(
        &binding.checkpoint_authority_verifying_key,
        &checkpoint.authority_signature_preimage()?,
        &checkpoint.authority_signature_base64,
    )
}

fn verify_checkpoint_predecessor_path(
    binding: &TrustedHostNoTeeEndpointBinding,
    from: &CurrentKeyAuthorizationPin,
    to: &CurrentKeyAuthorizationPin,
    path: &TrustedHostNoTeeCheckpointPredecessorPathWire,
) -> Result<
    Vec<SignedEndpointKeyAuthorizationCheckpoint>,
    EndpointClientError,
> {
    path.validate_shape()?;
    if path.from_checkpoint_sequence != from.exact_checkpoint_sequence
        || path.from_checkpoint_sha256 != from.exact_checkpoint_sha256
        || path.to_checkpoint_sequence != to.exact_checkpoint_sequence
        || path.to_checkpoint_sha256 != to.exact_checkpoint_sha256
        || from.checkpoint_authority_key_id
            != to.checkpoint_authority_key_id
        || from.checkpoint_authority_key_spki_sha256
            != to.checkpoint_authority_key_spki_sha256
    {
        return Err(EndpointClientError::Invalid(
            "checkpoint predecessor path does not bind the accepted and current authorities",
        ));
    }
    verify_checkpoint_authority_signature(
        binding,
        &from.signed_current_key_authorization,
    )?;
    let mut chain = Vec::with_capacity(
        path.successors.len().saturating_add(1),
    );
    chain.push(from.signed_current_key_authorization.clone());
    let mut previous = &from.signed_current_key_authorization;
    for successor in &path.successors {
        verify_checkpoint_authority_signature(binding, successor)?;
        if successor.payload.exact_endpoint_generation
                < previous.payload.exact_endpoint_generation
            || successor.payload.revocation_generation_high_water
                < previous.payload.revocation_generation_high_water
            || successor.payload.rollback_floor_checkpoint_sequence
                < previous
                    .payload
                    .rollback_floor_checkpoint_sequence
            || successor.payload.rollback_floor_endpoint_generation
                < previous
                    .payload
                    .rollback_floor_endpoint_generation
            || successor.payload.rollback_floor_consumer_sequence
                < previous
                    .payload
                    .rollback_floor_consumer_sequence
            || (successor.payload.revocation_generation_high_water
                    == previous
                        .payload
                        .revocation_generation_high_water
                && successor.payload.revocation_root_sha256
                    != previous.payload.revocation_root_sha256)
        {
            return Err(EndpointClientError::Invalid(
                "checkpoint predecessor path rolls back generation, revocation, or signed floors",
            ));
        }
        chain.push(successor.clone());
        previous = successor;
    }
    if chain.last()
            != Some(&to.signed_current_key_authorization)
    {
        return Err(EndpointClientError::Invalid(
            "checkpoint predecessor path terminal checkpoint differs from the accepted current checkpoint",
        ));
    }
    Ok(chain)
}

fn verify_signed_consume_head(
    authority: &CurrentKeyAuthorizationPin,
    expected_domain: BoottimeDomain,
    signed_head: &SignedTrustedHostNoTeeConsumeHeadWire,
) -> Result<EndpointConsumeCursor, EndpointClientError> {
    signed_head.validate_shape()?;
    let statement = &signed_head.statement;
    authority.verify_claim(
        expected_domain,
        statement.endpoint_role,
        &authority.endpoint_process_identity_sha256,
        statement.endpoint_generation,
        &statement.current_key_authorization_checkpoint_sha256,
        authority.exact_revocation_generation_high_water,
        &authority.exact_revocation_root_sha256,
        &signed_head.signing_key_id,
        &signed_head.signing_key_spki_sha256,
        statement.observed_at_boottime_nanos,
    )?;
    verify_preimage_signature(
        &authority.verifying_key,
        &signed_head.signature_preimage()?,
        &signed_head.signature_base64,
    )?;
    let cursor = EndpointConsumeCursor::from(
        statement.cursor.clone(),
    );
    cursor.validate(authority.rollback_floor_consumer_sequence)?;
    Ok(cursor)
}

fn verify_fresh_current_head_attestation(
    binding: &TrustedHostNoTeeEndpointBinding,
    pending: &PendingTrustedHostExchange,
    response_observed_at_boottime_nanos: u64,
    attestation: &SignedTrustedHostNoTeeCurrentHeadWire,
    checkpoint: &SignedEndpointKeyAuthorizationCheckpoint,
) -> Result<(), EndpointClientError> {
    attestation.validate_shape()?;
    let statement = &attestation.statement;
    if attestation.authority_key_id
            != binding.credential.checkpoint_authority_key_id
        || attestation.authority_key_spki_sha256
            != binding
                .credential
                .checkpoint_authority_key_spki_sha256
        || statement.endpoint_role != pending.endpoint_role
        || statement.request_nonce_sha256
            != pending.request_nonce_sha256
        || statement.request_sha256 != pending.request_sha256
        || statement.checkpoint_sequence
            != checkpoint.payload.checkpoint_sequence
        || statement.checkpoint_sha256
            != checkpoint.checkpoint_sha256
        || statement.endpoint_generation
            != checkpoint.payload.exact_endpoint_generation
        || statement.revocation_generation_high_water
            != checkpoint
                .payload
                .revocation_generation_high_water
        || statement.revocation_root_sha256
            != checkpoint.payload.revocation_root_sha256
        || statement.issued_at_boottime_nanos
            < pending.requested_at_boottime_nanos
        || statement.issued_at_boottime_nanos
            > response_observed_at_boottime_nanos
        || statement.deadline
            != ProtocolBoottimeDeadline::from_runtime(
                pending.deadline,
            )
    {
        return Err(EndpointClientError::Invalid(
            "checkpoint authority current-head attestation is not fresh or does not bind the exact request and checkpoint",
        ));
    }
    pending.deadline.require_live()?;
    verify_preimage_signature(
        &binding.checkpoint_authority_verifying_key,
        &attestation.authority_signature_preimage()?,
        &attestation.authority_signature_base64,
    )
}

fn validate_signed_floor_evidence(
    credential: &TrustedHostNoTeeEndpointBindingCredential,
    checkpoint_authority_verifying_key: VerifyingKey,
    evidence: TrustedHostNoTeeSignedFloorEvidenceWire,
    initialization_deadline: BoottimeDeadline,
) -> Result<TrustedHostNoTeeAcceptedFloor, EndpointClientError> {
    evidence.validate_shape()?;
    if evidence.endpoint_role != credential.endpoint_role {
        return Err(EndpointClientError::Invalid(
            "signed floor evidence role differs from its endpoint configuration",
        ));
    }
    let signing_key = decode_ed25519_spki_base64(
        &evidence.signing_public_key_spki_base64,
        "signed floor endpoint key",
    )?;
    let endpoint_process_identity_sha256 = evidence
        .key_authorization
        .payload
        .endpoint_process_identity_sha256
        .clone();
    let authority = authorization_pin_from_checkpoint(
        credential.endpoint_role,
        &endpoint_process_identity_sha256,
        signing_key,
        checkpoint_authority_verifying_key,
        evidence.key_authorization,
    )?;
    if authority.checkpoint_authority_key_id
            != credential.checkpoint_authority_key_id
        || authority.checkpoint_authority_key_spki_sha256
            != credential.checkpoint_authority_key_spki_sha256
        || authority.exact_checkpoint_sequence
            < credential.minimum_checkpoint_sequence
        || authority.exact_endpoint_generation
            < credential.minimum_endpoint_generation
        || authority.exact_revocation_generation_high_water
            < credential.minimum_revocation_generation
        || authority.rollback_floor_checkpoint_sequence
            < credential.minimum_checkpoint_sequence
        || authority.rollback_floor_endpoint_generation
            < credential.minimum_endpoint_generation
        || authority.rollback_floor_consumer_sequence
            < credential.minimum_consumer_sequence
    {
        return Err(EndpointClientError::Invalid(
            "signed floor checkpoint is below the systemd-configured authority or monotonic floor",
        ));
    }
    let observed_at =
        evidence.consume_head.statement.observed_at_boottime_nanos;
    if observed_at > boottime_now_nanos()? {
        return Err(EndpointClientError::Invalid(
            "signed floor consume head is from the future",
        ));
    }
    authority.validate_at(initialization_deadline.domain(), observed_at)?;
    let consume_cursor = verify_signed_consume_head(
        &authority,
        initialization_deadline.domain(),
        &evidence.consume_head,
    )?;
    if consume_cursor.sequence_high_water
        < credential.minimum_consumer_sequence
    {
        return Err(EndpointClientError::Invalid(
            "signed floor consume head is below the systemd-configured consumer floor",
        ));
    }
    initialization_deadline.require_live()?;
    Ok(TrustedHostNoTeeAcceptedFloor {
        current_key_authorization: authority,
        consume_cursor,
        consume_head_observed_at_boottime_nanos: observed_at,
    })
}

fn checkpoint_chain_contains_exact(
    checkpoint_chain: &[SignedEndpointKeyAuthorizationCheckpoint],
    candidate: &SignedEndpointKeyAuthorizationCheckpoint,
) -> bool {
    checkpoint_chain
        .iter()
        .filter(|checkpoint| *checkpoint == candidate)
        .count()
        == 1
}

fn verify_durable_consume_inclusion_path(
    binding: &TrustedHostNoTeeEndpointBinding,
    expected_domain: BoottimeDomain,
    from_cursor: &EndpointConsumeCursor,
    from_observed_at_boottime_nanos: u64,
    to_cursor: &EndpointConsumeCursor,
    to_observed_at_boottime_nanos: u64,
    checkpoint_chain: &[SignedEndpointKeyAuthorizationCheckpoint],
    path: &TrustedHostNoTeeDurableConsumeInclusionPathWire,
) -> Result<(), EndpointClientError> {
    path.validate_shape()?;
    if path.endpoint_role != binding.credential.endpoint_role
        || path.from_sequence_high_water
            != from_cursor.sequence_high_water
        || path.from_predecessor_receipt_sha256
            != from_cursor.expected_predecessor_receipt_sha256
        || path.to_sequence_high_water
            != to_cursor.sequence_high_water
        || path.to_predecessor_receipt_sha256
            != to_cursor.expected_predecessor_receipt_sha256
        || from_observed_at_boottime_nanos == 0
        || to_observed_at_boottime_nanos
            < from_observed_at_boottime_nanos
    {
        return Err(EndpointClientError::Invalid(
            "durable-consume inclusion path does not bind the accepted and current heads",
        ));
    }
    let mut previous_consumed_at =
        from_observed_at_boottime_nanos;
    let mut previous_checkpoint_sequence = checkpoint_chain
        .first()
        .ok_or(EndpointClientError::Invalid(
            "durable-consume inclusion path has no checkpoint ancestry",
        ))?
        .payload
        .checkpoint_sequence;
    for successor in &path.successors {
        if !checkpoint_chain_contains_exact(
            checkpoint_chain,
            &successor.signing_key_authorization,
        ) {
            return Err(EndpointClientError::Invalid(
                "durable-consume inclusion receipt uses a checkpoint outside the exact predecessor path",
            ));
        }
        let signing_key = decode_ed25519_spki_base64(
            &successor.signing_public_key_spki_base64,
            "durable-consume inclusion signing key",
        )?;
        let signed = successor.persisted.signed_envelope();
        let authority = authorization_pin_from_checkpoint(
            binding.credential.endpoint_role,
            &signed.endpoint_process_identity_sha256,
            signing_key,
            binding.checkpoint_authority_verifying_key.clone(),
            successor.signing_key_authorization.clone(),
        )?;
        if authority.exact_checkpoint_sequence
            < previous_checkpoint_sequence
        {
            return Err(EndpointClientError::Invalid(
                "durable-consume inclusion path moved backward in the checkpoint predecessor chain",
            ));
        }
        previous_checkpoint_sequence =
            authority.exact_checkpoint_sequence;
        let observed_at =
            successor.persisted.consumed_at_boottime_nanos();
        if observed_at < previous_consumed_at
            || observed_at > to_observed_at_boottime_nanos
        {
            return Err(EndpointClientError::Invalid(
                "durable-consume inclusion receipt time is nonmonotonic or later than the signed current head",
            ));
        }
        previous_consumed_at = observed_at;
        authority.validate_at(expected_domain, observed_at)?;
        authority.verify_claim(
            expected_domain,
            signed.endpoint_role,
            &signed.endpoint_process_identity_sha256,
            signed.endpoint_generation,
            &signed.current_key_authorization_checkpoint_sha256,
            signed.revocation_generation,
            &signed.revocation_root_sha256,
            &signed.signing_key_id,
            &signed.signing_key_spki_sha256,
            observed_at,
        )?;
        verify_signature(
            &authority.verifying_key,
            binding
                .credential
                .endpoint_role
                .receipt_signature_domain(),
            &signed.canonical_signature_payload()?,
            &signed.signature_base64,
        )?;
    }
    Ok(())
}

fn verify_trusted_host_response_signature(
    pin: &EndpointTrustPin,
    pending: &PendingTrustedHostExchange,
    signed: &SignedEndpointResponseEnvelope,
    signature_payload: &[u8],
) -> Result<(), EndpointClientError> {
    if signed.endpoint_process_identity != pin.endpoint_process_identity
        || signed.endpoint_process_identity_sha256
            != pin.endpoint_process_identity_sha256
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host response process identity differs from the current endpoint pin",
        ));
    }
    pin.current_key_authorization.verify_claim(
        pin.boottime_domain,
        signed.endpoint_role,
        &signed.endpoint_process_identity_sha256,
        signed.endpoint_generation,
        &signed.current_key_authorization_checkpoint_sha256,
        signed.revocation_generation,
        &signed.revocation_root_sha256,
        &signed.signing_key_id,
        &signed.signing_key_spki_sha256,
        signed.observed_at_boottime_nanos,
    )?;
    verify_signature(
        &pin.current_key_authorization.verifying_key,
        pin.endpoint_role.response_signature_domain(),
        signature_payload,
        &signed.signature_base64,
    )?;
    pending.deadline.require_live()?;
    pin.current_key_authorization.validate_at(
        pin.boottime_domain,
        boottime_now_nanos()?,
    )
}

fn verify_trusted_host_current_response(
    binding: &TrustedHostNoTeeEndpointBinding,
    pending: &PendingTrustedHostExchange,
    frame: &[u8],
) -> Result<EndpointTrustPin, EndpointClientError> {
    let accepted_floor = match &pending.expected {
        PendingTrustedHostRequest::Current { accepted_floor } => {
            accepted_floor
        }
        PendingTrustedHostRequest::Historical { .. } => {
            return Err(EndpointClientError::Invalid(
                "current endpoint response completed a different request",
            ));
        }
    };
    let (signed, response, _, signature_payload) =
        decode_trusted_host_response(pending, frame)?;
    let (
        current_head_attestation,
        current_key_authorization,
        current_signing_public_key_spki_base64,
        checkpoint_predecessor_path,
        current_consume_head,
        consume_head_inclusion_path,
    ) = match response {
        TrustedHostNoTeeTrustResponseWire::CurrentEndpointTrust {
            current_head_attestation,
            current_key_authorization,
            current_signing_public_key_spki_base64,
            checkpoint_predecessor_path,
            current_consume_head,
            consume_head_inclusion_path,
        } => (
            current_head_attestation,
            current_key_authorization,
            current_signing_public_key_spki_base64,
            checkpoint_predecessor_path,
            current_consume_head,
            consume_head_inclusion_path,
        ),
        TrustedHostNoTeeTrustResponseWire::
            HistoricalDurableConsume { .. } => {
                return Err(EndpointClientError::Invalid(
                    "historical endpoint response returned for a current trust query",
                ));
            }
    };
    let current_signing_key = decode_ed25519_spki_base64(
        &current_signing_public_key_spki_base64,
        "current endpoint signing key",
    )?;
    let current_authority = authorization_pin_from_checkpoint(
        pending.endpoint_role,
        &signed.endpoint_process_identity_sha256,
        current_signing_key,
        binding.checkpoint_authority_verifying_key.clone(),
        current_key_authorization,
    )?;
    verify_fresh_current_head_attestation(
        binding,
        pending,
        signed.observed_at_boottime_nanos,
        &current_head_attestation,
        &current_authority.signed_current_key_authorization,
    )?;
    if current_authority.checkpoint_authority_key_id
            != binding
                .credential
                .checkpoint_authority_key_id
        || current_authority.checkpoint_authority_key_spki_sha256
            != binding
                .credential
                .checkpoint_authority_key_spki_sha256
        || current_authority.exact_checkpoint_sequence
            < binding.credential.minimum_checkpoint_sequence
        || current_authority.exact_endpoint_generation
            < binding.credential.minimum_endpoint_generation
        || current_authority
                .exact_revocation_generation_high_water
            < binding.credential.minimum_revocation_generation
        || current_authority.rollback_floor_checkpoint_sequence
            < binding.credential.minimum_checkpoint_sequence
        || current_authority.rollback_floor_endpoint_generation
            < binding.credential.minimum_endpoint_generation
        || current_authority.rollback_floor_consumer_sequence
            < binding.credential.minimum_consumer_sequence
    {
        return Err(EndpointClientError::Invalid(
            "current checkpoint authority or monotonic floor differs from systemd credential pins",
        ));
    }
    let checkpoint_chain = verify_checkpoint_predecessor_path(
        binding,
        &accepted_floor.current_key_authorization,
        &current_authority,
        &checkpoint_predecessor_path,
    )?;
    current_authority.validate_at(
        pending.deadline.domain(),
        signed.observed_at_boottime_nanos,
    )?;
    let consume_cursor = verify_signed_consume_head(
        &current_authority,
        pending.deadline.domain(),
        &current_consume_head,
    )?;
    if current_consume_head.statement.observed_at_boottime_nanos
            < pending.requested_at_boottime_nanos
        || current_consume_head.statement.observed_at_boottime_nanos
            > signed.observed_at_boottime_nanos
        || consume_cursor.sequence_high_water
            < binding.credential.minimum_consumer_sequence
    {
        return Err(EndpointClientError::Invalid(
            "current endpoint consume head is stale or below the systemd signed floor",
        ));
    }
    verify_durable_consume_inclusion_path(
        binding,
        pending.deadline.domain(),
        &accepted_floor.consume_cursor,
        accepted_floor.consume_head_observed_at_boottime_nanos,
        &consume_cursor,
        current_consume_head.statement.observed_at_boottime_nanos,
        &checkpoint_chain,
        &consume_head_inclusion_path,
    )?;
    let pin = EndpointTrustPin {
        endpoint_role: pending.endpoint_role,
        socket_path: binding.credential.socket_path.clone(),
        endpoint_uid: binding.credential.endpoint_uid,
        endpoint_gid: binding.credential.endpoint_gid,
        endpoint_process_identity:
            signed.endpoint_process_identity.clone(),
        endpoint_process_identity_sha256:
            signed.endpoint_process_identity_sha256.clone(),
        exact_endpoint_generation:
            current_authority.exact_endpoint_generation,
        boottime_domain: pending.deadline.domain(),
        current_key_authorization: current_authority,
        consume_cursor,
        consume_head_observed_at_boottime_nanos:
            current_consume_head.statement.observed_at_boottime_nanos,
    };
    pin.validate()?;
    verify_trusted_host_response_signature(
        &pin,
        pending,
        &signed,
        &signature_payload,
    )?;
    let live =
        LiveEndpointProcess::observe(pending.socket.as_raw_fd(), &pin)?;
    live.revalidate(pending.socket.as_raw_fd(), &pin)?;
    pending.deadline.require_live()?;
    Ok(pin)
}

fn verify_trusted_host_historical_response(
    binding: &TrustedHostNoTeeEndpointBinding,
    pending: &mut PendingTrustedHostExchange,
    frame: &[u8],
) -> Result<(), EndpointClientError> {
    let (
        expected_persisted,
        identity,
        expected_current_head,
        current_pin,
    ) = match &pending.expected {
        PendingTrustedHostRequest::Historical {
            persisted,
            identity,
            current_head,
            current_pin,
        } => (persisted, identity, current_head, current_pin),
        PendingTrustedHostRequest::Current { .. } => {
            return Err(EndpointClientError::Invalid(
                "historical endpoint response completed a current trust request",
            ));
        }
    };
    let (signed, response, _, signature_payload) =
        decode_trusted_host_response(pending, frame)?;
    verify_trusted_host_response_signature(
        current_pin,
        pending,
        &signed,
        &signature_payload,
    )?;
    let (
        current_head_attestation,
        persisted,
        historical_key_authorization,
        historical_signing_public_key_spki_base64,
        historical_checkpoint_predecessor_path,
        current_consume_head,
        durable_consume_inclusion_path,
    ) = match response {
        TrustedHostNoTeeTrustResponseWire::
            HistoricalDurableConsume {
                current_head_attestation,
                persisted,
                historical_key_authorization,
                historical_signing_public_key_spki_base64,
                historical_checkpoint_predecessor_path,
                current_consume_head,
                durable_consume_inclusion_path,
            } => (
                current_head_attestation,
                persisted,
                historical_key_authorization,
                historical_signing_public_key_spki_base64,
                historical_checkpoint_predecessor_path,
                current_consume_head,
                durable_consume_inclusion_path,
            ),
        TrustedHostNoTeeTrustResponseWire::CurrentEndpointTrust {
            ..
        } => {
            return Err(EndpointClientError::Invalid(
                "current endpoint response returned for historical verification",
            ));
        }
    };
    verify_fresh_current_head_attestation(
        binding,
        pending,
        signed.observed_at_boottime_nanos,
        &current_head_attestation,
        &current_pin
            .current_key_authorization
            .signed_current_key_authorization,
    )?;
    if &persisted != expected_persisted {
        return Err(EndpointClientError::Invalid(
            "historical endpoint response changed the exact persisted consume receipt",
        ));
    }
    let observed_current_head = verify_signed_consume_head(
        &current_pin.current_key_authorization,
        pending.deadline.domain(),
        &current_consume_head,
    )?;
    if current_consume_head.statement.observed_at_boottime_nanos
            < pending.requested_at_boottime_nanos
        || current_consume_head.statement.observed_at_boottime_nanos
            > signed.observed_at_boottime_nanos
        || &observed_current_head != expected_current_head
    {
        return Err(EndpointClientError::Invalid(
            "historical endpoint response is not bound to the requested current consume head",
        ));
    }
    persisted.validate_exact_bytes(pending.endpoint_role, identity)?;
    let historical_signing_key = decode_ed25519_spki_base64(
        &historical_signing_public_key_spki_base64,
        "historical endpoint signing key",
    )?;
    let receipt = &persisted.signed_envelope;
    let historical_authority = authorization_pin_from_checkpoint(
        pending.endpoint_role,
        &receipt.endpoint_process_identity_sha256,
        historical_signing_key,
        binding.checkpoint_authority_verifying_key.clone(),
        historical_key_authorization,
    )?;
    let checkpoint_chain = verify_checkpoint_predecessor_path(
        binding,
        &historical_authority,
        &current_pin.current_key_authorization,
        &historical_checkpoint_predecessor_path,
    )?;
    let consumed_at =
        persisted.statement.consumed_at_boottime_nanos;
    historical_authority.validate_at(
        pending.deadline.domain(),
        consumed_at,
    )?;
    historical_authority.verify_claim(
        pending.deadline.domain(),
        receipt.endpoint_role,
        &receipt.endpoint_process_identity_sha256,
        receipt.endpoint_generation,
        &receipt.current_key_authorization_checkpoint_sha256,
        receipt.revocation_generation,
        &receipt.revocation_root_sha256,
        &receipt.signing_key_id,
        &receipt.signing_key_spki_sha256,
        consumed_at,
    )?;
    let receipt_signature_payload =
        receipt.canonical_signature_payload()?;
    verify_signature(
        &historical_authority.verifying_key,
        pending.endpoint_role.receipt_signature_domain(),
        &receipt_signature_payload,
        &receipt.signature_base64,
    )?;
    let historical_cursor = EndpointConsumeCursor {
        sequence_high_water:
            persisted.statement.consumer_sequence,
        expected_next_sequence: persisted
            .statement
            .consumer_sequence
            .checked_add(1)
            .ok_or(EndpointClientError::Invalid(
                "historical durable consume sequence overflow",
            ))?,
        expected_predecessor_receipt_sha256:
            receipt.envelope_sha256.clone(),
    };
    historical_cursor.validate(1)?;
    verify_durable_consume_inclusion_path(
        binding,
        pending.deadline.domain(),
        &historical_cursor,
        consumed_at,
        &observed_current_head,
        current_consume_head.statement.observed_at_boottime_nanos,
        &checkpoint_chain,
        &durable_consume_inclusion_path,
    )?;
    if let Some(live_peer) = pending.live_peer.as_ref() {
        live_peer.revalidate(
            pending.socket.as_raw_fd(),
            current_pin,
        )?;
    } else {
        return Err(EndpointClientError::Invalid(
            "historical verification lacks a retained live endpoint peer",
        ));
    }
    pending.deadline.require_live()?;
    Ok(())
}

struct LiveEndpointProcess {
    pidfd: OwnedFd,
    executable: OwnedFd,
    identity: EndpointProcessIdentity,
}

impl LiveEndpointProcess {
    fn observe(
        socket_fd: RawFd,
        pin: &EndpointTrustPin,
    ) -> Result<Self, EndpointClientError> {
        let credentials = peer_credentials(socket_fd)?;
        if credentials.pid <= 0
            || credentials.uid != pin.endpoint_uid
            || credentials.gid != pin.endpoint_gid
            || credentials.pid
                != pin.endpoint_process_identity.endpoint_pid
        {
            return Err(EndpointClientError::Invalid(
                "SO_PEERCRED does not match the pinned endpoint process",
            ));
        }
        let pidfd = peer_pidfd(socket_fd)?;
        let pidfd_stat = descriptor_stat(pidfd.as_raw_fd())?;
        let start_time_ticks =
            process_start_time_ticks(credentials.pid)?;
        let executable = open_proc_executable(credentials.pid)?;
        let executable_stat = descriptor_stat(executable.as_raw_fd())?;
        if executable_stat.length == 0
            || executable_stat.length > MAX_EXECUTABLE_BYTES
            || executable_stat.mode & libc::S_IFMT
                != libc::S_IFREG
        {
            return Err(EndpointClientError::Invalid(
                "endpoint executable is not a bounded regular file",
            ));
        }
        let executable_sha256 = sha256_descriptor(
            executable.as_raw_fd(),
            executable_stat.length,
        )?;
        let executable_ima_sha256 =
            ima_xattr_sha256(executable.as_raw_fd())?;
        let executable_fs_verity_sha256 =
            fs_verity_sha256(executable.as_raw_fd())?;
        let observed = EndpointProcessIdentity {
            endpoint_role: pin.endpoint_role,
            endpoint_uid: credentials.uid,
            endpoint_gid: credentials.gid,
            endpoint_pid: credentials.pid,
            endpoint_start_time_ticks: start_time_ticks,
            endpoint_pidfd_inode: pidfd_stat.inode,
            endpoint_pidfd_stat_sha256: pidfd_stat_identity_sha256(
                pidfd_stat.device,
                pidfd_stat.inode,
                pidfd_stat.mode,
                pidfd_stat.uid,
                pidfd_stat.gid,
            ),
            executable_device: executable_stat.device,
            executable_inode: executable_stat.inode,
            executable_length: executable_stat.length,
            executable_sha256,
            executable_ima_sha256,
            executable_fs_verity_sha256,
            identity_sha256: Sha256Digest::compute(
                b"temporary-nonzero-process-identity",
            ),
        };
        let mut observed = observed;
        observed.identity_sha256 =
            observed.computed_identity_sha256()?;
        observed.validate_shape()?;
        if observed != pin.endpoint_process_identity
            || observed.identity_sha256
                != pin.endpoint_process_identity_sha256
        {
            return Err(EndpointClientError::Invalid(
                "live endpoint process does not match the signed process identity",
            ));
        }
        let live = Self {
            pidfd,
            executable,
            identity: observed,
        };
        live.revalidate(socket_fd, pin)?;
        Ok(live)
    }

    fn revalidate(
        &self,
        socket_fd: RawFd,
        pin: &EndpointTrustPin,
    ) -> Result<(), EndpointClientError> {
        let credentials = peer_credentials(socket_fd)?;
        if credentials.pid != self.identity.endpoint_pid
            || credentials.uid != self.identity.endpoint_uid
            || credentials.gid != self.identity.endpoint_gid
            || self.identity != pin.endpoint_process_identity
        {
            return Err(EndpointClientError::Invalid(
                "connected endpoint peer identity changed",
            ));
        }
        pidfd_require_live(
            self.pidfd.as_raw_fd(),
            self.identity.endpoint_pid,
        )?;
        let pidfd_stat = descriptor_stat(self.pidfd.as_raw_fd())?;
        if pidfd_stat.inode != self.identity.endpoint_pidfd_inode
            || pidfd_stat_identity_sha256(
                pidfd_stat.device,
                pidfd_stat.inode,
                pidfd_stat.mode,
                pidfd_stat.uid,
                pidfd_stat.gid,
            ) != self.identity.endpoint_pidfd_stat_sha256
            || process_start_time_ticks(self.identity.endpoint_pid)?
                != self.identity.endpoint_start_time_ticks
        {
            return Err(EndpointClientError::Invalid(
                "endpoint pidfd or process start identity changed",
            ));
        }
        let executable_stat =
            descriptor_stat(self.executable.as_raw_fd())?;
        if executable_stat.device != self.identity.executable_device
            || executable_stat.inode != self.identity.executable_inode
            || executable_stat.length != self.identity.executable_length
            || ima_xattr_sha256(self.executable.as_raw_fd())?
                != self.identity.executable_ima_sha256
            || fs_verity_sha256(self.executable.as_raw_fd())?
                != self.identity.executable_fs_verity_sha256
        {
            return Err(EndpointClientError::Invalid(
                "retained endpoint executable identity changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DescriptorStat {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
}

fn descriptor_stat(fd: RawFd) -> Result<DescriptorStat, EndpointClientError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_ino == 0
        || stat.st_size < 0
    {
        return Err(EndpointClientError::Invalid(
            "descriptor stat identity is unavailable",
        ));
    }
    Ok(DescriptorStat {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode as u32,
        uid: stat.st_uid,
        gid: stat.st_gid,
        length: stat.st_size as u64,
    })
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred, EndpointClientError> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred
                as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(EndpointClientError::Invalid(
            "SO_PEERCRED returned an invalid credential length",
        ));
    }
    Ok(credentials)
}

fn peer_pidfd(socket_fd: RawFd) -> Result<OwnedFd, EndpointClientError> {
    let mut raw_pidfd: libc::c_int = -1;
    let mut length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            SO_PEERPIDFD_OPT,
            &mut raw_pidfd as *mut libc::c_int
                as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == libc::ENOPROTOOPT
                    || code == libc::EINVAL
        ) {
            return Err(EndpointClientError::Invalid(
                "Linux SO_PEERPIDFD is unavailable; trusted-host peer identity fails closed",
            ));
        }
        return Err(EndpointClientError::InvalidOwned(format!(
            "Linux SO_PEERPIDFD failed closed: {error}"
        )));
    }
    if length as usize != size_of::<libc::c_int>()
        || raw_pidfd < 0
    {
        return Err(EndpointClientError::Invalid(
            "SO_PEERPIDFD did not return one retained peer pidfd",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw_pidfd) })
}

fn pidfd_require_live(
    pidfd: RawFd,
    expected_pid: i32,
) -> Result<(), EndpointClientError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 || pidfd_process_id(pidfd)? != expected_pid {
        return Err(EndpointClientError::Invalid(
            "endpoint pidfd is not live or no longer identifies the peer PID",
        ));
    }
    Ok(())
}

fn pidfd_process_id(pidfd: RawFd) -> Result<i32, EndpointClientError> {
    let path = CString::new(format!("/proc/self/fdinfo/{pidfd}"))
        .map_err(|_| {
            EndpointClientError::Invalid(
                "pidfd fdinfo path contains NUL",
            )
        })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let bytes = read_bounded_descriptor(
        fd.as_raw_fd(),
        MAX_PROC_STAT_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        EndpointClientError::Invalid("pidfd fdinfo is not UTF-8")
    })?;
    let mut parsed = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:\t") {
            if parsed.is_some() {
                return Err(EndpointClientError::Invalid(
                    "pidfd fdinfo contains duplicate Pid fields",
                ));
            }
            parsed = Some(value.trim().parse::<i32>().map_err(|_| {
                EndpointClientError::Invalid(
                    "pidfd fdinfo Pid is invalid",
                )
            })?);
        }
    }
    parsed.filter(|pid| *pid > 0).ok_or(
        EndpointClientError::Invalid(
            "pidfd does not identify a live process",
        ),
    )
}

fn process_start_time_ticks(
    pid: i32,
) -> Result<u64, EndpointClientError> {
    let path = CString::new(format!("/proc/{pid}/stat")).map_err(
        |_| EndpointClientError::Invalid("process stat path contains NUL"),
    )?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let bytes = read_bounded_descriptor(
        fd.as_raw_fd(),
        MAX_PROC_STAT_BYTES,
    )?;
    let stat = std::str::from_utf8(&bytes).map_err(|_| {
        EndpointClientError::Invalid("process stat is not UTF-8")
    })?;
    let close = stat.rfind(')').ok_or(
        EndpointClientError::Invalid(
            "process stat comm field is invalid",
        ),
    )?;
    let start_time = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(EndpointClientError::Invalid(
            "process stat start identity is missing",
        ))?
        .parse::<u64>()
        .map_err(|_| {
            EndpointClientError::Invalid(
                "process stat start identity is invalid",
            )
        })?;
    if start_time == 0 {
        return Err(EndpointClientError::Invalid(
            "process start identity is zero",
        ));
    }
    Ok(start_time)
}

fn open_proc_executable(pid: i32) -> Result<OwnedFd, EndpointClientError> {
    let path = CString::new(format!("/proc/{pid}/exe")).map_err(
        |_| EndpointClientError::Invalid("process exe path contains NUL"),
    )?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_bounded_descriptor(
    fd: RawFd,
    maximum_bytes: usize,
) -> Result<Vec<u8>, EndpointClientError> {
    let capacity = maximum_bytes.checked_add(1).ok_or(
        EndpointClientError::Invalid(
            "bounded descriptor read capacity overflow",
        ),
    )?;
    let mut bytes = vec![0_u8; capacity];
    let read = unsafe {
        libc::read(
            fd,
            bytes.as_mut_ptr() as *mut libc::c_void,
            bytes.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let read = usize::try_from(read).map_err(|_| {
        EndpointClientError::Invalid(
            "descriptor read length conversion failed",
        )
    })?;
    if read == 0 || read > maximum_bytes {
        return Err(EndpointClientError::Invalid(
            "descriptor data is empty or exceeds its fixed bound",
        ));
    }
    bytes.truncate(read);
    Ok(bytes)
}

fn sha256_descriptor(
    fd: RawFd,
    length: u64,
) -> Result<Sha256Digest, EndpointClientError> {
    if length == 0 || length > MAX_EXECUTABLE_BYTES {
        return Err(EndpointClientError::Invalid(
            "executable digest length is invalid",
        ));
    }
    let before = descriptor_stat(fd)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < length {
        let remaining = length - offset;
        let requested = usize::try_from(
            remaining.min(buffer.len() as u64),
        )
        .map_err(|_| {
            EndpointClientError::Invalid(
                "executable digest request length overflow",
            )
        })?;
        let offset_i64 = i64::try_from(offset).map_err(|_| {
            EndpointClientError::Invalid(
                "executable digest offset overflow",
            )
        })?;
        let read = unsafe {
            libc::pread(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                requested,
                offset_i64,
            )
        };
        if read <= 0 {
            return Err(if read < 0 {
                io::Error::last_os_error().into()
            } else {
                EndpointClientError::Invalid(
                    "executable changed while hashing",
                )
            });
        }
        let read = usize::try_from(read).map_err(|_| {
            EndpointClientError::Invalid(
                "executable digest read length overflow",
            )
        })?;
        hasher.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or(
            EndpointClientError::Invalid(
                "executable digest offset overflow",
            ),
        )?;
    }
    let after = descriptor_stat(fd)?;
    if before.device != after.device
        || before.inode != after.inode
        || before.length != after.length
        || before.mode != after.mode
        || before.uid != after.uid
        || before.gid != after.gid
    {
        return Err(EndpointClientError::Invalid(
            "executable descriptor changed while hashing",
        ));
    }
    Sha256Digest::parse(format!(
        "sha256:{}",
        hex::encode(hasher.finalize())
    ))
    .map_err(|_| {
        EndpointClientError::Invalid(
            "executable digest encoding failed",
        )
    })
}

fn ima_xattr_sha256(fd: RawFd) -> Result<Sha256Digest, EndpointClientError> {
    let name = b"security.ima\0";
    let length = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            0,
        )
    };
    if length <= 0
        || usize::try_from(length).ok().is_none_or(|length| {
            length > MAX_IMA_XATTR_BYTES
        })
    {
        return Err(EndpointClientError::Invalid(
            "IMA executable identity is unavailable or unbounded",
        ));
    }
    let mut value = vec![0_u8; length as usize];
    let read = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            value.as_mut_ptr() as *mut libc::c_void,
            value.len(),
        )
    };
    if read != length {
        return Err(EndpointClientError::Invalid(
            "IMA executable identity changed during read",
        ));
    }
    let digest = Sha256Digest::compute(&value);
    require_nonzero_digest("process.executableImaSha256", &digest)?;
    Ok(digest)
}

#[repr(C, align(8))]
struct FsVerityDigest {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; 64],
}

fn fs_verity_sha256(
    fd: RawFd,
) -> Result<Sha256Digest, EndpointClientError> {
    let mut buffer = FsVerityDigest {
        digest_algorithm: 0,
        digest_size: 64,
        digest: [0_u8; 64],
    };
    if unsafe {
        libc::ioctl(
            fd,
            FS_IOC_MEASURE_VERITY,
            &mut buffer as *mut FsVerityDigest,
        )
    } != 0
        || buffer.digest_algorithm != FS_VERITY_HASH_ALG_SHA256
        || buffer.digest_size != 32
    {
        return Err(EndpointClientError::Invalid(
            "mandatory SHA-256 fs-verity executable evidence is unavailable",
        ));
    }
    let digest = Sha256Digest::parse(format!(
        "sha256:{}",
        hex::encode(&buffer.digest[..32])
    ))
    .map_err(|_| {
        EndpointClientError::Invalid(
            "fs-verity digest encoding failed",
        )
    })?;
    require_nonzero_digest(
        "process.executableFsVeritySha256",
        &digest,
    )?;
    Ok(digest)
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn fill_getrandom_exact(
    output: &mut [u8],
) -> Result<(), EndpointClientError> {
    let mut offset = 0_usize;
    while offset < output.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                output[offset..].as_mut_ptr(),
                output.len() - offset,
                GETRANDOM_NONBLOCK,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code) if code == libc::EINTR => continue,
                Some(code) if code == libc::ENOSYS => {
                    return Err(EndpointClientError::Invalid(
                        "Linux getrandom is unavailable; trust request nonce generation fails closed",
                    ));
                }
                Some(code) if code == libc::EAGAIN => {
                    return Err(EndpointClientError::Invalid(
                        "Linux getrandom entropy is not initialized; trust request nonce generation fails closed",
                    ));
                }
                _ => {
                    return Err(EndpointClientError::InvalidOwned(
                        format!(
                            "Linux getrandom failed closed: {error}"
                        ),
                    ));
                }
            }
        }
        let count = usize::try_from(read).map_err(|_| {
            EndpointClientError::Invalid(
                "Linux getrandom returned an invalid byte count",
            )
        })?;
        if count == 0 || count > output.len() - offset {
            return Err(EndpointClientError::Invalid(
                "Linux getrandom returned an invalid short read",
            ));
        }
        offset += count;
    }
    Ok(())
}

fn openat2_beneath(
    directory_fd: RawFd,
    relative_path: &CString,
    flags: libc::c_int,
    label: &'static str,
) -> Result<OwnedFd, EndpointClientError> {
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: OPENAT2_RESOLVE_BENEATH
            | OPENAT2_RESOLVE_NO_SYMLINKS
            | OPENAT2_RESOLVE_NO_MAGICLINKS,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory_fd,
            relative_path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            return Err(EndpointClientError::Invalid(
                "Linux openat2 is unavailable; trusted-host credential loading fails closed",
            ));
        }
        return Err(EndpointClientError::InvalidOwned(format!(
            "{label} openat2 failed closed: {error}"
        )));
    }
    let raw_fd = libc::c_int::try_from(raw).map_err(|_| {
        EndpointClientError::Invalid(
            "openat2 returned a descriptor outside c_int",
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

fn systemd_credentials_directory(
) -> Result<OwnedFd, EndpointClientError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or(EndpointClientError::Invalid(
            "CREDENTIALS_DIRECTORY is absent",
        ))?;
    if !directory.is_absolute()
        || directory.as_os_str().as_bytes().contains(&0)
    {
        return Err(EndpointClientError::Invalid(
            "CREDENTIALS_DIRECTORY must be an absolute non-NUL path",
        ));
    }
    let directory_bytes = directory.as_os_str().as_bytes();
    if directory_bytes == b"/" {
        return Err(EndpointClientError::Invalid(
            "CREDENTIALS_DIRECTORY must not be the filesystem root",
        ));
    }
    if directory_bytes[1..]
        .split(|byte| *byte == b'/')
        .any(|component| {
            component.is_empty()
                || component == b"."
                || component == b".."
        })
    {
        return Err(EndpointClientError::Invalid(
            "CREDENTIALS_DIRECTORY must contain only canonical absolute path components",
        ));
    }
    let relative_directory = CString::new(&directory_bytes[1..]).map_err(
        |_| {
            EndpointClientError::Invalid(
                "CREDENTIALS_DIRECTORY contains NUL",
            )
        },
    )?;
    let root_path = CString::new("/").map_err(|_| {
        EndpointClientError::Invalid(
            "filesystem root path encoding failed",
        )
    })?;
    let raw_root = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_PATH
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
        )
    };
    if raw_root < 0 {
        return Err(EndpointClientError::InvalidOwned(format!(
            "filesystem root descriptor failed closed: {}",
            io::Error::last_os_error()
        )));
    }
    let root = unsafe { OwnedFd::from_raw_fd(raw_root) };
    let retained = openat2_beneath(
        root.as_raw_fd(),
        &relative_directory,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        "CREDENTIALS_DIRECTORY",
    )?;
    let stat = descriptor_stat(retained.as_raw_fd())?;
    let effective_uid = unsafe { libc::geteuid() };
    if stat.mode & libc::S_IFMT as u32
            != libc::S_IFDIR as u32
        || stat.mode & 0o022 != 0
        || (stat.uid != 0 && stat.uid != effective_uid)
    {
        return Err(EndpointClientError::Invalid(
            "retained CREDENTIALS_DIRECTORY descriptor metadata is unsafe",
        ));
    }
    Ok(retained)
}

fn validate_systemd_credential_name(
    name: &str,
) -> Result<(), EndpointClientError> {
    if name.is_empty()
        || name.len() > 255
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
        })
        || name == "."
        || name == ".."
    {
        return Err(EndpointClientError::Invalid(
            "systemd credential name is invalid",
        ));
    }
    Ok(())
}

fn read_systemd_credential(
    directory: &OwnedFd,
    name: &str,
    maximum_bytes: usize,
    deadline: BoottimeDeadline,
) -> Result<Vec<u8>, EndpointClientError> {
    validate_systemd_credential_name(name)?;
    if maximum_bytes == 0
        || maximum_bytes > MAX_SYSTEMD_CREDENTIAL_BYTES
    {
        return Err(EndpointClientError::Invalid(
            "systemd credential bound is invalid",
        ));
    }
    deadline.require_live()?;
    let child_name = CString::new(name).map_err(|_| {
        EndpointClientError::Invalid(
            "systemd credential name contains NUL",
        )
    })?;
    let credential_fd = openat2_beneath(
        directory.as_raw_fd(),
        &child_name,
        libc::O_RDONLY | libc::O_CLOEXEC,
        "systemd credential",
    )?;
    let mut file = File::from(credential_fd);
    let before = file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum_bytes as u64
        || before.mode() & 0o022 != 0
        || (before.uid() != 0 && before.uid() != effective_uid)
    {
        return Err(EndpointClientError::Invalid(
            "systemd credential metadata is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(
            u64::try_from(maximum_bytes)
                .map_err(|_| {
                    EndpointClientError::Invalid(
                        "systemd credential bound conversion failed",
                    )
                })?
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)?;
    deadline.require_live()?;
    let after = file.metadata()?;
    if bytes.len() != before.len() as usize
        || bytes.len() > maximum_bytes
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
    {
        return Err(EndpointClientError::Invalid(
            "systemd credential changed while it was read",
        ));
    }
    Ok(bytes)
}

fn read_systemd_verifying_key(
    directory: &OwnedFd,
    credential_name: &str,
    deadline: BoottimeDeadline,
) -> Result<VerifyingKey, EndpointClientError> {
    let bytes = read_systemd_credential(
        directory,
        credential_name,
        64 * 1024,
        deadline,
    )?;
    if bytes.len() == 32 {
        let raw: [u8; 32] = bytes.try_into().map_err(|_| {
            EndpointClientError::Invalid(
                "raw Ed25519 public key length changed",
            )
        })?;
        return VerifyingKey::from_bytes(&raw).map_err(|_| {
            EndpointClientError::Invalid(
                "systemd credential is not an Ed25519 public key",
            )
        });
    }
    if let Ok(key) = VerifyingKey::from_public_key_der(&bytes) {
        return Ok(key);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        EndpointClientError::Invalid(
            "systemd public-key credential is not raw, DER, or PEM",
        )
    })?;
    VerifyingKey::from_public_key_pem(text.trim()).map_err(|_| {
        EndpointClientError::Invalid(
            "systemd public-key credential is not Ed25519",
        )
    })
}

fn validate_configured_verifying_key(
    key: &VerifyingKey,
    expected_spki_sha256: &Sha256Digest,
    label: &'static str,
) -> Result<(), EndpointClientError> {
    require_nonzero_digest(label, expected_spki_sha256)?;
    let spki = key.to_public_key_der().map_err(|_| {
        EndpointClientError::Invalid(
            "configured Ed25519 key cannot be encoded as SPKI DER",
        )
    })?;
    if &Sha256Digest::compute(spki.as_bytes())
        != expected_spki_sha256
    {
        return Err(EndpointClientError::InvalidOwned(format!(
            "{label} SPKI digest differs from the systemd credential configuration"
        )));
    }
    Ok(())
}

fn validate_trusted_host_configuration(
    configuration: &TrustedHostNoTeeEndpointConfigCredential,
) -> Result<(), EndpointClientError> {
    if configuration.api_version != POLICY_CUSTODY_PROTOCOL_VERSION
        || configuration.attestation_mode
            != TRUSTED_HOST_NO_TEE_MODE
        || !configuration.co_located
        || configuration.hardware_proof
        || configuration.maximum_frame_bytes == 0
        || configuration.maximum_frame_bytes
            > MAX_ENDPOINT_FRAME_BYTES
        || configuration.endpoints.is_empty()
        || configuration.endpoints.len() > 6
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host configuration must be bounded, co-located, and explicitly no-hardware",
        ));
    }
    let mut roles = BTreeMap::new();
    for endpoint in &configuration.endpoints {
        validate_systemd_credential_name(
            &endpoint.signed_floor_evidence_credential,
        )?;
        validate_systemd_credential_name(
            &endpoint
                .checkpoint_authority_public_key_credential,
        )?;
        require_nonzero_digest(
            "trustedHostConfig.checkpointAuthorityKeyId",
            &endpoint.checkpoint_authority_key_id,
        )?;
        require_nonzero_digest(
            "trustedHostConfig.checkpointAuthorityKeySpkiSha256",
            &endpoint.checkpoint_authority_key_spki_sha256,
        )?;
        if !endpoint.socket_path.is_absolute()
            || endpoint
                .socket_path
                .as_os_str()
                .as_bytes()
                .is_empty()
            || endpoint
                .socket_path
                .as_os_str()
                .as_bytes()
                .contains(&0)
            || endpoint
                    .socket_path
                    .as_os_str()
                    .as_bytes()
                    .len()
                >= unsafe {
                    zeroed::<libc::sockaddr_un>()
                        .sun_path
                        .len()
                }
            || endpoint.signed_floor_evidence_credential
                == endpoint
                    .checkpoint_authority_public_key_credential
            || endpoint.minimum_checkpoint_sequence == 0
            || endpoint.minimum_endpoint_generation == 0
            || endpoint.minimum_revocation_generation == 0
            || endpoint.minimum_consumer_sequence == 0
            || roles
                .insert(endpoint.endpoint_role, ())
                .is_some()
        {
            return Err(EndpointClientError::Invalid(
                "trusted-host endpoint path, role, or key separation is invalid",
            ));
        }
    }
    if !roles.contains_key(&PolicyCustodyEndpointRole::SignerHsm)
        || !roles
            .contains_key(&PolicyCustodyEndpointRole::SettlementStore)
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host configuration requires signer HSM and settlement store endpoints",
        ));
    }
    Ok(())
}

fn require_independent_signer_and_store_bindings(
    bindings:
        &BTreeMap<
            PolicyCustodyEndpointRole,
            TrustedHostNoTeeEndpointBinding,
        >,
) -> Result<(), EndpointClientError> {
    let signer = bindings
        .get(&PolicyCustodyEndpointRole::SignerHsm)
        .ok_or(EndpointClientError::Invalid(
            "trusted-host signer HSM binding is absent",
        ))?;
    let store = bindings
        .get(&PolicyCustodyEndpointRole::SettlementStore)
        .ok_or(EndpointClientError::Invalid(
            "trusted-host settlement store binding is absent",
        ))?;
    if signer.credential.socket_path
            == store.credential.socket_path
        || signer.credential.endpoint_uid
            == store.credential.endpoint_uid
        || signer
                .signed_floor
                .current_key_authorization
                .signing_key_id
            == store
                .signed_floor
                .current_key_authorization
                .signing_key_id
        || signer
                .signed_floor
                .current_key_authorization
                .signing_key_spki_sha256
            == store
                .signed_floor
                .current_key_authorization
                .signing_key_spki_sha256
        || signer
                .signed_floor
                .current_key_authorization
                .verifying_key
            == store
                .signed_floor
                .current_key_authorization
                .verifying_key
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host signer HSM and settlement store are not independently addressed and keyed",
        ));
    }
    Ok(())
}

fn create_progress_epoll() -> Result<OwnedFd, EndpointClientError> {
    let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if raw < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOSYS) {
            return Err(EndpointClientError::Invalid(
                "Linux epoll is unavailable; trusted-host progress polling fails closed",
            ));
        }
        return Err(EndpointClientError::InvalidOwned(format!(
            "Linux epoll initialization failed closed: {error}"
        )));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn progress_events_for_stage(stage: PendingSocketStage) -> u32 {
    let interest = match stage {
        PendingSocketStage::Connecting
        | PendingSocketStage::Sending => libc::EPOLLOUT as u32,
        PendingSocketStage::Receiving => libc::EPOLLIN as u32,
    };
    interest
        | libc::EPOLLERR as u32
        | libc::EPOLLHUP as u32
        | libc::EPOLLRDHUP as u32
}

fn register_progress_socket(
    epoll_fd: RawFd,
    socket_fd: RawFd,
    stage: PendingSocketStage,
) -> Result<(), EndpointClientError> {
    let mut event: libc::epoll_event = unsafe { zeroed() };
    event.events = progress_events_for_stage(stage);
    event.u64 = TRUSTED_HOST_EPOLL_TOKEN;
    if unsafe {
        libc::epoll_ctl(
            epoll_fd,
            libc::EPOLL_CTL_ADD,
            socket_fd,
            &mut event,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn modify_progress_socket(
    epoll_fd: RawFd,
    socket_fd: RawFd,
    stage: PendingSocketStage,
) -> Result<(), EndpointClientError> {
    let mut event: libc::epoll_event = unsafe { zeroed() };
    event.events = progress_events_for_stage(stage);
    event.u64 = TRUSTED_HOST_EPOLL_TOKEN;
    if unsafe {
        libc::epoll_ctl(
            epoll_fd,
            libc::EPOLL_CTL_MOD,
            socket_fd,
            &mut event,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn unregister_progress_socket(
    epoll_fd: RawFd,
    socket_fd: RawFd,
) -> Result<(), EndpointClientError> {
    if unsafe {
        libc::epoll_ctl(
            epoll_fd,
            libc::EPOLL_CTL_DEL,
            socket_fd,
            std::ptr::null_mut(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn take_progress_socket_event(
    epoll_fd: RawFd,
) -> Result<Option<u32>, EndpointClientError> {
    let mut event: libc::epoll_event = unsafe { zeroed() };
    let count = unsafe {
        libc::epoll_wait(epoll_fd, &mut event, 1, 0)
    };
    if count < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(error.into());
    }
    if count == 0 {
        return Ok(None);
    }
    if count != 1 || event.u64 != TRUSTED_HOST_EPOLL_TOKEN {
        return Err(EndpointClientError::Invalid(
            "trusted-host progress epoll returned an unknown event",
        ));
    }
    Ok(Some(event.events))
}

fn start_seqpacket_nonblocking(
    path: &Path,
) -> Result<(OwnedFd, bool), EndpointClientError> {
    if !path.is_absolute() {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint socket path must be absolute",
        ));
    }
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty() || path_bytes.contains(&0) {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint socket path is invalid",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if path_bytes.len() >= address.sun_path.len() {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address
        .sun_path
        .iter_mut()
        .zip(path_bytes.iter().copied())
    {
        *target = source as libc::c_char;
    }
    let address_length = size_of::<libc::sa_family_t>()
        .checked_add(path_bytes.len())
        .and_then(|length| length.checked_add(1))
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or(EndpointClientError::Invalid(
            "trusted-host endpoint socket address length is invalid",
        ))?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET
                | libc::SOCK_CLOEXEC
                | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let connected = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            &address as *const libc::sockaddr_un
                as *const libc::sockaddr,
            address_length,
        )
    };
    if connected == 0 {
        return Ok((socket, true));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::EISCONN => Ok((socket, true)),
        Some(code)
            if code == libc::EINPROGRESS
                || code == libc::EALREADY
                || code == libc::EAGAIN
                || code == libc::EWOULDBLOCK
                || code == libc::EINTR =>
        {
            Ok((socket, false))
        }
        _ => Err(error.into()),
    }
}

fn validate_trusted_host_peer_credentials(
    socket_fd: RawFd,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), EndpointClientError> {
    let credentials = peer_credentials(socket_fd)?;
    if credentials.pid <= 0
        || credentials.uid != expected_uid
        || credentials.gid != expected_gid
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint UDS peer credentials do not match the configured role",
        ));
    }
    Ok(())
}

fn try_send_seqpacket_nonblocking(
    fd: RawFd,
    frame: &[u8],
) -> Result<bool, EndpointClientError> {
    if frame.is_empty() || frame.len() > MAX_ENDPOINT_FRAME_BYTES {
        return Err(EndpointClientError::Invalid(
            "trusted-host outbound frame bound is invalid",
        ));
    }
    let sent = unsafe {
        libc::send(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        let error = io::Error::last_os_error();
        if is_would_block(&error)
            || error.kind() == io::ErrorKind::Interrupted
        {
            return Ok(false);
        }
        return Err(error.into());
    }
    if usize::try_from(sent).ok() != Some(frame.len()) {
        return Err(EndpointClientError::Invalid(
            "trusted-host SOCK_SEQPACKET request was not sent atomically",
        ));
    }
    Ok(true)
}

fn try_receive_seqpacket_nonblocking(
    fd: RawFd,
    maximum_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, EndpointClientError> {
    if maximum_frame_bytes == 0
        || maximum_frame_bytes > MAX_ENDPOINT_FRAME_BYTES
    {
        return Err(EndpointClientError::Invalid(
            "trusted-host inbound frame bound is invalid",
        ));
    }
    let mut frame = vec![0_u8; maximum_frame_bytes];
    let received = unsafe {
        libc::recv(
            fd,
            frame.as_mut_ptr() as *mut libc::c_void,
            frame.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        let error = io::Error::last_os_error();
        if is_would_block(&error)
            || error.kind() == io::ErrorKind::Interrupted
        {
            return Ok(None);
        }
        return Err(error.into());
    }
    let received = usize::try_from(received).map_err(|_| {
        EndpointClientError::Invalid(
            "trusted-host endpoint response length conversion failed",
        )
    })?;
    if received == 0 {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint closed without a response",
        ));
    }
    if received > maximum_frame_bytes {
        return Err(EndpointClientError::Invalid(
            "trusted-host endpoint response exceeded its frame bound",
        ));
    }
    frame.truncate(received);
    Ok(Some(frame))
}

fn wait_socket(
    fd: RawFd,
    interest: PollInterest,
    deadline: BoottimeDeadline,
) -> Result<ProgressFd, EndpointClientError> {
    let descriptor = unsafe { BorrowedFd::borrow_raw(fd) };
    let targets = [PollTarget::socket(descriptor, interest)];
    match poll_until(deadline, &targets)? {
        WaitOutcome::DeadlineExpired => {
            Err(EndpointClientError::DeadlineExpired)
        }
        WaitOutcome::Progress(mut ready) if ready.len() == 1 => {
            Ok(ready.remove(0))
        }
        WaitOutcome::Progress(_) => Err(EndpointClientError::Invalid(
            "BOOTTIME socket poll returned an invalid ready set",
        )),
    }
}

fn connect_seqpacket(
    path: &Path,
    deadline: BoottimeDeadline,
) -> Result<OwnedFd, EndpointClientError> {
    if !path.is_absolute() {
        return Err(EndpointClientError::Invalid(
            "endpoint socket path must be absolute",
        ));
    }
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty() || path_bytes.contains(&0) {
        return Err(EndpointClientError::Invalid(
            "endpoint socket path is invalid",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    if path_bytes.len() >= address.sun_path.len() {
        return Err(EndpointClientError::Invalid(
            "endpoint socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address
        .sun_path
        .iter_mut()
        .zip(path_bytes.iter().copied())
    {
        *target = source as libc::c_char;
    }
    let address_length = size_of::<libc::sa_family_t>()
        .checked_add(path_bytes.len())
        .and_then(|length| length.checked_add(1))
        .ok_or(EndpointClientError::Invalid(
            "endpoint socket address length overflow",
        ))?;
    let address_length =
        libc::socklen_t::try_from(address_length).map_err(|_| {
            EndpointClientError::Invalid(
                "endpoint socket address length is invalid",
            )
        })?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET
                | libc::SOCK_CLOEXEC
                | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    loop {
        let connected = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &address as *const libc::sockaddr_un
                    as *const libc::sockaddr,
                address_length,
            )
        };
        if connected == 0 {
            return Ok(socket);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == libc::EISCONN => return Ok(socket),
            Some(code)
                if code == libc::EAGAIN
                    || code == libc::EWOULDBLOCK
                    || code == libc::EINTR =>
            {
                let ready = wait_socket(
                    socket.as_raw_fd(),
                    PollInterest::WRITABLE,
                    deadline,
                )?;
                if ready.errored() || ready.hung_up() {
                    return Err(EndpointClientError::Invalid(
                        "endpoint connection failed before deadline",
                    ));
                }
                continue;
            }
            Some(code) if code == libc::EINPROGRESS => {
                let ready = wait_socket(
                    socket.as_raw_fd(),
                    PollInterest::WRITABLE,
                    deadline,
                )?;
                if ready.errored()
                    || ready.hung_up()
                    || !ready.writable()
                {
                    return Err(EndpointClientError::Invalid(
                        "endpoint connection failed before deadline",
                    ));
                }
                let socket_error =
                    socket_pending_error(socket.as_raw_fd())?;
                if socket_error == 0 {
                    return Ok(socket);
                }
                return Err(
                    io::Error::from_raw_os_error(socket_error).into()
                );
            }
            _ => return Err(error.into()),
        }
    }
}

fn socket_pending_error(fd: RawFd) -> Result<i32, EndpointClientError> {
    let mut socket_error: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut socket_error as *mut libc::c_int
                as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::c_int>()
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(socket_error)
}

fn send_seqpacket(
    fd: RawFd,
    frame: &[u8],
    deadline: BoottimeDeadline,
) -> Result<(), EndpointClientError> {
    if frame.is_empty() || frame.len() > MAX_ENDPOINT_FRAME_BYTES {
        return Err(EndpointClientError::Invalid(
            "outbound endpoint frame bound is invalid",
        ));
    }
    loop {
        let ready =
            wait_socket(fd, PollInterest::WRITABLE, deadline)?;
        if ready.errored() || ready.hung_up() || !ready.writable() {
            return Err(EndpointClientError::Invalid(
                "endpoint closed before request send",
            ));
        }
        let sent = unsafe {
            libc::send(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if is_would_block(&error)
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(error.into());
        }
        if usize::try_from(sent).ok() != Some(frame.len()) {
            return Err(EndpointClientError::Invalid(
                "SOCK_SEQPACKET request was not sent atomically",
            ));
        }
        return Ok(());
    }
}

fn receive_seqpacket(
    fd: RawFd,
    maximum_frame_bytes: usize,
    deadline: BoottimeDeadline,
) -> Result<Vec<u8>, EndpointClientError> {
    if maximum_frame_bytes == 0
        || maximum_frame_bytes > MAX_ENDPOINT_FRAME_BYTES
    {
        return Err(EndpointClientError::Invalid(
            "inbound endpoint frame bound is invalid",
        ));
    }
    let mut frame = vec![0_u8; maximum_frame_bytes];
    loop {
        let ready =
            wait_socket(fd, PollInterest::READABLE, deadline)?;
        if ready.errored() {
            return Err(EndpointClientError::Invalid(
                "endpoint reported a response transport error",
            ));
        }
        let received = unsafe {
            libc::recv(
                fd,
                frame.as_mut_ptr() as *mut libc::c_void,
                frame.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if is_would_block(&error)
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(error.into());
        }
        let received = usize::try_from(received).map_err(|_| {
            EndpointClientError::Invalid(
                "endpoint response length conversion failed",
            )
        })?;
        if received == 0 {
            return Err(EndpointClientError::Invalid(
                "endpoint closed without a response",
            ));
        }
        if received > maximum_frame_bytes {
            return Err(EndpointClientError::Invalid(
                "endpoint response exceeded the frame bound",
            ));
        }
        frame.truncate(received);
        return Ok(frame);
    }
}

fn is_would_block(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EAGAIN || code == libc::EWOULDBLOCK
    )
}
