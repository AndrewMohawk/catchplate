//! TrustedHostNoTee durable recovery-store authority.
//!
//! The service is intentionally recovery-only: registrations and initial
//! settlement material are supplied as a validated durable seed. Every served
//! request is wrapped in a signed, monotonic version record and committed to
//! the shared append journal before the reply can be acknowledged.

use super::common::{
    decode_canonical_frame, encode_canonical_frame,
    AuthenticatedInheritedSeqpacket, DurableAppendJournal,
    ExpectedPeerCredentials, NonblockingExchangeProgress,
    NonblockingRequestReplyExchange, ServiceCurrentHeadBindingV3,
    ServiceError, ServiceRequestFrameV3, ServiceResponseFrameV3,
    TrustedHostServiceRoleV3, MAX_SERVICE_FRAME_BYTES,
};
use super::wire::{
    CasDispositionV3, CurrentAuthoritySubjectV3,
    CleanupStepMaterialV3,
    DurableOwnershipRecordV3,
    DurableRecoveryStoreReplyV3, DurableRecoveryStoreRequestV3,
    OwnershipCasTransitionV3, OwnershipPhaseV3,
    PolicyCustodyServiceRoleV3, RecoveryKeyV3, RecoveryMaterialV3,
    StoredCleanupConsumptionEvidenceV3,
    StoredSignedEndpointResponseV3,
    ServiceResponseSignatureV3, SignedServiceResponseV3,
    MAX_RECOVERY_SCAN_RECORDS,
    POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION,
};
use super::super::boottime::{
    boottime_now_nanos,
    BoottimeDeadline as AbsoluteBoottimeDeadline,
    LinuxAbsoluteBoottimePoller, PollInterest, PollTarget,
};
use super::super::protocol::{
    domain_separated_signature_preimage, endpoint_response_sha256,
    require_nonzero_digest, DurableSettlementRecord,
    EndpointProcessIdentity, PolicyCustodyEndpointRole,
    ProtocolBoottimeDeadline, WatchdogLeaseV3,
};
use super::super::watchdog_recovery::{
    AuthorizedCleanupStep, CasDisposition, CasTransitionResult,
    CleanupTraceRequestBindings, DurableOwnershipRecord,
    DurableRecoveryStore, ExactCleanupBinding, OwnershipPhase,
    RecoveryDigest, RecoveryError, RecoveryKey, RecoveryScanPage,
    StoredCleanupEvidence, TrustedHostRecoveryProtocol,
    UnverifiedCleanupAuthorizationConsumption,
    UnverifiedSignedEndpointResponse,
};
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};

const RECOVERY_STORE_VERSION: &str =
    "serverware.policyCustodyDurableRecoveryStoreVersion/v3";
const RECOVERY_STORE_TRANSACTION_VERSION: &str =
    "serverware.policyCustodyDurableRecoveryStoreTransaction/v3";
const RECOVERY_STORE_STATE_ROOT_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableRecoveryStoreStateRoot/v3";
const RECOVERY_STORE_VERSION_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableRecoveryStoreVersion/v3";
const RECOVERY_STORE_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableRecoveryStoreRequest/v3";
const RECOVERY_STORE_IDEMPOTENCY_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableRecoveryStoreIdempotency/v3";
const RECOVERY_STORE_CURRENT_HEAD_REQUEST_BINDING_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableRecoveryStoreCurrentHeadRequestBinding/v3";
const RECOVERY_STORE_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyServiceResponse/v3";
const OWNERSHIP_TRANSITION_STATE_DOMAIN: &[u8] =
    b"serverware.policyCustodyDurableOwnershipTransitionState/v3";
const RECOVERY_STORE_ENDPOINT_ROLE: PolicyCustodyEndpointRole =
    PolicyCustodyEndpointRole::SettlementStore;
const MAX_RECOVERY_STORE_JOURNAL_RECORDS: usize = 1_000_000;
const MAX_RECOVERY_STORE_JOURNAL_BYTES: usize =
    256 * 1024 * 1024;

fn service_error(error: ServiceError) -> RecoveryError {
    match error {
        ServiceError::IdempotencyConflict => RecoveryError::Conflict(
            "recovery-store idempotency key changed its exact request",
        ),
        ServiceError::Io(_) | ServiceError::JournalBusy => {
            RecoveryError::Durable(
                "recovery-store durable service is unavailable",
            )
        }
        ServiceError::Protocol(_)
        | ServiceError::Invalid(_)
        | ServiceError::InvalidOwned(_) => RecoveryError::Authorization(
            "recovery-store v3 service frame is invalid",
        ),
    }
}

fn protocol_error() -> RecoveryError {
    RecoveryError::Authorization(
        "recovery-store runtime and wire projections disagree",
    )
}

fn require_live(
    deadline: &AbsoluteBoottimeDeadline,
) -> Result<(), RecoveryError> {
    deadline.require_live().map_err(|_| {
        RecoveryError::Deadline(
            "recovery-store operation crossed its exact BOOTTIME deadline",
        )
    })
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid(
            "recovery-store value is not canonical JSON",
        )
    })?;
    Ok(hash_domain_frames(domain, &[canonical.as_slice()]))
}

fn duplicate_cloexec(fd: RawFd) -> Result<OwnedFd, ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "recovery-store progress descriptor is invalid",
        ));
    }
    loop {
        let duplicate =
            unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(duplicate) });
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
}

fn signature_payload(
    signature: &ServiceResponseSignatureV3,
) -> Result<Vec<u8>, ServiceError> {
    canonical_json_bytes(&(
        &signature.api_version,
        signature.service_role,
        &signature.request_id_sha256,
        &signature.response_sha256,
        &signature.endpoint_process_identity,
        signature.endpoint_generation,
        &signature.current_key_authorization_checkpoint_sha256,
        signature.revocation_generation,
        &signature.revocation_root_sha256,
        signature.observed_at_boottime_nanos,
        &signature.signing_key_id,
        &signature.signing_key_spki_sha256,
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "recovery-store signature payload is not canonical",
        )
    })
}

fn signature_receipt(
    signature: &ServiceResponseSignatureV3,
) -> Result<Sha256Digest, ServiceError> {
    Ok(hash_domain_frames(
        RECOVERY_STORE_RESPONSE_SIGNATURE_DOMAIN,
        &[
            signature_payload(signature)?.as_slice(),
            signature.signature_base64.as_bytes(),
        ],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableRecoveryStoreVersionV3 {
    api_version: String,
    sequence: u64,
    previous_version_sha256: Option<Sha256Digest>,
    exact_request_frame_sha256: Sha256Digest,
    reply_sha256: Sha256Digest,
    state_root_sha256: Sha256Digest,
    version_sha256: Sha256Digest,
}

impl DurableRecoveryStoreVersionV3 {
    fn new(
        sequence: u64,
        previous_version_sha256: Option<Sha256Digest>,
        exact_request_frame: &[u8],
        reply: &DurableRecoveryStoreReplyV3,
        state_root_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        let reply_bytes = encode_canonical_frame(reply)?;
        let mut version = Self {
            api_version: RECOVERY_STORE_VERSION.to_string(),
            sequence,
            previous_version_sha256,
            exact_request_frame_sha256:
                Sha256Digest::compute(exact_request_frame),
            reply_sha256: Sha256Digest::compute(&reply_bytes),
            state_root_sha256,
            version_sha256: Sha256Digest::compute(&[]),
        };
        version.version_sha256 =
            version.computed_version_sha256()?;
        version.validate(exact_request_frame, reply)?;
        Ok(version)
    }

    fn computed_version_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        canonical_digest(
            RECOVERY_STORE_VERSION_DOMAIN,
            &(
                &self.api_version,
                self.sequence,
                &self.previous_version_sha256,
                &self.exact_request_frame_sha256,
                &self.reply_sha256,
                &self.state_root_sha256,
            ),
        )
    }

    fn validate(
        &self,
        exact_request_frame: &[u8],
        reply: &DurableRecoveryStoreReplyV3,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "recoveryStoreVersion.exactRequestFrameSha256",
            &self.exact_request_frame_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreVersion.replySha256",
            &self.reply_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreVersion.stateRootSha256",
            &self.state_root_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreVersion.versionSha256",
            &self.version_sha256,
        )?;
        if let Some(previous) = &self.previous_version_sha256 {
            require_nonzero_digest(
                "recoveryStoreVersion.previousVersionSha256",
                previous,
            )?;
        }
        let reply_bytes = encode_canonical_frame(reply)?;
        if self.api_version != RECOVERY_STORE_VERSION
            || self.sequence == 0
            || exact_request_frame.is_empty()
            || exact_request_frame.len() > MAX_SERVICE_FRAME_BYTES
            || self.exact_request_frame_sha256
                != Sha256Digest::compute(exact_request_frame)
            || self.reply_sha256 != Sha256Digest::compute(&reply_bytes)
            || self.version_sha256
                != self.computed_version_sha256()?
        {
            return Err(ServiceError::Invalid(
                "recovery-store version record is inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionedDurableRecoveryStoreReplyV3 {
    reply: DurableRecoveryStoreReplyV3,
    version: DurableRecoveryStoreVersionV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableRecoveryStoreTransactionV3 {
    api_version: String,
    exact_request_frame: Vec<u8>,
    signed_reply:
        SignedServiceResponseV3<VersionedDurableRecoveryStoreReplyV3>,
}

impl DurableRecoveryStoreTransactionV3 {
    fn validate(
        &self,
        expected_request: &ServiceRequestFrameV3,
    ) -> Result<(), ServiceError> {
        if self.api_version != RECOVERY_STORE_TRANSACTION_VERSION
            || self.exact_request_frame.is_empty()
            || self.exact_request_frame.len() > MAX_SERVICE_FRAME_BYTES
        {
            return Err(ServiceError::Invalid(
                "recovery-store transaction has invalid bounds",
            ));
        }
        let embedded_request: ServiceRequestFrameV3 =
            decode_canonical_frame(&self.exact_request_frame)?;
        if &embedded_request != expected_request {
            return Err(ServiceError::IdempotencyConflict);
        }
        self.signed_reply.response.reply.validate()?;
        self.signed_reply.response.version.validate(
            &self.exact_request_frame,
            &self.signed_reply.response.reply,
        )?;
        self.signed_reply.validate(
            PolicyCustodyServiceRoleV3::DurableRecoveryStore,
            &expected_request.binding.request_id_sha256,
            &expected_request.binding.deadline,
        )?;
        Ok(())
    }
}

/// Software response authority for the explicitly non-TEE profile.
pub(super) struct TrustedHostNoTeeRecoveryStoreSigningAuthority {
    signing_key: SigningKey,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    endpoint_process_identity: EndpointProcessIdentity,
    endpoint_generation: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl TrustedHostNoTeeRecoveryStoreSigningAuthority {
    pub(super) fn new(
        signing_key: SigningKey,
        signing_key_id: Sha256Digest,
        endpoint_process_identity: EndpointProcessIdentity,
        endpoint_generation: u64,
        current_key_authorization_checkpoint_sha256: Sha256Digest,
        revocation_generation: u64,
        revocation_root_sha256: Sha256Digest,
    ) -> Result<Self, ServiceError> {
        endpoint_process_identity.validate_shape()?;
        require_nonzero_digest(
            "recoveryStoreSigner.signingKeyId",
            &signing_key_id,
        )?;
        require_nonzero_digest(
            "recoveryStoreSigner.currentCheckpointSha256",
            &current_key_authorization_checkpoint_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreSigner.revocationRootSha256",
            &revocation_root_sha256,
        )?;
        if endpoint_process_identity.endpoint_role
                != RECOVERY_STORE_ENDPOINT_ROLE
            || endpoint_generation == 0
            || revocation_generation == 0
        {
            return Err(ServiceError::Invalid(
                "recovery-store signer authority is incomplete",
            ));
        }
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store signing key has no canonical SPKI",
                )
            })?;
        Ok(Self {
            signing_key,
            signing_key_id,
            signing_key_spki_sha256:
                Sha256Digest::compute(spki.as_ref()),
            endpoint_process_identity,
            endpoint_generation,
            current_key_authorization_checkpoint_sha256,
            revocation_generation,
            revocation_root_sha256,
        })
    }

    pub(super) fn install_current_head(
        &mut self,
        endpoint_generation: u64,
        current_key_authorization_checkpoint_sha256: Sha256Digest,
        revocation_generation: u64,
        revocation_root_sha256: Sha256Digest,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "recoveryStoreSigner.currentCheckpointSha256",
            &current_key_authorization_checkpoint_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreSigner.revocationRootSha256",
            &revocation_root_sha256,
        )?;
        if endpoint_generation == 0 || revocation_generation == 0 {
            return Err(ServiceError::Invalid(
                "recovery-store current authority head is incomplete",
            ));
        }
        if endpoint_generation < self.endpoint_generation
            || revocation_generation < self.revocation_generation
            || (endpoint_generation == self.endpoint_generation
                && current_key_authorization_checkpoint_sha256
                    != self
                        .current_key_authorization_checkpoint_sha256)
            || (revocation_generation == self.revocation_generation
                && revocation_root_sha256
                    != self.revocation_root_sha256)
        {
            return Err(ServiceError::Invalid(
                "recovery-store current authority head would roll back or fork",
            ));
        }
        self.endpoint_generation = endpoint_generation;
        self.current_key_authorization_checkpoint_sha256 =
            current_key_authorization_checkpoint_sha256;
        self.revocation_generation = revocation_generation;
        self.revocation_root_sha256 = revocation_root_sha256;
        Ok(())
    }

    fn response_verifier(
        &self,
    ) -> Result<
        TrustedHostNoTeeRecoveryStoreResponseVerifier,
        ServiceError,
    > {
        TrustedHostNoTeeRecoveryStoreResponseVerifier::new(
            self.signing_key.verifying_key(),
            self.signing_key_id.clone(),
            self.endpoint_process_identity.clone(),
        )
    }

    fn sign(
        &self,
        request: &ServiceRequestFrameV3,
        response: VersionedDurableRecoveryStoreReplyV3,
    ) -> Result<
        SignedServiceResponseV3<
            VersionedDurableRecoveryStoreReplyV3,
        >,
        ServiceError,
    > {
        validate_request_bound_current_head(request)?;
        let head =
            &request.binding.current_head.signed_current_head.statement;
        if head.endpoint_role != RECOVERY_STORE_ENDPOINT_ROLE
            || head.endpoint_generation != self.endpoint_generation
            || head.checkpoint_sha256
                != self
                    .current_key_authorization_checkpoint_sha256
            || head.revocation_generation_high_water
                != self.revocation_generation
            || head.revocation_root_sha256
                != self.revocation_root_sha256
            || head.deadline != request.binding.deadline
        {
            return Err(ServiceError::Invalid(
                "recovery-store signer does not match the request's fresh current head",
            ));
        }
        let exact_canonical_response_bytes =
            encode_canonical_frame(&response)?;
        let observed_at_boottime_nanos =
            boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store signer lacks CLOCK_BOOTTIME",
                )
            })?;
        if observed_at_boottime_nanos == 0
            || observed_at_boottime_nanos
                < head.issued_at_boottime_nanos
            || observed_at_boottime_nanos
                >= request
                    .binding
                    .deadline
                    .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "recovery-store response was not signed inside the exact current-head deadline",
            ));
        }
        let mut signature = ServiceResponseSignatureV3 {
            api_version:
                super::wire::POLICY_CUSTODY_SERVICES_WIRE_VERSION
                    .to_string(),
            service_role:
                PolicyCustodyServiceRoleV3::DurableRecoveryStore,
            request_id_sha256:
                request.binding.request_id_sha256.clone(),
            response_sha256: endpoint_response_sha256(
                &exact_canonical_response_bytes,
            ),
            endpoint_process_identity:
                self.endpoint_process_identity.clone(),
            endpoint_generation: self.endpoint_generation,
            current_key_authorization_checkpoint_sha256:
                self
                    .current_key_authorization_checkpoint_sha256
                    .clone(),
            revocation_generation: self.revocation_generation,
            revocation_root_sha256:
                self.revocation_root_sha256.clone(),
            observed_at_boottime_nanos,
            signing_key_id: self.signing_key_id.clone(),
            signing_key_spki_sha256:
                self.signing_key_spki_sha256.clone(),
            signature_base64: String::new(),
            receipt_sha256: Sha256Digest::compute(&[]),
        };
        let preimage = domain_separated_signature_preimage(
            RECOVERY_STORE_RESPONSE_SIGNATURE_DOMAIN,
            &signature_payload(&signature)?,
        )?;
        signature.signature_base64 = URL_SAFE_NO_PAD
            .encode(self.signing_key.sign(&preimage).to_bytes());
        signature.receipt_sha256 = signature_receipt(&signature)?;
        let exact_signature_envelope_bytes =
            encode_canonical_frame(&signature)?;
        let signed = SignedServiceResponseV3 {
            response,
            exact_canonical_response_bytes,
            signature,
            exact_signature_envelope_bytes,
        };
        signed.validate(
            PolicyCustodyServiceRoleV3::DurableRecoveryStore,
            &request.binding.request_id_sha256,
            &request.binding.deadline,
        )?;
        Ok(signed)
    }
}

#[derive(Debug, Clone)]
pub(super) struct DurableRecoveryStoreSeedV3 {
    pub(super) ownership: Vec<DurableOwnershipRecordV3>,
    pub(super) recovery_material: Vec<RecoveryMaterialV3>,
}

#[derive(Clone, Default)]
struct RecoveryStoreState {
    ownership: BTreeMap<String, DurableOwnershipRecordV3>,
    material: BTreeMap<String, RecoveryMaterialV3>,
}

impl RecoveryStoreState {
    fn from_seed(
        seed: DurableRecoveryStoreSeedV3,
    ) -> Result<Self, ServiceError> {
        let mut state = Self::default();
        for record in seed.ownership {
            record.validate()?;
            let key = record.ownership_id_sha256.as_str().to_string();
            if state.ownership.insert(key, record).is_some() {
                return Err(ServiceError::Invalid(
                    "recovery-store seed repeats an ownership identity",
                ));
            }
        }
        for material in seed.recovery_material {
            material.validate()?;
            let key = material
                .owner
                .ownership_id_sha256
                .as_str()
                .to_string();
            let owner = state.ownership.get(&key).ok_or(
                ServiceError::Invalid(
                    "recovery material has no seeded owner",
                ),
            )?;
            if owner != &material.owner
                || state.material.insert(key, material).is_some()
            {
                return Err(ServiceError::Invalid(
                    "recovery material does not exactly match one seeded owner",
                ));
            }
        }
        state.state_root_sha256()?;
        Ok(state)
    }

    fn state_root_sha256(&self) -> Result<Sha256Digest, ServiceError> {
        canonical_digest(
            RECOVERY_STORE_STATE_ROOT_DOMAIN,
            &(&self.ownership, &self.material),
        )
    }

    fn refresh_material(
        material: &mut RecoveryMaterialV3,
    ) -> Result<(), ServiceError> {
        material.material_sha256 =
            material.expected_material_sha256()?;
        material.validate()?;
        Ok(())
    }

    fn settlement_key_matches(
        material: &RecoveryMaterialV3,
        key: &RecoveryKeyV3,
    ) -> bool {
        material.owner.operation_id_sha256
                == key.operation_id_sha256
            && material.owner.durable_request_sha256
                == key.durable_request_sha256
            && material.owner.termination_fence_sha256
                == key.termination_fence_sha256
    }

    fn material_for_key(
        &self,
        key: &RecoveryKeyV3,
    ) -> Option<&RecoveryMaterialV3> {
        self.material
            .values()
            .find(|material| Self::settlement_key_matches(material, key))
    }

    fn material_for_key_mut(
        &mut self,
        key: &RecoveryKeyV3,
    ) -> Option<&mut RecoveryMaterialV3> {
        self.material
            .values_mut()
            .find(|material| Self::settlement_key_matches(material, key))
    }

    fn evaluate(
        &self,
        request: &DurableRecoveryStoreRequestV3,
    ) -> Result<(DurableRecoveryStoreReplyV3, Self), ServiceError> {
        let mut next = self.clone();
        let reply = match request {
            DurableRecoveryStoreRequestV3::ScanIncomplete {
                continuation,
                maximum_records,
                ..
            } => {
                let limit = usize::from(*maximum_records);
                let start_after =
                    continuation.as_ref().map(Sha256Digest::as_str);
                let incomplete: Vec<_> = self
                    .ownership
                    .values()
                    .filter(|record| {
                        record.phase != OwnershipPhaseV3::Terminal
                            && start_after.is_none_or(|cursor| {
                                record.ownership_id_sha256.as_str()
                                    > cursor
                            })
                    })
                    .take(limit.saturating_add(1))
                    .cloned()
                    .collect();
                let has_more = incomplete.len() > limit;
                let records = incomplete
                    .iter()
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>();
                let continuation = has_more
                    .then(|| {
                        records
                            .last()
                            .map(|record| {
                                record.ownership_id_sha256.clone()
                            })
                    })
                    .flatten();
                DurableRecoveryStoreReplyV3::ScanIncomplete {
                    records,
                    continuation,
                }
            }
            DurableRecoveryStoreRequestV3::QueryOwnership {
                ownership_id_sha256,
                ..
            } => DurableRecoveryStoreReplyV3::QueryOwnership {
                authoritative: self
                    .ownership
                    .get(ownership_id_sha256.as_str())
                    .cloned(),
            },
            DurableRecoveryStoreRequestV3::CasOwnership {
                expected,
                transition,
                ..
            } => {
                let current = self
                    .ownership
                    .get(expected.ownership_id_sha256.as_str())
                    .ok_or(ServiceError::Invalid(
                        "ownership CAS references an unknown owner",
                    ))?;
                let candidate =
                    transition_ownership(expected, transition)?;
                let (disposition, authoritative) =
                    if current == expected {
                        next.install_owner(candidate.clone())?;
                        (CasDispositionV3::Applied, candidate)
                    } else if current == &candidate {
                        (
                            CasDispositionV3::AlreadyApplied,
                            current.clone(),
                        )
                    } else {
                        (CasDispositionV3::Conflict, current.clone())
                    };
                DurableRecoveryStoreReplyV3::CasOwnership {
                    disposition,
                    authoritative,
                }
            }
            DurableRecoveryStoreRequestV3::QuerySettlement {
                key, ..
            } => DurableRecoveryStoreReplyV3::QuerySettlement {
                authoritative: self
                    .material_for_key(key)
                    .and_then(|material| {
                        material.settlement_chain.last().cloned()
                    }),
            },
            DurableRecoveryStoreRequestV3::CasSettlement {
                key,
                expected_revision,
                expected_state_sha256,
                candidate,
                ..
            } => {
                let current = self
                    .material_for_key(key)
                    .and_then(|material| material.settlement_chain.last())
                    .ok_or(ServiceError::Invalid(
                        "settlement CAS references missing recovery material",
                    ))?;
                let disposition =
                    if current.state_revision == *expected_revision
                        && current.state_sha256
                            == *expected_state_sha256
                    {
                        candidate.validate_successor(current)?;
                        next.install_settlement(
                            key,
                            candidate.clone(),
                        )?;
                        CasDispositionV3::Applied
                    } else if current == candidate {
                        CasDispositionV3::AlreadyApplied
                    } else {
                        CasDispositionV3::Conflict
                    };
                let authoritative = if disposition
                    == CasDispositionV3::Applied
                {
                    candidate.clone()
                } else {
                    current.clone()
                };
                DurableRecoveryStoreReplyV3::CasSettlement {
                    disposition,
                    authoritative,
                }
            }
            DurableRecoveryStoreRequestV3::RecoveryMaterial {
                ownership_id_sha256,
                ..
            } => DurableRecoveryStoreReplyV3::RecoveryMaterial {
                material: self
                    .material
                    .get(ownership_id_sha256.as_str())
                    .cloned(),
            },
        };
        reply.validate()?;
        next.state_root_sha256()?;
        Ok((reply, next))
    }

    fn install_owner(
        &mut self,
        owner: DurableOwnershipRecordV3,
    ) -> Result<(), ServiceError> {
        owner.validate()?;
        let key = owner.ownership_id_sha256.as_str().to_string();
        self.ownership.insert(key.clone(), owner.clone());
        if let Some(material) = self.material.get_mut(&key) {
            material.owner = owner;
            Self::refresh_material(material)?;
        }
        Ok(())
    }

    fn install_settlement(
        &mut self,
        key: &RecoveryKeyV3,
        candidate: DurableSettlementRecord,
    ) -> Result<(), ServiceError> {
        let material =
            self.material_for_key_mut(key).ok_or(
                ServiceError::Invalid(
                    "settlement update has no recovery material",
                ),
            )?;
        let current = material.settlement_chain.last().ok_or(
            ServiceError::Invalid(
                "recovery material has no settlement head",
            ),
        )?;
        candidate.validate_successor(current)?;
        material.settlement_chain.push(candidate);
        Self::refresh_material(material)
    }
}

fn transition_ownership(
    expected: &DurableOwnershipRecordV3,
    transition: &OwnershipCasTransitionV3,
) -> Result<DurableOwnershipRecordV3, ServiceError> {
    expected.validate()?;
    let revision = expected.revision.checked_add(1).ok_or(
        ServiceError::Invalid(
            "ownership revision exhausted",
        ),
    )?;
    let (phase, watchdog_lease, settlement_state_sha256) =
        match transition {
            OwnershipCasTransitionV3::Reconciling {
                watchdog_lease,
            } => (
                OwnershipPhaseV3::Reconciling,
                watchdog_lease.clone(),
                None,
            ),
            OwnershipCasTransitionV3::Terminal {
                watchdog_lease,
                settlement_state_sha256,
            } => (
                OwnershipPhaseV3::Terminal,
                watchdog_lease.clone(),
                Some(settlement_state_sha256.clone()),
            ),
        };
    let state_sha256 = canonical_digest(
        OWNERSHIP_TRANSITION_STATE_DOMAIN,
        &(
            &expected.record_sha256,
            &expected.state_sha256,
            revision,
            phase,
            &watchdog_lease,
            &settlement_state_sha256,
            &expected.ownership_id_sha256,
            &expected.operation_id_sha256,
            &expected.durable_request_sha256,
            &expected.termination_fence_sha256,
        ),
    )?;
    let mut candidate = expected.clone();
    candidate.revision = revision;
    candidate.phase = phase;
    candidate.predecessor_sha256 = expected.state_sha256.clone();
    candidate.state_sha256 = state_sha256;
    candidate.watchdog_lease = Some(watchdog_lease);
    candidate.record_sha256 =
        candidate.expected_record_sha256()?;
    candidate.validate()?;
    Ok(candidate)
}

fn runtime_owner_to_wire(
    record: &DurableOwnershipRecord,
) -> Result<DurableOwnershipRecordV3, RecoveryError> {
    let phase = match record.phase {
        OwnershipPhase::Armed => OwnershipPhaseV3::Armed,
        OwnershipPhase::Reconciling => OwnershipPhaseV3::Reconciling,
        OwnershipPhase::Terminal => OwnershipPhaseV3::Terminal,
    };
    let mut wire = DurableOwnershipRecordV3 {
        api_version:
            POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION.to_string(),
        registration: record.registration.clone(),
        signed_ownership_ack: record.signed_ownership_ack.clone(),
        ownership_id_sha256: record.ownership_id_sha256.clone(),
        revision: record.revision,
        phase,
        operation: record.operation,
        operation_id_sha256: record.operation_id_sha256.clone(),
        durable_request_sha256:
            record.durable_request_sha256.clone(),
        request_sha256: record.request_sha256.clone(),
        supervisor_capability_sha256:
            record.supervisor_capability_sha256.clone(),
        termination_fence_sha256:
            record.termination_fence_sha256.clone(),
        parent: record.parent.clone(),
        supervisor: record.supervisor.clone(),
        worker: record.worker.clone(),
        cgroup: record.cgroup.clone(),
        predecessor_sha256: record.predecessor_sha256.clone(),
        state_sha256: record.state_sha256.clone(),
        operation_deadline: ProtocolBoottimeDeadline::from_runtime(
            record.operation_deadline,
        ),
        cleanup_deadline: ProtocolBoottimeDeadline::from_runtime(
            record.cleanup_deadline,
        ),
        watchdog_lease: record.watchdog_lease.clone(),
        record_sha256: Sha256Digest::compute(&[]),
    };
    wire.record_sha256 = wire
        .expected_record_sha256()
        .map_err(|_| protocol_error())?;
    wire.validate().map_err(|_| protocol_error())?;
    Ok(wire)
}

pub(super) fn wire_owner_to_runtime(
    record: DurableOwnershipRecordV3,
) -> Result<DurableOwnershipRecord, RecoveryError> {
    record.validate().map_err(|_| protocol_error())?;
    let operation_deadline =
        record.operation_deadline.to_runtime().map_err(|_| {
            RecoveryError::Deadline(
                "ownership operation deadline is not the current BOOTTIME domain",
            )
        })?;
    let cleanup_deadline =
        record.cleanup_deadline.to_runtime().map_err(|_| {
            RecoveryError::Deadline(
                "ownership cleanup deadline is not the current BOOTTIME domain",
            )
        })?;
    if ProtocolBoottimeDeadline::from_runtime(operation_deadline)
            != record.operation_deadline
        || ProtocolBoottimeDeadline::from_runtime(cleanup_deadline)
            != record.cleanup_deadline
    {
        return Err(RecoveryError::Deadline(
            "ownership BOOTTIME deadline projection is not exact",
        ));
    }
    let phase = match record.phase {
        OwnershipPhaseV3::Armed => OwnershipPhase::Armed,
        OwnershipPhaseV3::Reconciling => OwnershipPhase::Reconciling,
        OwnershipPhaseV3::Terminal => OwnershipPhase::Terminal,
    };
    Ok(DurableOwnershipRecord {
        registration: record.registration,
        signed_ownership_ack: record.signed_ownership_ack,
        ownership_id_sha256: record.ownership_id_sha256,
        revision: record.revision,
        phase,
        operation: record.operation,
        operation_id_sha256: record.operation_id_sha256,
        durable_request_sha256: record.durable_request_sha256,
        request_sha256: record.request_sha256,
        supervisor_capability_sha256:
            record.supervisor_capability_sha256,
        termination_fence_sha256:
            record.termination_fence_sha256,
        parent: record.parent,
        supervisor: record.supervisor,
        worker: record.worker,
        cgroup: record.cgroup,
        predecessor_sha256: record.predecessor_sha256,
        state_sha256: record.state_sha256,
        operation_deadline,
        cleanup_deadline,
        watchdog_lease: record.watchdog_lease,
    })
}

#[derive(Debug, Clone)]
pub(super) struct RecoveryRuntimeMaterialV3 {
    pub(super) owner: DurableOwnershipRecord,
    pub(super) settlement_chain: Vec<DurableSettlementRecord>,
    pub(super) authorized_cleanup_steps: Vec<AuthorizedCleanupStep>,
    pub(super) stored_cleanup_evidence: Vec<StoredCleanupEvidence>,
}

fn cleanup_binding_from_step(
    owner: &DurableOwnershipRecord,
    step: &CleanupStepMaterialV3,
) -> Result<ExactCleanupBinding, RecoveryError> {
    step.validate().map_err(|_| {
        RecoveryError::Authorization(
            "recovery cleanup step is invalid",
        )
    })?;
    let payload = &step.authorization.payload;
    if payload.operation != owner.operation
        || payload.operation_id_sha256 != owner.operation_id_sha256
        || payload.durable_request_sha256
            != owner.durable_request_sha256
        || payload.request_sha256 != owner.request_sha256
        || payload.fence_token_sha256
            != owner.termination_fence_sha256
        || payload.cgroup_identity != owner.cgroup.protocol
        || payload.operation_deadline
            != ProtocolBoottimeDeadline::from_runtime(
                owner.operation_deadline,
            )
        || payload.absolute_boottime_deadline
            != ProtocolBoottimeDeadline::from_runtime(
                owner.cleanup_deadline,
            )
    {
        return Err(RecoveryError::Authorization(
            "recovery cleanup step belongs to another exact durable owner",
        ));
    }
    Ok(ExactCleanupBinding {
        action: payload.action,
        executor_role: payload.executor_role,
        endpoint_role: payload.endpoint_role,
        operation: payload.operation,
        operation_id_sha256: payload.operation_id_sha256.clone(),
        durable_request_sha256:
            payload.durable_request_sha256.clone(),
        request_sha256: payload.request_sha256.clone(),
        termination_fence_sha256:
            payload.fence_token_sha256.clone(),
        cgroup: owner.cgroup.clone(),
        predecessor: payload.predecessor.clone(),
        authorization_nonce_sha256:
            payload.authorization_nonce_sha256.clone(),
        operation_deadline: payload.operation_deadline.clone(),
        cleanup_deadline:
            payload.absolute_boottime_deadline.clone(),
    })
}

fn trace_bindings_from_step(
    step: &CleanupStepMaterialV3,
) -> CleanupTraceRequestBindings {
    CleanupTraceRequestBindings {
        before_query_nonce_sha256:
            step.before_query_nonce_sha256.clone(),
        before_query_request_sha256:
            step.before_query_request_sha256.clone(),
        cas_nonce_sha256: step.cas_nonce_sha256.clone(),
        cas_request_sha256: step.cas_request_sha256.clone(),
        after_query_nonce_sha256:
            step.after_query_nonce_sha256.clone(),
        after_query_request_sha256:
            step.after_query_request_sha256.clone(),
    }
}

fn stored_endpoint_to_runtime<R>(
    stored: StoredSignedEndpointResponseV3<R>,
) -> UnverifiedSignedEndpointResponse<R> {
    UnverifiedSignedEndpointResponse {
        response: stored.response,
        envelope: stored.envelope,
        exact_canonical_response:
            stored.exact_canonical_response.into_boxed_slice(),
        exact_signature_payload:
            stored.exact_signature_payload.into_boxed_slice(),
    }
}

fn stored_consumption_to_runtime(
    stored: StoredCleanupConsumptionEvidenceV3,
) -> UnverifiedCleanupAuthorizationConsumption {
    UnverifiedCleanupAuthorizationConsumption {
        before: stored_endpoint_to_runtime(stored.before),
        compare_and_swap:
            stored_endpoint_to_runtime(stored.compare_and_swap),
        after: stored_endpoint_to_runtime(stored.after),
        persisted: stored.persisted,
        exact_signature_payload: stored
            .exact_consumption_signature_payload
            .into_boxed_slice(),
    }
}

pub(super) fn recovery_material_to_runtime(
    material: RecoveryMaterialV3,
) -> Result<RecoveryRuntimeMaterialV3, RecoveryError> {
    material.validate().map_err(|_| {
        RecoveryError::Authorization(
            "recovery material is not a valid bounded wire object",
        )
    })?;
    let owner = wire_owner_to_runtime(material.owner)?;
    let mut authorized_cleanup_steps =
        Vec::with_capacity(material.cleanup_plan.len());
    for step in material.cleanup_plan {
        let binding = cleanup_binding_from_step(&owner, &step)?;
        authorized_cleanup_steps.push(AuthorizedCleanupStep {
            authorization: step.authorization.clone(),
            binding,
            expected_consumption_sequence:
                step.expected_consumption_sequence,
            expected_consumption_predecessor_receipt_sha256: step
                .expected_consumption_predecessor_receipt_sha256
                .clone(),
            expected_result_sequence:
                step.expected_result_sequence,
            trace_requests: trace_bindings_from_step(&step),
        });
    }
    let mut stored_cleanup_evidence =
        Vec::with_capacity(material.stored_cleanup_results.len());
    for stored in material.stored_cleanup_results {
        let binding =
            cleanup_binding_from_step(&owner, &stored.step)?;
        let trace_requests =
            trace_bindings_from_step(&stored.step);
        stored_cleanup_evidence.push(StoredCleanupEvidence {
            authorization: stored.authorization,
            binding,
            expected_consumption_sequence:
                stored.step.expected_consumption_sequence,
            expected_consumption_predecessor_receipt_sha256: stored
                .step
                .expected_consumption_predecessor_receipt_sha256,
            expected_result_sequence:
                stored.step.expected_result_sequence,
            trace_requests,
            consumption:
                stored_consumption_to_runtime(stored.consumption),
            result: stored.result,
            durable_effect: stored.durable_effect,
        });
    }
    Ok(RecoveryRuntimeMaterialV3 {
        owner,
        settlement_chain: material.settlement_chain,
        authorized_cleanup_steps,
        stored_cleanup_evidence,
    })
}

fn runtime_key_to_wire(key: &RecoveryKey) -> RecoveryKeyV3 {
    RecoveryKeyV3 {
        operation_id_sha256: key.operation_id_sha256.clone(),
        durable_request_sha256: key.durable_request_sha256.clone(),
        termination_fence_sha256:
            key.termination_fence_sha256.clone(),
    }
}

fn runtime_disposition(
    disposition: CasDispositionV3,
) -> CasDisposition {
    match disposition {
        CasDispositionV3::Applied => CasDisposition::Applied,
        CasDispositionV3::AlreadyApplied => {
            CasDisposition::AlreadyApplied
        }
        CasDispositionV3::Conflict => CasDisposition::Conflict,
    }
}

/// Serving state and handler for the durable-recovery-store role.
pub(super) struct TrustedHostNoTeeDurableRecoveryStoreServer {
    state: RecoveryStoreState,
    version_sequence: u64,
    version_head_sha256: Option<Sha256Digest>,
    journal: DurableAppendJournal,
    signer: TrustedHostNoTeeRecoveryStoreSigningAuthority,
}

impl TrustedHostNoTeeDurableRecoveryStoreServer {
    pub(super) fn from_seed(
        journal_directory: OwnedFd,
        seed: DurableRecoveryStoreSeedV3,
        signer: TrustedHostNoTeeRecoveryStoreSigningAuthority,
    ) -> Result<Self, ServiceError> {
        let mut journal = DurableAppendJournal::from_directory(
            journal_directory,
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            MAX_SERVICE_FRAME_BYTES,
        )?;
        let replay = journal.verified_complete_chain(
            MAX_RECOVERY_STORE_JOURNAL_RECORDS,
            MAX_RECOVERY_STORE_JOURNAL_BYTES,
        )?;
        if !replay.records.is_empty()
            || replay.terminal_head.is_some()
        {
            return Err(ServiceError::Invalid(
                "existing recovery-store journal requires verified startup recovery",
            ));
        }
        Ok(Self {
            state: RecoveryStoreState::from_seed(seed)?,
            version_sequence: 0,
            version_head_sha256: None,
            journal,
            signer,
        })
    }

    pub(super) fn from_recovered_journal(
        journal_directory: OwnedFd,
        seed: DurableRecoveryStoreSeedV3,
        signer: TrustedHostNoTeeRecoveryStoreSigningAuthority,
    ) -> Result<Self, ServiceError> {
        let mut journal = DurableAppendJournal::from_directory(
            journal_directory,
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            MAX_SERVICE_FRAME_BYTES,
        )?;
        let replay = journal.verified_complete_chain(
            MAX_RECOVERY_STORE_JOURNAL_RECORDS,
            MAX_RECOVERY_STORE_JOURNAL_BYTES,
        )?;
        let recovered_sequence =
            u64::try_from(replay.records.len()).map_err(
                |_| {
                    ServiceError::Invalid(
                        "recovery-store journal sequence is not representable",
                    )
                },
            )?;
        let expected_terminal = replay.records.last().map(|record| {
            (
                record.sequence,
                record.idempotency_sha256.clone(),
                record.head_sha256.clone(),
            )
        });
        let terminal_head = replay.terminal_head.clone();
        let mut server = Self {
            state: RecoveryStoreState::from_seed(seed)?,
            version_sequence: 0,
            version_head_sha256: None,
            journal,
            signer,
        };
        for entry in replay.records {
            let request_frame: ServiceRequestFrameV3 =
                decode_canonical_frame(
                    &entry.exact_request_bytes,
                )?;
            let response_frame: ServiceResponseFrameV3 =
                decode_canonical_frame(
                    &entry.exact_response_bytes,
                )?;
            let transaction: DurableRecoveryStoreTransactionV3 =
                response_frame.decode_payload()?;
            if request_frame.binding.idempotency_sha256
                != entry.idempotency_sha256
                || transaction.exact_request_frame
                    != entry.exact_request_bytes
            {
                return Err(ServiceError::Invalid(
                    "recovery-store journal record changed its exact request or idempotency identity",
                ));
            }
            let persisted = server
                .journal
                .append_exact_exchange(
                    entry.idempotency_sha256,
                    &entry.exact_request_bytes,
                    &entry.exact_response_bytes,
                )?
                .exact_response_bytes()
                .to_vec();
            if persisted != entry.exact_response_bytes {
                return Err(ServiceError::IdempotencyConflict);
            }
            server.apply_exact_response_frame(&persisted)?;
        }
        let terminal_is_exact = match (
            expected_terminal,
            terminal_head.as_ref(),
        ) {
            (None, None) => {
                server.journal.current_head_sha256().is_none()
            }
            (
                Some((
                    record_sequence,
                    record_idempotency,
                    record_head,
                )),
                Some(head),
            ) => {
                head.sequence == record_sequence
                    && head.idempotency_sha256
                        == record_idempotency
                    && head.head_sha256 == record_head
                    && server.journal.current_head_sha256()
                        == Some(&head.head_sha256)
                    && !head.exact_head_bytes.is_empty()
            }
            _ => false,
        };
        if server.version_sequence != recovered_sequence
            || !terminal_is_exact
        {
            return Err(ServiceError::Invalid(
                "recovery-store verified transaction sequence does not cover the terminal common journal head",
            ));
        }
        Ok(server)
    }

    pub(super) fn version_head_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.version_head_sha256.as_ref()
    }

    pub(super) fn handle_exact_request_frame(
        &mut self,
        exact_request_frame: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let request_frame: ServiceRequestFrameV3 =
            decode_canonical_frame(exact_request_frame)?;
        request_frame.validate(
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            RECOVERY_STORE_ENDPOINT_ROLE,
        )?;
        let request: DurableRecoveryStoreRequestV3 =
            request_frame.decode_payload()?;
        request.validate()?;
        if request.request_id_sha256()
                != &request_frame.binding.request_id_sha256
            || request.deadline() != &request_frame.binding.deadline
        {
            return Err(ServiceError::Invalid(
                "recovery-store payload changed its framed request id or deadline",
            ));
        }
        validate_request_bound_current_head(&request_frame)?;
        request.deadline().to_runtime()?.require_live().map_err(
            |_| {
                ServiceError::Invalid(
                    "recovery-store request deadline is not live",
                )
            },
        )?;

        if let Some(persisted) = self
            .journal
            .repair_and_lookup_persisted_exact_response(
                &request_frame.binding.idempotency_sha256,
            )?
        {
            let repaired = self
                .journal
                .append_exact_exchange(
                    request_frame
                        .binding
                        .idempotency_sha256
                        .clone(),
                    exact_request_frame,
                    &persisted,
                )?
                .exact_response_bytes()
                .to_vec();
            if repaired != persisted {
                return Err(ServiceError::IdempotencyConflict);
            }
            self.apply_exact_response_frame(&repaired)?;
            request.deadline().to_runtime()?.require_live().map_err(
                |_| {
                    ServiceError::Invalid(
                        "recovery-store exact retry crossed its deadline; query the authoritative state",
                    )
                },
            )?;
            return Ok(repaired);
        }

        let (reply, next_state) = self.state.evaluate(&request)?;
        let next_sequence =
            self.version_sequence.checked_add(1).ok_or(
                ServiceError::Invalid(
                    "recovery-store version sequence exhausted",
                ),
            )?;
        let version = DurableRecoveryStoreVersionV3::new(
            next_sequence,
            self.version_head_sha256.clone(),
            exact_request_frame,
            &reply,
            next_state.state_root_sha256()?,
        )?;
        let signed_reply = self.signer.sign(
            &request_frame,
            VersionedDurableRecoveryStoreReplyV3 {
                reply,
                version,
            },
        )?;
        let transaction = DurableRecoveryStoreTransactionV3 {
            api_version:
                RECOVERY_STORE_TRANSACTION_VERSION.to_string(),
            exact_request_frame: exact_request_frame.to_vec(),
            signed_reply,
        };
        transaction.validate(&request_frame)?;
        let response_frame = ServiceResponseFrameV3::from_payload(
            request_frame.binding.clone(),
            &transaction,
        )?;
        let candidate_exact_response =
            encode_canonical_frame(&response_frame)?;
        let outcome = self.journal.append_exact_exchange(
            request_frame.binding.idempotency_sha256.clone(),
            exact_request_frame,
            &candidate_exact_response,
        )?;
        let persisted = outcome.exact_response_bytes().to_vec();
        self.apply_exact_response_frame(&persisted)?;
        request.deadline().to_runtime()?.require_live().map_err(
            |_| {
                ServiceError::Invalid(
                    "recovery-store commit crossed its deadline; query the authoritative state",
                )
            },
        )?;
        Ok(persisted)
    }

    fn apply_exact_response_frame(
        &mut self,
        exact_response: &[u8],
    ) -> Result<(), ServiceError> {
        let response_frame: ServiceResponseFrameV3 =
            decode_canonical_frame(exact_response)?;
        let transaction: DurableRecoveryStoreTransactionV3 =
            response_frame.decode_payload()?;
        let request_frame: ServiceRequestFrameV3 =
            decode_canonical_frame(&transaction.exact_request_frame)?;
        response_frame.validate_for_request(
            &request_frame.binding,
            RECOVERY_STORE_ENDPOINT_ROLE,
        )?;
        transaction.validate(&request_frame)?;
        self.signer
            .response_verifier()?
            .verify(&request_frame, &transaction.signed_reply)?;
        self.apply_transaction(&transaction)
    }

    fn apply_transaction(
        &mut self,
        transaction: &DurableRecoveryStoreTransactionV3,
    ) -> Result<(), ServiceError> {
        let version = &transaction.signed_reply.response.version;
        if version.sequence <= self.version_sequence {
            if version.sequence == self.version_sequence
                && self.version_head_sha256.as_ref()
                    != Some(&version.version_sha256)
            {
                return Err(ServiceError::Invalid(
                    "recovery-store replay conflicts with the current version head",
                ));
            }
            return Ok(());
        }
        if version.sequence != self.version_sequence.saturating_add(1)
            || version.previous_version_sha256
                != self.version_head_sha256
        {
            return Err(ServiceError::Invalid(
                "recovery-store version replay is not contiguous",
            ));
        }
        let mut candidate_state = self.state.clone();
        match &transaction.signed_reply.response.reply {
            DurableRecoveryStoreReplyV3::CasOwnership {
                authoritative, ..
            } => {
                let key = authoritative
                    .ownership_id_sha256
                    .as_str()
                    .to_string();
                match candidate_state.ownership.get(&key) {
                    Some(current)
                        if current.revision
                            > authoritative.revision => {}
                    Some(current)
                        if current.revision
                                == authoritative.revision
                            && current != authoritative =>
                    {
                        return Err(ServiceError::Invalid(
                            "replayed ownership revision changed its exact bytes",
                        ));
                    }
                    _ => candidate_state
                        .install_owner(authoritative.clone())?,
                }
            }
            DurableRecoveryStoreReplyV3::CasSettlement {
                disposition,
                authoritative,
            } if *disposition != CasDispositionV3::Conflict => {
                let key = RecoveryKeyV3 {
                    operation_id_sha256: authoritative
                        .identity
                        .operation_id_sha256
                        .clone(),
                    durable_request_sha256: authoritative
                        .identity
                        .durable_request_sha256
                        .clone(),
                    termination_fence_sha256: authoritative
                        .identity
                        .fence_token_sha256
                        .clone(),
                };
                let current = self
                    .state
                    .material_for_key(&key)
                    .and_then(|material| {
                        material.settlement_chain.last()
                    })
                    .ok_or(ServiceError::Invalid(
                        "replayed settlement has no recovery material",
                    ))?;
                if current.state_revision < authoritative.state_revision {
                    candidate_state.install_settlement(
                        &key,
                        authoritative.clone(),
                    )?;
                } else if current.state_revision
                        == authoritative.state_revision
                    && current != authoritative
                {
                    return Err(ServiceError::Invalid(
                        "replayed settlement revision changed its exact bytes",
                    ));
                }
            }
            _ => {}
        }
        if candidate_state.state_root_sha256()?
            != version.state_root_sha256
        {
            return Err(ServiceError::Invalid(
                "recovery-store transaction state root is not authoritative",
            ));
        }
        self.state = candidate_state;
        self.version_sequence = version.sequence;
        self.version_head_sha256 =
            Some(version.version_sha256.clone());
        Ok(())
    }
}

/// Pinned software verifier. The current-head object remains request-specific;
/// the key and service process identity are deployment pins.
pub(super) struct TrustedHostNoTeeRecoveryStoreResponseVerifier {
    verifying_key: VerifyingKey,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    endpoint_process_identity: EndpointProcessIdentity,
}

impl TrustedHostNoTeeRecoveryStoreResponseVerifier {
    pub(super) fn new(
        verifying_key: VerifyingKey,
        signing_key_id: Sha256Digest,
        endpoint_process_identity: EndpointProcessIdentity,
    ) -> Result<Self, ServiceError> {
        endpoint_process_identity.validate_shape()?;
        require_nonzero_digest(
            "recoveryStoreVerifier.signingKeyId",
            &signing_key_id,
        )?;
        if endpoint_process_identity.endpoint_role
            != RECOVERY_STORE_ENDPOINT_ROLE
        {
            return Err(ServiceError::Invalid(
                "recovery-store verifier pins the wrong endpoint role",
            ));
        }
        let spki = verifying_key.to_public_key_der().map_err(|_| {
            ServiceError::Invalid(
                "recovery-store verifying key has no canonical SPKI",
            )
        })?;
        Ok(Self {
            verifying_key,
            signing_key_id,
            signing_key_spki_sha256:
                Sha256Digest::compute(spki.as_ref()),
            endpoint_process_identity,
        })
    }

    fn verify(
        &self,
        request: &ServiceRequestFrameV3,
        signed: &SignedServiceResponseV3<
            VersionedDurableRecoveryStoreReplyV3,
        >,
    ) -> Result<(), ServiceError> {
        validate_request_bound_current_head(request)?;
        signed.validate(
            PolicyCustodyServiceRoleV3::DurableRecoveryStore,
            &request.binding.request_id_sha256,
            &request.binding.deadline,
        )?;
        let signature = &signed.signature;
        let head =
            &request.binding.current_head.signed_current_head.statement;
        if signature.endpoint_process_identity
                != self.endpoint_process_identity
            || signature.signing_key_id != self.signing_key_id
            || signature.signing_key_spki_sha256
                != self.signing_key_spki_sha256
            || signature.endpoint_generation
                != head.endpoint_generation
            || signature
                .current_key_authorization_checkpoint_sha256
                != head.checkpoint_sha256
            || signature.revocation_generation
                != head.revocation_generation_high_water
            || signature.revocation_root_sha256
                != head.revocation_root_sha256
            || signature.observed_at_boottime_nanos
                < head.issued_at_boottime_nanos
            || signature.observed_at_boottime_nanos
                >= request
                    .binding
                    .deadline
                    .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "recovery-store signature does not match the fresh current head or pinned service identity",
            ));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&signature.signature_base64)
            .map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store signature is not canonical base64url",
                )
            })?;
        if URL_SAFE_NO_PAD.encode(&signature_bytes)
            != signature.signature_base64
        {
            return Err(ServiceError::Invalid(
                "recovery-store signature has a noncanonical encoding",
            ));
        }
        let signature_value =
            Signature::from_slice(&signature_bytes).map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store signature has the wrong length",
                )
            })?;
        let preimage = domain_separated_signature_preimage(
            RECOVERY_STORE_RESPONSE_SIGNATURE_DOMAIN,
            &signature_payload(signature)?,
        )?;
        self.verifying_key
            .verify_strict(&preimage, &signature_value)
            .map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store software signature verification failed",
                )
            })
    }
}

/// Supplies a newly verified, request-deadline-bound authority head for every
/// operation. The client deliberately has no one-shot head installation path:
/// an implementation must retain its own nonblocking exchange state and
/// signal progress through this descriptor.
pub(super) trait VerifiedRecoveryStoreCurrentHeadProvider {
    fn progress_fd(&self) -> BorrowedFd<'_>;

    fn try_fresh_current_head_nonblocking(
        &mut self,
        exact_request: &RecoveryStoreCurrentHeadRequestBindingV3,
    ) -> Result<Option<ServiceCurrentHeadBindingV3>, RecoveryError>;
}

/// The complete request identity that must exist before a request-specific
/// checkpoint-authority head is requested. It deliberately excludes the head
/// itself, so neither the request ID nor idempotency digest can depend on the
/// attestation that authorizes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecoveryStoreCurrentHeadRequestBindingV3 {
    api_version: String,
    subject: CurrentAuthoritySubjectV3,
    service_role: TrustedHostServiceRoleV3,
    request_id_sha256: Sha256Digest,
    idempotency_sha256: Sha256Digest,
    request_payload_sha256: Sha256Digest,
    deadline: ProtocolBoottimeDeadline,
    binding_sha256: Sha256Digest,
}

impl RecoveryStoreCurrentHeadRequestBindingV3 {
    fn new(
        request_id_sha256: Sha256Digest,
        request_payload_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
    ) -> Result<Self, ServiceError> {
        let mut binding = Self {
            api_version:
                POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                    .to_string(),
            subject: CurrentAuthoritySubjectV3::Endpoint {
                endpoint_role: RECOVERY_STORE_ENDPOINT_ROLE,
            },
            service_role:
                TrustedHostServiceRoleV3::DurableRecoveryStore,
            request_id_sha256,
            idempotency_sha256: Sha256Digest::compute(&[]),
            request_payload_sha256,
            deadline,
            binding_sha256: Sha256Digest::compute(&[]),
        };
        binding.idempotency_sha256 =
            binding.expected_idempotency_sha256()?;
        binding.binding_sha256 =
            binding.expected_binding_sha256()?;
        binding.validate()?;
        Ok(binding)
    }

    fn expected_idempotency_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        canonical_digest(
            RECOVERY_STORE_IDEMPOTENCY_DOMAIN,
            &(
                &self.api_version,
                &self.subject,
                self.service_role,
                &self.request_id_sha256,
                &self.request_payload_sha256,
                &self.deadline,
            ),
        )
    }

    fn expected_binding_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        canonical_digest(
            RECOVERY_STORE_CURRENT_HEAD_REQUEST_BINDING_DOMAIN,
            &(
                &self.api_version,
                &self.subject,
                self.service_role,
                &self.request_id_sha256,
                &self.idempotency_sha256,
                &self.request_payload_sha256,
                &self.deadline,
            ),
        )
    }

    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "recoveryStoreCurrentHeadRequest.requestIdSha256",
            &self.request_id_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreCurrentHeadRequest.idempotencySha256",
            &self.idempotency_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreCurrentHeadRequest.requestPayloadSha256",
            &self.request_payload_sha256,
        )?;
        require_nonzero_digest(
            "recoveryStoreCurrentHeadRequest.bindingSha256",
            &self.binding_sha256,
        )?;
        self.deadline.to_runtime()?;
        if self.api_version
                != POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
            || self.subject
                != (CurrentAuthoritySubjectV3::Endpoint {
                    endpoint_role: RECOVERY_STORE_ENDPOINT_ROLE,
                })
            || self.service_role
                != TrustedHostServiceRoleV3::DurableRecoveryStore
            || self.idempotency_sha256
                != self.expected_idempotency_sha256()?
            || self.binding_sha256
                != self.expected_binding_sha256()?
        {
            return Err(ServiceError::Invalid(
                "recovery-store current-head request binding is incomplete or inconsistent",
            ));
        }
        Ok(())
    }

    pub(super) fn subject(&self) -> &CurrentAuthoritySubjectV3 {
        &self.subject
    }

    pub(super) fn endpoint_role(
        &self,
    ) -> PolicyCustodyEndpointRole {
        RECOVERY_STORE_ENDPOINT_ROLE
    }

    pub(super) fn request_id_sha256(&self) -> &Sha256Digest {
        &self.request_id_sha256
    }

    pub(super) fn idempotency_sha256(&self) -> &Sha256Digest {
        &self.idempotency_sha256
    }

    pub(super) fn request_payload_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.request_payload_sha256
    }

    pub(super) fn deadline(&self) -> &ProtocolBoottimeDeadline {
        &self.deadline
    }

    pub(super) fn binding_sha256(&self) -> &Sha256Digest {
        &self.binding_sha256
    }

    pub(super) fn validate_current_head(
        &self,
        current_head: &ServiceCurrentHeadBindingV3,
    ) -> Result<(), ServiceError> {
        self.validate()?;
        current_head.validate(
            self.endpoint_role(),
            &self.deadline,
        )?;
        let statement =
            &current_head.signed_current_head.statement;
        if statement.request_nonce_sha256
                != self.request_id_sha256
            || statement.request_sha256
                != self.idempotency_sha256
            || statement.endpoint_role != self.endpoint_role()
            || statement.deadline != self.deadline
        {
            return Err(ServiceError::Invalid(
                "recovery-store current head is not bound to the exact forthcoming request",
            ));
        }
        Ok(())
    }

    fn validate_frame_binding(
        &self,
        frame: &ServiceRequestFrameV3,
    ) -> Result<(), ServiceError> {
        self.validate()?;
        self.validate_current_head(&frame.binding.current_head)?;
        if frame.binding.service_role != self.service_role
            || frame.binding.request_id_sha256
                != self.request_id_sha256
            || frame.binding.idempotency_sha256
                != self.idempotency_sha256
            || frame.binding.request_payload_sha256
                != self.request_payload_sha256
            || frame.binding.deadline != self.deadline
        {
            return Err(ServiceError::Invalid(
                "recovery-store service frame changed its pre-authorized request binding",
            ));
        }
        Ok(())
    }
}

fn validate_request_bound_current_head(
    frame: &ServiceRequestFrameV3,
) -> Result<(), ServiceError> {
    let exact_request =
        RecoveryStoreCurrentHeadRequestBindingV3::new(
            frame.binding.request_id_sha256.clone(),
            frame.binding.request_payload_sha256.clone(),
            frame.binding.deadline.clone(),
        )?;
    if frame.binding.idempotency_sha256
        != exact_request.idempotency_sha256
    {
        return Err(ServiceError::Invalid(
            "recovery-store frame idempotency does not bind its exact canonical payload",
        ));
    }
    exact_request.validate_frame_binding(frame)
}

#[derive(Clone, PartialEq, Eq)]
enum ClientOperationScope {
    ScanIncomplete,
    QueryOwnership(Sha256Digest),
    CasOwnership(Sha256Digest),
    QuerySettlement(RecoveryKeyV3),
    CasSettlement(RecoveryKeyV3),
    RecoveryMaterial(Sha256Digest),
}

impl ClientOperationScope {
    fn resolves(&self, ambiguous: &Self) -> bool {
        matches!(
            (self, ambiguous),
            (
                Self::QueryOwnership(query),
                Self::CasOwnership(mutation),
            ) if query == mutation
        ) || matches!(
            (self, ambiguous),
            (
                Self::QuerySettlement(query),
                Self::CasSettlement(mutation),
            ) if query == mutation
        )
    }

    fn reply_matches(
        &self,
        reply: &DurableRecoveryStoreReplyV3,
    ) -> bool {
        matches!(
            (self, reply),
            (
                Self::ScanIncomplete,
                DurableRecoveryStoreReplyV3::ScanIncomplete { .. },
            )
                | (
                    Self::QueryOwnership(_),
                    DurableRecoveryStoreReplyV3::QueryOwnership {
                        ..
                    },
                )
                | (
                    Self::CasOwnership(_),
                    DurableRecoveryStoreReplyV3::CasOwnership {
                        ..
                    },
                )
                | (
                    Self::QuerySettlement(_),
                    DurableRecoveryStoreReplyV3::QuerySettlement {
                        ..
                    },
                )
                | (
                    Self::CasSettlement(_),
                    DurableRecoveryStoreReplyV3::CasSettlement {
                        ..
                    },
                )
                | (
                    Self::RecoveryMaterial(_),
                    DurableRecoveryStoreReplyV3::RecoveryMaterial {
                        ..
                    },
                )
        )
    }
}

struct ClientFlight {
    operation_scope: ClientOperationScope,
    operation_fingerprint: Sha256Digest,
    exact_request_frame: Vec<u8>,
    request_frame: ServiceRequestFrameV3,
    transport_ambiguous: bool,
    resolves_ambiguous_mutation: bool,
}

#[derive(Clone)]
struct PendingCurrentHeadFlight {
    operation_scope: ClientOperationScope,
    operation_fingerprint: Sha256Digest,
    request: DurableRecoveryStoreRequestV3,
    exact_request:
        RecoveryStoreCurrentHeadRequestBindingV3,
    resolves_ambiguous_mutation: bool,
}

/// Concrete local authenticated UDS adapter used by watchdog recovery.
pub(super) struct TrustedHostNoTeeDurableRecoveryStoreClient {
    exchange: NonblockingRequestReplyExchange,
    progress_socket: OwnedFd,
    progress: LinuxAbsoluteBoottimePoller,
    verifier: TrustedHostNoTeeRecoveryStoreResponseVerifier,
    client_instance_sha256: Sha256Digest,
    next_request_sequence: u64,
    current_head_provider:
        Box<dyn VerifiedRecoveryStoreCurrentHeadProvider>,
    current_head_progress: OwnedFd,
    last_endpoint_generation: Option<u64>,
    last_checkpoint_sha256: Option<Sha256Digest>,
    last_revocation_generation: Option<u64>,
    last_revocation_root_sha256: Option<Sha256Digest>,
    last_head_issued_at_boottime_nanos: Option<u64>,
    pending_current_head: Option<PendingCurrentHeadFlight>,
    flight: Option<ClientFlight>,
    unresolved_mutation: Option<ClientFlight>,
}

impl TrustedHostNoTeeDurableRecoveryStoreClient {
    pub(super) fn from_inherited_socket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        verifier: TrustedHostNoTeeRecoveryStoreResponseVerifier,
        client_instance_sha256: Sha256Digest,
        current_head_provider:
            Box<dyn VerifiedRecoveryStoreCurrentHeadProvider>,
    ) -> Result<Self, ServiceError> {
        require_nonzero_digest(
            "recoveryStoreClient.instanceSha256",
            &client_instance_sha256,
        )?;
        let current_head_progress = duplicate_cloexec(
            current_head_provider.progress_fd().as_raw_fd(),
        )?;
        let progress_socket =
            duplicate_cloexec(socket.as_raw_fd())?;
        let peer = AuthenticatedInheritedSeqpacket::from_inherited(
            socket,
            expected_peer,
        )?;
        Ok(Self {
            exchange: NonblockingRequestReplyExchange::new(peer),
            progress_socket,
            progress: LinuxAbsoluteBoottimePoller::new().map_err(|_| {
                ServiceError::Invalid(
                    "recovery-store client progress poller is unavailable",
                )
            })?,
            verifier,
            client_instance_sha256,
            next_request_sequence: 0,
            current_head_provider,
            current_head_progress,
            last_endpoint_generation: None,
            last_checkpoint_sha256: None,
            last_revocation_generation: None,
            last_revocation_root_sha256: None,
            last_head_issued_at_boottime_nanos: None,
            pending_current_head: None,
            flight: None,
            unresolved_mutation: None,
        })
    }

    pub(super) fn replace_inherited_socket_after_ambiguity(
        &mut self,
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
    ) -> Result<(), RecoveryError> {
        if !self.exchange.is_idle()
            || !(self.flight.as_ref().is_some_and(|flight| {
                flight.transport_ambiguous
            }) || self.unresolved_mutation.is_some())
        {
            return Err(RecoveryError::Conflict(
                "recovery-store socket replacement requires an idle ambiguous operation",
            ));
        }
        let progress_socket =
            duplicate_cloexec(socket.as_raw_fd())
                .map_err(service_error)?;
        let peer = AuthenticatedInheritedSeqpacket::from_inherited(
            socket,
            expected_peer,
        )
        .map_err(service_error)?;
        self.exchange = NonblockingRequestReplyExchange::new(peer);
        self.progress_socket = progress_socket;
        Ok(())
    }

    fn validate_and_record_current_head(
        &mut self,
        fresh_current_head: ServiceCurrentHeadBindingV3,
        exact_request:
            &RecoveryStoreCurrentHeadRequestBindingV3,
    ) -> Result<(), RecoveryError> {
        exact_request
            .validate_current_head(&fresh_current_head)
            .map_err(service_error)?;
        let head =
            &fresh_current_head.signed_current_head.statement;
        if self.last_endpoint_generation.is_some_and(
                |last| head.endpoint_generation < last,
            )
            || self.last_revocation_generation.is_some_and(
                |last| {
                    head.revocation_generation_high_water < last
                },
            )
            || self.last_head_issued_at_boottime_nanos.is_some_and(
                |last| head.issued_at_boottime_nanos <= last,
            )
            || (self.last_endpoint_generation
                    == Some(head.endpoint_generation)
                && self.last_checkpoint_sha256.as_ref()
                    != Some(&head.checkpoint_sha256))
            || (self.last_revocation_generation
                    == Some(head.revocation_generation_high_water)
                && self.last_revocation_root_sha256.as_ref()
                    != Some(&head.revocation_root_sha256))
        {
            return Err(RecoveryError::Authorization(
                "recovery-store current head would replay, roll back, or fork",
            ));
        }
        self.last_endpoint_generation =
            Some(head.endpoint_generation);
        self.last_checkpoint_sha256 =
            Some(head.checkpoint_sha256.clone());
        self.last_revocation_generation =
            Some(head.revocation_generation_high_water);
        self.last_revocation_root_sha256 =
            Some(head.revocation_root_sha256.clone());
        self.last_head_issued_at_boottime_nanos =
            Some(head.issued_at_boottime_nanos);
        Ok(())
    }

    fn operation_fingerprint<T: Serialize>(
        operation: &'static str,
        value: &T,
    ) -> Result<Sha256Digest, RecoveryError> {
        canonical_digest(
            RECOVERY_STORE_REQUEST_DOMAIN,
            &(operation, value),
        )
        .map_err(service_error)
    }

    fn try_round_trip<F>(
        &mut self,
        operation_scope: ClientOperationScope,
        operation_fingerprint: Sha256Digest,
        deadline: &AbsoluteBoottimeDeadline,
        build_request: F,
    ) -> Result<Option<DurableRecoveryStoreReplyV3>, RecoveryError>
    where
        F: FnOnce(Sha256Digest) -> DurableRecoveryStoreRequestV3,
    {
        require_live(deadline)?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        if let Some(flight) = &self.flight {
            if flight.operation_fingerprint
                != operation_fingerprint
                || flight.request_frame.binding.deadline
                    != protocol_deadline
                || flight.operation_scope != operation_scope
            {
                if flight.transport_ambiguous
                    && operation_scope
                        .resolves(&flight.operation_scope)
                    && self.exchange.is_idle()
                    && self.unresolved_mutation.is_none()
                {
                    self.unresolved_mutation =
                        self.flight.take();
                } else {
                    return Err(RecoveryError::Conflict(
                        "recovery-store client has another in-flight or unresolved operation",
                    ));
                }
            }
        }
        if let Some(pending) = &self.pending_current_head {
            if pending.operation_fingerprint
                    != operation_fingerprint
                || pending.exact_request.deadline
                    != protocol_deadline
                || pending.operation_scope != operation_scope
            {
                return Err(RecoveryError::Conflict(
                    "recovery-store client has a different exact request awaiting its one-shot current head",
                ));
            }
        }

        if self.flight.is_none() {
            if self.unresolved_mutation.as_ref().is_some_and(
                |ambiguous| {
                    ambiguous.operation_fingerprint
                        == operation_fingerprint
                        && ambiguous.request_frame.binding.deadline
                            == protocol_deadline
                },
            ) {
                let mut exact_retry =
                    self.unresolved_mutation.take().ok_or(
                        RecoveryError::Invalid(
                            "recovery-store ambiguous request disappeared",
                        ),
                    )?;
                if encode_canonical_frame(&exact_retry.request_frame)
                    .map_err(service_error)?
                    != exact_retry.exact_request_frame
                {
                    return Err(RecoveryError::Authorization(
                        "recovery-store ambiguous request bytes changed before retry",
                    ));
                }
                self.exchange
                    .begin(
                        &exact_retry.request_frame,
                        TrustedHostServiceRoleV3::DurableRecoveryStore,
                        RECOVERY_STORE_ENDPOINT_ROLE,
                        &[],
                        0,
                        0,
                    )
                    .map_err(service_error)?;
                exact_retry.transport_ambiguous = false;
                self.flight = Some(exact_retry);
            }
        }

        if self.flight.as_ref().is_some_and(|flight| {
            flight.operation_fingerprint == operation_fingerprint
                && flight.request_frame.binding.deadline
                    == protocol_deadline
                && flight.transport_ambiguous
        }) {
            if !self.exchange.is_idle() {
                return Err(RecoveryError::Invalid(
                    "recovery-store ambiguous exchange is not idle",
                ));
            }
            let flight = self.flight.as_ref().ok_or(
                RecoveryError::Invalid(
                    "recovery-store ambiguous request disappeared",
                ),
            )?;
            if encode_canonical_frame(&flight.request_frame)
                .map_err(service_error)?
                != flight.exact_request_frame
            {
                return Err(RecoveryError::Authorization(
                    "recovery-store exact retry changed its request bytes",
                ));
            }
            self.exchange
                .begin(
                    &flight.request_frame,
                    TrustedHostServiceRoleV3::DurableRecoveryStore,
                    RECOVERY_STORE_ENDPOINT_ROLE,
                    &[],
                    0,
                    0,
                )
                .map_err(service_error)?;
            self.flight
                .as_mut()
                .ok_or(RecoveryError::Invalid(
                    "recovery-store exact retry lost its flight",
                ))?
                .transport_ambiguous = false;
        }

        if self.flight.is_none() {
            if self.pending_current_head.is_none() {
                let resolves_ambiguous_mutation =
                    if let Some(ambiguous) =
                        &self.unresolved_mutation
                    {
                        if !operation_scope
                            .resolves(&ambiguous.operation_scope)
                        {
                            return Err(RecoveryError::Conflict(
                                "recovery-store operation does not authoritatively resolve the retained ambiguous mutation",
                            ));
                        }
                        true
                    } else {
                        false
                    };
                self.next_request_sequence = self
                    .next_request_sequence
                    .checked_add(1)
                    .ok_or(RecoveryError::Invalid(
                        "recovery-store request sequence exhausted",
                    ))?;
                let request_id_sha256 = canonical_digest(
                    RECOVERY_STORE_REQUEST_DOMAIN,
                    &(
                        &self.client_instance_sha256,
                        self.next_request_sequence,
                        &operation_fingerprint,
                    ),
                )
                .map_err(service_error)?;
                let request =
                    build_request(request_id_sha256.clone());
                request.validate().map_err(|_| protocol_error())?;
                if request.request_id_sha256()
                        != &request_id_sha256
                    || request.deadline() != &protocol_deadline
                {
                    return Err(RecoveryError::Deadline(
                        "recovery-store request changed its exact request id or deadline",
                    ));
                }
                let canonical_request =
                    encode_canonical_frame(&request)
                        .map_err(service_error)?;
                let exact_request =
                    RecoveryStoreCurrentHeadRequestBindingV3::new(
                        request_id_sha256,
                        Sha256Digest::compute(
                            &canonical_request,
                        ),
                        protocol_deadline.clone(),
                    )
                    .map_err(service_error)?;
                self.pending_current_head =
                    Some(PendingCurrentHeadFlight {
                        operation_scope:
                            operation_scope.clone(),
                        operation_fingerprint:
                            operation_fingerprint.clone(),
                        request,
                        exact_request,
                        resolves_ambiguous_mutation,
                    });
            }

            let exact_request = self
                .pending_current_head
                .as_ref()
                .ok_or(RecoveryError::Invalid(
                    "recovery-store pending current-head request disappeared",
                ))?
                .exact_request
                .clone();
            let Some(current_head) = self
                .current_head_provider
                .try_fresh_current_head_nonblocking(
                    &exact_request,
                )?
            else {
                self.progress
                    .arm_progress(&[PollTarget::socket(
                        self.current_head_progress.as_fd(),
                        PollInterest::READABLE,
                    )])
                    .map_err(|_| {
                        RecoveryError::Transient(
                            "recovery-store current-head progress registration failed",
                        )
                    })?;
                return Ok(None);
            };
            self.validate_and_record_current_head(
                current_head.clone(),
                &exact_request,
            )?;
            let pending = self
                .pending_current_head
                .as_ref()
                .cloned()
                .ok_or(RecoveryError::Invalid(
                    "recovery-store authorized pending request disappeared",
                ))?;
            if pending.exact_request != exact_request {
                return Err(RecoveryError::Authorization(
                    "recovery-store pending request changed while obtaining its one-shot current head",
                ));
            }
            let request_frame = ServiceRequestFrameV3::from_payload(
                TrustedHostServiceRoleV3::DurableRecoveryStore,
                pending
                    .exact_request
                    .request_id_sha256
                    .clone(),
                pending
                    .exact_request
                    .idempotency_sha256
                    .clone(),
                pending.exact_request.deadline.clone(),
                current_head,
                &pending.request,
            )
            .map_err(service_error)?;
            pending
                .exact_request
                .validate_frame_binding(&request_frame)
                .map_err(service_error)?;
            let exact_request_frame =
                encode_canonical_frame(&request_frame)
                    .map_err(service_error)?;
            self.pending_current_head = None;
            let begin_result = self.exchange.begin(
                &request_frame,
                TrustedHostServiceRoleV3::DurableRecoveryStore,
                RECOVERY_STORE_ENDPOINT_ROLE,
                &[],
                0,
                0,
            );
            self.flight = Some(ClientFlight {
                operation_fingerprint:
                    pending.operation_fingerprint,
                exact_request_frame,
                request_frame,
                operation_scope: pending.operation_scope,
                transport_ambiguous: begin_result.is_err(),
                resolves_ambiguous_mutation:
                    pending.resolves_ambiguous_mutation,
            });
            begin_result.map_err(service_error)?;
        }

        let progressed = self.exchange.try_progress();
        let completed = match progressed {
            Ok(NonblockingExchangeProgress::Pending) => {
                self.progress
                    .arm_progress(&[PollTarget::socket(
                        self.progress_socket.as_fd(),
                        PollInterest::READ_WRITE,
                    )])
                    .map_err(|_| {
                        RecoveryError::Transient(
                            "recovery-store UDS progress registration failed",
                        )
                    })?;
                return Ok(None);
            }
            Ok(NonblockingExchangeProgress::Complete(completed)) => {
                completed
            }
            Err(error) => {
                if let Some(flight) = self.flight.as_mut() {
                    flight.transport_ambiguous = true;
                }
                return Err(RecoveryError::Transient(
                    match error {
                        ServiceError::Io(_) => {
                            "recovery-store transport failed with an exact request retained for retry or query"
                        }
                        _ => {
                            "recovery-store exchange failed with an exact request retained for fail-closed resolution"
                        }
                    },
                ));
            }
        };
        if !completed.rights.is_empty() {
            if let Some(flight) = self.flight.as_mut() {
                flight.transport_ambiguous = true;
            }
            return Err(RecoveryError::Authorization(
                "recovery-store response smuggled unexpected descriptors",
            ));
        }
        let result = (|| {
            let flight = self.flight.as_ref().ok_or(
                RecoveryError::Invalid(
                    "recovery-store completion has no matching request",
                ),
            )?;
            let transaction: DurableRecoveryStoreTransactionV3 =
                completed
                    .response
                    .decode_payload()
                    .map_err(service_error)?;
            transaction
                .validate(&flight.request_frame)
                .map_err(service_error)?;
            if transaction.exact_request_frame
                != flight.exact_request_frame
            {
                return Err(RecoveryError::Authorization(
                    "recovery-store response changed the exact request bytes",
                ));
            }
            self.verifier
                .verify(&flight.request_frame, &transaction.signed_reply)
                .map_err(service_error)?;
            if !flight.operation_scope.reply_matches(
                &transaction.signed_reply.response.reply,
            ) {
                return Err(RecoveryError::Authorization(
                    "recovery-store response operation does not match the exact request",
                ));
            }
            require_live(deadline)?;
            Ok(transaction.signed_reply.response.reply.clone())
        })();
        match result {
            Ok(reply) => {
                let completed_flight = self.flight.take().ok_or(
                    RecoveryError::Invalid(
                        "recovery-store verified completion lost its flight",
                    ),
                )?;
                if completed_flight
                    .resolves_ambiguous_mutation
                {
                    self.unresolved_mutation = None;
                }
                Ok(Some(reply))
            }
            Err(error) => {
                if let Some(flight) = self.flight.as_mut() {
                    flight.transport_ambiguous = true;
                }
                Err(error)
            }
        }
    }

    pub(super) fn try_recovery_material_nonblocking(
        &mut self,
        ownership_id_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Option<RecoveryMaterialV3>>, RecoveryError> {
        let fingerprint = Self::operation_fingerprint(
            "recovery-material",
            &(
                ownership_id_sha256,
                ProtocolBoottimeDeadline::from_runtime(*deadline),
            ),
        )?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        self.try_round_trip(
            ClientOperationScope::RecoveryMaterial(
                ownership_id_sha256.clone(),
            ),
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::RecoveryMaterial {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    ownership_id_sha256:
                        ownership_id_sha256.clone(),
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(|reply| match reply {
            DurableRecoveryStoreReplyV3::RecoveryMaterial {
                material,
            } => Ok(material),
            _ => Err(RecoveryError::Authorization(
                "recovery-store returned the wrong reply operation",
            )),
        })
        .transpose()
    }

    pub(super) fn try_recovery_runtime_material_nonblocking(
        &mut self,
        ownership_id_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Option<RecoveryRuntimeMaterialV3>>, RecoveryError>
    {
        self.try_recovery_material_nonblocking(
            ownership_id_sha256,
            deadline,
        )?
        .map(|material| {
            material.map(recovery_material_to_runtime).transpose()
        })
        .transpose()
    }
}

impl DurableRecoveryStore<TrustedHostRecoveryProtocol>
    for TrustedHostNoTeeDurableRecoveryStoreClient
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress.progress_fd()
    }

    fn try_scan_incomplete_ownership_nonblocking(
        &mut self,
        continuation: Option<RecoveryDigest>,
        maximum_records: usize,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<RecoveryScanPage<DurableOwnershipRecord>>,
        RecoveryError,
    > {
        if maximum_records == 0
            || maximum_records > MAX_RECOVERY_SCAN_RECORDS
        {
            return Err(RecoveryError::Invalid(
                "recovery-store scan exceeds its fixed bound",
            ));
        }
        let maximum_records_u16 =
            u16::try_from(maximum_records).map_err(|_| {
                RecoveryError::Invalid(
                    "recovery-store scan bound is not representable",
                )
            })?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let fingerprint = Self::operation_fingerprint(
            "scan-incomplete",
            &(
                &continuation,
                maximum_records_u16,
                &protocol_deadline,
            ),
        )?;
        self.try_round_trip(
            ClientOperationScope::ScanIncomplete,
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::ScanIncomplete {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    continuation,
                    maximum_records: maximum_records_u16,
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(|reply| match reply {
            DurableRecoveryStoreReplyV3::ScanIncomplete {
                records,
                continuation,
            } => {
                let records = records
                    .into_iter()
                    .map(wire_owner_to_runtime)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(RecoveryScanPage {
                    records,
                    continuation,
                })
            }
            _ => Err(RecoveryError::Authorization(
                "recovery-store returned the wrong reply operation",
            )),
        })
        .transpose()
    }

    fn try_query_ownership_nonblocking(
        &mut self,
        ownership_id_sha256: &RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<Option<Option<DurableOwnershipRecord>>, RecoveryError>
    {
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let fingerprint = Self::operation_fingerprint(
            "query-ownership",
            &(ownership_id_sha256, &protocol_deadline),
        )?;
        self.try_round_trip(
            ClientOperationScope::QueryOwnership(
                ownership_id_sha256.clone(),
            ),
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::QueryOwnership {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    ownership_id_sha256:
                        ownership_id_sha256.clone(),
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(|reply| match reply {
            DurableRecoveryStoreReplyV3::QueryOwnership {
                authoritative,
            } => authoritative
                .map(wire_owner_to_runtime)
                .transpose(),
            _ => Err(RecoveryError::Authorization(
                "recovery-store returned the wrong reply operation",
            )),
        })
        .transpose()
    }

    fn try_cas_ownership_reconciling_nonblocking(
        &mut self,
        expected: &DurableOwnershipRecord,
        watchdog_lease: &WatchdogLeaseV3,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<DurableOwnershipRecord>>,
        RecoveryError,
    > {
        let expected_wire = runtime_owner_to_wire(expected)?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let transition = OwnershipCasTransitionV3::Reconciling {
            watchdog_lease: watchdog_lease.clone(),
        };
        let fingerprint = Self::operation_fingerprint(
            "cas-ownership-reconciling",
            &(&expected_wire, &transition, &protocol_deadline),
        )?;
        let operation_scope = ClientOperationScope::CasOwnership(
            expected_wire.ownership_id_sha256.clone(),
        );
        self.try_round_trip(
            operation_scope,
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::CasOwnership {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    expected: expected_wire,
                    transition,
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(map_ownership_cas_reply)
        .transpose()
    }

    fn try_cas_ownership_terminal_nonblocking(
        &mut self,
        expected: &DurableOwnershipRecord,
        watchdog_lease: &WatchdogLeaseV3,
        settlement_state_sha256: RecoveryDigest,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<DurableOwnershipRecord>>,
        RecoveryError,
    > {
        let expected_wire = runtime_owner_to_wire(expected)?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let transition = OwnershipCasTransitionV3::Terminal {
            watchdog_lease: watchdog_lease.clone(),
            settlement_state_sha256,
        };
        let fingerprint = Self::operation_fingerprint(
            "cas-ownership-terminal",
            &(&expected_wire, &transition, &protocol_deadline),
        )?;
        let operation_scope = ClientOperationScope::CasOwnership(
            expected_wire.ownership_id_sha256.clone(),
        );
        self.try_round_trip(
            operation_scope,
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::CasOwnership {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    expected: expected_wire,
                    transition,
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(map_ownership_cas_reply)
        .transpose()
    }

    fn try_query_settlement_nonblocking(
        &mut self,
        key: &RecoveryKey,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<Option<DurableSettlementRecord>>,
        RecoveryError,
    > {
        let key = runtime_key_to_wire(key);
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let fingerprint = Self::operation_fingerprint(
            "query-settlement",
            &(&key, &protocol_deadline),
        )?;
        let operation_scope =
            ClientOperationScope::QuerySettlement(key.clone());
        self.try_round_trip(
            operation_scope,
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::QuerySettlement {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    key,
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(|reply| match reply {
            DurableRecoveryStoreReplyV3::QuerySettlement {
                authoritative,
            } => Ok(authoritative),
            _ => Err(RecoveryError::Authorization(
                "recovery-store returned the wrong reply operation",
            )),
        })
        .transpose()
    }

    fn try_cas_one_settlement_transition_nonblocking(
        &mut self,
        key: &RecoveryKey,
        expected_revision: u64,
        expected_state_sha256: RecoveryDigest,
        transition: &DurableSettlementRecord,
        deadline: &AbsoluteBoottimeDeadline,
    ) -> Result<
        Option<CasTransitionResult<DurableSettlementRecord>>,
        RecoveryError,
    > {
        let key = runtime_key_to_wire(key);
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let candidate = transition.clone();
        let fingerprint = Self::operation_fingerprint(
            "cas-settlement",
            &(
                &key,
                expected_revision,
                &expected_state_sha256,
                &candidate,
                &protocol_deadline,
            ),
        )?;
        let operation_scope =
            ClientOperationScope::CasSettlement(key.clone());
        self.try_round_trip(
            operation_scope,
            fingerprint,
            deadline,
            |request_id_sha256| {
                DurableRecoveryStoreRequestV3::CasSettlement {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_STORE_WIRE_VERSION
                            .to_string(),
                    request_id_sha256,
                    key,
                    expected_revision,
                    expected_state_sha256,
                    candidate,
                    deadline: protocol_deadline,
                }
            },
        )?
        .map(|reply| match reply {
            DurableRecoveryStoreReplyV3::CasSettlement {
                disposition,
                authoritative,
            } => Ok(CasTransitionResult {
                disposition: runtime_disposition(disposition),
                authoritative_state: authoritative,
            }),
            _ => Err(RecoveryError::Authorization(
                "recovery-store returned the wrong reply operation",
            )),
        })
        .transpose()
    }
}

fn map_ownership_cas_reply(
    reply: DurableRecoveryStoreReplyV3,
) -> Result<
    CasTransitionResult<DurableOwnershipRecord>,
    RecoveryError,
> {
    match reply {
        DurableRecoveryStoreReplyV3::CasOwnership {
            disposition,
            authoritative,
        } => Ok(CasTransitionResult {
            disposition: runtime_disposition(disposition),
            authoritative_state:
                wire_owner_to_runtime(authoritative)?,
        }),
        _ => Err(RecoveryError::Authorization(
            "recovery-store returned the wrong reply operation",
        )),
    }
}
