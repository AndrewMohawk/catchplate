//! TrustedHostNoTee current-signature authority.
//!
//! This service owns its current Ed25519 verification keys, endpoint
//! generations, checkpoint sequence, and revocation heads. Caller-supplied
//! key metadata is only a claim to compare with that state; it can never select
//! a historical key. The deployment report explicitly describes co-located
//! software with no hardware key protection or hardware attestation.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "the TrustedHostNoTee current-signature authority requires Linux AF_UNIX SOCK_SEQPACKET, SO_PEERCRED, epoll, and CLOCK_BOOTTIME semantics"
);

use super::common::{
    decode_canonical_frame, AuthenticatedInheritedSeqpacket,
    ExpectedPeerCredentials, NonblockingExchangeProgress,
    NonblockingRequestReplyExchange, ReceivedSeqpacket,
    ServiceCurrentHeadBindingV3, ServiceError,
    ServiceRequestBindingV3,
    ServiceRequestFrameV3, ServiceResponseFrameV3,
    TrustedHostNoTeeServiceReportV3, TrustedHostServiceRoleV3,
};
use super::durable_recovery_store::{
    RecoveryStoreCurrentHeadRequestBindingV3,
    VerifiedRecoveryStoreCurrentHeadProvider,
};
use super::wire::{
    CurrentAuthoritySubjectV3,
    CurrentCleanupAuthorityVerificationV3,
    CurrentEndpointSignatureVerificationV3,
    CurrentSignatureAuthorityReplyV3,
    CurrentSignatureAuthorityRequestV3, CurrentTrustHeadV3,
    PolicyCustodyServiceRoleV3, ServiceResponseSignatureV3,
    SignatureRejectionV3, SignedServiceResponseV3,
    POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION,
    POLICY_CUSTODY_SERVICES_WIRE_VERSION,
};
use super::super::boottime::{
    boottime_now_nanos, BoottimeDeadline,
};
use super::super::endpoint_clients::{
    CurrentEndpointTrustProvider, EndpointClientError,
    EndpointTrustPin, HistoricalDurableConsumeVerification,
};
use super::super::protocol::{
    domain_separated_signature_preimage, endpoint_request_sha256,
    endpoint_response_sha256, PolicyCustodyEndpointRole,
    ProtocolBoottimeDeadline,
};
use super::super::watchdog_recovery::{
    CurrentCleanupAuthorityVerification,
    CurrentSignatureAuthority, CurrentSignatureVerification,
    RecoveryError,
};
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::rc::Rc;

const SERVICE_RESPONSE_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyServiceResponse/v3";
const CURRENT_TRUST_HEAD_DOMAIN: &[u8] =
    b"serverware.policyCustodyCurrentTrustHead/v3";
const CURRENT_SIGNATURE_REQUEST_ID_DOMAIN: &[u8] =
    b"serverware.policyCustodyCurrentSignatureRequestId/v3";
const MAX_PROGRESS_EVENTS: usize = 16;
const MAX_CURRENT_SIGNATURE_SUBJECTS: usize = 64;

struct CurrentSignatureServiceSigner {
    pin: EndpointTrustPin,
    signing_key: SigningKey,
    report: TrustedHostNoTeeServiceReportV3,
}

impl CurrentSignatureServiceSigner {
    fn new(
        pin: EndpointTrustPin,
        signing_key: SigningKey,
        signing_credential_sha256: Sha256Digest,
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
    ) -> Result<Self, ServiceError> {
        pin.validate().map_err(|_| {
            ServiceError::Invalid(
                "current-signature service signing pin is not current",
            )
        })?;
        require_signing_key_matches_pin(&signing_key, &pin)?;
        let report = TrustedHostNoTeeServiceReportV3::new(
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
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
            pin.endpoint_process_identity_sha256.clone(),
            Some(signing_credential_sha256),
        )?;
        Ok(Self {
            pin,
            signing_key,
            report,
        })
    }

    fn endpoint_role(&self) -> PolicyCustodyEndpointRole {
        self.pin.endpoint_role
    }

    fn report(&self) -> &TrustedHostNoTeeServiceReportV3 {
        &self.report
    }

    fn sign_response<T: Serialize>(
        &self,
        request_id_sha256: &Sha256Digest,
        response: T,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<SignedServiceResponseV3<T>, ServiceError> {
        self.pin.validate().map_err(|_| {
            ServiceError::Invalid(
                "current-signature service signing pin expired",
            )
        })?;
        deadline.to_runtime()?.require_live().map_err(|_| {
            ServiceError::Invalid(
                "current-signature response deadline expired",
            )
        })?;
        let observed_at_boottime_nanos = boottime_now_nanos()
            .map_err(|_| {
                ServiceError::Invalid(
                    "CLOCK_BOOTTIME is unavailable while signing current-signature response",
                )
            })?;
        if observed_at_boottime_nanos
            >= deadline.absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "current-signature response crossed its deadline",
            ));
        }
        let exact_canonical_response_bytes =
            canonical_json_bytes(&response).map_err(|_| {
                ServiceError::Invalid(
                    "current-signature response is not canonical",
                )
            })?;
        let current = &self.pin.current_key_authorization;
        let mut signature = ServiceResponseSignatureV3 {
            api_version:
                POLICY_CUSTODY_SERVICES_WIRE_VERSION.to_string(),
            service_role:
                PolicyCustodyServiceRoleV3::CurrentSignatureAuthority,
            request_id_sha256: request_id_sha256.clone(),
            response_sha256: endpoint_response_sha256(
                &exact_canonical_response_bytes,
            ),
            endpoint_process_identity:
                self.pin.endpoint_process_identity.clone(),
            endpoint_generation: self.pin.exact_endpoint_generation,
            current_key_authorization_checkpoint_sha256:
                current.exact_checkpoint_sha256.clone(),
            revocation_generation:
                current.exact_revocation_generation_high_water,
            revocation_root_sha256:
                current.exact_revocation_root_sha256.clone(),
            observed_at_boottime_nanos,
            signing_key_id: current.signing_key_id.clone(),
            signing_key_spki_sha256:
                current.signing_key_spki_sha256.clone(),
            signature_base64: String::new(),
            receipt_sha256: Sha256Digest::compute(&[]),
        };
        let signature_payload =
            service_signature_payload(&signature)?;
        let preimage = domain_separated_signature_preimage(
            self.pin.endpoint_role.response_signature_domain(),
            &signature_payload,
        )?;
        signature.signature_base64 = URL_SAFE_NO_PAD.encode(
            self.signing_key.sign(&preimage).to_bytes(),
        );
        signature.receipt_sha256 = hash_domain_frames(
            SERVICE_RESPONSE_RECEIPT_DOMAIN,
            &[
                signature_payload.as_slice(),
                signature.signature_base64.as_bytes(),
            ],
        );
        let exact_signature_envelope_bytes =
            canonical_json_bytes(&signature).map_err(|_| {
                ServiceError::Invalid(
                    "current-signature service envelope is not canonical",
                )
            })?;
        let signed = SignedServiceResponseV3 {
            response,
            exact_canonical_response_bytes,
            signature,
            exact_signature_envelope_bytes,
        };
        signed.validate(
            PolicyCustodyServiceRoleV3::CurrentSignatureAuthority,
            request_id_sha256,
            deadline,
        )?;
        Ok(signed)
    }
}

/// A response prepared for the shared local seqpacket serving loop.
pub(super) struct PreparedCurrentSignatureResponse {
    pub(super) frame: ServiceResponseFrameV3,
    pub(super) rights: Vec<OwnedFd>,
}

/// Role handler with authority-owned current key/checkpoint/revocation state.
pub(super) struct TrustedHostNoTeeCurrentSignatureAuthorityServer {
    signer: CurrentSignatureServiceSigner,
    subjects: BTreeMap<CurrentAuthoritySubjectKey, EndpointTrustPin>,
}
impl super::generation_service::Owner for TrustedHostNoTeeCurrentSignatureAuthorityServer {
    fn generation_state(&self,_deadline:u64)->Result<Sha256Digest,ServiceError> {
        self.signer.pin.validate().map_err(|_|ServiceError::Invalid("generation signer currentness unavailable"))?;
        let mut originals=Vec::new();
        for pin in self.subjects.values() {
            pin.validate().map_err(|_|ServiceError::Invalid("generation subject currentness unavailable"))?;
            originals.push((&pin.endpoint_process_identity,&pin.current_key_authorization.signed_current_key_authorization,
                pin.consume_cursor.sequence_high_water,pin.consume_cursor.expected_next_sequence,
                &pin.consume_cursor.expected_predecessor_receipt_sha256));
        }
        Ok(Sha256Digest::compute(&super::encode_canonical_frame(&(&self.signer.report,originals))?))
    }
    fn sign_generation_effect(&self,effect:super::generation_service::Effect)->Result<super::generation_service::Receipt,ServiceError> {
        super::generation_service::sign(effect,&self.signer.signing_key)
    }
    fn sign_generation_transition(&self,epoch:super::super::authority_history::AuthorityEpochRefV3,
        request:&super::super::production_dispatch::ClosedProductionGenerationRequestV4,head:Sha256Digest,result:Sha256Digest,now:u64)
        ->Result<super::super::production_dispatch::SignedProductionGenerationServiceTransitionV4,ServiceError>{
        super::generation_service::sign_transition(epoch,request,head,result,now,&self.signer.signing_key)
    }
    fn sign_generation_observation(&self,payload:super::generation_service::ObservationPayload)->Result<super::generation_service::Observation,ServiceError> {
        super::generation_service::sign_observation(payload,&self.signer.signing_key)
    }
}
impl super::dispatch_service::Owner for TrustedHostNoTeeCurrentSignatureAuthorityServer {
    fn sign_commitment_transition(&self,input:&super::dispatch_service::TransitionInput)
        ->Result<super::super::production_dispatch::SignedProductionServiceTransitionV4,ServiceError> {
        self.signer.pin.validate().map_err(|_|ServiceError::Invalid("CommitRequest current signer changed"))?;
        input.sign(&self.signer.signing_key)
    }
}
impl super::spool_current::Owner for TrustedHostNoTeeCurrentSignatureAuthorityServer {
    fn sign_spool_current(&self,input:&super::spool_current::Input)
        ->Result<super::super::production_dispatch::SignedProductionServiceTransitionV4,ServiceError>{
        self.signer.pin.validate().map_err(|_|ServiceError::Invalid("native spool current signer changed"))?;
        input.sign(&self.signer.signing_key)
    }
}
impl super::publication_service::Owner for TrustedHostNoTeeCurrentSignatureAuthorityServer {
    fn sign_publication_snapshot(&self,_input:&super::publication_service::SnapshotInput)
        ->Result<super::publication::Snapshot,ServiceError>{Err(ServiceError::Invalid("only DRS may snapshot publication state"))}
    fn sign_publication_witness(&self,input:&super::publication_service::WitnessInput)
        ->Result<super::publication_service::Witness,ServiceError>{
        self.signer.pin.validate().map_err(|_|ServiceError::Invalid("publication current signer changed"))?;
        input.sign(&self.signer.signing_key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CurrentAuthoritySubjectKey {
    Endpoint(PolicyCustodyEndpointRole),
    CleanupAuthorizationAuthority(PolicyCustodyEndpointRole),
}

impl From<&CurrentAuthoritySubjectV3>
    for CurrentAuthoritySubjectKey
{
    fn from(subject: &CurrentAuthoritySubjectV3) -> Self {
        match subject {
            CurrentAuthoritySubjectV3::Endpoint {
                endpoint_role,
            } => Self::Endpoint(*endpoint_role),
            CurrentAuthoritySubjectV3::
                CleanupAuthorizationAuthority {
                    authority_role,
                } => {
                    Self::CleanupAuthorizationAuthority(
                        *authority_role,
                    )
                }
        }
    }
}

impl TrustedHostNoTeeCurrentSignatureAuthorityServer {
    pub(super) fn new(
        service_signing_pin: EndpointTrustPin,
        service_signing_key: SigningKey,
        service_signing_credential_sha256: Sha256Digest,
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
        current_subjects:
            Vec<(CurrentAuthoritySubjectV3, EndpointTrustPin)>,
    ) -> Result<Self, ServiceError> {
        if current_subjects.is_empty()
            || current_subjects.len()
                > MAX_CURRENT_SIGNATURE_SUBJECTS
        {
            return Err(ServiceError::Invalid(
                "current-signature authority subject count is outside its fixed bound",
            ));
        }
        let mut subjects = BTreeMap::new();
        for (subject, pin) in current_subjects {
            pin.validate().map_err(|_| {
                ServiceError::Invalid(
                    "current-signature subject pin is not current",
                )
            })?;
            if subject_endpoint_role(&subject)
                != pin.endpoint_role
            {
                return Err(ServiceError::Invalid(
                    "current-signature subject variant does not match its endpoint pin",
                ));
            }
            let key = CurrentAuthoritySubjectKey::from(&subject);
            if subjects.insert(key, pin).is_some() {
                return Err(ServiceError::Invalid(
                    "current-signature authority has duplicate subject configuration",
                ));
            }
        }
        Ok(Self {
            signer: CurrentSignatureServiceSigner::new(
                service_signing_pin,
                service_signing_key,
                service_signing_credential_sha256,
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
            )?,
            subjects,
        })
    }

    pub(super) fn trusted_host_report(
        &self,
    ) -> &TrustedHostNoTeeServiceReportV3 {
        self.signer.report()
    }

    pub(super) fn handle_authenticated_packet(
        &self,
        authenticated_peer: &AuthenticatedInheritedSeqpacket,
        packet: ReceivedSeqpacket,
    ) -> Result<PreparedCurrentSignatureResponse, ServiceError> {
        let credentials = authenticated_peer.peer_credentials();
        if credentials.pid <= 0 || !packet.rights.is_empty() {
            return Err(ServiceError::Invalid(
                "current-signature request is not an authenticated descriptor-free local packet",
            ));
        }
        let frame: ServiceRequestFrameV3 =
            decode_canonical_frame(&packet.frame)?;
        frame.validate(
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            self.signer.endpoint_role(),
        )?;
        let request: CurrentSignatureAuthorityRequestV3 =
            frame.decode_payload()?;
        request.validate()?;
        validate_request_binding(&frame, &request)?;
        validate_exact_current_head_for_request(
            &frame.binding,
            &self.signer.pin,
            &request_idempotency(&request)?,
        )?;
        let reply = self.handle_request(&request)?;
        reply.validate()?;
        let signed = self.signer.sign_response(
            &frame.binding.request_id_sha256,
            reply,
            &frame.binding.deadline,
        )?;
        Ok(PreparedCurrentSignatureResponse {
            frame: ServiceResponseFrameV3::from_payload(
                frame.binding,
                &signed,
            )?,
            rights: Vec::new(),
        })
    }

    fn handle_request(
        &self,
        request: &CurrentSignatureAuthorityRequestV3,
    ) -> Result<CurrentSignatureAuthorityReplyV3, ServiceError> {
        match request {
            CurrentSignatureAuthorityRequestV3::VerifyEndpoint(
                verification,
            ) => self.verify_endpoint(verification),
            CurrentSignatureAuthorityRequestV3::VerifyCleanup(
                verification,
            ) => self.verify_cleanup(verification),
            CurrentSignatureAuthorityRequestV3::CurrentHead {
                subject,
                minimum_checkpoint_sequence,
                minimum_revocation_generation,
                deadline,
                ..
            } => {
                let pin = self.subject_pin(subject)?;
                let current =
                    &pin.current_key_authorization;
                if current.exact_checkpoint_sequence
                        < *minimum_checkpoint_sequence
                    || current
                        .exact_revocation_generation_high_water
                        < *minimum_revocation_generation
                {
                    return Err(ServiceError::Invalid(
                        "current-signature head is below the caller rollback floor",
                    ));
                }
                Ok(
                    CurrentSignatureAuthorityReplyV3::CurrentHead {
                        current_head: current_trust_head(
                            subject.clone(),
                            pin,
                            deadline,
                        )?,
                    },
                )
            }
        }
    }

    fn verify_endpoint(
        &self,
        request: &CurrentEndpointSignatureVerificationV3,
    ) -> Result<CurrentSignatureAuthorityReplyV3, ServiceError> {
        let subject = CurrentAuthoritySubjectV3::Endpoint {
            endpoint_role: request.endpoint_role,
        };
        let pin = self.subject_pin(&subject)?;
        let current_head = current_trust_head(
            subject,
            pin,
            &request.deadline,
        )?;
        let rejection = classify_endpoint_claim(request, pin)?;
        if let Some(reason) = rejection {
            return Ok(
                CurrentSignatureAuthorityReplyV3::Rejected {
                    reason,
                    current_head,
                },
            );
        }
        let preimage = domain_separated_signature_preimage(
            &request.signature_domain,
            &request.signature_payload,
        )?;
        let verified = verify_preimage_signature(
            &pin.current_key_authorization.verifying_key,
            &preimage,
            &request.signature_base64,
        )
        .is_ok();
        Ok(if verified {
            CurrentSignatureAuthorityReplyV3::Verified {
                current_head,
            }
        } else {
            CurrentSignatureAuthorityReplyV3::Rejected {
                reason: SignatureRejectionV3::InvalidSignature,
                current_head,
            }
        })
    }

    fn verify_cleanup(
        &self,
        request: &CurrentCleanupAuthorityVerificationV3,
    ) -> Result<CurrentSignatureAuthorityReplyV3, ServiceError> {
        let subject =
            CurrentAuthoritySubjectV3::CleanupAuthorizationAuthority {
                authority_role: request.authority_role,
            };
        let pin = self.subject_pin(&subject)?;
        let current_head = current_trust_head(
            subject,
            pin,
            &request.deadline,
        )?;
        let rejection = classify_cleanup_claim(request, pin)?;
        if let Some(reason) = rejection {
            return Ok(
                CurrentSignatureAuthorityReplyV3::Rejected {
                    reason,
                    current_head,
                },
            );
        }
        let verified = verify_preimage_signature(
            &pin.current_key_authorization.verifying_key,
            &request.signature_preimage,
            &request.signature_base64,
        )
        .is_ok();
        Ok(if verified {
            CurrentSignatureAuthorityReplyV3::Verified {
                current_head,
            }
        } else {
            CurrentSignatureAuthorityReplyV3::Rejected {
                reason: SignatureRejectionV3::InvalidSignature,
                current_head,
            }
        })
    }

    fn subject_pin(
        &self,
        subject: &CurrentAuthoritySubjectV3,
    ) -> Result<&EndpointTrustPin, ServiceError> {
        self.subjects
            .get(&CurrentAuthoritySubjectKey::from(subject))
            .ok_or(ServiceError::Invalid(
                "current-signature subject variant is not configured",
            ))
    }
}

fn classify_endpoint_claim(
    request: &CurrentEndpointSignatureVerificationV3,
    pin: &EndpointTrustPin,
) -> Result<Option<SignatureRejectionV3>, ServiceError> {
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "current endpoint authority state is not fresh",
        )
    })?;
    let now = boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "CLOCK_BOOTTIME is unavailable during endpoint verification",
        )
    })?;
    if now >= request.deadline.absolute_boottime_nanos() {
        return Ok(Some(SignatureRejectionV3::ExpiredDeadline));
    }
    let current = &pin.current_key_authorization;
    if request.revocation_generation
        < current.exact_revocation_generation_high_water
        || request.endpoint_generation
            < pin.exact_endpoint_generation
        || request.trust_checkpoint_id_sha256
            != current.exact_checkpoint_sha256
    {
        return Ok(Some(SignatureRejectionV3::StaleCheckpoint));
    }
    if request.revocation_generation
            > current.exact_revocation_generation_high_water
        || request.revocation_root_sha256
            != current.exact_revocation_root_sha256
        || request.observed_at_boottime_nanos > now
    {
        return Ok(Some(SignatureRejectionV3::RollbackDetected));
    }
    if request.endpoint_role != pin.endpoint_role
        || request.endpoint_process_identity_sha256
            != pin.endpoint_process_identity_sha256
        || request.endpoint_generation
            != pin.exact_endpoint_generation
        || request.signing_key_id != current.signing_key_id
        || request.signing_key_spki_sha256
            != current.signing_key_spki_sha256
    {
        return Ok(Some(SignatureRejectionV3::KeyMismatch));
    }
    let checkpoint = &current.signed_current_key_authorization.payload;
    if request.observed_at_boottime_nanos
            < checkpoint
                .valid_from_boottime
                .absolute_boottime_nanos()
        || request.observed_at_boottime_nanos
            >= checkpoint
                .valid_until_boottime
                .absolute_boottime_nanos()
    {
        return Ok(Some(SignatureRejectionV3::StaleCheckpoint));
    }
    Ok(None)
}

fn classify_cleanup_claim(
    request: &CurrentCleanupAuthorityVerificationV3,
    pin: &EndpointTrustPin,
) -> Result<Option<SignatureRejectionV3>, ServiceError> {
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "current cleanup authority state is not fresh",
        )
    })?;
    let now = boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "CLOCK_BOOTTIME is unavailable during cleanup verification",
        )
    })?;
    if now >= request.deadline.absolute_boottime_nanos() {
        return Ok(Some(SignatureRejectionV3::ExpiredDeadline));
    }
    let current = &pin.current_key_authorization;
    if request.revocation_generation
        < current.exact_revocation_generation_high_water
        || request.trust_checkpoint_id_sha256
            != current.exact_checkpoint_sha256
    {
        return Ok(Some(SignatureRejectionV3::StaleCheckpoint));
    }
    if request.revocation_generation
            > current.exact_revocation_generation_high_water
        || request.revocation_root_sha256
            != current.exact_revocation_root_sha256
    {
        return Ok(Some(SignatureRejectionV3::RollbackDetected));
    }
    if request.authority_role != pin.endpoint_role
        || request.authority_key_id != current.signing_key_id
        || request.authority_key_spki_sha256
            != current.signing_key_spki_sha256
    {
        return Ok(Some(SignatureRejectionV3::KeyMismatch));
    }
    Ok(None)
}

fn current_trust_head(
    subject: CurrentAuthoritySubjectV3,
    pin: &EndpointTrustPin,
    request_deadline: &ProtocolBoottimeDeadline,
) -> Result<CurrentTrustHeadV3, ServiceError> {
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "current-signature subject pin is not current",
        )
    })?;
    request_deadline
        .to_runtime()?
        .require_live()
        .map_err(|_| {
            ServiceError::Invalid(
                "current-signature request deadline expired",
            )
        })?;
    if subject_endpoint_role(&subject) != pin.endpoint_role {
        return Err(ServiceError::Invalid(
            "current-signature subject does not match its configured role",
        ));
    }
    let observed_at_boottime_nanos = boottime_now_nanos()
        .map_err(|_| {
            ServiceError::Invalid(
                "CLOCK_BOOTTIME is unavailable while producing current trust head",
            )
        })?;
    let current = &pin.current_key_authorization;
    let mut head = CurrentTrustHeadV3 {
        api_version:
            POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION.to_string(),
        subject,
        endpoint_process_identity:
            pin.endpoint_process_identity.clone(),
        endpoint_generation: pin.exact_endpoint_generation,
        key_authorization_checkpoint:
            current.signed_current_key_authorization.clone(),
        revocation_generation:
            current.exact_revocation_generation_high_water,
        revocation_root_sha256:
            current.exact_revocation_root_sha256.clone(),
        observed_at_boottime_nanos,
        valid_until_boottime:
            current
                .signed_current_key_authorization
                .payload
                .valid_until_boottime
                .clone(),
        head_sha256: Sha256Digest::compute(&[]),
    };
    head.head_sha256 = current_trust_head_sha256(&head)?;
    head.validate()?;
    Ok(head)
}

fn current_trust_head_sha256(
    head: &CurrentTrustHeadV3,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(&(
        &head.api_version,
        &head.subject,
        &head.endpoint_process_identity,
        head.endpoint_generation,
        &head.key_authorization_checkpoint,
        head.revocation_generation,
        &head.revocation_root_sha256,
        head.observed_at_boottime_nanos,
        &head.valid_until_boottime,
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "current trust head is not canonical",
        )
    })?;
    Ok(hash_domain_frames(
        CURRENT_TRUST_HEAD_DOMAIN,
        &[canonical.as_slice()],
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingCurrentSignatureOperation {
    VerifyEndpoint,
    VerifyCleanup,
    CurrentHead,
}

struct PendingCurrentSignatureRequest {
    operation: PendingCurrentSignatureOperation,
    request_id_sha256: Sha256Digest,
    deadline: ProtocolBoottimeDeadline,
}

struct InstalledRecoveryStoreCurrentHead {
    exact_request_binding_sha256: Sha256Digest,
    current_head: ServiceCurrentHeadBindingV3,
}

/// Nonblocking authority client. Its epoll descriptor aggregates the service
/// socket and the delegated endpoint-trust provider progress descriptor, so
/// the inherited `CurrentEndpointTrustProvider::progress_fd` contract remains
/// correct for both sets of operations.
pub(super) struct TrustedHostNoTeeCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    exchange: NonblockingRequestReplyExchange,
    progress_epoll: OwnedFd,
    _service_progress_socket: OwnedFd,
    current_head: ServiceCurrentHeadBindingV3,
    service_signing_pin: EndpointTrustPin,
    cleanup_authority_role: PolicyCustodyEndpointRole,
    delegated_trust: T,
    pending: Option<PendingCurrentSignatureRequest>,
    recovery_store_current_heads: BTreeMap<
        CurrentAuthoritySubjectKey,
        VecDeque<InstalledRecoveryStoreCurrentHead>,
    >,
    recovery_store_head_high_water:
        BTreeMap<CurrentAuthoritySubjectKey, u64>,
}

impl<T> TrustedHostNoTeeCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    pub(super) fn from_inherited_socket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        current_head: ServiceCurrentHeadBindingV3,
        service_signing_pin: EndpointTrustPin,
        cleanup_authority_role: PolicyCustodyEndpointRole,
        delegated_trust: T,
    ) -> Result<Self, ServiceError> {
        service_signing_pin.validate().map_err(|_| {
            ServiceError::Invalid(
                "current-signature client service pin is not current",
            )
        })?;
        validate_current_head_binding(
            &current_head,
            &service_signing_pin,
            &current_head.signed_current_head.statement.deadline,
        )?;
        let service_progress_socket =
            duplicate_cloexec(socket.as_raw_fd())?;
        let progress_epoll = create_progress_epoll(
            service_progress_socket.as_fd(),
            delegated_trust.progress_fd(),
        )?;
        let peer =
            AuthenticatedInheritedSeqpacket::from_inherited(
                socket,
                expected_peer,
            )?;
        Ok(Self {
            exchange: NonblockingRequestReplyExchange::new(peer),
            progress_epoll,
            _service_progress_socket: service_progress_socket,
            current_head,
            service_signing_pin,
            cleanup_authority_role,
            delegated_trust,
            pending: None,
            recovery_store_current_heads: BTreeMap::new(),
            recovery_store_head_high_water: BTreeMap::new(),
        })
    }

    pub(super) fn peer_credentials(
        &self,
    ) -> super::common::PeerCredentialsV3 {
        self.exchange.peer_credentials()
    }

    /// Installs one checkpoint-authority attestation for one future
    /// recovery-store flight. The exact signed object is consumed once; it is
    /// never rewritten into a different request binding.
    pub(super) fn install_fresh_recovery_store_current_head(
        &mut self,
        exact_request:
            &RecoveryStoreCurrentHeadRequestBindingV3,
        current_head: ServiceCurrentHeadBindingV3,
    ) -> Result<(), ServiceError> {
        if self.pending.is_some() || !self.exchange.is_idle() {
            return Err(ServiceError::Invalid(
                "cannot install a recovery-store current head during a service exchange",
            ));
        }
        exact_request.validate()?;
        exact_request.validate_current_head(&current_head)?;
        let subject_key =
            CurrentAuthoritySubjectKey::from(
                exact_request.subject(),
            );
        let queue = self
            .recovery_store_current_heads
            .entry(subject_key)
            .or_default();
        if queue.iter().any(|candidate| {
            candidate
                .current_head
                .exact_attestation_sha256
                == current_head.exact_attestation_sha256
                || &candidate.exact_request_binding_sha256
                    == exact_request.binding_sha256()
        }) {
            return Err(ServiceError::IdempotencyConflict);
        }
        queue.push_back(InstalledRecoveryStoreCurrentHead {
            exact_request_binding_sha256:
                exact_request.binding_sha256().clone(),
            current_head,
        });
        Ok(())
    }

    /// Replaces the one-flight service head used to authenticate the next
    /// request to this authority. Exact request binding is checked after the
    /// request frame is constructed.
    pub(super) fn install_fresh_service_current_head(
        &mut self,
        current_head: ServiceCurrentHeadBindingV3,
    ) -> Result<(), ServiceError> {
        if self.pending.is_some() || !self.exchange.is_idle() {
            return Err(ServiceError::Invalid(
                "cannot replace the current-signature service head during an exchange",
            ));
        }
        validate_current_head_binding(
            &current_head,
            &self.service_signing_pin,
            &current_head.signed_current_head.statement.deadline,
        )?;
        self.current_head = current_head;
        Ok(())
    }

    pub(super) fn try_current_head_nonblocking(
        &mut self,
        subject: CurrentAuthoritySubjectV3,
        minimum_checkpoint_sequence: u64,
        minimum_revocation_generation: u64,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<CurrentTrustHeadV3>, RecoveryError> {
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let request_id_sha256 = current_head_request_id(
            &subject,
            minimum_checkpoint_sequence,
            minimum_revocation_generation,
            &protocol_deadline,
        )
        .map_err(service_to_recovery)?;
        let request =
            CurrentSignatureAuthorityRequestV3::CurrentHead {
                api_version:
                    POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id_sha256.clone(),
                subject: subject.clone(),
                minimum_checkpoint_sequence,
                minimum_revocation_generation,
                deadline: protocol_deadline.clone(),
            };
        self.ensure_request(
            PendingCurrentSignatureOperation::CurrentHead,
            request_id_sha256.clone(),
            protocol_deadline.clone(),
            &request,
        )?;
        let Some(reply) = self.try_complete(
            PendingCurrentSignatureOperation::CurrentHead,
            &request_id_sha256,
            &protocol_deadline,
        )?
        else {
            return Ok(None);
        };
        match reply {
            CurrentSignatureAuthorityReplyV3::CurrentHead {
                current_head,
            } if current_head.subject == subject => {
                Ok(Some(current_head))
            }
            _ => Err(RecoveryError::Authorization(
                "current-signature head query returned an unexpected outcome",
            )),
        }
    }

    fn ensure_request(
        &mut self,
        operation: PendingCurrentSignatureOperation,
        request_id_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
        request: &CurrentSignatureAuthorityRequestV3,
    ) -> Result<(), RecoveryError> {
        if let Some(pending) = &self.pending {
            if pending.operation != operation
                || pending.request_id_sha256
                    != request_id_sha256
                || pending.deadline != deadline
            {
                return Err(RecoveryError::Conflict(
                    "a different current-signature request is already in flight",
                ));
            }
            return Ok(());
        }
        request.validate().map_err(|_| {
            RecoveryError::Invalid(
                "current-signature request is invalid",
            )
        })?;
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            request_id_sha256.clone(),
            request_idempotency(request)
                .map_err(service_to_recovery)?,
            deadline.clone(),
            self.current_head.clone(),
            request,
        )
        .map_err(service_to_recovery)?;
        validate_exact_current_head_for_request(
            &frame.binding,
            &self.service_signing_pin,
            &request_idempotency(request)
                .map_err(service_to_recovery)?,
        )
        .map_err(service_to_recovery)?;
        self.exchange
            .begin(
                &frame,
                TrustedHostServiceRoleV3::CurrentSignatureAuthority,
                self.service_signing_pin.endpoint_role,
                &[],
                0,
                0,
            )
            .map_err(service_to_recovery)?;
        self.pending = Some(PendingCurrentSignatureRequest {
            operation,
            request_id_sha256,
            deadline,
        });
        Ok(())
    }

    fn try_complete(
        &mut self,
        operation: PendingCurrentSignatureOperation,
        request_id_sha256: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<
        Option<CurrentSignatureAuthorityReplyV3>,
        RecoveryError,
    > {
        drain_progress_epoll(self.progress_epoll.as_raw_fd())
            .map_err(service_to_recovery)?;
        for _ in 0..2 {
            match self.exchange.try_progress() {
                Ok(NonblockingExchangeProgress::Pending) => {}
                Ok(NonblockingExchangeProgress::Complete(
                    completed,
                )) => {
                    let pending = self.pending.take().ok_or(
                        RecoveryError::Invalid(
                            "current-signature exchange completed without pending state",
                        ),
                    )?;
                    if pending.operation != operation
                        || &pending.request_id_sha256
                            != request_id_sha256
                        || &pending.deadline != deadline
                        || !completed.rights.is_empty()
                    {
                        return Err(RecoveryError::Conflict(
                            "current-signature completion changed request identity or returned descriptors",
                        ));
                    }
                    let signed: SignedServiceResponseV3<
                        CurrentSignatureAuthorityReplyV3,
                    > = completed
                        .response
                        .decode_payload()
                        .map_err(service_to_recovery)?;
                    verify_signed_service_response(
                        &signed,
                        request_id_sha256,
                        deadline,
                        &self.service_signing_pin,
                    )
                    .map_err(service_to_recovery)?;
                    signed.response.validate().map_err(|_| {
                        RecoveryError::Authorization(
                            "current-signature reply is invalid",
                        )
                    })?;
                    return Ok(Some(signed.response));
                }
                Err(error) => {
                    self.pending = None;
                    return Err(service_to_recovery(error));
                }
            }
        }
        Ok(None)
    }

    fn require_no_service_exchange(
        &self,
    ) -> Result<(), EndpointClientError> {
        if self.pending.is_some() {
            return Err(EndpointClientError::Invalid(
                "endpoint-trust delegation cannot overlap a current-signature service exchange",
            ));
        }
        Ok(())
    }
}

/// A single-thread, non-reentrant multiplexer for one current-signature
/// connection. Clones share the exact exchange state; `try_borrow_mut`
/// rejects overlapping calls instead of allowing two protocol flights to
/// interleave on the seqpacket.
pub(super) struct SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    inner:
        Rc<RefCell<TrustedHostNoTeeCurrentSignatureAuthorityClient<T>>>,
    progress_fd: Rc<OwnedFd>,
}

impl<T> Clone for SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            progress_fd: Rc::clone(&self.progress_fd),
        }
    }
}

impl<T> SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    pub(super) fn new(
        client: TrustedHostNoTeeCurrentSignatureAuthorityClient<T>,
    ) -> Result<Self, ServiceError> {
        let progress_fd =
            duplicate_cloexec(client.progress_epoll.as_raw_fd())?;
        Ok(Self {
            inner: Rc::new(RefCell::new(client)),
            progress_fd: Rc::new(progress_fd),
        })
    }

    pub(super) fn install_fresh_recovery_store_current_head(
        &self,
        exact_request:
            &RecoveryStoreCurrentHeadRequestBindingV3,
        current_head: ServiceCurrentHeadBindingV3,
    ) -> Result<(), ServiceError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                ServiceError::Invalid(
                    "current-signature shared connection is already executing another bounded exchange",
                )
            })?
            .install_fresh_recovery_store_current_head(
                exact_request,
                current_head,
            )
    }
}

impl<T> VerifiedRecoveryStoreCurrentHeadProvider
    for SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_fd.as_fd()
    }

    fn try_fresh_current_head_nonblocking(
        &mut self,
        exact_request:
            &RecoveryStoreCurrentHeadRequestBindingV3,
    ) -> Result<Option<ServiceCurrentHeadBindingV3>, RecoveryError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                RecoveryError::Authorization(
                    "current-signature shared connection rejected an overlapping recovery-store head exchange",
                )
            })?
            .try_fresh_current_head_nonblocking(exact_request)
    }
}

impl<T> CurrentSignatureAuthority
    for SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn try_verify_current_endpoint_signature_nonblocking(
        &mut self,
        request: CurrentSignatureVerification<'_>,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                RecoveryError::Authorization(
                    "current-signature shared connection rejected an overlapping endpoint verification",
                )
            })?
            .try_verify_current_endpoint_signature_nonblocking(
                request,
                deadline,
            )
    }

    fn try_verify_current_cleanup_authority_nonblocking(
        &mut self,
        request: CurrentCleanupAuthorityVerification<'_>,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                RecoveryError::Authorization(
                    "current-signature shared connection rejected an overlapping cleanup-authority verification",
                )
            })?
            .try_verify_current_cleanup_authority_nonblocking(
                request,
                deadline,
            )
    }
}

impl<T> CurrentEndpointTrustProvider
    for SharedCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_fd.as_fd()
    }

    fn try_current_endpoint_trust_nonblocking(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<EndpointTrustPin>, EndpointClientError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                EndpointClientError::Invalid(
                    "current-signature shared connection rejected an overlapping endpoint-trust exchange",
                )
            })?
            .try_current_endpoint_trust_nonblocking(
                endpoint_role,
                verification_deadline,
            )
    }

    fn try_verify_historical_durable_consume_nonblocking(
        &mut self,
        request: HistoricalDurableConsumeVerification<'_>,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, EndpointClientError> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| {
                EndpointClientError::Invalid(
                    "current-signature shared connection rejected an overlapping historical verification",
                )
            })?
            .try_verify_historical_durable_consume_nonblocking(
                request,
                verification_deadline,
            )
    }
}

impl<T> VerifiedRecoveryStoreCurrentHeadProvider
    for TrustedHostNoTeeCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_epoll.as_fd()
    }

    fn try_fresh_current_head_nonblocking(
        &mut self,
        exact_request:
            &RecoveryStoreCurrentHeadRequestBindingV3,
    ) -> Result<Option<ServiceCurrentHeadBindingV3>, RecoveryError> {
        self.require_no_service_exchange()
            .map_err(endpoint_to_recovery)?;
        drain_progress_epoll(self.progress_epoll.as_raw_fd())
            .map_err(service_to_recovery)?;
        exact_request
            .validate()
            .map_err(service_to_recovery)?;
        let subject_key =
            CurrentAuthoritySubjectKey::from(
                exact_request.subject(),
            );
        let endpoint_role = exact_request.endpoint_role();
        let deadline = exact_request
            .deadline()
            .to_runtime()
            .map_err(|_| {
                RecoveryError::Deadline(
                    "recovery-store current-head request has an invalid BOOTTIME deadline",
                )
            })?;
        deadline.require_live().map_err(|_| {
            RecoveryError::Deadline(
                "recovery-store current-head request crossed its exact BOOTTIME deadline",
            )
        })?;
        let Some(pin) = self
            .delegated_trust
            .try_current_endpoint_trust_nonblocking(
                endpoint_role,
                &deadline,
            )
            .map_err(endpoint_to_recovery)?
        else {
            return Ok(None);
        };
        let installed = self
            .recovery_store_current_heads
            .get_mut(&subject_key)
            .and_then(VecDeque::pop_front)
            .ok_or(RecoveryError::Authorization(
                "no subject-specific one-shot checkpoint-authority current head is installed for the exact recovery-store flight",
            ))?;
        if &installed.exact_request_binding_sha256
            != exact_request.binding_sha256()
        {
            return Err(RecoveryError::Authorization(
                "recovery-store one-shot current head was installed for a different exact request binding",
            ));
        }
        let binding = installed.current_head;
        exact_request
            .validate_current_head(&binding)
            .map_err(service_to_recovery)?;
        validate_current_head_binding(
            &binding,
            &pin,
            exact_request.deadline(),
        )
        .map_err(service_to_recovery)?;
        let issued_at = binding
            .signed_current_head
            .statement
            .issued_at_boottime_nanos;
        if self
            .recovery_store_head_high_water
            .get(&subject_key)
            .is_some_and(|previous| issued_at <= *previous)
        {
            return Err(RecoveryError::Authorization(
                "recovery-store current head replays or rolls back a prior flight",
            ));
        }
        self.recovery_store_head_high_water
            .insert(subject_key, issued_at);
        Ok(Some(binding))
    }
}

impl<T> CurrentEndpointTrustProvider
    for TrustedHostNoTeeCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_epoll.as_fd()
    }

    fn try_current_endpoint_trust_nonblocking(
        &mut self,
        endpoint_role: PolicyCustodyEndpointRole,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<EndpointTrustPin>, EndpointClientError> {
        self.require_no_service_exchange()?;
        drain_progress_epoll(self.progress_epoll.as_raw_fd())
            .map_err(service_to_endpoint)?;
        self.delegated_trust
            .try_current_endpoint_trust_nonblocking(
                endpoint_role,
                verification_deadline,
            )
    }

    fn try_verify_historical_durable_consume_nonblocking(
        &mut self,
        request: HistoricalDurableConsumeVerification<'_>,
        verification_deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, EndpointClientError> {
        self.require_no_service_exchange()?;
        drain_progress_epoll(self.progress_epoll.as_raw_fd())
            .map_err(service_to_endpoint)?;
        self.delegated_trust
            .try_verify_historical_durable_consume_nonblocking(
                request,
                verification_deadline,
            )
    }
}

impl<T> CurrentSignatureAuthority
    for TrustedHostNoTeeCurrentSignatureAuthorityClient<T>
where
    T: CurrentEndpointTrustProvider,
{
    fn try_verify_current_endpoint_signature_nonblocking(
        &mut self,
        request: CurrentSignatureVerification<'_>,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let request_id_sha256 = endpoint_request_id(
            request,
            &protocol_deadline,
        )
        .map_err(service_to_recovery)?;
        let wire =
            CurrentEndpointSignatureVerificationV3 {
                api_version:
                    POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id_sha256.clone(),
                endpoint_role: request.endpoint_role,
                endpoint_process_identity_sha256:
                    request
                        .endpoint_process_identity_sha256
                        .clone(),
                endpoint_generation: request.endpoint_generation,
                signing_key_id: request.signing_key_id.clone(),
                signing_key_spki_sha256:
                    request.signing_key_spki_sha256.clone(),
                trust_checkpoint_id_sha256:
                    request
                        .trust_checkpoint_id_sha256
                        .clone(),
                revocation_generation:
                    request.revocation_generation,
                revocation_root_sha256:
                    request.revocation_root_sha256.clone(),
                signature_domain:
                    request.signature_domain.to_vec(),
                signature_payload:
                    request.signature_payload.to_vec(),
                signature_base64:
                    request.signature_base64.to_string(),
                observed_at_boottime_nanos:
                    request.observed_at_boottime_nanos,
                deadline: protocol_deadline.clone(),
            };
        let envelope =
            CurrentSignatureAuthorityRequestV3::VerifyEndpoint(
                wire.clone(),
            );
        self.ensure_request(
            PendingCurrentSignatureOperation::VerifyEndpoint,
            request_id_sha256.clone(),
            protocol_deadline.clone(),
            &envelope,
        )?;
        let Some(reply) = self.try_complete(
            PendingCurrentSignatureOperation::VerifyEndpoint,
            &request_id_sha256,
            &protocol_deadline,
        )?
        else {
            return Ok(None);
        };
        interpret_endpoint_verification(reply, &wire)
    }

    fn try_verify_current_cleanup_authority_nonblocking(
        &mut self,
        request: CurrentCleanupAuthorityVerification<'_>,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<()>, RecoveryError> {
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let request_id_sha256 = cleanup_request_id(
            self.cleanup_authority_role,
            request,
            &protocol_deadline,
        )
        .map_err(service_to_recovery)?;
        let wire =
            CurrentCleanupAuthorityVerificationV3 {
                api_version:
                    POLICY_CUSTODY_CURRENT_SIGNATURE_WIRE_VERSION
                        .to_string(),
                request_id_sha256: request_id_sha256.clone(),
                authority_role: self.cleanup_authority_role,
                authority_key_id:
                    request.authority_key_id.clone(),
                authority_key_spki_sha256:
                    request.authority_key_spki_sha256.clone(),
                trust_checkpoint_id_sha256:
                    request
                        .trust_checkpoint_id_sha256
                        .clone(),
                revocation_generation:
                    request.revocation_generation,
                revocation_root_sha256:
                    request.revocation_root_sha256.clone(),
                signature_preimage:
                    request.signature_preimage.to_vec(),
                signature_base64:
                    request.signature_base64.to_string(),
                deadline: protocol_deadline.clone(),
            };
        let envelope =
            CurrentSignatureAuthorityRequestV3::VerifyCleanup(
                wire.clone(),
            );
        self.ensure_request(
            PendingCurrentSignatureOperation::VerifyCleanup,
            request_id_sha256.clone(),
            protocol_deadline.clone(),
            &envelope,
        )?;
        let Some(reply) = self.try_complete(
            PendingCurrentSignatureOperation::VerifyCleanup,
            &request_id_sha256,
            &protocol_deadline,
        )?
        else {
            return Ok(None);
        };
        interpret_cleanup_verification(reply, &wire)
    }
}

fn interpret_endpoint_verification(
    reply: CurrentSignatureAuthorityReplyV3,
    request: &CurrentEndpointSignatureVerificationV3,
) -> Result<Option<()>, RecoveryError> {
    match reply {
        CurrentSignatureAuthorityReplyV3::Verified {
            current_head,
        } => {
            require_endpoint_head_matches(
                &current_head,
                request,
            )?;
            Ok(Some(()))
        }
        CurrentSignatureAuthorityReplyV3::Rejected { .. } => {
            Err(RecoveryError::Authorization(
                "current-signature authority rejected stale, revoked, mismatched, or invalid endpoint evidence",
            ))
        }
        CurrentSignatureAuthorityReplyV3::CurrentHead { .. } => {
            Err(RecoveryError::Authorization(
                "current-signature endpoint verification returned a head-only reply",
            ))
        }
    }
}

fn interpret_cleanup_verification(
    reply: CurrentSignatureAuthorityReplyV3,
    request: &CurrentCleanupAuthorityVerificationV3,
) -> Result<Option<()>, RecoveryError> {
    match reply {
        CurrentSignatureAuthorityReplyV3::Verified {
            current_head,
        } => {
            require_cleanup_head_matches(
                &current_head,
                request,
            )?;
            Ok(Some(()))
        }
        CurrentSignatureAuthorityReplyV3::Rejected { .. } => {
            Err(RecoveryError::Authorization(
                "current-signature authority rejected stale, revoked, mismatched, or invalid cleanup evidence",
            ))
        }
        CurrentSignatureAuthorityReplyV3::CurrentHead { .. } => {
            Err(RecoveryError::Authorization(
                "current-signature cleanup verification returned a head-only reply",
            ))
        }
    }
}

fn require_endpoint_head_matches(
    head: &CurrentTrustHeadV3,
    request: &CurrentEndpointSignatureVerificationV3,
) -> Result<(), RecoveryError> {
    head.validate().map_err(|_| {
        RecoveryError::Authorization(
            "current-signature endpoint head is invalid",
        )
    })?;
    if head.subject
            != (CurrentAuthoritySubjectV3::Endpoint {
                endpoint_role: request.endpoint_role,
            })
        || head.endpoint_process_identity.identity_sha256
            != request.endpoint_process_identity_sha256
        || head.endpoint_generation
            != request.endpoint_generation
        || head.key_authorization_checkpoint.checkpoint_sha256
            != request.trust_checkpoint_id_sha256
        || head.revocation_generation
            != request.revocation_generation
        || head.revocation_root_sha256
            != request.revocation_root_sha256
    {
        return Err(RecoveryError::Authorization(
            "verified endpoint reply does not prove the exact caller-claimed current head",
        ));
    }
    Ok(())
}

fn require_cleanup_head_matches(
    head: &CurrentTrustHeadV3,
    request: &CurrentCleanupAuthorityVerificationV3,
) -> Result<(), RecoveryError> {
    head.validate().map_err(|_| {
        RecoveryError::Authorization(
            "current-signature cleanup head is invalid",
        )
    })?;
    if head.subject
            != (CurrentAuthoritySubjectV3::
                CleanupAuthorizationAuthority {
                    authority_role: request.authority_role,
                })
        || head.key_authorization_checkpoint.checkpoint_sha256
            != request.trust_checkpoint_id_sha256
        || head.revocation_generation
            != request.revocation_generation
        || head.revocation_root_sha256
            != request.revocation_root_sha256
        || head
            .key_authorization_checkpoint
            .payload
            .authorized_signing_key_id
            != request.authority_key_id
        || head
            .key_authorization_checkpoint
            .payload
            .authorized_signing_key_spki_sha256
            != request.authority_key_spki_sha256
    {
        return Err(RecoveryError::Authorization(
            "verified cleanup reply does not prove the exact caller-claimed current head",
        ));
    }
    Ok(())
}

fn validate_request_binding(
    frame: &ServiceRequestFrameV3,
    request: &CurrentSignatureAuthorityRequestV3,
) -> Result<(), ServiceError> {
    let (request_id, deadline) = request_metadata(request);
    if request_id != &frame.binding.request_id_sha256
        || deadline != &frame.binding.deadline
        || request_id != &expected_request_id(request)?
        || frame.binding.idempotency_sha256
            != request_idempotency(request)?
    {
        return Err(ServiceError::Invalid(
            "current-signature request body does not match its outer request binding",
        ));
    }
    deadline.to_runtime()?.require_live().map_err(|_| {
        ServiceError::Invalid(
            "current-signature request deadline expired",
        )
    })
}

fn request_metadata(
    request: &CurrentSignatureAuthorityRequestV3,
) -> (&Sha256Digest, &ProtocolBoottimeDeadline) {
    match request {
        CurrentSignatureAuthorityRequestV3::VerifyEndpoint(
            request,
        ) => (&request.request_id_sha256, &request.deadline),
        CurrentSignatureAuthorityRequestV3::VerifyCleanup(
            request,
        ) => (&request.request_id_sha256, &request.deadline),
        CurrentSignatureAuthorityRequestV3::CurrentHead {
            request_id_sha256,
            deadline,
            ..
        } => (request_id_sha256, deadline),
    }
}

fn expected_request_id(
    request: &CurrentSignatureAuthorityRequestV3,
) -> Result<Sha256Digest, ServiceError> {
    match request {
        CurrentSignatureAuthorityRequestV3::VerifyEndpoint(
            request,
        ) => endpoint_wire_request_id(request),
        CurrentSignatureAuthorityRequestV3::VerifyCleanup(
            request,
        ) => cleanup_wire_request_id(request),
        CurrentSignatureAuthorityRequestV3::CurrentHead {
            subject,
            minimum_checkpoint_sequence,
            minimum_revocation_generation,
            deadline,
            ..
        } => current_head_request_id(
            subject,
            *minimum_checkpoint_sequence,
            *minimum_revocation_generation,
            deadline,
        ),
    }
}

fn endpoint_request_id(
    request: CurrentSignatureVerification<'_>,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "verify-endpoint",
        request.endpoint_role,
        request.endpoint_process_identity_sha256,
        request.endpoint_generation,
        request.signing_key_id,
        request.signing_key_spki_sha256,
        request.trust_checkpoint_id_sha256,
        request.revocation_generation,
        request.revocation_root_sha256,
        request.signature_domain,
        request.signature_payload,
        request.signature_base64,
        request.observed_at_boottime_nanos,
        deadline,
    ))
}

fn endpoint_wire_request_id(
    request: &CurrentEndpointSignatureVerificationV3,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "verify-endpoint",
        request.endpoint_role,
        &request.endpoint_process_identity_sha256,
        request.endpoint_generation,
        &request.signing_key_id,
        &request.signing_key_spki_sha256,
        &request.trust_checkpoint_id_sha256,
        request.revocation_generation,
        &request.revocation_root_sha256,
        request.signature_domain.as_slice(),
        request.signature_payload.as_slice(),
        request.signature_base64.as_str(),
        request.observed_at_boottime_nanos,
        &request.deadline,
    ))
}

fn cleanup_request_id(
    authority_role: PolicyCustodyEndpointRole,
    request: CurrentCleanupAuthorityVerification<'_>,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "verify-cleanup",
        authority_role,
        request.authority_key_id,
        request.authority_key_spki_sha256,
        request.trust_checkpoint_id_sha256,
        request.revocation_generation,
        request.revocation_root_sha256,
        request.signature_preimage,
        request.signature_base64,
        deadline,
    ))
}

fn cleanup_wire_request_id(
    request: &CurrentCleanupAuthorityVerificationV3,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "verify-cleanup",
        request.authority_role,
        &request.authority_key_id,
        &request.authority_key_spki_sha256,
        &request.trust_checkpoint_id_sha256,
        request.revocation_generation,
        &request.revocation_root_sha256,
        request.signature_preimage.as_slice(),
        request.signature_base64.as_str(),
        &request.deadline,
    ))
}

fn current_head_request_id(
    subject: &CurrentAuthoritySubjectV3,
    minimum_checkpoint_sequence: u64,
    minimum_revocation_generation: u64,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "current-head",
        subject,
        minimum_checkpoint_sequence,
        minimum_revocation_generation,
        deadline,
    ))
}

fn request_id_digest<T: Serialize>(
    value: &T,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid(
            "current-signature request identity is not canonical",
        )
    })?;
    Ok(hash_domain_frames(
        CURRENT_SIGNATURE_REQUEST_ID_DOMAIN,
        &[canonical.as_slice()],
    ))
}

fn request_idempotency(
    request: &CurrentSignatureAuthorityRequestV3,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(request).map_err(|_| {
        ServiceError::Invalid(
            "current-signature idempotency input is not canonical",
        )
    })?;
    Ok(endpoint_request_sha256(&canonical))
}

fn subject_endpoint_role(
    subject: &CurrentAuthoritySubjectV3,
) -> PolicyCustodyEndpointRole {
    match subject {
        CurrentAuthoritySubjectV3::Endpoint {
            endpoint_role,
        } => *endpoint_role,
        CurrentAuthoritySubjectV3::
            CleanupAuthorizationAuthority {
                authority_role,
            } => *authority_role,
    }
}

fn require_signing_key_matches_pin(
    signing_key: &SigningKey,
    pin: &EndpointTrustPin,
) -> Result<(), ServiceError> {
    let verifying_key = signing_key.verifying_key();
    let spki = verifying_key.to_public_key_der().map_err(|_| {
        ServiceError::Invalid(
            "current-signature signing key cannot be encoded as SPKI",
        )
    })?;
    if verifying_key
            != pin.current_key_authorization.verifying_key
        || Sha256Digest::compute(spki.as_bytes())
            != pin
                .current_key_authorization
                .signing_key_spki_sha256
    {
        return Err(ServiceError::Invalid(
            "current-signature software signing key does not match its current checkpoint",
        ));
    }
    Ok(())
}

fn validate_current_head_binding(
    binding: &ServiceCurrentHeadBindingV3,
    pin: &EndpointTrustPin,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<(), ServiceError> {
    binding.validate(pin.endpoint_role, deadline)?;
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "current-signature service endpoint pin is not current",
        )
    })?;
    let signed = &binding.signed_current_head;
    let statement = &signed.statement;
    let current = &pin.current_key_authorization;
    if statement.checkpoint_sequence
            != current.exact_checkpoint_sequence
        || statement.checkpoint_sha256
            != current.exact_checkpoint_sha256
        || statement.endpoint_generation
            != pin.exact_endpoint_generation
        || statement.revocation_generation_high_water
            != current.exact_revocation_generation_high_water
        || statement.revocation_root_sha256
            != current.exact_revocation_root_sha256
        || signed.authority_key_id
            != current.checkpoint_authority_key_id
        || signed.authority_key_spki_sha256
            != current
                .checkpoint_authority_key_spki_sha256
    {
        return Err(ServiceError::Invalid(
            "current-signature service head is stale or mismatched",
        ));
    }
    verify_preimage_signature(
        &current.checkpoint_authority_verifying_key,
        &signed.authority_signature_preimage()?,
        &signed.authority_signature_base64,
    )
}

fn validate_exact_current_head_for_request(
    binding: &ServiceRequestBindingV3,
    pin: &EndpointTrustPin,
    exact_idempotency_sha256: &Sha256Digest,
) -> Result<(), ServiceError> {
    binding.validate(
        binding.service_role,
        pin.endpoint_role,
    )?;
    validate_current_head_binding(
        &binding.current_head,
        pin,
        &binding.deadline,
    )?;
    let statement =
        &binding.current_head.signed_current_head.statement;
    if statement.request_nonce_sha256
            != binding.request_id_sha256
        || statement.request_sha256
            != binding.idempotency_sha256
        || &binding.idempotency_sha256
            != exact_idempotency_sha256
        || statement.endpoint_role != pin.endpoint_role
        || statement.endpoint_generation
            != pin.exact_endpoint_generation
        || statement.checkpoint_sha256
            != pin
                .current_key_authorization
                .exact_checkpoint_sha256
        || statement.revocation_generation_high_water
            != pin
                .current_key_authorization
                .exact_revocation_generation_high_water
        || statement.revocation_root_sha256
            != pin
                .current_key_authorization
                .exact_revocation_root_sha256
        || statement.deadline != binding.deadline
    {
        return Err(ServiceError::Invalid(
            "current-signature current-head evidence is not bound to the exact request id, payload-derived idempotency digest, role, process checkpoint, generation, revocation head, and deadline",
        ));
    }
    Ok(())
}

fn verify_signed_service_response<T: Serialize>(
    signed: &SignedServiceResponseV3<T>,
    request_id_sha256: &Sha256Digest,
    deadline: &ProtocolBoottimeDeadline,
    pin: &EndpointTrustPin,
) -> Result<(), ServiceError> {
    signed.validate(
        PolicyCustodyServiceRoleV3::CurrentSignatureAuthority,
        request_id_sha256,
        deadline,
    )?;
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "current-signature response service pin is not current",
        )
    })?;
    let signature = &signed.signature;
    let current = &pin.current_key_authorization;
    if signature.endpoint_process_identity
            != pin.endpoint_process_identity
        || signature.endpoint_generation
            != pin.exact_endpoint_generation
        || signature.current_key_authorization_checkpoint_sha256
            != current.exact_checkpoint_sha256
        || signature.revocation_generation
            != current.exact_revocation_generation_high_water
        || signature.revocation_root_sha256
            != current.exact_revocation_root_sha256
        || signature.signing_key_id != current.signing_key_id
        || signature.signing_key_spki_sha256
            != current.signing_key_spki_sha256
    {
        return Err(ServiceError::Invalid(
            "current-signature response did not use the exact current non-revoked service key",
        ));
    }
    let payload = service_signature_payload(signature)?;
    let preimage = domain_separated_signature_preimage(
        pin.endpoint_role.response_signature_domain(),
        &payload,
    )?;
    verify_preimage_signature(
        &current.verifying_key,
        &preimage,
        &signature.signature_base64,
    )
}

fn service_signature_payload(
    signature: &ServiceResponseSignatureV3,
) -> Result<Vec<u8>, ServiceError> {
    canonical_json_bytes(&(
        &signature.api_version,
        signature.service_role,
        &signature.request_id_sha256,
        &signature.response_sha256,
        &signature.endpoint_process_identity,
        signature.endpoint_generation,
        &signature
            .current_key_authorization_checkpoint_sha256,
        signature.revocation_generation,
        &signature.revocation_root_sha256,
        signature.observed_at_boottime_nanos,
        &signature.signing_key_id,
        &signature.signing_key_spki_sha256,
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "service response signature payload is not canonical",
        )
    })
}

fn verify_preimage_signature(
    key: &VerifyingKey,
    preimage: &[u8],
    signature_base64: &str,
) -> Result<(), ServiceError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| {
            ServiceError::Invalid(
                "Ed25519 signature is not canonical base64url",
            )
        })?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes)
        != signature_base64
    {
        return Err(ServiceError::Invalid(
            "Ed25519 signature base64url is noncanonical",
        ));
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| {
            ServiceError::Invalid(
                "Ed25519 signature length is invalid",
            )
        })?;
    key.verify_strict(preimage, &signature).map_err(|_| {
        ServiceError::Invalid(
            "Ed25519 signature verification failed",
        )
    })
}

fn duplicate_cloexec(fd: RawFd) -> Result<OwnedFd, ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "cannot duplicate an invalid descriptor",
        ));
    }
    let duplicated =
        unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(ServiceError::Io(
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn create_progress_epoll(
    service_socket: BorrowedFd<'_>,
    delegated_progress: BorrowedFd<'_>,
) -> Result<OwnedFd, ServiceError> {
    let epoll = unsafe {
        libc::epoll_create1(libc::EPOLL_CLOEXEC)
    };
    if epoll < 0 {
        return Err(ServiceError::Io(
            io::Error::last_os_error(),
        ));
    }
    let epoll = unsafe { OwnedFd::from_raw_fd(epoll) };
    register_progress_fd(
        epoll.as_raw_fd(),
        service_socket,
        1,
        true,
    )?;
    register_progress_fd(
        epoll.as_raw_fd(),
        delegated_progress,
        2,
        false,
    )?;
    Ok(epoll)
}

fn register_progress_fd(
    epoll: RawFd,
    descriptor: BorrowedFd<'_>,
    token: u64,
    writable: bool,
) -> Result<(), ServiceError> {
    if epoll == descriptor.as_raw_fd() {
        return Err(ServiceError::Invalid(
            "current-signature progress epoll cannot monitor itself",
        ));
    }
    // Level triggering is required for a delegated epoll descriptor: an outer
    // edge can otherwise be consumed before the nested provider is drained.
    let mut interests = libc::EPOLLIN | libc::EPOLLERR;
    if writable {
        interests |= libc::EPOLLOUT | libc::EPOLLRDHUP;
    }
    let mut event = libc::epoll_event {
        events: interests as u32,
        u64: token,
    };
    if unsafe {
        libc::epoll_ctl(
            epoll,
            libc::EPOLL_CTL_ADD,
            descriptor.as_raw_fd(),
            &mut event,
        )
    } != 0
    {
        return Err(ServiceError::Io(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn drain_progress_epoll(
    epoll: RawFd,
) -> Result<(), ServiceError> {
    let mut events = [
        libc::epoll_event { events: 0, u64: 0 };
        MAX_PROGRESS_EVENTS
    ];
    loop {
        let count = unsafe {
            libc::epoll_wait(
                epoll,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                0,
            )
        };
        if count >= 0 {
            if count == events.len() as libc::c_int {
                continue;
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(ServiceError::Io(error));
        }
    }
}

fn service_to_recovery(error: ServiceError) -> RecoveryError {
    match error {
        ServiceError::Io(_) | ServiceError::JournalBusy => {
            RecoveryError::Transient(
                "current-signature service is temporarily unavailable",
            )
        }
        ServiceError::IdempotencyConflict => {
            RecoveryError::Conflict(
                "current-signature idempotency key conflicts with an in-flight request",
            )
        }
        ServiceError::Protocol(_)
        | ServiceError::Invalid(_)
        | ServiceError::InvalidOwned(_) => {
            RecoveryError::Authorization(
                "current-signature service rejected an invalid, stale, or unauthenticated exchange",
            )
        }
    }
}

fn endpoint_to_recovery(
    error: EndpointClientError,
) -> RecoveryError {
    match error {
        EndpointClientError::Io(_)
        | EndpointClientError::Boottime(_) => {
            RecoveryError::Transient(
                "current-signature delegated trust provider is temporarily unavailable",
            )
        }
        EndpointClientError::DeadlineExpired => {
            RecoveryError::Deadline(
                "current-signature delegated trust deadline expired",
            )
        }
        EndpointClientError::Protocol(_)
        | EndpointClientError::Invalid(_)
        | EndpointClientError::InvalidOwned(_) => {
            RecoveryError::Authorization(
                "current-signature delegated trust provider rejected stale, rolled-back, or unauthenticated endpoint state",
            )
        }
    }
}

fn service_to_endpoint(
    error: ServiceError,
) -> EndpointClientError {
    match error {
        ServiceError::Io(error) => {
            EndpointClientError::Io(error)
        }
        ServiceError::InvalidOwned(message) => {
            EndpointClientError::InvalidOwned(message)
        }
        ServiceError::Protocol(_)
        | ServiceError::Invalid(_)
        | ServiceError::IdempotencyConflict
        | ServiceError::JournalBusy => {
            EndpointClientError::Invalid(
                "current-signature progress aggregation failed",
            )
        }
    }
}
