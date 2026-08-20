//! TrustedHostNoTee recovery-target authority.
//!
//! The authority is intentionally host-local and software-only. Registration
//! is accepted only over an already authenticated local seqpacket connection,
//! and only when the exact ordered six-descriptor SCM_RIGHTS set still matches
//! the durable watchdog ownership manifest. Queries return duplicates of the
//! retained worker pidfd and operation-cgroup descriptor; they never reopen a
//! PID or cgroup path.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "the TrustedHostNoTee recovery-target authority requires Linux pidfd, statx, kcmp, cgroup-v2, AF_UNIX SOCK_SEQPACKET, and SCM_RIGHTS semantics"
);

use super::common::{
    decode_canonical_frame, AuthenticatedInheritedSeqpacket,
    DurableAppendJournal, ExpectedPeerCredentials,
    NonblockingExchangeProgress,
    NonblockingRequestReplyExchange, ReceivedSeqpacket,
    ServiceCurrentHeadBindingV3, ServiceError,
    ServiceRequestBindingV3, ServiceRequestFrameV3,
    ServiceResponseFrameV3, TrustedHostNoTeeServiceReportV3,
    TrustedHostServiceRoleV3,
};
use super::wire::{
    DescriptorRegistrationV3, PolicyCustodyServiceRoleV3,
    RecoveryTargetBootstrapReplyV3,
    RecoveryTargetBootstrapRequestV3,
    RecoveryTargetExpectedManifestV3,
    RecoveryTargetProviderReplyV3, RecoveryTargetProviderRequestV3,
    RecoveryTargetReadinessSealV3, RecoveryTargetV3,
    RetainedDescriptorIdentitySetV3,
    ServiceResponseSignatureV3, SignedServiceResponseV3,
    MAX_RECOVERY_SCAN_RECORDS,
    POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION,
    POLICY_CUSTODY_SERVICES_WIRE_VERSION,
};
use super::super::boottime::{
    boottime_now_nanos, BoottimeDeadline,
};
use super::super::endpoint_clients::EndpointTrustPin;
use super::super::protocol::{
    domain_separated_signature_preimage, endpoint_request_sha256,
    endpoint_response_sha256, require_nonzero_digest,
    PolicyCustodyEndpointRole, ProtocolBoottimeDeadline,
    WatchdogRegistrationFdRole, WatchdogRetainedFdIdentityV3,
};
use super::super::watchdog_recovery::{
    CleanupTarget, DurableOwnershipRecord, RecoveryError,
    RecoveryTargetProvider,
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
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io;
use std::mem::zeroed;
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};

const SERVICE_RESPONSE_RECEIPT_DOMAIN: &[u8] =
    b"serverware.policyCustodyServiceResponse/v3";
const RECOVERY_TARGET_REQUEST_ID_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTargetRequestId/v3";
const RECOVERY_TARGET_DIGEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTarget/v3";
const REAP_LINEAGE_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTargetReapLineage/v3";
const REAP_LINEAGE_PROOF_DOMAIN: &[u8] =
    b"serverware.policyCustodyRecoveryTargetReapLineageProof/v3";
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAX_PROGRESS_EVENTS: usize = 8;
const MAX_FDINFO_BYTES: usize = 16 * 1024;
const MAX_PROC_STAT_BYTES: usize = 64 * 1024;
const MAX_RECOVERY_TARGET_BOOTSTRAP_RECORDS: usize = 2_050;
const MAX_RECOVERY_TARGET_BOOTSTRAP_BYTES: usize =
    128 * 1024 * 1024;

/// Launcher-signed evidence that the retained parent is the designated
/// subreaper and that the exact supervisor/worker lineage was established
/// before recovery-target readiness. The proof is supplied from durable
/// deployment state and is never synthesized by this serving process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableReapLineageStatementV3 {
    api_version: String,
    ownership_id_sha256: Sha256Digest,
    registration_sha256: Sha256Digest,
    ownership_ack_envelope_sha256: Sha256Digest,
    parent: super::super::protocol::WatchdogProcessIdentityV3,
    supervisor: super::super::protocol::WatchdogProcessIdentityV3,
    worker: super::super::protocol::WatchdogProcessIdentityV3,
    fd_manifest_sha256: Sha256Digest,
    reaper_pid: libc::pid_t,
    reaper_is_subreaper: bool,
    supervisor_parent_pid: libc::pid_t,
    worker_parent_pid: libc::pid_t,
    observed_at_boottime_nanos: u64,
    valid_until_boottime: ProtocolBoottimeDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SignedDurableReapLineageProofV3 {
    statement: DurableReapLineageStatementV3,
    authority_key_id: Sha256Digest,
    authority_key_spki_sha256: Sha256Digest,
    authority_signature_base64: String,
    proof_sha256: Sha256Digest,
}

impl SignedDurableReapLineageProofV3 {
    fn signature_payload(&self) -> Result<Vec<u8>, ServiceError> {
        canonical_json_bytes(&(
            &self.statement,
            &self.authority_key_id,
            &self.authority_key_spki_sha256,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "durable reap-lineage proof is not canonical",
            )
        })
    }

    fn expected_proof_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        Ok(hash_domain_frames(
            REAP_LINEAGE_PROOF_DOMAIN,
            &[
                self.signature_payload()?.as_slice(),
                self.authority_signature_base64.as_bytes(),
            ],
        ))
    }

    fn verify_authority(
        &self,
        authority_key_id: &Sha256Digest,
        authority_key_spki_sha256: &Sha256Digest,
        authority_verifying_key: &VerifyingKey,
    ) -> Result<(), ServiceError> {
        self.statement.parent.validate()?;
        self.statement.supervisor.validate()?;
        self.statement.worker.validate()?;
        require_nonzero_digest(
            "reapLineage.ownershipIdSha256",
            &self.statement.ownership_id_sha256,
        )?;
        require_nonzero_digest(
            "reapLineage.registrationSha256",
            &self.statement.registration_sha256,
        )?;
        require_nonzero_digest(
            "reapLineage.ownershipAckEnvelopeSha256",
            &self.statement.ownership_ack_envelope_sha256,
        )?;
        require_nonzero_digest(
            "reapLineage.fdManifestSha256",
            &self.statement.fd_manifest_sha256,
        )?;
        require_nonzero_digest(
            "reapLineage.authorityKeyId",
            &self.authority_key_id,
        )?;
        require_nonzero_digest(
            "reapLineage.authorityKeySpkiSha256",
            &self.authority_key_spki_sha256,
        )?;
        require_nonzero_digest(
            "reapLineage.proofSha256",
            &self.proof_sha256,
        )?;
        if self.statement.api_version
                != POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION
            || self.authority_key_id != *authority_key_id
            || self.authority_key_spki_sha256
                != *authority_key_spki_sha256
            || self.proof_sha256 != self.expected_proof_sha256()?
            || !self.statement.reaper_is_subreaper
            || self.statement.reaper_pid <= 1
            || self.statement.supervisor_parent_pid <= 1
            || self.statement.worker_parent_pid <= 1
            || self.statement.observed_at_boottime_nanos == 0
            || self.statement.observed_at_boottime_nanos
                >= self
                    .statement
                    .valid_until_boottime
                    .absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "durable reap-lineage proof is incomplete, expired, or signed by the wrong authority",
            ));
        }
        self.statement
            .valid_until_boottime
            .to_runtime()?
            .require_live()
            .map_err(|_| {
                ServiceError::Invalid(
                    "durable reap-lineage proof expired before service readiness",
                )
            })?;
        if self.statement.observed_at_boottime_nanos
            > boottime_now_nanos().map_err(|_| {
                ServiceError::Invalid(
                    "CLOCK_BOOTTIME is unavailable while validating reap lineage",
                )
            })?
        {
            return Err(ServiceError::Invalid(
                "durable reap-lineage proof was issued in the future",
            ));
        }
        let preimage = domain_separated_signature_preimage(
            REAP_LINEAGE_SIGNATURE_DOMAIN,
            &self.signature_payload()?,
        )?;
        verify_preimage_signature(
            authority_verifying_key,
            &preimage,
            &self.authority_signature_base64,
        )
    }

    fn validate_against_registration(
        &self,
        registration: &DescriptorRegistrationV3,
    ) -> Result<(), ServiceError> {
        let statement = &self.statement;
        let exact = &registration.registration;
        if statement.ownership_id_sha256
                != registration.ownership_id_sha256
            || statement.registration_sha256
                != exact.registration_sha256
            || statement.ownership_ack_envelope_sha256
                != registration.signed_ownership_ack.envelope_sha256
            || statement.parent != exact.parent
            || statement.supervisor != exact.supervisor
            || statement.worker != exact.worker
            || statement.fd_manifest_sha256
                != exact.fd_manifest_sha256
            || statement.reaper_pid != exact.parent.pid
            || statement.supervisor_parent_pid
                != exact.parent.pid
            || statement.worker_parent_pid
                != exact.supervisor.pid
            || statement.observed_at_boottime_nanos
                < registration.registered_at_boottime_nanos
            || statement.valid_until_boottime
                != exact.cleanup_deadline
        {
            return Err(ServiceError::Invalid(
                "durable reap-lineage proof does not bind the exact owner, signed registration, retained descriptors, parent/subreaper, supervisor, worker, and cleanup deadline",
            ));
        }
        Ok(())
    }
}

struct RecoveryTargetServiceSigner {
    pin: EndpointTrustPin,
    signing_key: SigningKey,
    report: TrustedHostNoTeeServiceReportV3,
}

impl RecoveryTargetServiceSigner {
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
                "recovery-target service signing pin is not current",
            )
        })?;
        require_signing_key_matches_pin(&signing_key, &pin)?;
        let report = TrustedHostNoTeeServiceReportV3::new(
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
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

    fn sign_response<T: Serialize + Clone>(
        &self,
        request_id_sha256: &Sha256Digest,
        response: T,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<SignedServiceResponseV3<T>, ServiceError> {
        self.pin.validate().map_err(|_| {
            ServiceError::Invalid(
                "recovery-target service signing pin expired",
            )
        })?;
        let runtime_deadline = deadline.to_runtime()?;
        runtime_deadline.require_live().map_err(|_| {
            ServiceError::Invalid(
                "recovery-target response deadline expired",
            )
        })?;
        let observed_at_boottime_nanos = boottime_now_nanos()
            .map_err(|_| {
                ServiceError::Invalid(
                    "CLOCK_BOOTTIME is unavailable while signing recovery-target response",
                )
            })?;
        if observed_at_boottime_nanos
            >= deadline.absolute_boottime_nanos()
        {
            return Err(ServiceError::Invalid(
                "recovery-target response crossed its deadline",
            ));
        }
        let exact_canonical_response_bytes =
            canonical_json_bytes(&response).map_err(|_| {
                ServiceError::Invalid(
                    "recovery-target response is not canonical",
                )
            })?;
        let current = &self.pin.current_key_authorization;
        let mut signature = ServiceResponseSignatureV3 {
            api_version:
                POLICY_CUSTODY_SERVICES_WIRE_VERSION.to_string(),
            service_role:
                PolicyCustodyServiceRoleV3::RecoveryTargetProvider,
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
        signature.receipt_sha256 = service_receipt_sha256(
            &signature_payload,
            &signature.signature_base64,
        );
        let exact_signature_envelope_bytes =
            canonical_json_bytes(&signature).map_err(|_| {
                ServiceError::Invalid(
                    "recovery-target service signature is not canonical",
                )
            })?;
        let signed = SignedServiceResponseV3 {
            response,
            exact_canonical_response_bytes,
            signature,
            exact_signature_envelope_bytes,
        };
        signed.validate(
            PolicyCustodyServiceRoleV3::RecoveryTargetProvider,
            request_id_sha256,
            deadline,
        )?;
        Ok(signed)
    }
}

struct RegisteredRecoveryTarget {
    registration: DescriptorRegistrationV3,
    reap_lineage_proof_sha256: Sha256Digest,
    retained: [OwnedFd; 6],
}

impl RegisteredRecoveryTarget {
    fn target(&self) -> Result<RecoveryTargetV3, ServiceError> {
        let registration = &self.registration;
        let mut target = RecoveryTargetV3 {
            api_version:
                POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION.to_string(),
            ownership_id_sha256:
                registration.ownership_id_sha256.clone(),
            operation_id_sha256:
                registration.registration.operation_id_sha256.clone(),
            durable_request_sha256:
                registration
                    .registration
                    .durable_request_sha256
                    .clone(),
            termination_fence_sha256:
                registration.registration.fence_token_sha256.clone(),
            worker: registration.registration.worker.clone(),
            cgroup: registration.registration.cgroup.clone(),
            retained_descriptors:
                registration.retained_descriptors.clone(),
            target_sha256: Sha256Digest::compute(&[]),
        };
        target.target_sha256 = recovery_target_sha256(&target)?;
        target.validate()?;
        Ok(target)
    }

    fn duplicate_query_rights(
        &self,
    ) -> Result<[OwnedFd; 2], ServiceError> {
        let worker = duplicate_cloexec(
            self.retained[2].as_raw_fd(),
        )?;
        let cgroup = duplicate_cloexec(
            self.retained[3].as_raw_fd(),
        )?;
        verify_returned_target_descriptors(
            worker.as_fd(),
            cgroup.as_fd(),
            &self.registration.retained_descriptors,
        )?;
        Ok([worker, cgroup])
    }
}

/// A response prepared by the role handler for the shared nonblocking serving
/// loop. The loop serializes `frame` and transfers exactly `rights`.
pub(super) struct PreparedRecoveryTargetResponse {
    pub(super) frame: ServiceResponseFrameV3,
    pub(super) rights: Vec<OwnedFd>,
}

/// Host-local role handler. `AuthenticatedInheritedSeqpacket` is required as a
/// capability proving that the serving loop already pinned `SO_PEERCRED`.
pub(super) struct TrustedHostNoTeeRecoveryTargetProviderServer {
    signer: RecoveryTargetServiceSigner,
    maximum_registrations: usize,
    operation_generation: u64,
    shared_configuration_sha256: Sha256Digest,
    journal: Option<DurableAppendJournal>,
    expected_manifest: Option<RecoveryTargetExpectedManifestV3>,
    readiness_seal: Option<RecoveryTargetReadinessSealV3>,
    reap_lineage_proofs: BTreeMap<
        Sha256Digest,
        SignedDurableReapLineageProofV3,
    >,
    registrations:
        BTreeMap<Sha256Digest, RegisteredRecoveryTarget>,
}

impl TrustedHostNoTeeRecoveryTargetProviderServer {
    pub(super) fn new(
        signing_pin: EndpointTrustPin,
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
        deployment_configuration_sha256: Sha256Digest,
        maximum_registrations: usize,
        lineage_authority_key_id: Sha256Digest,
        lineage_authority_key_spki_sha256: Sha256Digest,
        lineage_authority_verifying_key: VerifyingKey,
        durable_reap_lineage_proofs:
            Vec<SignedDurableReapLineageProofV3>,
    ) -> Result<Self, ServiceError> {
        Self::new_with_generation(
            signing_pin,
            signing_key,
            signing_credential_sha256,
            operation_generation,
            service_restart_epoch,
            service_invocation_id_sha256,
            readiness_epoch,
            durability_worker_queue_depth,
            maximum_durability_worker_nanos,
            authority_history_manifest_sha256,
            production_dispatch_protocol_set_sha256,
            shared_configuration_sha256,
            deployment_configuration_sha256.clone(),
            deployment_configuration_sha256,
            maximum_registrations,
            lineage_authority_key_id,
            lineage_authority_key_spki_sha256,
            lineage_authority_verifying_key,
            durable_reap_lineage_proofs,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_generation(
        signing_pin: EndpointTrustPin,
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
        maximum_registrations: usize,
        lineage_authority_key_id: Sha256Digest,
        lineage_authority_key_spki_sha256: Sha256Digest,
        lineage_authority_verifying_key: VerifyingKey,
        durable_reap_lineage_proofs:
            Vec<SignedDurableReapLineageProofV3>,
    ) -> Result<Self, ServiceError> {
        if maximum_registrations == 0
            || maximum_registrations
                > MAX_RECOVERY_SCAN_RECORDS
        {
            return Err(ServiceError::Invalid(
                "recovery-target registration bound must be nonzero and within the protocol hard limit",
            ));
        }
        require_nonzero_digest(
            "reapLineage.authorityKeyId",
            &lineage_authority_key_id,
        )?;
        require_nonzero_digest(
            "reapLineage.authorityKeySpkiSha256",
            &lineage_authority_key_spki_sha256,
        )?;
        if lineage_authority_key_spki_sha256
            == signing_pin
                .current_key_authorization
                .signing_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "reap-lineage authority must be independent of the recovery-target service signer",
            ));
        }
        let lineage_spki = lineage_authority_verifying_key
            .to_public_key_der()
            .map_err(|_| {
                ServiceError::Invalid(
                    "reap-lineage authority key cannot be encoded as SPKI",
                )
            })?;
        if Sha256Digest::compute(lineage_spki.as_bytes())
            != lineage_authority_key_spki_sha256
        {
            return Err(ServiceError::Invalid(
                "reap-lineage authority key does not match its SPKI pin",
            ));
        }
        let mut reap_lineage_proofs = BTreeMap::new();
        for proof in durable_reap_lineage_proofs {
            proof.verify_authority(
                &lineage_authority_key_id,
                &lineage_authority_key_spki_sha256,
                &lineage_authority_verifying_key,
            )?;
            let ownership_id =
                proof.statement.ownership_id_sha256.clone();
            if reap_lineage_proofs
                .insert(ownership_id, proof)
                .is_some()
            {
                return Err(ServiceError::Invalid(
                    "duplicate durable reap-lineage proof",
                ));
            }
        }
        Ok(Self {
            signer: RecoveryTargetServiceSigner::new(
                signing_pin,
                signing_key,
                signing_credential_sha256,
                operation_generation,
                service_restart_epoch,
                service_invocation_id_sha256,
                readiness_epoch,
                durability_worker_queue_depth,
                maximum_durability_worker_nanos,
                authority_history_manifest_sha256,
                production_dispatch_protocol_set_sha256,
                shared_configuration_sha256.clone(),
                deployment_generation_sha256,
                deployment_configuration_sha256,
            )?,
            maximum_registrations,
            operation_generation,
            shared_configuration_sha256,
            journal: None,
            expected_manifest: None,
            readiness_seal: None,
            reap_lineage_proofs,
            registrations: BTreeMap::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_recovered_journal(
        journal_directory: OwnedFd,
        operation_generation: u64,
        service_restart_epoch: u64,
        service_invocation_id_sha256: Sha256Digest,
        readiness_epoch: u64,
        durability_worker_queue_depth: u16,
        maximum_durability_worker_nanos: u64,
        authority_history_manifest_sha256: Sha256Digest,
        production_dispatch_protocol_set_sha256: Sha256Digest,
        shared_configuration_sha256: Sha256Digest,
        signing_pin: EndpointTrustPin,
        signing_key: SigningKey,
        signing_credential_sha256: Sha256Digest,
        deployment_generation_sha256: Sha256Digest,
        deployment_configuration_sha256: Sha256Digest,
        maximum_registrations: usize,
        lineage_authority_key_id: Sha256Digest,
        lineage_authority_key_spki_sha256: Sha256Digest,
        lineage_authority_verifying_key: VerifyingKey,
        durable_reap_lineage_proofs:
            Vec<SignedDurableReapLineageProofV3>,
    ) -> Result<Self, ServiceError> {
        if operation_generation == 0 {
            return Err(ServiceError::Invalid(
                "recovery-target operation generation must be nonzero",
            ));
        }
        require_nonzero_digest(
            "recoveryTarget.sharedConfigurationSha256",
            &shared_configuration_sha256,
        )?;
        let mut server = Self::new_with_generation(
            signing_pin,
            signing_key,
            signing_credential_sha256,
            operation_generation,
            service_restart_epoch,
            service_invocation_id_sha256,
            readiness_epoch,
            durability_worker_queue_depth,
            maximum_durability_worker_nanos,
            authority_history_manifest_sha256,
            production_dispatch_protocol_set_sha256,
            shared_configuration_sha256.clone(),
            deployment_generation_sha256,
            deployment_configuration_sha256,
            maximum_registrations,
            lineage_authority_key_id,
            lineage_authority_key_spki_sha256,
            lineage_authority_verifying_key,
            durable_reap_lineage_proofs,
        )?;
        let mut journal = DurableAppendJournal::from_directory(
            journal_directory,
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            super::common::MAX_SERVICE_FRAME_BYTES,
        )?;
        let chain = journal.verified_complete_chain(
            MAX_RECOVERY_TARGET_BOOTSTRAP_RECORDS,
            MAX_RECOVERY_TARGET_BOOTSTRAP_BYTES,
        )?;
        let mut recovered_registration_ordinals =
            BTreeSet::new();
        let mut recovered_manifest_is_sealed = false;
        let mut recovered_reattachment_epochs =
            BTreeSet::new();
        for record in chain.records {
            let request: RecoveryTargetBootstrapRequestV3 =
                decode_canonical_frame(&record.exact_request_bytes)?;
            let reply: RecoveryTargetBootstrapReplyV3 =
                decode_canonical_frame(&record.exact_response_bytes)?;
            match (request, reply) {
                (
                    RecoveryTargetBootstrapRequestV3::
                        InstallManifest { manifest },
                    RecoveryTargetBootstrapReplyV3::
                        ManifestInstalled {
                            manifest_sha256,
                        },
                ) => {
                    manifest.validate()?;
                    if manifest.operation_generation
                            != operation_generation
                        || manifest.shared_configuration_sha256
                            != shared_configuration_sha256
                        || manifest.service_configuration_sha256
                            != server
                                .signer
                                .report()
                                .deployment_configuration_sha256
                        || manifest.manifest_sha256
                            != manifest_sha256
                        || manifest.ordered_registrations.len()
                            > maximum_registrations
                    {
                        return Err(ServiceError::Invalid(
                            "recovery-target recovered manifest changed generation, configuration, digest, or bound",
                        ));
                    }
                    if let Some(existing) =
                        server.expected_manifest.as_ref()
                    {
                        if existing != &manifest {
                            if !recovered_manifest_is_sealed {
                                return Err(ServiceError::Invalid(
                                    "recovery-target journal replaces an unsealed manifest",
                                ));
                            }
                            recovered_registration_ordinals.clear();
                            recovered_manifest_is_sealed = false;
                        }
                    }
                    server.expected_manifest =
                        Some(manifest);
                }
                (
                    RecoveryTargetBootstrapRequestV3::Register {
                        manifest_sha256,
                        ordinal,
                        registration,
                    },
                    RecoveryTargetBootstrapReplyV3::Registered {
                        manifest_sha256: reply_manifest,
                        ordinal: reply_ordinal,
                        ownership_id_sha256,
                        registration_sha256,
                    },
                ) => {
                    let manifest = server
                        .expected_manifest
                        .as_ref()
                        .ok_or(ServiceError::Invalid(
                            "recovery-target journal registers before its manifest",
                        ))?;
                    if recovered_manifest_is_sealed {
                        return Err(ServiceError::Invalid(
                            "recovery-target journal registers after sealing the current manifest",
                        ));
                    }
                    let index = usize::from(ordinal)
                        .checked_sub(1)
                        .ok_or(ServiceError::Invalid(
                            "recovery-target journal registration ordinal is zero",
                        ))?;
                    let expected_ordinal =
                        u16::try_from(
                            recovered_registration_ordinals
                                .len()
                                .checked_add(1)
                                .ok_or(ServiceError::Invalid(
                                    "recovery-target recovered registration count overflowed",
                                ))?,
                        )
                        .map_err(|_| {
                            ServiceError::Invalid(
                                "recovery-target recovered registration ordinal is not representable",
                            )
                        })?;
                    if manifest_sha256 != manifest.manifest_sha256
                        || reply_manifest != manifest_sha256
                        || reply_ordinal != ordinal
                        || ordinal != expected_ordinal
                        || !recovered_registration_ordinals
                            .insert(ordinal)
                        || manifest.ordered_registrations.get(index)
                            != Some(&registration)
                        || ownership_id_sha256
                            != registration.ownership_id_sha256
                        || registration_sha256
                            != registration
                                .registration
                                .registration_sha256
                    {
                        return Err(ServiceError::Invalid(
                            "recovery-target recovered registration does not match its exact manifest ordinal",
                        ));
                    }
                }
                (
                    RecoveryTargetBootstrapRequestV3::Seal {
                        manifest_sha256,
                        reattachment_epoch_sha256,
                    },
                    RecoveryTargetBootstrapReplyV3::Sealed {
                        seal,
                    },
                ) => {
                    let manifest = server
                        .expected_manifest
                        .as_ref()
                        .ok_or(ServiceError::Invalid(
                            "recovery-target journal seals before its manifest",
                        ))?;
                    if manifest_sha256 != manifest.manifest_sha256 {
                        return Err(ServiceError::Invalid(
                            "recovery-target recovered seal changed its manifest",
                        ));
                    }
                    if manifest.ordered_registrations.is_empty()
                        || recovered_registration_ordinals.len()
                            != manifest.ordered_registrations.len()
                        || seal.reattachment_epoch_sha256
                            != reattachment_epoch_sha256
                        || record
                            .previous_head_sha256
                            .as_ref()
                            != Some(
                                &seal
                                    .journal_head_before_seal_sha256,
                            )
                        || !recovered_reattachment_epochs
                            .insert(
                                reattachment_epoch_sha256,
                            )
                    {
                        return Err(ServiceError::Invalid(
                            "recovery-target journal seal does not follow the complete exact registrations, predecessor head, and fresh reattachment epoch",
                        ));
                    }
                    seal.validate_against(manifest)?;
                    server.readiness_seal = Some(seal);
                    recovered_manifest_is_sealed = true;
                }
                _ => {
                    return Err(ServiceError::Invalid(
                        "recovery-target journal bootstrap request and response operations differ",
                    ))
                }
            }
        }
        server.operation_generation = operation_generation;
        server.shared_configuration_sha256 =
            shared_configuration_sha256;
        server.journal = Some(journal);
        // A recovered seal never restores process-local descriptors.
        server.readiness_seal = None;
        Ok(server)
    }

    pub(super) fn handle_authenticated_bootstrap_packet(
        &mut self,
        authenticated_peer: &AuthenticatedInheritedSeqpacket,
        packet: ReceivedSeqpacket,
    ) -> Result<Vec<u8>, ServiceError> {
        if authenticated_peer.peer_credentials().pid <= 0
            || self.journal.is_none()
            || self.readiness_seal.is_some()
        {
            return Err(ServiceError::Invalid(
                "recovery-target bootstrap is unavailable or already sealed",
            ));
        }
        let request: RecoveryTargetBootstrapRequestV3 =
            decode_canonical_frame(&packet.frame)?;
        let reply = match &request {
            RecoveryTargetBootstrapRequestV3::InstallManifest {
                manifest,
            } => {
                if !packet.rights.is_empty() {
                    return Err(ServiceError::Invalid(
                        "recovery-target manifest bootstrap must not carry SCM_RIGHTS",
                    ));
                }
                manifest.validate()?;
                if manifest.operation_generation
                        != self.operation_generation
                    || manifest.shared_configuration_sha256
                        != self.shared_configuration_sha256
                    || manifest.service_configuration_sha256
                        != self
                            .signer
                            .report()
                            .deployment_configuration_sha256
                    || manifest.ordered_registrations.len()
                        > self.maximum_registrations
                {
                    return Err(ServiceError::Invalid(
                        "recovery-target bootstrap manifest changed generation, configuration, or registration bound",
                    ));
                }
                if self.expected_manifest.as_ref().is_some_and(
                    |existing| existing != manifest,
                ) {
                    return Err(ServiceError::IdempotencyConflict);
                }
                self.expected_manifest = Some(manifest.clone());
                RecoveryTargetBootstrapReplyV3::ManifestInstalled {
                    manifest_sha256:
                        manifest.manifest_sha256.clone(),
                }
            }
            RecoveryTargetBootstrapRequestV3::Register {
                manifest_sha256,
                ordinal,
                registration,
            } => {
                if packet.rights.len() != 6 {
                    return Err(ServiceError::Invalid(
                        "recovery-target bootstrap registration requires exactly six SCM_RIGHTS descriptors",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "recovery-target bootstrap registration arrived before its manifest",
                    ))?;
                let index = usize::from(*ordinal)
                    .checked_sub(1)
                    .ok_or(ServiceError::Invalid(
                        "recovery-target bootstrap ordinal must be positive",
                    ))?;
                if manifest_sha256 != &manifest.manifest_sha256
                    || index != self.registrations.len()
                    || manifest.ordered_registrations.get(index)
                        != Some(registration)
                {
                    return Err(ServiceError::Invalid(
                        "recovery-target bootstrap registration is out of order or differs from the exact manifest",
                    ));
                }
                let (registered, returned) =
                    self.register(
                        registration.clone(),
                        packet.rights,
                    )?;
                if !returned.is_empty()
                    || !matches!(
                        registered,
                        RecoveryTargetProviderReplyV3::Register {
                            authoritative
                        } if authoritative == *registration
                    )
                {
                    return Err(ServiceError::Invalid(
                        "recovery-target bootstrap registration did not retain the exact descriptor set",
                    ));
                }
                RecoveryTargetBootstrapReplyV3::Registered {
                    manifest_sha256: manifest_sha256.clone(),
                    ordinal: *ordinal,
                    ownership_id_sha256:
                        registration.ownership_id_sha256.clone(),
                    registration_sha256: registration
                        .registration
                        .registration_sha256
                        .clone(),
                }
            }
            RecoveryTargetBootstrapRequestV3::Seal {
                manifest_sha256,
                reattachment_epoch_sha256,
            } => {
                if !packet.rights.is_empty() {
                    return Err(ServiceError::Invalid(
                        "recovery-target bootstrap seal must not carry SCM_RIGHTS",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "recovery-target bootstrap seal arrived before its manifest",
                    ))?;
                if manifest_sha256 != &manifest.manifest_sha256
                    || reattachment_epoch_sha256
                        == &Sha256Digest::compute(&[])
                    || manifest.ordered_registrations.is_empty()
                    || self.registrations.len()
                        != manifest.ordered_registrations.len()
                {
                    return Err(ServiceError::Invalid(
                        "recovery-target cannot seal an empty or incomplete current-process registration set",
                    ));
                }
                for registration in &manifest.ordered_registrations {
                    let observed = self
                        .registrations
                        .get(&registration.ownership_id_sha256)
                        .ok_or(ServiceError::Invalid(
                            "recovery-target current process lacks an expected registration",
                        ))?;
                    if observed.registration != *registration {
                        return Err(ServiceError::Invalid(
                            "recovery-target current-process registration changed exact descriptor identities",
                        ));
                    }
                }
                let journal_head = self
                    .journal
                    .as_ref()
                    .and_then(DurableAppendJournal::current_head_sha256)
                    .cloned()
                    .ok_or(ServiceError::Invalid(
                        "recovery-target cannot seal before a durable manifest head exists",
                    ))?;
                let mut seal = RecoveryTargetReadinessSealV3 {
                    api_version:
                        POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION
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
                    ordered_ownership_ids: manifest
                        .ordered_registrations
                        .iter()
                        .map(|registration| {
                            registration
                                .ownership_id_sha256
                                .clone()
                        })
                        .collect(),
                    ordered_registration_sha256: manifest
                        .ordered_registrations
                        .iter()
                        .map(|registration| {
                            registration
                                .registration
                                .registration_sha256
                                .clone()
                        })
                        .collect(),
                    journal_head_before_seal_sha256: journal_head,
                    seal_sha256: Sha256Digest::compute(&[]),
                };
                seal.seal_sha256 =
                    seal.expected_seal_sha256()?;
                seal.validate_against(manifest)?;
                RecoveryTargetBootstrapReplyV3::Sealed {
                    seal,
                }
            }
        };
        let exact_reply =
            super::common::encode_canonical_frame(&reply)?;
        let idempotency = Sha256Digest::compute(&packet.frame);
        let persisted = self
            .journal
            .as_mut()
            .ok_or(ServiceError::Invalid(
                "recovery-target bootstrap journal disappeared",
            ))?
            .append_exact_exchange(
                idempotency,
                &packet.frame,
                &exact_reply,
            )?
            .exact_response_bytes()
            .to_vec();
        if persisted != exact_reply {
            return Err(ServiceError::IdempotencyConflict);
        }
        if let RecoveryTargetBootstrapReplyV3::Sealed { seal } =
            reply
        {
            self.readiness_seal = Some(seal);
        }
        Ok(persisted)
    }

    pub(super) fn bootstrap_is_sealed(&self) -> bool {
        self.readiness_seal.is_some()
            && self.expected_manifest.as_ref().is_some_and(
                |manifest| {
                    !manifest.ordered_registrations.is_empty()
                        && self.registrations.len()
                            == manifest.ordered_registrations.len()
                },
            )
    }

    pub(super) fn readiness_seal(
        &self,
    ) -> Result<&RecoveryTargetReadinessSealV3, ServiceError> {
        if !self.bootstrap_is_sealed() {
            return Err(ServiceError::Invalid(
                "recovery-target readiness is not durably sealed for the current process",
            ));
        }
        self.readiness_seal.as_ref().ok_or(ServiceError::Invalid(
            "recovery-target readiness seal is absent",
        ))
    }

    pub(super) fn trusted_host_report(
        &self,
    ) -> &TrustedHostNoTeeServiceReportV3 {
        self.signer.report()
    }

    pub(super) fn handle_authenticated_packet(
        &mut self,
        authenticated_peer: &AuthenticatedInheritedSeqpacket,
        packet: ReceivedSeqpacket,
    ) -> Result<PreparedRecoveryTargetResponse, ServiceError> {
        if !self.bootstrap_is_sealed() {
            return Err(ServiceError::Invalid(
                "recovery-target normal protocol is unavailable before durable bootstrap readiness",
            ));
        }
        let credentials = authenticated_peer.peer_credentials();
        if credentials.pid <= 0 {
            return Err(ServiceError::Invalid(
                "recovery-target peer authentication is incomplete",
            ));
        }
        let frame: ServiceRequestFrameV3 =
            decode_canonical_frame(&packet.frame)?;
        frame.validate(
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            self.signer.endpoint_role(),
        )?;
        let request: RecoveryTargetProviderRequestV3 =
            frame.decode_payload()?;
        request.validate()?;
        validate_request_binding(&frame, &request)?;
        validate_exact_current_head_for_request(
            &frame.binding,
            &self.signer.pin,
            &request_idempotency(&request)?,
        )?;

        let (reply, rights) = match request {
            RecoveryTargetProviderRequestV3::Register {
                registration,
                ..
            } => {
                if packet.rights.len() != 6 {
                    return Err(ServiceError::Invalid(
                        "recovery-target registration requires exactly six SCM_RIGHTS descriptors",
                    ));
                }
                let manifest = self
                    .expected_manifest
                    .as_ref()
                    .ok_or(ServiceError::Invalid(
                        "recovery-target runtime registration lacks a sealed manifest",
                    ))?;
                if !manifest
                    .ordered_registrations
                    .iter()
                    .any(|expected| expected == &registration)
                {
                    return Err(ServiceError::Invalid(
                        "recovery-target runtime registration cannot extend the durably sealed manifest",
                    ));
                }
                self.register(registration, packet.rights)?
            }
            RecoveryTargetProviderRequestV3::Query {
                ownership_id_sha256,
                expected_worker_pidfd_stat_sha256,
                expected_cgroup_fd_stat_sha256,
                expected_fd_manifest_sha256,
                ..
            } => {
                if !packet.rights.is_empty() {
                    return Err(ServiceError::Invalid(
                        "recovery-target query must not carry SCM_RIGHTS descriptors",
                    ));
                }
                self.query(
                    &ownership_id_sha256,
                    &expected_worker_pidfd_stat_sha256,
                    &expected_cgroup_fd_stat_sha256,
                    &expected_fd_manifest_sha256,
                )?
            }
        };
        reply.validate()?;
        let signed = self.signer.sign_response(
            &frame.binding.request_id_sha256,
            reply,
            &frame.binding.deadline,
        )?;
        let response =
            ServiceResponseFrameV3::from_payload(
                frame.binding,
                &signed,
            )?;
        Ok(PreparedRecoveryTargetResponse {
            frame: response,
            rights,
        })
    }

    fn register(
        &mut self,
        registration: DescriptorRegistrationV3,
        rights: Vec<OwnedFd>,
    ) -> Result<
        (RecoveryTargetProviderReplyV3, Vec<OwnedFd>),
        ServiceError,
    > {
        registration.validate()?;
        let retained: [OwnedFd; 6] =
            rights.try_into().map_err(|_| {
                ServiceError::Invalid(
                    "recovery-target registration descriptor count changed",
                )
            })?;
        verify_registration_descriptors(
            &registration,
            &retained,
        )?;
        let ownership_id =
            registration.ownership_id_sha256.clone();
        let lineage_proof = self
            .reap_lineage_proofs
            .get(&ownership_id)
            .ok_or(ServiceError::Invalid(
                "recovery-target registration lacks a launcher-signed durable parent/subreaper lineage proof",
            ))?;
        lineage_proof
            .validate_against_registration(&registration)?;
        verify_live_reap_lineage(&registration, &retained)?;
        if let Some(existing) =
            self.registrations.get(&ownership_id)
        {
            if existing.registration != registration
                || existing.reap_lineage_proof_sha256
                    != lineage_proof.proof_sha256
            {
                return Err(ServiceError::IdempotencyConflict);
            }
            return Ok((
                RecoveryTargetProviderReplyV3::Register {
                    authoritative: existing.registration.clone(),
                },
                Vec::new(),
            ));
        }
        if self.registrations.len() >= self.maximum_registrations {
            return Err(ServiceError::Invalid(
                "recovery-target registration bound is exhausted",
            ));
        }
        self.registrations.insert(
            ownership_id.clone(),
            RegisteredRecoveryTarget {
                registration: registration.clone(),
                reap_lineage_proof_sha256:
                    lineage_proof.proof_sha256.clone(),
                retained,
            },
        );
        Ok((
            RecoveryTargetProviderReplyV3::Register {
                authoritative: registration,
            },
            Vec::new(),
        ))
    }

    fn query(
        &self,
        ownership_id_sha256: &Sha256Digest,
        expected_worker_pidfd_stat_sha256: &Sha256Digest,
        expected_cgroup_fd_stat_sha256: &Sha256Digest,
        expected_fd_manifest_sha256: &Sha256Digest,
    ) -> Result<
        (RecoveryTargetProviderReplyV3, Vec<OwnedFd>),
        ServiceError,
    > {
        let registered =
            self.registrations.get(ownership_id_sha256).ok_or(
                ServiceError::Invalid(
                    "exact recovery target is not registered",
                ),
            )?;
        let descriptors =
            &registered.registration.retained_descriptors;
        if &descriptors.worker_pidfd.retained_fd_stat_sha256
                != expected_worker_pidfd_stat_sha256
            || &descriptors
                .operation_cgroup
                .retained_fd_stat_sha256
                != expected_cgroup_fd_stat_sha256
            || &descriptors.fd_manifest_sha256
                != expected_fd_manifest_sha256
        {
            return Err(ServiceError::Invalid(
                "recovery-target query does not match the registered owner descriptor identities",
            ));
        }
        let target = registered.target()?;
        let rights = registered.duplicate_query_rights()?;
        Ok((
            RecoveryTargetProviderReplyV3::Query {
                target: Some(target),
            },
            Vec::from(rights),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRecoveryTargetOperation {
    Register,
    Query,
}

struct PendingRecoveryTargetRequest {
    operation: PendingRecoveryTargetOperation,
    request_id_sha256: Sha256Digest,
    deadline: ProtocolBoottimeDeadline,
}

/// Nonblocking authenticated local-UDS client. The separate epoll descriptor
/// tracks the same socket open-file description consumed by the common
/// request/reply exchange, including send readiness and response readability.
pub(super) struct TrustedHostNoTeeRecoveryTargetProviderClient {
    exchange: NonblockingRequestReplyExchange,
    progress_epoll: OwnedFd,
    _progress_socket: OwnedFd,
    current_head: ServiceCurrentHeadBindingV3,
    service_signing_pin: EndpointTrustPin,
    pending: Option<PendingRecoveryTargetRequest>,
}

impl TrustedHostNoTeeRecoveryTargetProviderClient {
    pub(super) fn from_inherited_socket(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
        current_head: ServiceCurrentHeadBindingV3,
        service_signing_pin: EndpointTrustPin,
    ) -> Result<Self, ServiceError> {
        service_signing_pin.validate().map_err(|_| {
            ServiceError::Invalid(
                "recovery-target client service pin is not current",
            )
        })?;
        validate_current_head_binding(
            &current_head,
            &service_signing_pin,
            &current_head.signed_current_head.statement.deadline,
        )?;
        let progress_socket =
            duplicate_cloexec(socket.as_raw_fd())?;
        let progress_epoll =
            create_progress_epoll(progress_socket.as_fd())?;
        let peer =
            AuthenticatedInheritedSeqpacket::from_inherited(
                socket,
                expected_peer,
            )?;
        Ok(Self {
            exchange: NonblockingRequestReplyExchange::new(peer),
            progress_epoll,
            _progress_socket: progress_socket,
            current_head,
            service_signing_pin,
            pending: None,
        })
    }

    pub(super) fn peer_credentials(
        &self,
    ) -> super::common::PeerCredentialsV3 {
        self.exchange.peer_credentials()
    }

    pub(super) fn install_fresh_service_current_head(
        &mut self,
        current_head: ServiceCurrentHeadBindingV3,
    ) -> Result<(), ServiceError> {
        if self.pending.is_some() || !self.exchange.is_idle() {
            return Err(ServiceError::Invalid(
                "cannot replace the recovery-target service head during an exchange",
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

    pub(super) fn try_register_nonblocking(
        &mut self,
        registration: &DescriptorRegistrationV3,
        retained: [BorrowedFd<'_>; 6],
        deadline: &BoottimeDeadline,
    ) -> Result<Option<DescriptorRegistrationV3>, RecoveryError> {
        registration.validate().map_err(|_| {
            RecoveryError::Invalid(
                "recovery-target registration wire record is invalid",
            )
        })?;
        verify_registration_borrowed_descriptors(
            registration,
            &retained,
        )
        .map_err(service_to_recovery)?;
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let request_id_sha256 =
            register_request_id(registration, &protocol_deadline)
                .map_err(service_to_recovery)?;
        let request = RecoveryTargetProviderRequestV3::Register {
            api_version:
                POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION.to_string(),
            request_id_sha256: request_id_sha256.clone(),
            registration: registration.clone(),
            deadline: protocol_deadline.clone(),
        };
        self.ensure_request(
            PendingRecoveryTargetOperation::Register,
            request_id_sha256.clone(),
            protocol_deadline.clone(),
            &request,
            &retained,
            6,
            0,
        )?;
        let Some((reply, rights)) = self.try_complete(
            PendingRecoveryTargetOperation::Register,
            &request_id_sha256,
            &protocol_deadline,
        )?
        else {
            return Ok(None);
        };
        if !rights.is_empty() {
            return Err(RecoveryError::Authorization(
                "recovery-target registration reply returned descriptors",
            ));
        }
        match reply {
            RecoveryTargetProviderReplyV3::Register {
                authoritative,
            } if authoritative == *registration => {
                Ok(Some(authoritative))
            }
            _ => Err(RecoveryError::Conflict(
                "recovery-target registration reply changed the exact registration",
            )),
        }
    }

    fn ensure_request(
        &mut self,
        operation: PendingRecoveryTargetOperation,
        request_id_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
        request: &RecoveryTargetProviderRequestV3,
        outbound_rights: &[BorrowedFd<'_>],
        exact_request_rights_count: usize,
        exact_reply_rights_count: usize,
    ) -> Result<(), RecoveryError> {
        if let Some(pending) = &self.pending {
            if pending.operation != operation
                || pending.request_id_sha256
                    != request_id_sha256
                || pending.deadline != deadline
            {
                return Err(RecoveryError::Conflict(
                    "a different recovery-target request is already in flight",
                ));
            }
            return Ok(());
        }
        request.validate().map_err(|_| {
            RecoveryError::Invalid(
                "recovery-target request is invalid",
            )
        })?;
        let idempotency_sha256 =
            request_idempotency(request)
                .map_err(service_to_recovery)?;
        let frame = ServiceRequestFrameV3::from_payload(
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            request_id_sha256.clone(),
            idempotency_sha256,
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
                TrustedHostServiceRoleV3::RecoveryTargetProvider,
                self.service_signing_pin.endpoint_role,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
            )
            .map_err(service_to_recovery)?;
        self.pending = Some(PendingRecoveryTargetRequest {
            operation,
            request_id_sha256,
            deadline,
        });
        Ok(())
    }

    fn try_complete(
        &mut self,
        operation: PendingRecoveryTargetOperation,
        request_id_sha256: &Sha256Digest,
        deadline: &ProtocolBoottimeDeadline,
    ) -> Result<
        Option<(RecoveryTargetProviderReplyV3, Vec<OwnedFd>)>,
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
                            "recovery-target exchange completed without pending state",
                        ),
                    )?;
                    if pending.operation != operation
                        || &pending.request_id_sha256
                            != request_id_sha256
                        || &pending.deadline != deadline
                    {
                        return Err(RecoveryError::Conflict(
                            "recovery-target completion changed request identity",
                        ));
                    }
                    let signed: SignedServiceResponseV3<
                        RecoveryTargetProviderReplyV3,
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
                            "recovery-target reply is invalid",
                        )
                    })?;
                    return Ok(Some((
                        signed.response,
                        completed.rights,
                    )));
                }
                Err(error) => {
                    self.pending = None;
                    return Err(service_to_recovery(error));
                }
            }
        }
        Ok(None)
    }
}

impl RecoveryTargetProvider
    for TrustedHostNoTeeRecoveryTargetProviderClient
{
    fn progress_fd(&self) -> BorrowedFd<'_> {
        self.progress_epoll.as_fd()
    }

    fn try_cleanup_target_nonblocking(
        &mut self,
        owner: &DurableOwnershipRecord,
        deadline: &BoottimeDeadline,
    ) -> Result<Option<CleanupTarget>, RecoveryError> {
        if owner.cleanup_deadline != *deadline {
            return Err(RecoveryError::Deadline(
                "recovery-target query did not use the exact durable cleanup deadline",
            ));
        }
        let protocol_deadline =
            ProtocolBoottimeDeadline::from_runtime(*deadline);
        let request_id_sha256 =
            query_request_id(owner, &protocol_deadline)
                .map_err(service_to_recovery)?;
        let request = RecoveryTargetProviderRequestV3::Query {
            api_version:
                POLICY_CUSTODY_RECOVERY_TARGET_WIRE_VERSION.to_string(),
            request_id_sha256: request_id_sha256.clone(),
            ownership_id_sha256:
                owner.ownership_id_sha256.clone(),
            expected_worker_pidfd_stat_sha256:
                owner.worker.pidfd_stat_sha256.clone(),
            expected_cgroup_fd_stat_sha256:
                owner.cgroup.retained_fd_stat_sha256.clone(),
            expected_fd_manifest_sha256:
                owner.registration.fd_manifest_sha256.clone(),
            deadline: protocol_deadline.clone(),
        };
        self.ensure_request(
            PendingRecoveryTargetOperation::Query,
            request_id_sha256.clone(),
            protocol_deadline.clone(),
            &request,
            &[],
            0,
            2,
        )?;
        let Some((reply, rights)) = self.try_complete(
            PendingRecoveryTargetOperation::Query,
            &request_id_sha256,
            &protocol_deadline,
        )?
        else {
            return Ok(None);
        };
        let target = match reply {
            RecoveryTargetProviderReplyV3::Query {
                target: Some(target),
            } => target,
            _ => {
                return Err(RecoveryError::Authorization(
                    "recovery-target authority omitted the exact registered owner",
                ));
            }
        };
        validate_target_against_owner(&target, owner)?;
        let [worker_pidfd, operation_cgroup_fd]:
            [OwnedFd; 2] = rights.try_into().map_err(|_| {
                RecoveryError::Authorization(
                    "recovery-target query did not return exactly two descriptors",
                )
            })?;
        verify_returned_target_descriptors(
            worker_pidfd.as_fd(),
            operation_cgroup_fd.as_fd(),
            &target.retained_descriptors,
        )
        .map_err(service_to_recovery)?;
        Ok(Some(CleanupTarget {
            worker_pidfd,
            operation_cgroup_fd,
            worker: target.worker,
            cgroup: target.cgroup,
        }))
    }
}

fn validate_target_against_owner(
    target: &RecoveryTargetV3,
    owner: &DurableOwnershipRecord,
) -> Result<(), RecoveryError> {
    target.validate().map_err(|_| {
        RecoveryError::Authorization(
            "recovery-target response failed validation",
        )
    })?;
    let expected_worker = owner
        .registration
        .retained_fds
        .get(2)
        .ok_or(RecoveryError::Authorization(
            "durable owner omitted its retained worker pidfd identity",
        ))?;
    let expected_cgroup = owner
        .registration
        .retained_fds
        .get(3)
        .ok_or(RecoveryError::Authorization(
            "durable owner omitted its retained cgroup identity",
        ))?;
    if target.ownership_id_sha256
            != owner.ownership_id_sha256
        || target.operation_id_sha256
            != owner.operation_id_sha256
        || target.durable_request_sha256
            != owner.durable_request_sha256
        || target.termination_fence_sha256
            != owner.termination_fence_sha256
        || target.worker != owner.worker
        || target.cgroup != owner.cgroup
        || target.retained_descriptors.fd_manifest_sha256
            != owner.registration.fd_manifest_sha256
        || &target.retained_descriptors.worker_pidfd
            != expected_worker
        || &target.retained_descriptors.operation_cgroup
            != expected_cgroup
    {
        return Err(RecoveryError::Authorization(
            "recovery target does not match the exact durable owner",
        ));
    }
    Ok(())
}

fn validate_request_binding(
    frame: &ServiceRequestFrameV3,
    request: &RecoveryTargetProviderRequestV3,
) -> Result<(), ServiceError> {
    let (request_id, deadline) = request_metadata(request);
    if request_id != &frame.binding.request_id_sha256
        || deadline != &frame.binding.deadline
        || request_id
            != &expected_request_id(request)?
        || frame.binding.idempotency_sha256
            != request_idempotency(request)?
    {
        return Err(ServiceError::Invalid(
            "recovery-target request body does not match its outer request binding",
        ));
    }
    deadline.to_runtime()?.require_live().map_err(|_| {
        ServiceError::Invalid(
            "recovery-target request deadline expired",
        )
    })
}

fn request_metadata(
    request: &RecoveryTargetProviderRequestV3,
) -> (&Sha256Digest, &ProtocolBoottimeDeadline) {
    match request {
        RecoveryTargetProviderRequestV3::Register {
            request_id_sha256,
            deadline,
            ..
        }
        | RecoveryTargetProviderRequestV3::Query {
            request_id_sha256,
            deadline,
            ..
        } => (request_id_sha256, deadline),
    }
}

fn expected_request_id(
    request: &RecoveryTargetProviderRequestV3,
) -> Result<Sha256Digest, ServiceError> {
    match request {
        RecoveryTargetProviderRequestV3::Register {
            registration,
            deadline,
            ..
        } => register_request_id(registration, deadline),
        RecoveryTargetProviderRequestV3::Query {
            ownership_id_sha256,
            expected_worker_pidfd_stat_sha256,
            expected_cgroup_fd_stat_sha256,
            expected_fd_manifest_sha256,
            deadline,
            ..
        } => request_id_digest(&(
            "query",
            ownership_id_sha256,
            expected_worker_pidfd_stat_sha256,
            expected_cgroup_fd_stat_sha256,
            expected_fd_manifest_sha256,
            deadline,
        )),
    }
}

fn register_request_id(
    registration: &DescriptorRegistrationV3,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "register",
        &registration.ownership_id_sha256,
        &registration.registration_record_sha256,
        deadline,
    ))
}

fn query_request_id(
    owner: &DurableOwnershipRecord,
    deadline: &ProtocolBoottimeDeadline,
) -> Result<Sha256Digest, ServiceError> {
    request_id_digest(&(
        "query",
        &owner.ownership_id_sha256,
        &owner.worker.pidfd_stat_sha256,
        &owner.cgroup.retained_fd_stat_sha256,
        &owner.registration.fd_manifest_sha256,
        deadline,
    ))
}

fn request_id_digest<T: Serialize>(
    value: &T,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid(
            "recovery-target request identity is not canonical",
        )
    })?;
    Ok(hash_domain_frames(
        RECOVERY_TARGET_REQUEST_ID_DOMAIN,
        &[canonical.as_slice()],
    ))
}

fn request_idempotency(
    request: &RecoveryTargetProviderRequestV3,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(request).map_err(|_| {
        ServiceError::Invalid(
            "recovery-target idempotency input is not canonical",
        )
    })?;
    Ok(endpoint_request_sha256(&canonical))
}

fn recovery_target_sha256(
    target: &RecoveryTargetV3,
) -> Result<Sha256Digest, ServiceError> {
    let canonical = canonical_json_bytes(&(
        &target.api_version,
        &target.ownership_id_sha256,
        &target.operation_id_sha256,
        &target.durable_request_sha256,
        &target.termination_fence_sha256,
        &target.worker,
        &target.cgroup,
        &target.retained_descriptors,
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "recovery target cannot be canonicalized",
        )
    })?;
    Ok(hash_domain_frames(
        RECOVERY_TARGET_DIGEST_DOMAIN,
        &[canonical.as_slice()],
    ))
}

fn verify_registration_descriptors(
    registration: &DescriptorRegistrationV3,
    retained: &[OwnedFd; 6],
) -> Result<(), ServiceError> {
    let borrowed = [
        retained[0].as_fd(),
        retained[1].as_fd(),
        retained[2].as_fd(),
        retained[3].as_fd(),
        retained[4].as_fd(),
        retained[5].as_fd(),
    ];
    verify_registration_borrowed_descriptors(
        registration,
        &borrowed,
    )
}

fn verify_registration_borrowed_descriptors(
    registration: &DescriptorRegistrationV3,
    retained: &[BorrowedFd<'_>; 6],
) -> Result<(), ServiceError> {
    registration.validate()?;
    let expected = registration.retained_descriptors.ordered();
    for (descriptor, identity) in
        retained.iter().zip(expected)
    {
        require_cloexec(*descriptor)?;
        let observed =
            observe_retained_descriptor(identity.role, *descriptor)?;
        if &observed != identity {
            return Err(ServiceError::Invalid(
                "received recovery-target descriptor does not match its exact manifest identity",
            ));
        }
    }
    require_pidfd_descriptor(
        retained[0],
        WatchdogRegistrationFdRole::ParentPidfd,
        &registration.registration.parent,
    )?;
    require_pidfd_descriptor(
        retained[1],
        WatchdogRegistrationFdRole::SupervisorPidfd,
        &registration.registration.supervisor,
    )?;
    require_pidfd_descriptor(
        retained[2],
        WatchdogRegistrationFdRole::WorkerPidfd,
        &registration.registration.worker,
    )?;
    require_cgroup_v2_descriptor(retained[3])?;
    require_eventfd_descriptor(retained[4])?;
    require_eventfd_descriptor(retained[5])?;
    require_distinct_open_file_descriptions(retained)?;
    verify_returned_target_descriptors(
        retained[2],
        retained[3],
        &registration.retained_descriptors,
    )
}

fn verify_returned_target_descriptors(
    worker_pidfd: BorrowedFd<'_>,
    operation_cgroup: BorrowedFd<'_>,
    expected: &RetainedDescriptorIdentitySetV3,
) -> Result<(), ServiceError> {
    require_cloexec(worker_pidfd)?;
    require_cloexec(operation_cgroup)?;
    let worker = observe_retained_descriptor(
        WatchdogRegistrationFdRole::WorkerPidfd,
        worker_pidfd,
    )?;
    let cgroup = observe_retained_descriptor(
        WatchdogRegistrationFdRole::OperationCgroup,
        operation_cgroup,
    )?;
    if worker != expected.worker_pidfd
        || cgroup != expected.operation_cgroup
    {
        return Err(ServiceError::Invalid(
            "returned recovery-target descriptors changed identity",
        ));
    }
    require_pidfd_descriptor_identity_only(worker_pidfd)?;
    require_cgroup_v2_descriptor(operation_cgroup)?;
    if cgroup.mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(ServiceError::Invalid(
            "recovery-target cgroup descriptor is not a cgroup-v2 directory",
        ));
    }
    Ok(())
}

fn require_pidfd_descriptor(
    descriptor: BorrowedFd<'_>,
    role: WatchdogRegistrationFdRole,
    expected: &super::super::protocol::WatchdogProcessIdentityV3,
) -> Result<(), ServiceError> {
    expected.validate()?;
    require_pidfd_descriptor_identity_only(descriptor)?;
    let fdinfo = read_fdinfo(descriptor)?;
    let pid = unique_live_fdinfo_pid(&fdinfo)?;
    if pid != expected.pid {
        return Err(ServiceError::Invalid(
            "retained pidfd does not identify the exact registered process",
        ));
    }
    let observed = observe_retained_descriptor(
        role,
        descriptor,
    )?;
    if observed.inode != expected.pidfd_inode
        || observed.retained_fd_stat_sha256
            != expected.pidfd_stat_sha256
    {
        return Err(ServiceError::Invalid(
            "retained pidfd inode or stat identity differs from the registered process",
        ));
    }
    Ok(())
}

fn require_pidfd_descriptor_identity_only(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            descriptor.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EPERM) | Some(libc::ESRCH)
        ) {
            return Err(ServiceError::Invalid(
                "retained descriptor is not a Linux pidfd",
            ));
        }
    }
    let fdinfo = read_fdinfo(descriptor)?;
    let pid = unique_fdinfo_i32(&fdinfo, "Pid:")?;
    if pid == 0 || pid < -1 {
        return Err(ServiceError::Invalid(
            "pidfd fdinfo contains an impossible process identity",
        ));
    }
    Ok(())
}

fn require_eventfd_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    let fdinfo = read_fdinfo(descriptor)?;
    let eventfd_count = fdinfo
        .lines()
        .filter(|line| line.starts_with("eventfd-count:"))
        .count();
    let eventfd_id = fdinfo
        .lines()
        .filter(|line| line.starts_with("eventfd-id:"))
        .count();
    let timerfd_marker = fdinfo.lines().any(|line| {
        line.starts_with("clockid:")
            || line.starts_with("ticks:")
            || line.starts_with("settime flags:")
    });
    if eventfd_count != 1
        || eventfd_id != 1
        || timerfd_marker
    {
        return Err(ServiceError::Invalid(
            "retained heartbeat descriptor is not exactly an eventfd",
        ));
    }
    Ok(())
}

fn require_cgroup_v2_descriptor(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe {
        libc::fstatfs(descriptor.as_raw_fd(), &mut filesystem)
    } != 0
        || unsafe {
            libc::fstat(descriptor.as_raw_fd(), &mut stat)
        } != 0
        || filesystem.f_type != CGROUP2_SUPER_MAGIC
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(ServiceError::Invalid(
            "retained operation-cgroup descriptor is not exactly a cgroup-v2 directory",
        ));
    }
    Ok(())
}

fn verify_live_reap_lineage(
    registration: &DescriptorRegistrationV3,
    retained: &[OwnedFd; 6],
) -> Result<(), ServiceError> {
    let exact = &registration.registration;
    require_pidfd_descriptor(
        retained[0].as_fd(),
        WatchdogRegistrationFdRole::ParentPidfd,
        &exact.parent,
    )?;
    require_pidfd_descriptor(
        retained[1].as_fd(),
        WatchdogRegistrationFdRole::SupervisorPidfd,
        &exact.supervisor,
    )?;
    require_pidfd_descriptor(
        retained[2].as_fd(),
        WatchdogRegistrationFdRole::WorkerPidfd,
        &exact.worker,
    )?;
    let parent = read_proc_process(&exact.parent)?;
    let supervisor = read_proc_process(&exact.supervisor)?;
    let worker = read_proc_process(&exact.worker)?;
    if parent.pid != exact.parent.pid
        || supervisor.pid != exact.supervisor.pid
        || worker.pid != exact.worker.pid
        || supervisor.parent_pid != exact.parent.pid
        || worker.parent_pid != exact.supervisor.pid
    {
        return Err(ServiceError::Invalid(
            "live process lineage does not match the launcher-signed durable parent/subreaper proof",
        ));
    }
    Ok(())
}

struct ProcProcessObservation {
    pid: libc::pid_t,
    parent_pid: libc::pid_t,
}

fn read_proc_process(
    expected: &super::super::protocol::WatchdogProcessIdentityV3,
) -> Result<ProcProcessObservation, ServiceError> {
    let path = CString::new(format!("/proc/{}/stat", expected.pid))
        .map_err(|_| {
            ServiceError::Invalid(
                "registered process stat path contains NUL",
            )
        })?;
    let text = read_bounded_proc_file(
        &path,
        MAX_PROC_STAT_BYTES,
        "registered process stat",
    )?;
    let close = text.rfind(')').ok_or(ServiceError::Invalid(
        "registered process stat omits the command terminator",
    ))?;
    let prefix = &text[..close];
    let open = prefix.find('(').ok_or(ServiceError::Invalid(
        "registered process stat omits the command",
    ))?;
    let pid = prefix[..open]
        .trim()
        .parse::<libc::pid_t>()
        .map_err(|_| {
            ServiceError::Invalid(
                "registered process stat PID is invalid",
            )
        })?;
    let fields: Vec<&str> =
        text[close + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(ServiceError::Invalid(
            "registered process stat is truncated",
        ));
    }
    let parent_pid = fields[1]
        .parse::<libc::pid_t>()
        .map_err(|_| {
            ServiceError::Invalid(
                "registered process parent PID is invalid",
            )
        })?;
    let start_time_ticks =
        fields[19].parse::<u64>().map_err(|_| {
            ServiceError::Invalid(
                "registered process start time is invalid",
            )
        })?;
    if pid != expected.pid
        || start_time_ticks != expected.start_time_ticks
    {
        return Err(ServiceError::Invalid(
            "registered process PID or start time was reused",
        ));
    }
    Ok(ProcProcessObservation { pid, parent_pid })
}

fn read_fdinfo(
    descriptor: BorrowedFd<'_>,
) -> Result<String, ServiceError> {
    let path = CString::new(format!(
        "/proc/self/fdinfo/{}",
        descriptor.as_raw_fd()
    ))
    .map_err(|_| {
        ServiceError::Invalid("descriptor fdinfo path contains NUL")
    })?;
    read_bounded_proc_file(
        &path,
        MAX_FDINFO_BYTES,
        "descriptor fdinfo",
    )
}

fn read_bounded_proc_file(
    path: &CString,
    maximum_bytes: usize,
    description: &'static str,
) -> Result<String, ServiceError> {
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(ServiceError::Io(io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut bytes = vec![0_u8; maximum_bytes];
    let mut length = 0_usize;
    loop {
        if length == bytes.len() {
            return Err(ServiceError::InvalidOwned(format!(
                "{description} exceeds its fixed bound"
            )));
        }
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[length..].as_mut_ptr().cast(),
                bytes.len() - length,
            )
        };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(ServiceError::Io(error));
        }
        if read == 0 {
            break;
        }
        length = length
            .checked_add(usize::try_from(read).map_err(|_| {
                ServiceError::Invalid(
                    "proc read length is negative",
                )
            })?)
            .ok_or(ServiceError::Invalid(
                "proc read length overflow",
            ))?;
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(
        |_| ServiceError::InvalidOwned(format!(
            "{description} is not UTF-8"
        )),
    )?;
    Ok(text.to_owned())
}

fn unique_fdinfo_i32(
    fdinfo: &str,
    field: &'static str,
) -> Result<libc::pid_t, ServiceError> {
    let mut value = None;
    for line in fdinfo.lines() {
        if let Some(candidate) = line.strip_prefix(field) {
            if value.is_some() {
                return Err(ServiceError::Invalid(
                    "descriptor fdinfo contains a duplicate field",
                ));
            }
            value = Some(
                candidate
                    .trim()
                    .parse::<libc::pid_t>()
                    .map_err(|_| {
                        ServiceError::Invalid(
                            "descriptor fdinfo field is invalid",
                        )
                    })?,
            );
        }
    }
    value.ok_or(ServiceError::Invalid(
        "descriptor fdinfo omits the required field",
    ))
}

fn unique_live_fdinfo_pid(
    fdinfo: &str,
) -> Result<libc::pid_t, ServiceError> {
    let pid = unique_fdinfo_i32(fdinfo, "Pid:")?;
    if pid <= 1 {
        return Err(ServiceError::Invalid(
            "pidfd does not identify the exact live registered process",
        ));
    }
    Ok(pid)
}

fn observe_retained_descriptor(
    role: WatchdogRegistrationFdRole,
    descriptor: BorrowedFd<'_>,
) -> Result<WatchdogRetainedFdIdentityV3, ServiceError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: libc::statx = unsafe { zeroed() };
    const STATX_MNT_ID_MASK: libc::c_uint = 0x0000_1000;
    if unsafe {
        libc::fstat(descriptor.as_raw_fd(), &mut stat)
    } != 0
        || unsafe {
            libc::statx(
                descriptor.as_raw_fd(),
                b"\0".as_ptr().cast(),
                libc::AT_EMPTY_PATH
                    | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_BASIC_STATS
                    | STATX_MNT_ID_MASK,
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
            "recovery-target descriptor stat/statx identity is unavailable",
        ));
    }
    let frames: [&[u8]; 11] = [
        &stat.st_dev.to_be_bytes(),
        &stat.st_ino.to_be_bytes(),
        &stat.st_mode.to_be_bytes(),
        &stat.st_uid.to_be_bytes(),
        &stat.st_gid.to_be_bytes(),
        &(stat.st_size as u64).to_be_bytes(),
        &stat.st_mtime.to_be_bytes(),
        &stat.st_mtime_nsec.to_be_bytes(),
        &stat.st_ctime.to_be_bytes(),
        &stat.st_ctime_nsec.to_be_bytes(),
        &statx.stx_mnt_id.to_be_bytes(),
    ];
    let mut hasher = Sha256::new();
    for frame in frames {
        hasher.update((frame.len() as u64).to_be_bytes());
        hasher.update(frame);
    }
    let digest = Sha256Digest::parse(format!(
        "sha256:{}",
        hex::encode(hasher.finalize()),
    ))
    .map_err(|_| {
        ServiceError::Invalid(
            "recovery-target descriptor digest encoding failed",
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

fn require_distinct_open_file_descriptions(
    descriptors: &[BorrowedFd<'_>; 6],
) -> Result<(), ServiceError> {
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
                return Err(ServiceError::Invalid(
                    "recovery-target descriptor roles alias one open-file description",
                ));
            }
            if compared < 0 {
                return Err(ServiceError::Invalid(
                    "recovery-target descriptor alias proof is unavailable",
                ));
            }
        }
    }
    Ok(())
}

fn require_cloexec(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ServiceError> {
    let flags = unsafe {
        libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD)
    };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(ServiceError::Invalid(
            "recovery-target descriptor is not close-on-exec",
        ));
    }
    Ok(())
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
    socket: BorrowedFd<'_>,
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
    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN
            | libc::EPOLLOUT
            | libc::EPOLLRDHUP
            | libc::EPOLLERR
            | libc::EPOLLET) as u32,
        u64: 1,
    };
    if unsafe {
        libc::epoll_ctl(
            epoll.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            socket.as_raw_fd(),
            &mut event,
        )
    } != 0
    {
        return Err(ServiceError::Io(
            io::Error::last_os_error(),
        ));
    }
    Ok(epoll)
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

fn require_signing_key_matches_pin(
    signing_key: &SigningKey,
    pin: &EndpointTrustPin,
) -> Result<(), ServiceError> {
    let verifying_key = signing_key.verifying_key();
    let spki = verifying_key.to_public_key_der().map_err(|_| {
        ServiceError::Invalid(
            "recovery-target signing key cannot be encoded as SPKI",
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
            "recovery-target software signing key does not match its current checkpoint",
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
            "service endpoint pin is not current",
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
            "service current-head attestation is stale or does not match the pinned current checkpoint",
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
            "recovery-target current-head evidence is not bound to the exact request id, payload-derived idempotency digest, role, process checkpoint, generation, revocation head, and deadline",
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
        PolicyCustodyServiceRoleV3::RecoveryTargetProvider,
        request_id_sha256,
        deadline,
    )?;
    pin.validate().map_err(|_| {
        ServiceError::Invalid(
            "recovery-target response signing pin is not current",
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
            "recovery-target response did not use the exact current non-revoked service key",
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

fn service_receipt_sha256(
    signature_payload: &[u8],
    signature_base64: &str,
) -> Sha256Digest {
    hash_domain_frames(
        SERVICE_RESPONSE_RECEIPT_DOMAIN,
        &[signature_payload, signature_base64.as_bytes()],
    )
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
                "service signature is not canonical base64url",
            )
        })?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes)
        != signature_base64
    {
        return Err(ServiceError::Invalid(
            "service signature base64url is noncanonical",
        ));
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| {
            ServiceError::Invalid(
                "service Ed25519 signature length is invalid",
            )
        })?;
    key.verify_strict(preimage, &signature).map_err(|_| {
        ServiceError::Invalid(
            "service Ed25519 signature verification failed",
        )
    })
}

fn service_to_recovery(error: ServiceError) -> RecoveryError {
    match error {
        ServiceError::Io(_) | ServiceError::JournalBusy => {
            RecoveryError::Transient(
                "recovery-target service transport is temporarily unavailable",
            )
        }
        ServiceError::IdempotencyConflict => {
            RecoveryError::Conflict(
                "recovery-target idempotency key conflicts with existing state",
            )
        }
        ServiceError::Protocol(_)
        | ServiceError::Invalid(_)
        | ServiceError::InvalidOwned(_) => {
            RecoveryError::Authorization(
                "recovery-target service rejected an invalid or unauthenticated exchange",
            )
        }
    }
}
