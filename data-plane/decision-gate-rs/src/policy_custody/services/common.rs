//! Shared serving substrate for TrustedHostNoTee policy-custody services.
//!
//! This module deliberately provides transport and durability mechanics only.
//! Role-specific request semantics, signatures, and recovery transitions remain
//! in the individual v3 authority services.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "TrustedHostNoTee policy-custody services require Linux AF_UNIX SOCK_SEQPACKET, SO_PEERCRED, SCM_RIGHTS, and fsync semantics"
);

use super::super::protocol::{
    require_nonzero_digest, PolicyCustodyEndpointRole,
    ProtocolBoottimeDeadline, ProtocolError,
    SignedTrustedHostNoTeeCurrentHeadWire, MAX_ENDPOINT_FRAME_BYTES,
    POLICY_CUSTODY_PROTOCOL_VERSION,
};
use super::super::boottime::boottime_now_nanos;
use super::super::super::{
    canonical_json_bytes, hash_domain_frames, Sha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

pub(super) const TRUSTED_HOST_SERVICE_API_VERSION: &str =
    "serverware.policyCustodyTrustedHostService/v4";
pub(super) const MAX_SERVICE_FRAME_BYTES: usize =
    MAX_ENDPOINT_FRAME_BYTES;
pub(super) const MAX_SERVICE_RIGHTS: usize = 8;

const MAX_JOURNAL_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_JOURNAL_RECOVERY_RECORDS: usize = 1_000_000;
const MAX_JOURNAL_RECOVERY_BYTES: usize = 256 * 1024 * 1024;
const JOURNAL_HEAD_NAME: &str = "head.v3.json";
const JOURNAL_LOCK_NAME: &str = "writer.v3.lock";
const JOURNAL_RECORD_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostJournalRecord/v3";
const JOURNAL_HEAD_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostJournalHead/v3";
const SERVICE_REQUEST_BINDING_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostServiceRequestBinding/v3";
const SERVICE_REQUEST_FRAME_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostServiceRequestFrame/v3";
const SERVICE_RESPONSE_FRAME_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostServiceResponseFrame/v3";
const SERVICE_HANDSHAKE_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostServiceHandshakeRequest/v3";
const SERVICE_HANDSHAKE_REPLY_DOMAIN: &[u8] =
    b"serverware.policyCustodyTrustedHostServiceHandshakeReply/v3";
const SO_PEERPIDFD_OPT: libc::c_int = 77;
const MAX_PROC_STAT_BYTES: usize = 4096;
const MAX_PEER_SECURITY_LABEL_BYTES: usize = 4096;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const PEER_PROCESS_IDENTITY_DOMAIN: &[u8] =
    b"serverware.policyCustodyPeerProcessIdentity/v4";

#[derive(Debug)]
pub(in crate::policy_shadow::policy_custody) enum ServiceError {
    Io(io::Error),
    Protocol(ProtocolError),
    Invalid(&'static str),
    InvalidOwned(String),
    IdempotencyConflict,
    JournalBusy,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidOwned(message) => formatter.write_str(message),
            Self::IdempotencyConflict => formatter.write_str(
                "idempotency digest is already bound to different bytes",
            ),
            Self::JournalBusy => formatter.write_str(
                "durable journal already has an active writer",
            ),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for ServiceError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
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
pub(in crate::policy_shadow::policy_custody) enum TrustedHostServiceRoleV3 {
    DurableRecoveryStore,
    CleanupAuthorizationConsumer,
    RecoveryTargetProvider,
    CurrentSignatureAuthority,
    BoundedCleanupHelper,
}

impl TrustedHostServiceRoleV3 {
    fn journal_label(self) -> &'static str {
        match self {
            Self::DurableRecoveryStore => "durable-recovery-store",
            Self::CleanupAuthorizationConsumer => {
                "cleanup-authorization-consumer"
            }
            Self::RecoveryTargetProvider => "recovery-target-provider",
            Self::CurrentSignatureAuthority => {
                "current-signature-authority"
            }
            Self::BoundedCleanupHelper => "bounded-cleanup-helper",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TrustedHostPlacementV3 {
    CoLocated,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TrustedHostKeyProtectionV3 {
    SoftwareProcess,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TrustedHostHardwareAttestationV3 {
    None,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TrustedHostTransportV3 {
    LocalAuthenticatedUnixSeqpacket,
}

/// An explicit negative attestation: this profile is co-located software and
/// makes no TEE, hardware-key, or hardware-attestation claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct TrustedHostNoTeeServiceReportV3 {
    pub(in crate::policy_shadow::policy_custody) api_version: String,
    pub(in crate::policy_shadow::policy_custody)
        policy_custody_protocol_version: String,
    pub(in crate::policy_shadow::policy_custody)
        service_role: TrustedHostServiceRoleV3,
    pub(in crate::policy_shadow::policy_custody)
        placement: TrustedHostPlacementV3,
    pub(in crate::policy_shadow::policy_custody)
        key_protection: TrustedHostKeyProtectionV3,
    pub(in crate::policy_shadow::policy_custody) hardware_attestation:
        TrustedHostHardwareAttestationV3,
    pub(in crate::policy_shadow::policy_custody)
        transport: TrustedHostTransportV3,
    pub(in crate::policy_shadow::policy_custody)
        authority_is_co_located: bool,
    pub(in crate::policy_shadow::policy_custody) software_only: bool,
    pub(in crate::policy_shadow::policy_custody)
        hardware_key_protection: bool,
    pub(in crate::policy_shadow::policy_custody)
        hardware_attestation_available: bool,
    pub(in crate::policy_shadow::policy_custody)
        operation_generation: u64,
    pub(in crate::policy_shadow::policy_custody)
        service_restart_epoch: u64,
    pub(in crate::policy_shadow::policy_custody)
        service_invocation_id_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) readiness_epoch: u64,
    pub(in crate::policy_shadow::policy_custody)
        durability_worker_queue_depth: u16,
    pub(in crate::policy_shadow::policy_custody)
        maximum_durability_worker_nanos: u64,
    pub(in crate::policy_shadow::policy_custody)
        authority_history_manifest_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        production_dispatch_protocol_set_sha256:
        Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        shared_configuration_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        deployment_generation_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        deployment_configuration_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        service_process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        signing_credential_sha256: Option<Sha256Digest>,
}

impl TrustedHostNoTeeServiceReportV3 {
    pub(super) fn new(
        service_role: TrustedHostServiceRoleV3,
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
        service_process_identity_sha256: Sha256Digest,
        signing_credential_sha256: Option<Sha256Digest>,
    ) -> Result<Self, ServiceError> {
        let report = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            policy_custody_protocol_version:
                POLICY_CUSTODY_PROTOCOL_VERSION.to_string(),
            service_role,
            placement: TrustedHostPlacementV3::CoLocated,
            key_protection:
                TrustedHostKeyProtectionV3::SoftwareProcess,
            hardware_attestation:
                TrustedHostHardwareAttestationV3::None,
            transport:
                TrustedHostTransportV3::
                    LocalAuthenticatedUnixSeqpacket,
            authority_is_co_located: true,
            software_only: true,
            hardware_key_protection: false,
            hardware_attestation_available: false,
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
            service_process_identity_sha256,
            signing_credential_sha256,
        };
        report.validate_for_role(service_role)?;
        Ok(report)
    }

    pub(super) fn validate_for_role(
        &self,
        expected_role: TrustedHostServiceRoleV3,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "trustedHostServiceReport.serviceInvocationIdSha256",
            &self.service_invocation_id_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.authorityHistoryManifestSha256",
            &self.authority_history_manifest_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.productionDispatchProtocolSetSha256",
            &self.production_dispatch_protocol_set_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.sharedConfigurationSha256",
            &self.shared_configuration_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.deploymentGenerationSha256",
            &self.deployment_generation_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.deploymentConfigurationSha256",
            &self.deployment_configuration_sha256,
        )?;
        require_nonzero_digest(
            "trustedHostServiceReport.serviceProcessIdentitySha256",
            &self.service_process_identity_sha256,
        )?;
        if let Some(credential) = &self.signing_credential_sha256 {
            require_nonzero_digest(
                "trustedHostServiceReport.signingCredentialSha256",
                credential,
            )?;
        }
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.policy_custody_protocol_version
                != POLICY_CUSTODY_PROTOCOL_VERSION
            || self.service_role != expected_role
            || self.placement != TrustedHostPlacementV3::CoLocated
            || self.key_protection
                != TrustedHostKeyProtectionV3::SoftwareProcess
            || self.hardware_attestation
                != TrustedHostHardwareAttestationV3::None
            || self.transport
                != TrustedHostTransportV3::
                    LocalAuthenticatedUnixSeqpacket
            || self.operation_generation == 0
            || self.service_restart_epoch == 0
            || self.readiness_epoch == 0
            || self.readiness_epoch < self.service_restart_epoch
            || self.durability_worker_queue_depth == 0
            || self.durability_worker_queue_depth > 64
            || self.maximum_durability_worker_nanos == 0
            || !self.authority_is_co_located
            || !self.software_only
            || self.hardware_key_protection
            || self.hardware_attestation_available
            || self.signing_credential_sha256.is_none()
        {
            return Err(ServiceError::Invalid(
                "TrustedHostNoTee report is inconsistent",
            ));
        }
        Ok(())
    }
}

/// The complete signed current-head object is carried in every binding. A
/// digest alone is not accepted because it would omit the role, generations,
/// revocation root, and BOOTTIME validity statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceCurrentHeadBindingV3 {
    pub(super) signed_current_head:
        SignedTrustedHostNoTeeCurrentHeadWire,
    pub(super) exact_attestation_sha256: Sha256Digest,
}

impl ServiceCurrentHeadBindingV3 {
    pub(super) fn from_signed(
        signed_current_head: SignedTrustedHostNoTeeCurrentHeadWire,
    ) -> Result<Self, ServiceError> {
        signed_current_head.validate_shape()?;
        let exact_attestation_sha256 =
            Sha256Digest::compute(&encode_canonical_frame(
                &signed_current_head,
            )?);
        Ok(Self {
            signed_current_head,
            exact_attestation_sha256,
        })
    }

    pub(super) fn validate(
        &self,
        expected_endpoint_role: PolicyCustodyEndpointRole,
        exact_deadline: &ProtocolBoottimeDeadline,
    ) -> Result<(), ServiceError> {
        self.signed_current_head.validate_shape()?;
        require_nonzero_digest(
            "serviceCurrentHead.exactAttestationSha256",
            &self.exact_attestation_sha256,
        )?;
        let statement = &self.signed_current_head.statement;
        if statement.endpoint_role != expected_endpoint_role
            || &statement.deadline != exact_deadline
            || self.exact_attestation_sha256
                != Sha256Digest::compute(&encode_canonical_frame(
                    &self.signed_current_head,
                )?)
        {
            return Err(ServiceError::Invalid(
                "service current-head binding does not match the exact endpoint role, deadline, or signed attestation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceRequestBindingV3 {
    pub(super) api_version: String,
    pub(super) service_role: TrustedHostServiceRoleV3,
    pub(super) request_id_sha256: Sha256Digest,
    pub(super) idempotency_sha256: Sha256Digest,
    pub(super) request_payload_sha256: Sha256Digest,
    pub(super) deadline: ProtocolBoottimeDeadline,
    pub(super) current_head: ServiceCurrentHeadBindingV3,
    pub(super) binding_sha256: Sha256Digest,
}

impl ServiceRequestBindingV3 {
    pub(super) fn new(
        service_role: TrustedHostServiceRoleV3,
        request_id_sha256: Sha256Digest,
        idempotency_sha256: Sha256Digest,
        request_payload_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
        current_head: ServiceCurrentHeadBindingV3,
    ) -> Result<Self, ServiceError> {
        let mut binding = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            service_role,
            request_id_sha256,
            idempotency_sha256,
            request_payload_sha256,
            deadline,
            current_head,
            binding_sha256: Sha256Digest::compute(&[]),
        };
        binding.binding_sha256 =
            binding.computed_binding_sha256()?;
        Ok(binding)
    }

    fn computed_binding_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.request_id_sha256,
            &self.idempotency_sha256,
            &self.request_payload_sha256,
            &self.deadline,
            &self.current_head,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service request binding cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(
            SERVICE_REQUEST_BINDING_DOMAIN,
            &canonical,
        ))
    }

    pub(super) fn validate(
        &self,
        expected_role: TrustedHostServiceRoleV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "serviceRequest.requestIdSha256",
            &self.request_id_sha256,
        )?;
        require_nonzero_digest(
            "serviceRequest.idempotencySha256",
            &self.idempotency_sha256,
        )?;
        require_nonzero_digest(
            "serviceRequest.requestPayloadSha256",
            &self.request_payload_sha256,
        )?;
        require_nonzero_digest(
            "serviceRequest.bindingSha256",
            &self.binding_sha256,
        )?;
        self.deadline.to_runtime()?;
        self.current_head
            .validate(expected_endpoint_role, &self.deadline)?;
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.service_role != expected_role
            || self.binding_sha256
                != self.computed_binding_sha256()?
        {
            return Err(ServiceError::Invalid(
                "service request binding is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceRequestFrameV3 {
    pub(super) binding: ServiceRequestBindingV3,
    pub(super) canonical_request_base64: String,
    pub(super) frame_sha256: Sha256Digest,
}

impl ServiceRequestFrameV3 {
    pub(super) fn from_payload<T>(
        service_role: TrustedHostServiceRoleV3,
        request_id_sha256: Sha256Digest,
        idempotency_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
        current_head: ServiceCurrentHeadBindingV3,
        payload: &T,
    ) -> Result<Self, ServiceError>
    where
        T: Serialize,
    {
        let canonical_payload = encode_canonical_frame(payload)?;
        let binding = ServiceRequestBindingV3::new(
            service_role,
            request_id_sha256,
            idempotency_sha256,
            Sha256Digest::compute(&canonical_payload),
            deadline,
            current_head,
        )?;
        let mut frame = Self {
            binding,
            canonical_request_base64:
                URL_SAFE_NO_PAD.encode(canonical_payload),
            frame_sha256: Sha256Digest::compute(&[]),
        };
        frame.frame_sha256 = frame.computed_frame_sha256()?;
        Ok(frame)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ServiceError> {
        decode_canonical_base64(
            &self.canonical_request_base64,
            MAX_SERVICE_FRAME_BYTES,
            "service request payload",
        )
    }

    fn computed_frame_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.binding,
            &self.canonical_request_base64,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service request frame cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(
            SERVICE_REQUEST_FRAME_DOMAIN,
            &canonical,
        ))
    }

    pub(super) fn validate(
        &self,
        expected_role: TrustedHostServiceRoleV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        self.binding
            .validate(expected_role, expected_endpoint_role)?;
        require_nonzero_digest(
            "serviceRequest.frameSha256",
            &self.frame_sha256,
        )?;
        let payload = self.canonical_payload()?;
        if Sha256Digest::compute(&payload)
            != self.binding.request_payload_sha256
            || self.frame_sha256 != self.computed_frame_sha256()?
        {
            return Err(ServiceError::Invalid(
                "service request frame does not match its exact payload binding",
            ));
        }
        Ok(())
    }

    pub(super) fn decode_payload<T>(
        &self,
    ) -> Result<T, ServiceError>
    where
        T: DeserializeOwned + Serialize,
    {
        decode_canonical_frame(&self.canonical_payload()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ServiceResponseFrameV3 {
    pub(super) request_binding: ServiceRequestBindingV3,
    pub(super) canonical_response_base64: String,
    pub(super) response_sha256: Sha256Digest,
    pub(super) frame_sha256: Sha256Digest,
}

impl ServiceResponseFrameV3 {
    pub(super) fn from_payload<T>(
        request_binding: ServiceRequestBindingV3,
        payload: &T,
    ) -> Result<Self, ServiceError>
    where
        T: Serialize,
    {
        let canonical_response = encode_canonical_frame(payload)?;
        let mut frame = Self {
            request_binding,
            canonical_response_base64:
                URL_SAFE_NO_PAD.encode(&canonical_response),
            response_sha256:
                Sha256Digest::compute(&canonical_response),
            frame_sha256: Sha256Digest::compute(&[]),
        };
        frame.frame_sha256 = frame.computed_frame_sha256()?;
        Ok(frame)
    }

    fn canonical_response(&self) -> Result<Vec<u8>, ServiceError> {
        decode_canonical_base64(
            &self.canonical_response_base64,
            MAX_SERVICE_FRAME_BYTES,
            "service response payload",
        )
    }

    fn computed_frame_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.request_binding,
            &self.canonical_response_base64,
            &self.response_sha256,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service response frame cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(
            SERVICE_RESPONSE_FRAME_DOMAIN,
            &canonical,
        ))
    }

    pub(super) fn validate_for_request(
        &self,
        request: &ServiceRequestBindingV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        self.request_binding
            .validate(request.service_role, expected_endpoint_role)?;
        require_nonzero_digest(
            "serviceResponse.responseSha256",
            &self.response_sha256,
        )?;
        require_nonzero_digest(
            "serviceResponse.frameSha256",
            &self.frame_sha256,
        )?;
        let canonical_response = self.canonical_response()?;
        if &self.request_binding != request
            || self.response_sha256
                != Sha256Digest::compute(&canonical_response)
            || self.frame_sha256 != self.computed_frame_sha256()?
        {
            return Err(ServiceError::Invalid(
                "service response does not echo the exact request id, deadline, idempotency key, payload, and current head",
            ));
        }
        Ok(())
    }

    pub(super) fn decode_payload<T>(
        &self,
    ) -> Result<T, ServiceError>
    where
        T: DeserializeOwned + Serialize,
    {
        decode_canonical_frame(&self.canonical_response()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct ServiceHandshakeRequestV3 {
    pub(in crate::policy_shadow::policy_custody) api_version: String,
    pub(in crate::policy_shadow::policy_custody)
        service_role: TrustedHostServiceRoleV3,
    pub(in crate::policy_shadow::policy_custody)
        request_id_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        handshake_nonce_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        client_process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        client_configuration_generation_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        deadline: ProtocolBoottimeDeadline,
    pub(in crate::policy_shadow::policy_custody)
        expected_current_head: ServiceCurrentHeadBindingV3,
    pub(in crate::policy_shadow::policy_custody)
        request_rights_count: u8,
    pub(in crate::policy_shadow::policy_custody)
        reply_rights_count: u8,
    pub(in crate::policy_shadow::policy_custody)
        request_sha256: Sha256Digest,
}

impl ServiceHandshakeRequestV3 {
    pub(super) fn new(
        service_role: TrustedHostServiceRoleV3,
        request_id_sha256: Sha256Digest,
        handshake_nonce_sha256: Sha256Digest,
        client_process_identity_sha256: Sha256Digest,
        client_configuration_generation_sha256: Sha256Digest,
        deadline: ProtocolBoottimeDeadline,
        expected_current_head: ServiceCurrentHeadBindingV3,
        request_rights_count: u8,
        reply_rights_count: u8,
    ) -> Result<Self, ServiceError> {
        let mut request = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            service_role,
            request_id_sha256,
            handshake_nonce_sha256,
            client_process_identity_sha256,
            client_configuration_generation_sha256,
            deadline,
            expected_current_head,
            request_rights_count,
            reply_rights_count,
            request_sha256: Sha256Digest::compute(&[]),
        };
        request.request_sha256 =
            request.computed_request_sha256()?;
        Ok(request)
    }

    fn computed_request_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.request_id_sha256,
            &self.handshake_nonce_sha256,
            &self.client_process_identity_sha256,
            &self.client_configuration_generation_sha256,
            &self.deadline,
            &self.expected_current_head,
            self.request_rights_count,
            self.reply_rights_count,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service handshake request cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(
            SERVICE_HANDSHAKE_REQUEST_DOMAIN,
            &canonical,
        ))
    }

    pub(super) fn validate(
        &self,
        expected_role: TrustedHostServiceRoleV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "serviceHandshake.requestIdSha256",
            &self.request_id_sha256,
        )?;
        require_nonzero_digest(
            "serviceHandshake.handshakeNonceSha256",
            &self.handshake_nonce_sha256,
        )?;
        require_nonzero_digest(
            "serviceHandshake.clientProcessIdentitySha256",
            &self.client_process_identity_sha256,
        )?;
        require_nonzero_digest(
            "serviceHandshake.clientConfigurationGenerationSha256",
            &self.client_configuration_generation_sha256,
        )?;
        require_nonzero_digest(
            "serviceHandshake.requestSha256",
            &self.request_sha256,
        )?;
        self.deadline.to_runtime()?;
        self.expected_current_head
            .validate(expected_endpoint_role, &self.deadline)?;
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.service_role != expected_role
            || usize::from(self.request_rights_count)
                > MAX_SERVICE_RIGHTS
            || usize::from(self.reply_rights_count)
                > MAX_SERVICE_RIGHTS
            || self.request_sha256
                != self.computed_request_sha256()?
        {
            return Err(ServiceError::Invalid(
                "service handshake request is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow::policy_custody) struct ServiceHandshakeReplyV3 {
    pub(in crate::policy_shadow::policy_custody) api_version: String,
    pub(in crate::policy_shadow::policy_custody)
        service_role: TrustedHostServiceRoleV3,
    pub(in crate::policy_shadow::policy_custody)
        request_id_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        handshake_nonce_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        request_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        deadline: ProtocolBoottimeDeadline,
    pub(in crate::policy_shadow::policy_custody)
        current_head: ServiceCurrentHeadBindingV3,
    pub(in crate::policy_shadow::policy_custody)
        service_process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody)
        accepted_request_rights_count: u8,
    pub(in crate::policy_shadow::policy_custody)
        accepted_reply_rights_count: u8,
    pub(in crate::policy_shadow::policy_custody) trusted_host_report:
        TrustedHostNoTeeServiceReportV3,
    pub(in crate::policy_shadow::policy_custody)
        reply_sha256: Sha256Digest,
}

impl ServiceHandshakeReplyV3 {
    pub(super) fn for_request(
        request: &ServiceHandshakeRequestV3,
        service_process_identity_sha256: Sha256Digest,
        trusted_host_report: TrustedHostNoTeeServiceReportV3,
    ) -> Result<Self, ServiceError> {
        let mut reply = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            service_role: request.service_role,
            request_id_sha256: request.request_id_sha256.clone(),
            handshake_nonce_sha256:
                request.handshake_nonce_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            deadline: request.deadline.clone(),
            current_head: request.expected_current_head.clone(),
            service_process_identity_sha256,
            accepted_request_rights_count:
                request.request_rights_count,
            accepted_reply_rights_count: request.reply_rights_count,
            trusted_host_report,
            reply_sha256: Sha256Digest::compute(&[]),
        };
        reply.reply_sha256 = reply.computed_reply_sha256()?;
        Ok(reply)
    }

    fn computed_reply_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = canonical_json_bytes(&(
            &self.api_version,
            self.service_role,
            &self.request_id_sha256,
            &self.handshake_nonce_sha256,
            &self.request_sha256,
            &self.deadline,
            &self.current_head,
            &self.service_process_identity_sha256,
            self.accepted_request_rights_count,
            self.accepted_reply_rights_count,
            &self.trusted_host_report,
        ))
        .map_err(|_| {
            ServiceError::Invalid(
                "service handshake reply cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(
            SERVICE_HANDSHAKE_REPLY_DOMAIN,
            &canonical,
        ))
    }

    pub(in crate::policy_shadow::policy_custody) fn validate_for_request(
        &self,
        request: &ServiceHandshakeRequestV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    ) -> Result<(), ServiceError> {
        request.validate(request.service_role, expected_endpoint_role)?;
        self.current_head
            .validate(expected_endpoint_role, &self.deadline)?;
        self.trusted_host_report
            .validate_for_role(request.service_role)?;
        require_nonzero_digest(
            "serviceHandshakeReply.serviceProcessIdentitySha256",
            &self.service_process_identity_sha256,
        )?;
        require_nonzero_digest(
            "serviceHandshakeReply.replySha256",
            &self.reply_sha256,
        )?;
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.service_role != request.service_role
            || self.request_id_sha256 != request.request_id_sha256
            || self.handshake_nonce_sha256
                != request.handshake_nonce_sha256
            || self.request_sha256 != request.request_sha256
            || self.deadline != request.deadline
            || self.current_head != request.expected_current_head
            || self.service_process_identity_sha256
                != self
                    .trusted_host_report
                    .service_process_identity_sha256
            || self.accepted_request_rights_count
                != request.request_rights_count
            || self.accepted_reply_rights_count
                != request.reply_rights_count
            || self.reply_sha256 != self.computed_reply_sha256()?
        {
            return Err(ServiceError::Invalid(
                "service handshake reply does not bind the exact role, request, deadline, current head, rights contract, and software authority",
            ));
        }
        Ok(())
    }
}

/// Performs one bounded client-side handshake without taking ownership of the
/// connected socket. The caller can reuse that exact open-file description to
/// construct the role client after this returns.
pub(super) fn perform_client_handshake(
    socket: BorrowedFd<'_>,
    request: &ServiceHandshakeRequestV3,
    expected_service_role: TrustedHostServiceRoleV3,
    expected_endpoint_role: PolicyCustodyEndpointRole,
    expected_peer_path: &Path,
    expected_peer: ExpectedPeerCredentials,
    exact_request_rights_count: u8,
    exact_reply_rights_count: u8,
) -> Result<ServiceHandshakeReplyV3, ServiceError> {
    validate_connected_unix_seqpacket(socket.as_raw_fd())?;
    let authenticated = AuthenticatedInheritedSeqpacket::from_inherited(
        duplicate_cloexec(socket.as_raw_fd())?,
        expected_peer,
    )?;
    perform_authenticated_client_handshake(&authenticated,request,expected_service_role,
        expected_endpoint_role,expected_peer_path,exact_request_rights_count,exact_reply_rights_count)
}

/// Reuse the exact retained socket/inspection owner. Native callers cannot
/// recreate a direct-proc owner after privilege drop merely for the handshake.
pub(super) fn perform_authenticated_client_handshake(
    authenticated:&AuthenticatedInheritedSeqpacket,request:&ServiceHandshakeRequestV3,
    expected_service_role:TrustedHostServiceRoleV3,expected_endpoint_role:PolicyCustodyEndpointRole,
    expected_peer_path:&Path,exact_request_rights_count:u8,exact_reply_rights_count:u8,
)->Result<ServiceHandshakeReplyV3,ServiceError> {
    authenticated.revalidate_peer()?;
    let socket=authenticated.progress_fd();
    validate_exact_peer_path(
        socket.as_raw_fd(),
        expected_peer_path,
    )?;
    request.validate(
        expected_service_role,
        expected_endpoint_role,
    )?;
    if request.request_rights_count
            != exact_request_rights_count
        || request.reply_rights_count
            != exact_reply_rights_count
    {
        return Err(ServiceError::Invalid(
            "client handshake rights counts do not match the exact role contract",
        ));
    }
    request.deadline.to_runtime()?.require_live().map_err(|_| {
        ServiceError::Invalid(
            "client handshake deadline is not live",
        )
    })?;
    let exact_request = encode_canonical_frame(request)?;
    loop {
        request.deadline.to_runtime()?.require_live().map_err(|_|ServiceError::Invalid("client handshake deadline expired"))?;
        if authenticated.try_send(&exact_request,&[],0)? {break;}
        wait_for_handshake_io(
            socket.as_raw_fd(),
            libc::POLLOUT,
            request.deadline.absolute_boottime_nanos(),
        )?;
    }
    let packet = loop {
        request.deadline.to_runtime()?.require_live().map_err(|_|ServiceError::Invalid("client handshake deadline expired"))?;
        if let Some(packet) = authenticated.try_receive(0)? {
            break packet;
        }
        wait_for_handshake_io(
            socket.as_raw_fd(),
            libc::POLLIN,
            request.deadline.absolute_boottime_nanos(),
        )?;
    };
    let reply: ServiceHandshakeReplyV3 =
        decode_canonical_frame(&packet.frame)?;
    request.deadline.to_runtime()?.require_live().map_err(|_|ServiceError::Invalid("client handshake deadline expired"))?;
    reply.validate_for_request(request, expected_endpoint_role)?;
    authenticated.revalidate_peer()?;
    if reply.service_role != expected_service_role
        || reply.service_process_identity_sha256
            != *authenticated.peer_process_identity_sha256()
        || reply
            .trusted_host_report
            .service_process_identity_sha256
            != *authenticated.peer_process_identity_sha256()
        || reply.accepted_request_rights_count
            != exact_request_rights_count
        || reply.accepted_reply_rights_count
            != exact_reply_rights_count
    {
        return Err(ServiceError::Invalid(
            "client handshake reply changed the exact role or rights contract",
        ));
    }
    Ok(reply)
}

fn wait_for_handshake_io(
    fd: RawFd,
    events: libc::c_short,
    deadline_nanos: u64,
) -> Result<(), ServiceError> {
    let now = boottime_now_nanos().map_err(|_| {
        ServiceError::Invalid(
            "client handshake lacks CLOCK_BOOTTIME",
        )
    })?;
    if now >= deadline_nanos {
        return Err(ServiceError::Invalid(
            "client handshake crossed its exact deadline",
        ));
    }
    let remaining_millis = deadline_nanos
        .saturating_sub(now)
        .saturating_add(999_999)
        / 1_000_000;
    let timeout = i32::try_from(remaining_millis.min(1_000))
        .map_err(|_| {
            ServiceError::Invalid(
                "client handshake poll timeout overflowed",
            )
        })?;
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let ready = loop {
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
    if ready > 0
        && descriptor.revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
    {
        return Err(ServiceError::Invalid(
            "client handshake socket failed while waiting",
        ));
    }
    Ok(())
}

pub(super) fn validate_exact_peer_path(
    fd: RawFd,
    expected_path: &Path,
) -> Result<(), ServiceError> {
    let expected = expected_path.as_os_str().as_bytes();
    if !expected_path.is_absolute()
        || expected.is_empty()
        || expected.contains(&0)
    {
        return Err(ServiceError::Invalid(
            "client handshake expected peer path is invalid",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut length =
        size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let base = (&address as *const libc::sockaddr_un) as usize;
    let path_start = (&address.sun_path as *const _) as usize;
    let path_offset = path_start.checked_sub(base).ok_or(
        ServiceError::Invalid(
            "client handshake sockaddr_un path offset is invalid",
        ),
    )?;
    let exact_length = path_offset
        .checked_add(expected.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(ServiceError::Invalid(
            "client handshake peer path length overflowed",
        ))?;
    if expected.len() >= address.sun_path.len()
        || address.sun_family as i32 != libc::AF_UNIX
        || length as usize != exact_length
        || address.sun_path[0] == 0
    {
        return Err(ServiceError::Invalid(
            "client handshake peer is unnamed, abstract, truncated, or not the exact configured pathname",
        ));
    }
    let observed = unsafe {
        std::slice::from_raw_parts(
            address.sun_path.as_ptr().cast::<u8>(),
            expected.len() + 1,
        )
    };
    if &observed[..expected.len()] != expected
        || observed[expected.len()] != 0
    {
        return Err(ServiceError::Invalid(
            "client handshake peer pathname differs from configuration",
        ));
    }
    Ok(())
}

pub(in crate::policy_shadow::policy_custody) fn encode_canonical_frame<T>(
    value: &T,
) -> Result<Vec<u8>, ServiceError>
where
    T: Serialize,
{
    encode_canonical_value_bounded(value, MAX_SERVICE_FRAME_BYTES)
}

fn encode_canonical_value_bounded<T>(
    value: &T,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ServiceError>
where
    T: Serialize,
{
    let frame = canonical_json_bytes(value).map_err(|_| {
        ServiceError::Invalid("service frame cannot be canonicalized")
    })?;
    if frame.is_empty() || frame.len() > maximum_bytes {
        return Err(ServiceError::Invalid(
            "canonical service frame exceeds its fixed bound",
        ));
    }
    Ok(frame)
}

pub(in crate::policy_shadow::policy_custody) fn decode_canonical_frame<T>(
    frame: &[u8],
) -> Result<T, ServiceError>
where
    T: DeserializeOwned + Serialize,
{
    decode_canonical_value_bounded(frame, MAX_SERVICE_FRAME_BYTES)
}

fn decode_canonical_value_bounded<T>(
    frame: &[u8],
    maximum_bytes: usize,
) -> Result<T, ServiceError>
where
    T: DeserializeOwned + Serialize,
{
    if frame.is_empty() || frame.len() > maximum_bytes {
        return Err(ServiceError::Invalid(
            "service frame exceeds its fixed bound",
        ));
    }
    let value: T = serde_json::from_slice(frame).map_err(|_| {
        ServiceError::Invalid(
            "service frame is not valid typed JSON",
        )
    })?;
    if encode_canonical_value_bounded(&value, maximum_bytes)?
        != frame
    {
        return Err(ServiceError::Invalid(
            "service frame is not exact canonical JSON",
        ));
    }
    Ok(value)
}

fn decode_canonical_base64(
    encoded: &str,
    maximum_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, ServiceError> {
    if encoded.is_empty()
        || encoded.len()
            > maximum_bytes.saturating_mul(2)
    {
        return Err(ServiceError::InvalidOwned(format!(
            "{label} encoding exceeds its fixed bound"
        )));
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        ServiceError::InvalidOwned(format!(
            "{label} is not canonical base64url"
        ))
    })?;
    if decoded.is_empty()
        || decoded.len() > maximum_bytes
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(ServiceError::InvalidOwned(format!(
            "{label} is empty, oversized, or noncanonical"
        )));
    }
    Ok(decoded)
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> Sha256Digest {
    hash_domain_frames(domain, &[payload])
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PeerCredentialsV3 {
    pub(super) pid: i32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow::policy_custody) struct ExpectedPeerCredentials {
    pub(in crate::policy_shadow::policy_custody) pid: i32,
    pub(in crate::policy_shadow::policy_custody) uid: u32,
    pub(in crate::policy_shadow::policy_custody) gid: u32,
    pub(in crate::policy_shadow::policy_custody) process_identity_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) start_time_ticks: u64,
    pub(in crate::policy_shadow::policy_custody) executable_device: u64,
    pub(in crate::policy_shadow::policy_custody) executable_inode: u64,
    pub(in crate::policy_shadow::policy_custody) executable_length: u64,
    pub(in crate::policy_shadow::policy_custody) executable_sha256: [u8; 32],
    pub(in crate::policy_shadow::policy_custody) cgroup_path_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) cgroup_mount_id: u64,
    pub(in crate::policy_shadow::policy_custody) cgroup_inode: u64,
    pub(in crate::policy_shadow::policy_custody) security_label_sha256: Sha256Digest,
    pub(in crate::policy_shadow::policy_custody) configuration_generation_sha256: Sha256Digest,
}

impl ExpectedPeerCredentials {
    pub(super) fn computed_process_identity_sha256(
        &self,
    ) -> Sha256Digest {
        hash_domain_frames(
            PEER_PROCESS_IDENTITY_DOMAIN,
            &[
                &self.uid.to_be_bytes(),
                &self.gid.to_be_bytes(),
                &self.pid.to_be_bytes(),
                &self.start_time_ticks.to_be_bytes(),
                &self.executable_device.to_be_bytes(),
                &self.executable_inode.to_be_bytes(),
                &self.executable_length.to_be_bytes(),
                &self.executable_sha256,
                self.cgroup_path_sha256.as_str().as_bytes(),
                &self.cgroup_mount_id.to_be_bytes(),
                &self.cgroup_inode.to_be_bytes(),
                self.security_label_sha256.as_str().as_bytes(),
                self.configuration_generation_sha256
                    .as_str()
                    .as_bytes(),
            ],
        )
    }

    pub(in crate::policy_shadow::policy_custody) fn validate_claim(&self) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "expectedPeer.processIdentitySha256",
            &self.process_identity_sha256,
        )?;
        require_nonzero_digest(
            "expectedPeer.cgroupPathSha256",
            &self.cgroup_path_sha256,
        )?;
        require_nonzero_digest(
            "expectedPeer.securityLabelSha256",
            &self.security_label_sha256,
        )?;
        require_nonzero_digest(
            "expectedPeer.configurationGenerationSha256",
            &self.configuration_generation_sha256,
        )?;
        if self.process_identity_sha256
            != self.computed_process_identity_sha256()
            || self.cgroup_mount_id == 0
            || self.cgroup_inode == 0
        {
            return Err(ServiceError::Invalid(
                "configured peer process identity digest does not bind the exact credential, start-time, and executable measurements",
            ));
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        observed: PeerCredentialsV3,
    ) -> Result<(), ServiceError> {
        self.validate_claim()?;
        if self.pid <= 0
            || observed.pid <= 0
            || observed.uid != self.uid
            || observed.gid != self.gid
            || self.pid != observed.pid
            || self.start_time_ticks == 0
            || self.executable_device == 0
            || self.executable_inode == 0
            || self.executable_length == 0
            || self.executable_length > MAX_EXECUTABLE_BYTES
            || self.executable_sha256 == [0_u8; 32]
        {
            return Err(ServiceError::Invalid(
                "SO_PEERCRED or configured process identity does not match the exact service peer",
            ));
        }
        Ok(())
    }
}

pub(in crate::policy_shadow::policy_custody) struct ReceivedSeqpacket {
    pub(in crate::policy_shadow::policy_custody) frame: Vec<u8>,
    pub(in crate::policy_shadow::policy_custody) rights: Vec<OwnedFd>,
}

#[repr(align(16))]
struct AncillaryBuffer([u8; 512]);

/// A connected, inherited service socket. Construction rejects listeners,
/// streams, non-UNIX sockets, and peers outside the configured uid/gid/pid.
pub(in crate::policy_shadow::policy_custody) struct AuthenticatedInheritedSeqpacket {
    socket: OwnedFd,
    peer_credentials: PeerCredentialsV3,
    peer_pidfd: OwnedFd,
    peer_start_time_ticks: u64,
    inspection: PeerInspection,
    peer_process_identity_sha256: Sha256Digest,
    peer_configuration_generation_sha256: Sha256Digest,
}

enum PeerInspection {
    Direct(DirectPeerInspection),
    Retained(std::sync::Arc<super::guest::ordinary_inspection::client::Session>),
    NativeFacade(std::sync::Arc<super::guest::native_guest::proof_client::FacadeSession>),
    NativeReceiver(std::sync::Arc<super::native_facade_lifecycle::facade::Session>),
}

struct DirectPeerInspection {
    peer_executable: OwnedFd,
    peer_executable_identity: PeerExecutableIdentity,
    peer_executable_sha256: [u8; 32],
    peer_cgroup_identity: PeerCgroupIdentity,
    peer_security_label_sha256: Sha256Digest,
}

impl AuthenticatedInheritedSeqpacket {
    pub(super) fn from_native_receiver(socket:OwnedFd,expected:ExpectedPeerCredentials,
        inspection:std::sync::Arc<super::native_facade_lifecycle::facade::Session>)->Result<Self,ServiceError>{
        validate_connected_unix_seqpacket(socket.as_raw_fd())?;set_nonblocking_cloexec(socket.as_raw_fd())?;
        enable_passcred(socket.as_raw_fd())?;
        let peer_credentials=read_peer_credentials(socket.as_raw_fd())?;expected.validate(peer_credentials)?;
        let peer_pidfd=peer_pidfd(socket.as_raw_fd())?;require_live_pidfd(peer_pidfd.as_raw_fd(),peer_credentials.pid)?;
        inspection.require_expected(&expected).map_err(|_|ServiceError::Invalid("native receiver scope differs"))?;
        let owner=Self{socket,peer_credentials,peer_pidfd,peer_start_time_ticks:expected.start_time_ticks,
            peer_process_identity_sha256:expected.process_identity_sha256,
            peer_configuration_generation_sha256:expected.configuration_generation_sha256,
            inspection:PeerInspection::NativeReceiver(inspection)};
        owner.revalidate_peer()?;Ok(owner)
    }
    /// Only the retained same-child lifecycle source can select these measured
    /// fields. The result is then admitted by the unchanged full direct checks.
    pub(super) fn measure_native_driver(socket:OwnedFd,
        source:&super::guest::native_guest::driver_lifecycle::facade::Source)
        ->Result<(super::ExpectedPeerCredentialV3,Self),ServiceError>{
        source.check().map_err(|_|ServiceError::Invalid("native driver source is unavailable"))?;
        let credentials=read_peer_credentials(socket.as_raw_fd())?;
        source.require_process(credentials.pid,credentials.uid,credentials.gid)
            .map_err(|_|ServiceError::Invalid("native driver peer is outside retained child"))?;
        let executable=open_process_executable(credentials.pid)?;
        let identity=peer_executable_identity(executable.as_raw_fd())?;
        let group=process_cgroup_identity(credentials.pid)?;
        let mut expected=ExpectedPeerCredentials{pid:credentials.pid,uid:credentials.uid,gid:credentials.gid,
            process_identity_sha256:Sha256Digest::compute(&[]),start_time_ticks:process_start_time_ticks(credentials.pid)?,
            executable_device:identity.device,executable_inode:identity.inode,executable_length:identity.length,
            executable_sha256:sha256_descriptor(executable.as_raw_fd(),identity.length)?,
            cgroup_path_sha256:group.path_sha256,cgroup_mount_id:group.mount_id,cgroup_inode:group.inode,
            security_label_sha256:peer_security_label_sha256(socket.as_raw_fd())?,
            configuration_generation_sha256:source.configuration_generation().clone()};
        expected.process_identity_sha256=expected.computed_process_identity_sha256();
        source.require_expected(&expected).map_err(|_|ServiceError::Invalid("native driver observed identity differs"))?;
        let original=super::ExpectedPeerCredentialV3{pid:expected.pid,uid:expected.uid,gid:expected.gid,
            process_identity_sha256:expected.process_identity_sha256.clone(),start_time_ticks:expected.start_time_ticks,
            executable_device:expected.executable_device,executable_inode:expected.executable_inode,executable_length:expected.executable_length,
            executable_sha256:Sha256Digest::parse(format!("sha256:{}",hex::encode(expected.executable_sha256)))
                .map_err(|_|ServiceError::Invalid("native executable digest differs"))?,
            cgroup_path_sha256:expected.cgroup_path_sha256.clone(),cgroup_mount_id:expected.cgroup_mount_id,cgroup_inode:expected.cgroup_inode,
            security_label_sha256:expected.security_label_sha256.clone(),configuration_generation_sha256:expected.configuration_generation_sha256.clone()};
        let session=Self::from_inherited_direct(socket,expected)?;
        source.check().map_err(|_|ServiceError::Invalid("native driver source changed"))?;Ok((original,session))
    }
    /// Only a live full-admission bridge's retained parent-inspection owner
    /// can construct this branch. No JSON verdict or generic inspector callback.
    pub(super) fn from_native_facade(
        socket: OwnedFd, expected_peer: ExpectedPeerCredentials,
        inspection: std::sync::Arc<super::guest::native_guest::proof_client::FacadeSession>,
    ) -> Result<Self, ServiceError> {
        validate_connected_unix_seqpacket(socket.as_raw_fd())?;
        set_nonblocking_cloexec(socket.as_raw_fd())?;
        enable_passcred(socket.as_raw_fd())?;
        let peer_credentials=read_peer_credentials(socket.as_raw_fd())?;
        expected_peer.validate(peer_credentials)?;
        let peer_pidfd=peer_pidfd(socket.as_raw_fd())?;
        require_live_pidfd(peer_pidfd.as_raw_fd(),peer_credentials.pid)?;
        inspection.require_expected(&expected_peer)
            .map_err(|_|ServiceError::Invalid("native facade inspection binding differs"))?;
        let authenticated=Self{socket,peer_credentials,peer_pidfd,
            peer_start_time_ticks:expected_peer.start_time_ticks,
            peer_process_identity_sha256:expected_peer.process_identity_sha256,
            peer_configuration_generation_sha256:expected_peer.configuration_generation_sha256,
            inspection:PeerInspection::NativeFacade(inspection)};
        authenticated.revalidate_peer()?;
        Ok(authenticated)
    }

    pub(in crate::policy_shadow::policy_custody) fn from_inherited(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
    ) -> Result<Self, ServiceError> {
        Self::admit(socket, expected_peer, true)
    }

    /// Used only by the actual retained privileged inspection worker. This
    /// still executes every original host measurement and never re-enters IPC.
    pub(super) fn from_inherited_direct(
        socket: OwnedFd,
        expected_peer: ExpectedPeerCredentials,
    ) -> Result<Self, ServiceError> {
        Self::admit(socket, expected_peer, false)
    }

    fn admit(socket: OwnedFd, expected_peer: ExpectedPeerCredentials, inspected: bool)
        -> Result<Self, ServiceError> {
        validate_connected_unix_seqpacket(socket.as_raw_fd())?;
        set_nonblocking_cloexec(socket.as_raw_fd())?;
        enable_passcred(socket.as_raw_fd())?;
        let peer_credentials =
            read_peer_credentials(socket.as_raw_fd())?;
        expected_peer.validate(peer_credentials)?;
        let peer_pidfd = peer_pidfd(socket.as_raw_fd())?;
        require_live_pidfd(
            peer_pidfd.as_raw_fd(),
            peer_credentials.pid,
        )?;
        let peer_start_time_ticks =
            process_start_time_ticks(peer_credentials.pid)?;
        if peer_start_time_ticks != expected_peer.start_time_ticks {
            return Err(ServiceError::Invalid(
                "service peer process start time differs from configuration",
            ));
        }
        if inspected {
            if let Some(session) = super::guest::ordinary_inspection::client::bind_if_enabled(
                socket.as_fd(), &expected_peer, peer_pidfd.as_fd(),
            )? {
                let authenticated = Self { socket, peer_credentials, peer_pidfd, peer_start_time_ticks,
                    inspection: PeerInspection::Retained(session),
                    peer_process_identity_sha256: expected_peer.process_identity_sha256,
                    peer_configuration_generation_sha256: expected_peer.configuration_generation_sha256 };
                authenticated.revalidate_peer()?;
                return Ok(authenticated);
            }
        }
        let peer_executable =
            open_process_executable(peer_credentials.pid)?;
        let peer_executable_identity =
            peer_executable_identity(peer_executable.as_raw_fd())?;
        if peer_executable_identity.device
                != expected_peer.executable_device
            || peer_executable_identity.inode
                != expected_peer.executable_inode
            || peer_executable_identity.length
                != expected_peer.executable_length
            || sha256_descriptor(
                peer_executable.as_raw_fd(),
                peer_executable_identity.length,
            )? != expected_peer.executable_sha256
        {
            return Err(ServiceError::Invalid(
                "service peer executable identity differs from configuration",
            ));
        }
        let peer_cgroup_identity =
            process_cgroup_identity(peer_credentials.pid)?;
        if peer_cgroup_identity.path_sha256
                != expected_peer.cgroup_path_sha256
            || peer_cgroup_identity.mount_id
                != expected_peer.cgroup_mount_id
            || peer_cgroup_identity.inode
                != expected_peer.cgroup_inode
        {
            return Err(ServiceError::Invalid(
                "service peer cgroup identity differs from configuration",
            ));
        }
        let peer_security_label_sha256 =
            peer_security_label_sha256(socket.as_raw_fd())?;
        if peer_security_label_sha256
            != expected_peer.security_label_sha256
        {
            return Err(ServiceError::Invalid(
                "service peer SO_PEERSEC label differs from configuration",
            ));
        }
        let authenticated = Self {
            socket,
            peer_credentials,
            peer_pidfd,
            peer_start_time_ticks,
            inspection: PeerInspection::Direct(DirectPeerInspection {
                peer_executable, peer_executable_identity,
                peer_executable_sha256: expected_peer.executable_sha256,
                peer_cgroup_identity, peer_security_label_sha256,
            }),
            peer_process_identity_sha256:
                expected_peer.process_identity_sha256,
            peer_configuration_generation_sha256:
                expected_peer.configuration_generation_sha256,
        };
        authenticated.revalidate_peer()?;
        Ok(authenticated)
    }

    pub(super) fn peer_credentials(
        &self,
    ) -> PeerCredentialsV3 {
        self.peer_credentials
    }

    pub(super) fn peer_process_identity_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.peer_process_identity_sha256
    }

    pub(super) fn peer_configuration_generation_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.peer_configuration_generation_sha256
    }

    pub(in crate::policy_shadow::policy_custody) fn progress_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    pub(in crate::policy_shadow::policy_custody) fn try_send(
        &self,
        frame: &[u8],
        rights: &[OwnedFd],
        exact_rights_count: usize,
    ) -> Result<bool, ServiceError> {
        self.revalidate_peer()?;
        if frame.is_empty()
            || frame.len() > MAX_SERVICE_FRAME_BYTES
            || rights.len() != exact_rights_count
            || rights.len() > MAX_SERVICE_RIGHTS
        {
            return Err(ServiceError::Invalid(
                "outbound service packet violates its exact frame or SCM_RIGHTS bound",
            ));
        }
        let raw_rights: Vec<RawFd> = rights
            .iter()
            .map(|right| right.as_raw_fd())
            .collect();
        try_send_seqpacket_with_rights(
            self.socket.as_raw_fd(),
            frame,
            &raw_rights,
        )
    }

    pub(in crate::policy_shadow::policy_custody) fn try_receive(
        &self,
        exact_rights_count: usize,
    ) -> Result<Option<ReceivedSeqpacket>, ServiceError> {
        self.revalidate_peer()?;
        if exact_rights_count > MAX_SERVICE_RIGHTS {
            return Err(ServiceError::Invalid(
                "inbound SCM_RIGHTS count exceeds its fixed bound",
            ));
        }
        try_receive_seqpacket_with_rights(
            self.socket.as_raw_fd(),
            MAX_SERVICE_FRAME_BYTES,
            exact_rights_count,
            self.peer_credentials,
        )
    }

    /// Fixed native parent inspectors call the SAME actual peer checks before
    /// and after joining a received kernel packet PIDFD. This exposes no
    /// executable descriptor, target selector, or caller-created measurement.
    pub(super) fn revalidate_packet_pidfd(
        &self,
        sender: BorrowedFd<'_>,
    ) -> Result<(), ServiceError> {
        self.revalidate_peer()?;
        require_live_pidfd(sender.as_raw_fd(), self.peer_credentials.pid)?;
        if matches!(&self.inspection,PeerInspection::NativeFacade(_)|PeerInspection::NativeReceiver(_)) {
            return self.revalidate_peer();
        }
        if process_start_time_ticks(self.peer_credentials.pid)? != self.peer_start_time_ticks {
            return Err(ServiceError::Invalid("packet sender start identity changed"));
        }
        self.revalidate_peer()?;
        require_live_pidfd(sender.as_raw_fd(), self.peer_credentials.pid)
    }

    pub(super) fn into_socket(self) -> OwnedFd {
        self.socket
    }

    pub(in crate::policy_shadow::policy_custody) fn revalidate_peer(&self) -> Result<(), ServiceError> {
        let observed = read_peer_credentials(self.socket.as_raw_fd())?;
        if observed != self.peer_credentials {
            return Err(ServiceError::Invalid(
                "connected service peer credentials changed",
            ));
        }
        require_live_pidfd(
            self.peer_pidfd.as_raw_fd(),
            self.peer_credentials.pid,
        )?;
        if let PeerInspection::NativeFacade(session)=&self.inspection {
            return session.revalidate(self.socket.as_fd(),self.peer_pidfd.as_fd())
                .map_err(|_|ServiceError::Invalid("native facade retained inspection refused"));
        }
        if let PeerInspection::NativeReceiver(session)=&self.inspection {
            return session.revalidate(self.socket.as_fd(),self.peer_pidfd.as_fd())
                .map_err(|_|ServiceError::Invalid("native receiver retained inspection refused"));
        }
        if process_start_time_ticks(self.peer_credentials.pid)?
            != self.peer_start_time_ticks
        {
            return Err(ServiceError::Invalid(
                "connected service peer start identity changed",
            ));
        }
        let direct = match &self.inspection {
            PeerInspection::Retained(session) => return session.revalidate(
                self.socket.as_fd(), self.peer_pidfd.as_fd()),
            PeerInspection::Direct(direct) => direct,
            PeerInspection::NativeFacade(_)|PeerInspection::NativeReceiver(_) => return Err(ServiceError::Invalid("native facade inspection state differs")),
        };
        let retained = peer_executable_identity(
            direct.peer_executable.as_raw_fd(),
        )?;
        if retained != direct.peer_executable_identity {
            return Err(ServiceError::Invalid(
                "retained service peer executable changed",
            ));
        }
        let current =
            open_process_executable(self.peer_credentials.pid)?;
        let current_identity =
            peer_executable_identity(current.as_raw_fd())?;
        if current_identity != direct.peer_executable_identity {
            return Err(ServiceError::Invalid(
                "service peer executable was substituted",
            ));
        }
        if process_cgroup_identity(self.peer_credentials.pid)?
                != direct.peer_cgroup_identity
            || peer_security_label_sha256(self.socket.as_raw_fd())?
                != direct.peer_security_label_sha256
        {
            return Err(ServiceError::Invalid(
                "service peer cgroup or SO_PEERSEC identity changed",
            ));
        }
        if self.peer_process_identity_sha256
            != hash_domain_frames(
                PEER_PROCESS_IDENTITY_DOMAIN,
                &[
                    &self.peer_credentials.uid.to_be_bytes(),
                    &self.peer_credentials.gid.to_be_bytes(),
                    &self.peer_credentials.pid.to_be_bytes(),
                    &self.peer_start_time_ticks.to_be_bytes(),
                    &direct.peer_executable_identity.device.to_be_bytes(),
                    &direct.peer_executable_identity.inode.to_be_bytes(),
                    &direct.peer_executable_identity.length.to_be_bytes(),
                    &direct.peer_executable_sha256,
                    direct.peer_cgroup_identity
                        .path_sha256
                        .as_str()
                        .as_bytes(),
                    &direct.peer_cgroup_identity.mount_id.to_be_bytes(),
                    &direct.peer_cgroup_identity.inode.to_be_bytes(),
                    direct.peer_security_label_sha256
                        .as_str()
                        .as_bytes(),
                    self.peer_configuration_generation_sha256
                        .as_str()
                        .as_bytes(),
                ],
            )
        {
            return Err(ServiceError::Invalid(
                "retained service peer identity differs from the authenticated handshake identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerExecutableIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerCgroupIdentity {
    path_sha256: Sha256Digest,
    mount_id: u64,
    inode: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn peer_security_label_sha256(
    socket_fd: RawFd,
) -> Result<Sha256Digest, ServiceError> {
    let mut label = [0_u8; MAX_PEER_SECURITY_LABEL_BYTES];
    let mut length = label.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            label.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(ServiceError::Invalid(
            "Linux SO_PEERSEC is required for service peer authentication",
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        ServiceError::Invalid("SO_PEERSEC label length overflowed")
    })?;
    if length == 0 || length > label.len() {
        return Err(ServiceError::Invalid(
            "SO_PEERSEC returned an empty or oversized label",
        ));
    }
    let mut exact = &label[..length];
    if exact.last() == Some(&0) {
        exact = &exact[..exact.len().saturating_sub(1)];
    }
    if exact.is_empty() || exact.contains(&0) {
        return Err(ServiceError::Invalid(
            "SO_PEERSEC returned a noncanonical security label",
        ));
    }
    Ok(Sha256Digest::compute(exact))
}

fn process_cgroup_identity(
    pid: i32,
) -> Result<PeerCgroupIdentity, ServiceError> {
    let path = CString::new(format!("/proc/{pid}/cgroup"))
        .map_err(|_| {
            ServiceError::Invalid("process cgroup path contains NUL")
        })?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let bytes = read_bounded_descriptor(
        descriptor.as_raw_fd(),
        MAX_PROC_STAT_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        ServiceError::Invalid("process cgroup membership is not UTF-8")
    })?;
    let mut cgroup_path = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("0::") {
            if cgroup_path.is_some()
                || !value.starts_with('/')
                || value.as_bytes().contains(&0)
                || value.split('/').any(|component| {
                    component == "." || component == ".."
                })
            {
                return Err(ServiceError::Invalid(
                    "process cgroup v2 membership is ambiguous or noncanonical",
                ));
            }
            cgroup_path = Some(value.to_owned());
        }
    }
    let cgroup_path = cgroup_path.ok_or(ServiceError::Invalid(
        "process lacks one exact cgroup v2 membership",
    ))?;
    let root_path = CStr::from_bytes_with_nul(b"/sys/fs/cgroup\0")
        .map_err(|_| ServiceError::Invalid("cgroup root is invalid"))?;
    let root = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_PATH
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW,
        )
    };
    if root < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let root = unsafe { OwnedFd::from_raw_fd(root) };
    let relative = cgroup_path.trim_start_matches('/');
    let cgroup = if relative.is_empty() {
        let duplicated = unsafe {
            libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
        };
        if duplicated < 0 {
            return Err(io::Error::last_os_error().into());
        }
        unsafe { OwnedFd::from_raw_fd(duplicated) }
    } else {
        let relative = CString::new(relative).map_err(|_| {
            ServiceError::Invalid("cgroup relative path contains NUL")
        })?;
        let how = OpenHow {
            flags: (libc::O_PATH
                | libc::O_DIRECTORY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: 0x08 | 0x04 | 0x02,
        };
        let opened = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                relative.as_ptr(),
                &how as *const OpenHow,
                size_of::<OpenHow>(),
            )
        };
        if opened < 0 || opened > i64::from(i32::MAX) {
            return Err(ServiceError::Invalid(
                "peer cgroup cannot be retained with openat2",
            ));
        }
        unsafe { OwnedFd::from_raw_fd(opened as RawFd) }
    };
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(cgroup.as_raw_fd(), &mut stat) } != 0
        || stat.st_ino == 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(ServiceError::Invalid(
            "peer cgroup descriptor identity is invalid",
        ));
    }
    let mut statx: libc::statx = unsafe { zeroed() };
    if unsafe {
        libc::statx(
            cgroup.as_raw_fd(),
            CStr::from_bytes_with_nul(b"\0")
                .map_err(|_| {
                    ServiceError::Invalid("empty statx path is invalid")
                })?
                .as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS | 0x00001000,
            &mut statx,
        )
    } != 0
        || statx.stx_mask & 0x00001000 == 0
        || statx.stx_mnt_id == 0
        || statx.stx_ino != stat.st_ino as u64
    {
        return Err(ServiceError::Invalid(
            "peer cgroup mount identity is unavailable",
        ));
    }
    Ok(PeerCgroupIdentity {
        path_sha256: Sha256Digest::compute(cgroup_path.as_bytes()),
        mount_id: statx.stx_mnt_id,
        inode: stat.st_ino as u64,
    })
}

fn peer_pidfd(socket_fd: RawFd) -> Result<OwnedFd, ServiceError> {
    let mut raw_pidfd = -1;
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
        return Err(ServiceError::Invalid(
            "Linux SO_PEERPIDFD is required for service peer authentication",
        ));
    }
    if length as usize != size_of::<libc::c_int>()
        || raw_pidfd < 0
    {
        return Err(ServiceError::Invalid(
            "SO_PEERPIDFD did not return one retained peer pidfd",
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw_pidfd) })
}

fn require_live_pidfd(
    pidfd: RawFd,
    expected_pid: i32,
) -> Result<(), ServiceError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            0,
            ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 || pidfd_process_id(pidfd)? != expected_pid {
        return Err(ServiceError::Invalid(
            "retained service peer pidfd is dead or identifies another process",
        ));
    }
    Ok(())
}

fn pidfd_process_id(pidfd: RawFd) -> Result<i32, ServiceError> {
    let path = CString::new(format!("/proc/self/fdinfo/{pidfd}"))
        .map_err(|_| {
            ServiceError::Invalid("pidfd fdinfo path contains NUL")
        })?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let bytes = read_bounded_descriptor(
        descriptor.as_raw_fd(),
        MAX_PROC_STAT_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        ServiceError::Invalid("pidfd fdinfo is not UTF-8")
    })?;
    let mut parsed = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:\t") {
            if parsed.is_some() {
                return Err(ServiceError::Invalid(
                    "pidfd fdinfo contains duplicate Pid fields",
                ));
            }
            parsed = Some(value.trim().parse::<i32>().map_err(
                |_| {
                    ServiceError::Invalid(
                        "pidfd fdinfo Pid is invalid",
                    )
                },
            )?);
        }
    }
    parsed.filter(|pid| *pid > 0).ok_or(
        ServiceError::Invalid(
            "pidfd does not identify a live service peer",
        ),
    )
}

fn process_start_time_ticks(pid: i32) -> Result<u64, ServiceError> {
    let path = CString::new(format!("/proc/{pid}/stat")).map_err(
        |_| ServiceError::Invalid("process stat path contains NUL"),
    )?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let bytes = read_bounded_descriptor(
        descriptor.as_raw_fd(),
        MAX_PROC_STAT_BYTES,
    )?;
    let stat = std::str::from_utf8(&bytes).map_err(|_| {
        ServiceError::Invalid("process stat is not UTF-8")
    })?;
    let close = stat.rfind(')').ok_or(ServiceError::Invalid(
        "process stat comm field is invalid",
    ))?;
    let start_time = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(ServiceError::Invalid(
            "process stat start identity is missing",
        ))?
        .parse::<u64>()
        .map_err(|_| {
            ServiceError::Invalid(
                "process stat start identity is invalid",
            )
        })?;
    if start_time == 0 {
        return Err(ServiceError::Invalid(
            "process start identity is zero",
        ));
    }
    Ok(start_time)
}

fn open_process_executable(pid: i32) -> Result<OwnedFd, ServiceError> {
    let path = CString::new(format!("/proc/{pid}/exe")).map_err(
        |_| ServiceError::Invalid("process exe path contains NUL"),
    )?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn peer_executable_identity(
    descriptor: RawFd,
) -> Result<PeerExecutableIdentity, ServiceError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(descriptor, &mut stat) } != 0
        || stat.st_ino == 0
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_EXECUTABLE_BYTES
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return Err(ServiceError::Invalid(
            "service peer executable is not a bounded regular file",
        ));
    }
    Ok(PeerExecutableIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        length: stat.st_size as u64,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

fn read_bounded_descriptor(
    descriptor: RawFd,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ServiceError> {
    let capacity = maximum_bytes.checked_add(1).ok_or(
        ServiceError::Invalid(
            "bounded descriptor read capacity overflow",
        ),
    )?;
    let mut bytes = vec![0_u8; capacity];
    let read = unsafe {
        libc::read(
            descriptor,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let read = usize::try_from(read).map_err(|_| {
        ServiceError::Invalid(
            "descriptor read length conversion failed",
        )
    })?;
    if read == 0 || read > maximum_bytes {
        return Err(ServiceError::Invalid(
            "descriptor data is empty or exceeds its fixed bound",
        ));
    }
    bytes.truncate(read);
    Ok(bytes)
}

fn sha256_descriptor(
    descriptor: RawFd,
    length: u64,
) -> Result<[u8; 32], ServiceError> {
    if length == 0 || length > MAX_EXECUTABLE_BYTES {
        return Err(ServiceError::Invalid(
            "executable digest length is invalid",
        ));
    }
    let before = peer_executable_identity(descriptor)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < length {
        let requested = usize::try_from(
            (length - offset).min(buffer.len() as u64),
        )
        .map_err(|_| {
            ServiceError::Invalid(
                "executable digest request length overflow",
            )
        })?;
        let offset_i64 = i64::try_from(offset).map_err(|_| {
            ServiceError::Invalid(
                "executable digest offset overflow",
            )
        })?;
        let read = unsafe {
            libc::pread(
                descriptor,
                buffer.as_mut_ptr().cast(),
                requested,
                offset_i64,
            )
        };
        if read <= 0 {
            return Err(if read < 0 {
                io::Error::last_os_error().into()
            } else {
                ServiceError::Invalid(
                    "executable changed while hashing",
                )
            });
        }
        let read = usize::try_from(read).map_err(|_| {
            ServiceError::Invalid(
                "executable digest read length overflow",
            )
        })?;
        hasher.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or(
            ServiceError::Invalid(
                "executable digest offset overflow",
            ),
        )?;
    }
    if peer_executable_identity(descriptor)? != before {
        return Err(ServiceError::Invalid(
            "executable descriptor changed while hashing",
        ));
    }
    Ok(hasher.finalize().into())
}

pub(super) struct CompletedServiceExchange {
    pub(super) response: ServiceResponseFrameV3,
    pub(super) exact_response_frame: Vec<u8>,
    pub(super) rights: Vec<OwnedFd>,
}

pub(super) enum NonblockingExchangeProgress {
    Pending,
    Complete(CompletedServiceExchange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NonblockingExchangeFlightState {
    Idle,
    ExactRequestNotSent,
    ExactRequestSentAwaitingReply,
}

enum RequestReplyState {
    Idle,
    Sending {
        exact_request_frame: Vec<u8>,
        outbound_rights: Vec<OwnedFd>,
        exact_request_rights_count: usize,
        exact_reply_rights_count: usize,
        request_binding: ServiceRequestBindingV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    },
    Receiving {
        exact_request_frame: Vec<u8>,
        outbound_rights: Vec<OwnedFd>,
        exact_request_rights_count: usize,
        exact_reply_rights_count: usize,
        request_binding: ServiceRequestBindingV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    },
    FailedAfterSend {
        exact_request_frame: Vec<u8>,
        outbound_rights: Vec<OwnedFd>,
        exact_request_rights_count: usize,
        exact_reply_rights_count: usize,
        request_binding: ServiceRequestBindingV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
    },
}

/// Single-flight request/reply progress with no blocking syscall and no
/// self-referential borrows. The exact request and retained rights survive I/O
/// errors in both phases. Callers can therefore distinguish a request that was
/// not sent from an ambiguous request whose reply is still outstanding, and a
/// retry never constructs different bytes.
pub(super) struct NonblockingRequestReplyExchange {
    peer: AuthenticatedInheritedSeqpacket,
    state: RequestReplyState,
}

impl NonblockingRequestReplyExchange {
    pub(super) fn new(
        peer: AuthenticatedInheritedSeqpacket,
    ) -> Self {
        Self {
            peer,
            state: RequestReplyState::Idle,
        }
    }

    pub(super) fn peer_credentials(
        &self,
    ) -> PeerCredentialsV3 {
        self.peer.peer_credentials()
    }

    pub(super) fn is_idle(&self) -> bool {
        matches!(&self.state, RequestReplyState::Idle)
    }

    pub(super) fn flight_state(
        &self,
    ) -> NonblockingExchangeFlightState {
        match &self.state {
            RequestReplyState::Idle => {
                NonblockingExchangeFlightState::Idle
            }
            RequestReplyState::Sending { .. } => {
                NonblockingExchangeFlightState::ExactRequestNotSent
            }
            RequestReplyState::Receiving { .. }
            | RequestReplyState::FailedAfterSend { .. } => {
                NonblockingExchangeFlightState::
                    ExactRequestSentAwaitingReply
            }
        }
    }

    pub(super) fn replace_peer_and_retry_exact_flight(
        &mut self,
        peer: AuthenticatedInheritedSeqpacket,
    ) -> Result<(), ServiceError> {
        let state =
            std::mem::replace(&mut self.state, RequestReplyState::Idle);
        let retry = match state {
            RequestReplyState::Idle => {
                return Err(ServiceError::Invalid(
                    "cannot replace a service peer without an exact flight",
                ))
            }
            RequestReplyState::Sending {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            }
            | RequestReplyState::Receiving {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            }
            | RequestReplyState::FailedAfterSend {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            } => RequestReplyState::Sending {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            },
        };
        self.peer = peer;
        self.state = retry;
        Ok(())
    }

    pub(super) fn begin(
        &mut self,
        request: &ServiceRequestFrameV3,
        expected_role: TrustedHostServiceRoleV3,
        expected_endpoint_role: PolicyCustodyEndpointRole,
        outbound_rights: &[BorrowedFd<'_>],
        exact_request_rights_count: usize,
        exact_reply_rights_count: usize,
    ) -> Result<(), ServiceError> {
        if !self.is_idle() {
            return Err(ServiceError::Invalid(
                "a service exchange is already in flight",
            ));
        }
        request.validate(expected_role, expected_endpoint_role)?;
        if outbound_rights.len() != exact_request_rights_count
            || exact_request_rights_count > MAX_SERVICE_RIGHTS
            || exact_reply_rights_count > MAX_SERVICE_RIGHTS
        {
            return Err(ServiceError::Invalid(
                "service exchange SCM_RIGHTS contract is inconsistent",
            ));
        }
        let mut retained_rights =
            Vec::with_capacity(outbound_rights.len());
        for descriptor in outbound_rights {
            retained_rights.push(duplicate_cloexec(
                descriptor.as_raw_fd(),
            )?);
        }
        self.state = RequestReplyState::Sending {
            exact_request_frame: encode_canonical_frame(request)?,
            outbound_rights: retained_rights,
            exact_request_rights_count,
            exact_reply_rights_count,
            request_binding: request.binding.clone(),
            expected_endpoint_role,
        };
        Ok(())
    }

    pub(super) fn try_progress(
        &mut self,
    ) -> Result<NonblockingExchangeProgress, ServiceError> {
        let state =
            std::mem::replace(&mut self.state, RequestReplyState::Idle);
        match state {
            RequestReplyState::Idle => Err(ServiceError::Invalid(
                "no service exchange is in flight",
            )),
            RequestReplyState::Sending {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            } => {
                let sent = match self.peer.try_send(
                    &exact_request_frame,
                    &outbound_rights,
                    exact_request_rights_count,
                ) {
                    Ok(sent) => sent,
                    Err(error) => {
                        self.state = RequestReplyState::Sending {
                            exact_request_frame,
                            outbound_rights,
                            exact_request_rights_count,
                            exact_reply_rights_count,
                            request_binding,
                            expected_endpoint_role,
                        };
                        return Err(error);
                    }
                };
                if !sent {
                    self.state = RequestReplyState::Sending {
                        exact_request_frame,
                        outbound_rights,
                        exact_request_rights_count,
                        exact_reply_rights_count,
                        request_binding,
                        expected_endpoint_role,
                    };
                    return Ok(
                        NonblockingExchangeProgress::Pending,
                    );
                }
                self.state = RequestReplyState::Receiving {
                    exact_request_frame,
                    outbound_rights,
                    exact_request_rights_count,
                    exact_reply_rights_count,
                    request_binding,
                    expected_endpoint_role,
                };
                Ok(NonblockingExchangeProgress::Pending)
            }
            RequestReplyState::Receiving {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            } => {
                let packet = match self
                    .peer
                    .try_receive(exact_reply_rights_count)
                {
                    Ok(packet) => packet,
                    Err(error) => {
                        self.state = RequestReplyState::Receiving {
                            exact_request_frame,
                            outbound_rights,
                            exact_request_rights_count,
                            exact_reply_rights_count,
                            request_binding,
                            expected_endpoint_role,
                        };
                        return Err(error);
                    }
                };
                let Some(packet) = packet else {
                    self.state = RequestReplyState::Receiving {
                        exact_request_frame,
                        outbound_rights,
                        exact_request_rights_count,
                        exact_reply_rights_count,
                        request_binding,
                        expected_endpoint_role,
                    };
                    return Ok(
                        NonblockingExchangeProgress::Pending,
                    );
                };
                let response: ServiceResponseFrameV3 =
                    match decode_canonical_frame(&packet.frame) {
                        Ok(response) => response,
                        Err(error) => {
                            self.state =
                                RequestReplyState::FailedAfterSend {
                                    exact_request_frame,
                                    outbound_rights,
                                    exact_request_rights_count,
                                    exact_reply_rights_count,
                                    request_binding,
                                    expected_endpoint_role,
                                };
                            return Err(error);
                        }
                    };
                if let Err(error) = response.validate_for_request(
                    &request_binding,
                    expected_endpoint_role,
                ) {
                    self.state =
                        RequestReplyState::FailedAfterSend {
                            exact_request_frame,
                            outbound_rights,
                            exact_request_rights_count,
                            exact_reply_rights_count,
                            request_binding,
                            expected_endpoint_role,
                        };
                    return Err(error);
                }
                Ok(NonblockingExchangeProgress::Complete(
                    CompletedServiceExchange {
                        response,
                        exact_response_frame: packet.frame,
                        rights: packet.rights,
                    },
                ))
            }
            RequestReplyState::FailedAfterSend {
                exact_request_frame,
                outbound_rights,
                exact_request_rights_count,
                exact_reply_rights_count,
                request_binding,
                expected_endpoint_role,
            } => {
                self.state = RequestReplyState::FailedAfterSend {
                    exact_request_frame,
                    outbound_rights,
                    exact_request_rights_count,
                    exact_reply_rights_count,
                    request_binding,
                    expected_endpoint_role,
                };
                Err(ServiceError::Invalid(
                    "service exchange received an invalid reply after sending the exact request",
                ))
            }
        }
    }
}

fn validate_connected_unix_seqpacket(
    fd: RawFd,
) -> Result<(), ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "inherited service descriptor is invalid",
        ));
    }
    let socket_type = get_socket_int(fd, libc::SO_TYPE)?;
    let accepting = get_socket_int(fd, libc::SO_ACCEPTCONN)?;
    let mut peer_address: libc::sockaddr_storage =
        unsafe { zeroed() };
    let mut peer_length =
        size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            &mut peer_address as *mut libc::sockaddr_storage
                as *mut libc::sockaddr,
            &mut peer_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if socket_type != libc::SOCK_SEQPACKET
        || accepting != 0
        || (peer_length as usize)
            < size_of::<libc::sa_family_t>()
        || peer_address.ss_family as i32 != libc::AF_UNIX
    {
        return Err(ServiceError::Invalid(
            "inherited service descriptor is not a connected AF_UNIX SOCK_SEQPACKET peer",
        ));
    }
    Ok(())
}

fn get_socket_int(
    fd: RawFd,
    option: libc::c_int,
) -> Result<libc::c_int, ServiceError> {
    let mut value: libc::c_int = 0;
    let mut length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(ServiceError::Invalid(
            "socket option returned an invalid length",
        ));
    }
    Ok(value)
}

fn read_peer_credentials(
    fd: RawFd,
) -> Result<PeerCredentialsV3, ServiceError> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length =
        size_of::<libc::ucred>() as libc::socklen_t;
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
    if length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(ServiceError::Invalid(
            "SO_PEERCRED returned an invalid credential",
        ));
    }
    Ok(PeerCredentialsV3 {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn set_nonblocking_cloexec(fd: RawFd) -> Result<(), ServiceError> {
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe {
        libc::fcntl(fd, libc::F_SETFL, status | libc::O_NONBLOCK)
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor_flags =
        unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_SETFD,
            descriptor_flags | libc::FD_CLOEXEC,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn enable_passcred(fd: RawFd) -> Result<(), ServiceError> {
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if get_socket_int(fd, libc::SO_PASSCRED)? != 1 {
        return Err(ServiceError::Invalid(
            "service socket did not retain SO_PASSCRED",
        ));
    }
    Ok(())
}

fn duplicate_cloexec(fd: RawFd) -> Result<OwnedFd, ServiceError> {
    if fd < 0 {
        return Err(ServiceError::Invalid(
            "cannot retain an invalid descriptor",
        ));
    }
    let duplicate =
        unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn try_send_seqpacket_with_rights(
    socket_fd: RawFd,
    frame: &[u8],
    rights: &[RawFd],
) -> Result<bool, ServiceError> {
    let mut vector = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    let mut ancillary = AncillaryBuffer([0; 512]);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !rights.is_empty() {
        if rights.len() > MAX_SERVICE_RIGHTS
            || rights.iter().any(|descriptor| *descriptor < 0)
        {
            return Err(ServiceError::Invalid(
                "outbound SCM_RIGHTS set is invalid",
            ));
        }
        let rights_bytes = rights
            .len()
            .checked_mul(size_of::<RawFd>())
            .ok_or(ServiceError::Invalid(
                "outbound SCM_RIGHTS length overflow",
            ))?;
        let rights_bytes_u32 =
            libc::c_uint::try_from(rights_bytes).map_err(|_| {
                ServiceError::Invalid(
                    "outbound SCM_RIGHTS length is invalid",
                )
            })?;
        let control_length =
            unsafe { libc::CMSG_SPACE(rights_bytes_u32) } as usize;
        if control_length > ancillary.0.len() {
            return Err(ServiceError::Invalid(
                "outbound SCM_RIGHTS exceeds its fixed buffer",
            ));
        }
        message.msg_control = ancillary.0.as_mut_ptr().cast();
        message.msg_controllen = control_length;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(ServiceError::Invalid(
                "outbound SCM_RIGHTS header is unavailable",
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
            return Ok(true);
        }
        if sent >= 0 {
            return Err(ServiceError::Invalid(
                "SOCK_SEQPACKET send was not atomic",
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

fn try_receive_seqpacket_with_rights(
    socket_fd: RawFd,
    maximum_frame_bytes: usize,
    exact_rights_count: usize,
    expected_credentials: PeerCredentialsV3,
) -> Result<Option<ReceivedSeqpacket>, ServiceError> {
    let mut frame = vec![0_u8; maximum_frame_bytes];
    let mut vector = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut ancillary = AncillaryBuffer([0; 512]);
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
            "service peer closed without a reply",
        ));
    }
    let rights =
        received_rights(&message, expected_credentials)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(ServiceError::Invalid(
            "service packet or ancillary data was truncated",
        ));
    }
    let received = usize::try_from(received).map_err(|_| {
        ServiceError::Invalid(
            "service packet length conversion failed",
        )
    })?;
    if received > maximum_frame_bytes {
        return Err(ServiceError::Invalid(
            "service packet exceeds its fixed frame bound",
        ));
    }
    frame.truncate(received);

    if rights.len() != exact_rights_count {
        return Err(ServiceError::Invalid(
            "service packet SCM_RIGHTS count does not match the exact operation contract",
        ));
    }
    Ok(Some(ReceivedSeqpacket { frame, rights }))
}

fn received_rights(
    message: &libc::msghdr,
    expected_credentials: PeerCredentialsV3,
) -> Result<Vec<OwnedFd>, ServiceError> {
    let mut rights = Vec::new();
    let mut ancillary_messages = 0_usize;
    let mut credentials_seen = false;
    let mut validation_error: Option<&'static str> = None;
    let control_start = message.msg_control as usize;
    let control_end = control_start
        .checked_add(message.msg_controllen)
        .ok_or(ServiceError::Invalid(
            "service ancillary buffer range overflowed",
        ))?;
    let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        ancillary_messages = ancillary_messages
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "service ancillary message count overflowed",
            ))?;
        let is_rights = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
        };
        let is_credentials = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
        };
        if is_rights {
            let header_length = unsafe { (*header).cmsg_len };
            let rights_bytes =
                header_length.checked_sub(minimum);
            let data_start =
                unsafe { libc::CMSG_DATA(header) } as usize;
            let data_end = rights_bytes
                .and_then(|length| data_start.checked_add(length));
            let valid_rights_bytes =
                rights_bytes.filter(|length| {
                    length % size_of::<RawFd>() == 0
                        && data_start >= control_start
                        && data_end.is_some_and(|end| {
                            end <= control_end
                        })
                });
            if let Some(rights_bytes) = valid_rights_bytes {
                let rights_count =
                    rights_bytes / size_of::<RawFd>();
                let raw_rights = unsafe {
                    std::slice::from_raw_parts(
                        libc::CMSG_DATA(header).cast::<RawFd>(),
                        rights_count,
                    )
                };
                for raw in raw_rights {
                    if *raw < 0 {
                        validation_error.get_or_insert(
                            "SCM_RIGHTS supplied an invalid descriptor",
                        );
                        continue;
                    }
                    rights.push(unsafe {
                        OwnedFd::from_raw_fd(*raw)
                    });
                }
            } else {
                validation_error.get_or_insert(
                    "SCM_RIGHTS header or descriptor array is invalid",
                );
            }
        } else if is_credentials {
            let header_length = unsafe { (*header).cmsg_len };
            let expected_length = unsafe {
                libc::CMSG_LEN(size_of::<libc::ucred>() as u32)
            } as usize;
            let data_start =
                unsafe { libc::CMSG_DATA(header) } as usize;
            let data_end = data_start
                .checked_add(size_of::<libc::ucred>());
            if credentials_seen
                || header_length != expected_length
                || data_start < control_start
                || data_end.is_none_or(|end| end > control_end)
            {
                validation_error.get_or_insert(
                    "SCM_CREDENTIALS payload is missing, duplicate, or malformed",
                );
            } else {
                let credentials = unsafe {
                    ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::ucred>(),
                    )
                };
                let observed = PeerCredentialsV3 {
                    pid: credentials.pid,
                    uid: credentials.uid,
                    gid: credentials.gid,
                };
                if observed != expected_credentials {
                    validation_error.get_or_insert(
                        "SCM_CREDENTIALS does not match the retained service peer",
                    );
                }
                credentials_seen = true;
            }
        } else {
            validation_error.get_or_insert(
                "service packet contains an unsupported ancillary message",
            );
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if !credentials_seen {
        validation_error.get_or_insert(
            "service packet lacks mandatory SCM_CREDENTIALS",
        );
    }
    if ancillary_messages > 2 {
        validation_error.get_or_insert(
            "service packet contains too many ancillary messages",
        );
    }
    if rights.len() > MAX_SERVICE_RIGHTS {
        validation_error.get_or_insert(
            "SCM_RIGHTS payload exceeds its fixed descriptor bound",
        );
    }
    if let Some(error) = validation_error {
        return Err(ServiceError::Invalid(error));
    }
    Ok(rights)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalRecordV3 {
    api_version: String,
    service_role: TrustedHostServiceRoleV3,
    sequence: u64,
    idempotency_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exact_request_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exact_request_base64: Option<String>,
    exact_response_sha256: Sha256Digest,
    exact_response_base64: String,
    previous_head_sha256: Option<Sha256Digest>,
    record_sha256: Sha256Digest,
}

impl JournalRecordV3 {
    fn new(
        service_role: TrustedHostServiceRoleV3,
        sequence: u64,
        idempotency_sha256: Sha256Digest,
        exact_request: Option<&[u8]>,
        exact_response: &[u8],
        previous_head_sha256: Option<Sha256Digest>,
    ) -> Result<Self, ServiceError> {
        let mut record = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            service_role,
            sequence,
            idempotency_sha256,
            exact_request_sha256:
                exact_request.map(Sha256Digest::compute),
            exact_request_base64: exact_request
                .map(|request| URL_SAFE_NO_PAD.encode(request)),
            exact_response_sha256:
                Sha256Digest::compute(exact_response),
            exact_response_base64:
                URL_SAFE_NO_PAD.encode(exact_response),
            previous_head_sha256,
            record_sha256: Sha256Digest::compute(&[]),
        };
        record.record_sha256 =
            record.computed_record_sha256()?;
        record.validate(service_role, exact_response.len())?;
        Ok(record)
    }

    fn computed_record_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = if self.exact_request_sha256.is_none()
            && self.exact_request_base64.is_none()
        {
            canonical_json_bytes(&(
                &self.api_version,
                self.service_role,
                self.sequence,
                &self.idempotency_sha256,
                &self.exact_response_sha256,
                &self.exact_response_base64,
                &self.previous_head_sha256,
            ))
        } else {
            canonical_json_bytes(&(
                &self.api_version,
                self.service_role,
                self.sequence,
                &self.idempotency_sha256,
                &self.exact_request_sha256,
                &self.exact_request_base64,
                &self.exact_response_sha256,
                &self.exact_response_base64,
                &self.previous_head_sha256,
            ))
        }
        .map_err(|_| {
            ServiceError::Invalid(
                "journal record cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(JOURNAL_RECORD_DOMAIN, &canonical))
    }

    fn exact_request(
        &self,
        maximum_request_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.exact_request_base64
            .as_ref()
            .map(|encoded| {
                decode_canonical_base64(
                    encoded,
                    maximum_request_bytes,
                    "journal exact request",
                )
            })
            .transpose()
    }

    fn exact_response(
        &self,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ServiceError> {
        decode_canonical_base64(
            &self.exact_response_base64,
            maximum_response_bytes,
            "journal exact response",
        )
    }

    fn validate(
        &self,
        expected_role: TrustedHostServiceRoleV3,
        maximum_response_bytes: usize,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "journalRecord.idempotencySha256",
            &self.idempotency_sha256,
        )?;
        if let Some(request_sha256) = &self.exact_request_sha256 {
            require_nonzero_digest(
                "journalRecord.exactRequestSha256",
                request_sha256,
            )?;
        }
        require_nonzero_digest(
            "journalRecord.exactResponseSha256",
            &self.exact_response_sha256,
        )?;
        require_nonzero_digest(
            "journalRecord.recordSha256",
            &self.record_sha256,
        )?;
        if let Some(previous) = &self.previous_head_sha256 {
            require_nonzero_digest(
                "journalRecord.previousHeadSha256",
                previous,
            )?;
        }
        let request = self.exact_request(MAX_SERVICE_FRAME_BYTES)?;
        let response = self.exact_response(maximum_response_bytes)?;
        let request_is_consistent = match (
            &self.exact_request_sha256,
            &self.exact_request_base64,
            &request,
        ) {
            (None, None, None) => true,
            (Some(expected), Some(_), Some(bytes)) => {
                expected == &Sha256Digest::compute(bytes)
            }
            _ => false,
        };
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.service_role != expected_role
            || self.sequence == 0
            || !request_is_consistent
            || self.exact_response_sha256
                != Sha256Digest::compute(&response)
            || self.record_sha256
                != self.computed_record_sha256()?
        {
            return Err(ServiceError::Invalid(
                "durable journal record is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalHeadV3 {
    api_version: String,
    service_role: TrustedHostServiceRoleV3,
    sequence: u64,
    idempotency_sha256: Sha256Digest,
    record_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exact_request_sha256: Option<Sha256Digest>,
    exact_response_sha256: Sha256Digest,
    previous_head_sha256: Option<Sha256Digest>,
    head_sha256: Sha256Digest,
}

impl JournalHeadV3 {
    fn from_record(
        record: &JournalRecordV3,
    ) -> Result<Self, ServiceError> {
        let mut head = Self {
            api_version: TRUSTED_HOST_SERVICE_API_VERSION.to_string(),
            service_role: record.service_role,
            sequence: record.sequence,
            idempotency_sha256:
                record.idempotency_sha256.clone(),
            record_sha256: record.record_sha256.clone(),
            exact_request_sha256:
                record.exact_request_sha256.clone(),
            exact_response_sha256:
                record.exact_response_sha256.clone(),
            previous_head_sha256:
                record.previous_head_sha256.clone(),
            head_sha256: Sha256Digest::compute(&[]),
        };
        head.head_sha256 = head.computed_head_sha256()?;
        head.validate(record.service_role)?;
        Ok(head)
    }

    fn computed_head_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceError> {
        let canonical = if self.exact_request_sha256.is_none() {
            canonical_json_bytes(&(
                &self.api_version,
                self.service_role,
                self.sequence,
                &self.idempotency_sha256,
                &self.record_sha256,
                &self.exact_response_sha256,
                &self.previous_head_sha256,
            ))
        } else {
            canonical_json_bytes(&(
                &self.api_version,
                self.service_role,
                self.sequence,
                &self.idempotency_sha256,
                &self.record_sha256,
                &self.exact_request_sha256,
                &self.exact_response_sha256,
                &self.previous_head_sha256,
            ))
        }
        .map_err(|_| {
            ServiceError::Invalid(
                "journal head cannot be canonicalized",
            )
        })?;
        Ok(domain_digest(JOURNAL_HEAD_DOMAIN, &canonical))
    }

    fn validate(
        &self,
        expected_role: TrustedHostServiceRoleV3,
    ) -> Result<(), ServiceError> {
        require_nonzero_digest(
            "journalHead.idempotencySha256",
            &self.idempotency_sha256,
        )?;
        require_nonzero_digest(
            "journalHead.recordSha256",
            &self.record_sha256,
        )?;
        if let Some(request_sha256) = &self.exact_request_sha256 {
            require_nonzero_digest(
                "journalHead.exactRequestSha256",
                request_sha256,
            )?;
        }
        require_nonzero_digest(
            "journalHead.exactResponseSha256",
            &self.exact_response_sha256,
        )?;
        require_nonzero_digest(
            "journalHead.headSha256",
            &self.head_sha256,
        )?;
        if let Some(previous) = &self.previous_head_sha256 {
            require_nonzero_digest(
                "journalHead.previousHeadSha256",
                previous,
            )?;
        }
        if self.api_version != TRUSTED_HOST_SERVICE_API_VERSION
            || self.service_role != expected_role
            || self.sequence == 0
            || self.head_sha256 != self.computed_head_sha256()?
        {
            return Err(ServiceError::Invalid(
                "durable journal head is incomplete or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedJournalRecordV3 {
    pub(super) sequence: u64,
    pub(super) idempotency_sha256: Sha256Digest,
    pub(super) head_sha256: Sha256Digest,
    pub(super) previous_head_sha256: Option<Sha256Digest>,
    pub(super) exact_record_bytes: Vec<u8>,
    pub(super) exact_request_bytes: Vec<u8>,
    pub(super) exact_response_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedJournalTerminalHeadV3 {
    pub(super) sequence: u64,
    pub(super) idempotency_sha256: Sha256Digest,
    pub(super) record_sha256: Sha256Digest,
    pub(super) head_sha256: Sha256Digest,
    pub(super) exact_head_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedJournalChainV3 {
    pub(super) records: Vec<VerifiedJournalRecordV3>,
    pub(super) terminal_head: Option<VerifiedJournalTerminalHeadV3>,
}

#[derive(Debug, Clone)]
struct LoadedJournalRecordV3 {
    record: JournalRecordV3,
    exact_record_bytes: Vec<u8>,
}

pub(super) enum JournalAppendOutcome {
    Appended(Vec<u8>),
    Replayed(Vec<u8>),
}

impl JournalAppendOutcome {
    pub(super) fn exact_response_bytes(&self) -> &[u8] {
        match self {
            Self::Appended(bytes) | Self::Replayed(bytes) => bytes,
        }
    }
}

/// Single-writer append journal keyed by an operation's idempotency digest.
///
/// The durability order is:
/// 1. write and fsync the immutable record;
/// 2. install it without replacement and fsync the directory;
/// 3. write and fsync the new head;
/// 4. replace the head and fsync the directory again.
///
/// No response is acknowledged before all four steps succeed. If a crash lands
/// between record and head installation, querying the idempotency digest still
/// returns the exact persisted response and a retry completes the head update.
pub(super) struct DurableAppendJournal {
    directory: OwnedFd,
    _writer_lock: OwnedFd,
    service_role: TrustedHostServiceRoleV3,
    maximum_response_bytes: usize,
    current_head: Option<JournalHeadV3>,
    current_head_bytes: Option<Vec<u8>>,
    temporary_sequence: u64,
    orphan_policy: JournalOrphanPolicy,
}

enum JournalOrphanPolicy { RepairUnique, Refuse }

impl DurableAppendJournal {
    pub(super) fn from_directory(
        directory: OwnedFd,
        service_role: TrustedHostServiceRoleV3,
        maximum_response_bytes: usize,
    ) -> Result<Self, ServiceError> {
        Self::open_directory(directory,service_role,maximum_response_bytes,JournalOrphanPolicy::RepairUnique)
    }

    /// Generation admission must never turn a detached/unknown append into an
    /// admission decision. This source-selected owner keeps that rule for every
    /// subsequent lookup, append and recovery, not only the initial read.
    pub(super) fn from_directory_without_orphan_repair(
        directory: OwnedFd,
        service_role: TrustedHostServiceRoleV3,
        maximum_response_bytes: usize,
    ) -> Result<Self, ServiceError> {
        Self::open_directory(directory,service_role,maximum_response_bytes,JournalOrphanPolicy::Refuse)
    }

    fn open_directory(
        directory: OwnedFd,
        service_role: TrustedHostServiceRoleV3,
        maximum_response_bytes: usize,
        orphan_policy: JournalOrphanPolicy,
    ) -> Result<Self, ServiceError> {
        if maximum_response_bytes == 0
            || maximum_response_bytes > MAX_SERVICE_FRAME_BYTES
        {
            return Err(ServiceError::Invalid(
                "journal response bound is invalid",
            ));
        }
        require_directory(directory.as_raw_fd())?;
        let writer_lock = openat_owned(
            directory.as_raw_fd(),
            JOURNAL_LOCK_NAME,
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
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EWOULDBLOCK)
            ) {
                return Err(ServiceError::JournalBusy);
            }
            return Err(error.into());
        }
        let current_head_file: Option<(JournalHeadV3, Vec<u8>)> =
            read_optional_canonical_file_with_bytes(
                directory.as_raw_fd(),
                JOURNAL_HEAD_NAME,
                MAX_JOURNAL_METADATA_BYTES,
            )?;
        let (current_head, current_head_bytes) =
            match current_head_file {
                Some((head, bytes)) => {
                    (Some(head), Some(bytes))
                }
                None => (None, None),
            };
        if let Some(head) = &current_head {
            head.validate(service_role)?;
            let record = read_record_by_idempotency(
                directory.as_raw_fd(),
                service_role,
                maximum_response_bytes,
                &head.idempotency_sha256,
            )?
            .ok_or(ServiceError::Invalid(
                "journal head references a missing record",
            ))?;
            if record.sequence != head.sequence
                || record.record_sha256 != head.record_sha256
                || record.exact_request_sha256
                    != head.exact_request_sha256
                || record.exact_response_sha256
                    != head.exact_response_sha256
                || record.previous_head_sha256
                    != head.previous_head_sha256
            {
                return Err(ServiceError::Invalid(
                    "journal head does not match its immutable record",
                ));
            }
        }
        let mut journal = Self {
            directory,
            _writer_lock: writer_lock,
            service_role,
            maximum_response_bytes,
            current_head,
            current_head_bytes,
            temporary_sequence: 0,
            orphan_policy,
        };
        journal.repair_unique_orphan_record()?;
        Ok(journal)
    }

    pub(super) fn current_head_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.current_head
            .as_ref()
            .map(|head| &head.head_sha256)
    }

    pub(super) fn lookup_persisted_exact_response(
        &self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        require_nonzero_digest(
            "journalLookup.idempotencySha256",
            idempotency_sha256,
        )?;
        let Some(loaded) = read_record_by_idempotency_with_bytes(
            self.directory.as_raw_fd(),
            self.service_role,
            self.maximum_response_bytes,
            idempotency_sha256,
        )? else {
            return Ok(None);
        };
        if !self.record_is_in_current_chain(&loaded.record)? {
            return Err(ServiceError::Invalid(
                "journal replay record is not durably reachable from the current head; use the repairing lookup",
            ));
        }
        loaded
            .record
            .exact_response(self.maximum_response_bytes)
            .map(Some)
    }

    pub(super) fn repair_and_lookup_persisted_exact_response(
        &mut self,
        idempotency_sha256: &Sha256Digest,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        require_nonzero_digest(
            "journalRepairLookup.idempotencySha256",
            idempotency_sha256,
        )?;
        let Some(loaded) = read_record_by_idempotency_with_bytes(
            self.directory.as_raw_fd(),
            self.service_role,
            self.maximum_response_bytes,
            idempotency_sha256,
        )? else {
            return Ok(None);
        };
        if !self.record_is_in_current_chain(&loaded.record)? {
            let (_, detached) = self.load_chain_partition()?;
            if detached.len() != 1
                || detached[0].record.record_sha256
                    != loaded.record.record_sha256
            {
                return Err(ServiceError::Invalid(
                    "journal contains a detached record or fork that cannot be repaired unambiguously",
                ));
            }
            sync_fd(self.directory.as_raw_fd())?;
            self.ensure_record_is_headed(&loaded.record)?;
            let (_, residual) = self.load_chain_partition()?;
            if !residual.is_empty()
                || !self.record_is_in_current_chain(
                    &loaded.record,
                )?
            {
                return Err(ServiceError::Invalid(
                    "journal orphan repair did not produce one complete durable chain",
                ));
            }
        }
        loaded
            .record
            .exact_response(self.maximum_response_bytes)
            .map(Some)
    }

    pub(super) fn append_exact_response(
        &mut self,
        idempotency_sha256: Sha256Digest,
        exact_response: &[u8],
    ) -> Result<JournalAppendOutcome, ServiceError> {
        self.append_exact_exchange_internal(
            idempotency_sha256,
            None,
            exact_response,
        )
    }

    pub(super) fn append_exact_exchange(
        &mut self,
        idempotency_sha256: Sha256Digest,
        exact_request: &[u8],
        exact_response: &[u8],
    ) -> Result<JournalAppendOutcome, ServiceError> {
        if exact_request.is_empty()
            || exact_request.len() > MAX_SERVICE_FRAME_BYTES
        {
            return Err(ServiceError::Invalid(
                "journal request is empty or exceeds its fixed bound",
            ));
        }
        self.append_exact_exchange_internal(
            idempotency_sha256,
            Some(exact_request),
            exact_response,
        )
    }

    fn append_exact_exchange_internal(
        &mut self,
        idempotency_sha256: Sha256Digest,
        exact_request: Option<&[u8]>,
        exact_response: &[u8],
    ) -> Result<JournalAppendOutcome, ServiceError> {
        require_nonzero_digest(
            "journalAppend.idempotencySha256",
            &idempotency_sha256,
        )?;
        if exact_response.is_empty()
            || exact_response.len() > self.maximum_response_bytes
        {
            return Err(ServiceError::Invalid(
                "journal response is empty or exceeds its fixed bound",
            ));
        }
        if let Some(persisted) = self
            .repair_and_lookup_persisted_exact_response(
                &idempotency_sha256,
            )?
        {
            let existing = read_record_by_idempotency(
                self.directory.as_raw_fd(),
                self.service_role,
                self.maximum_response_bytes,
                &idempotency_sha256,
            )?
            .ok_or(ServiceError::Invalid(
                "journal replay record disappeared while the writer lock was held",
            ))?;
            let persisted_request = existing
                .exact_request(MAX_SERVICE_FRAME_BYTES)?;
            if persisted_request.as_deref() != exact_request {
                return Err(ServiceError::IdempotencyConflict);
            }
            if persisted != exact_response {
                return Err(ServiceError::IdempotencyConflict);
            }
            return Ok(JournalAppendOutcome::Replayed(persisted));
        }

        self.repair_unique_orphan_record()?;
        let sequence = self
            .current_head
            .as_ref()
            .map_or(Ok(1_u64), |head| {
                head.sequence.checked_add(1).ok_or(
                    ServiceError::Invalid(
                        "journal sequence exhausted",
                    ),
                )
            })?;
        let previous_head_sha256 = self
            .current_head
            .as_ref()
            .map(|head| head.head_sha256.clone());
        let record = JournalRecordV3::new(
            self.service_role,
            sequence,
            idempotency_sha256,
            exact_request,
            exact_response,
            previous_head_sha256,
        )?;
        let record_name =
            record_name(&record.idempotency_sha256)?;
        let record_bytes = encode_canonical_value_bounded(
            &record,
            MAX_JOURNAL_METADATA_BYTES,
        )?;
        self.install_immutable_record(
            &record_name,
            &record_bytes,
        )?;
        sync_fd(self.directory.as_raw_fd())?;
        self.ensure_record_is_headed(&record)?;
        Ok(JournalAppendOutcome::Appended(
            exact_response.to_vec(),
        ))
    }

    pub(super) fn verified_complete_chain(
        &mut self,
        maximum_records: usize,
        maximum_total_bytes: usize,
    ) -> Result<VerifiedJournalChainV3, ServiceError> {
        if maximum_records == 0
            || maximum_records > MAX_JOURNAL_RECOVERY_RECORDS
            || maximum_total_bytes == 0
            || maximum_total_bytes > MAX_JOURNAL_RECOVERY_BYTES
        {
            return Err(ServiceError::Invalid(
                "journal recovery bounds are invalid",
            ));
        }
        self.repair_unique_orphan_record()?;
        let (mut newest_first, detached) =
            self.load_chain_partition()?;
        if !detached.is_empty() {
            return Err(ServiceError::Invalid(
                "journal contains records outside the terminal durable chain",
            ));
        }
        if newest_first.len() > maximum_records {
            return Err(ServiceError::Invalid(
                "journal recovery record count exceeds its caller bound",
            ));
        }
        newest_first.reverse();
        let mut total_bytes = self
            .current_head_bytes
            .as_ref()
            .map_or(0, Vec::len);
        let mut records =
            Vec::with_capacity(newest_first.len());
        for loaded in newest_first {
            let exact_request = loaded
                .record
                .exact_request(MAX_SERVICE_FRAME_BYTES)?
                .ok_or(ServiceError::Invalid(
                    "journal record lacks exact request bytes required for startup recovery",
                ))?;
            let exact_response = loaded
                .record
                .exact_response(self.maximum_response_bytes)?;
            total_bytes = total_bytes
                .checked_add(loaded.exact_record_bytes.len())
                .and_then(|total| {
                    total.checked_add(exact_request.len())
                })
                .and_then(|total| {
                    total.checked_add(exact_response.len())
                })
                .ok_or(ServiceError::Invalid(
                    "journal recovery byte count overflowed",
                ))?;
            if total_bytes > maximum_total_bytes {
                return Err(ServiceError::Invalid(
                    "journal recovery bytes exceed the caller bound",
                ));
            }
            let record_head =
                JournalHeadV3::from_record(&loaded.record)?;
            records.push(VerifiedJournalRecordV3 {
                sequence: loaded.record.sequence,
                idempotency_sha256:
                    loaded.record.idempotency_sha256,
                head_sha256: record_head.head_sha256,
                previous_head_sha256:
                    loaded.record.previous_head_sha256,
                exact_record_bytes:
                    loaded.exact_record_bytes,
                exact_request_bytes: exact_request,
                exact_response_bytes: exact_response,
            });
        }
        let terminal_head = match (
            &self.current_head,
            &self.current_head_bytes,
        ) {
            (None, None) => None,
            (Some(head), Some(bytes)) => {
                Some(VerifiedJournalTerminalHeadV3 {
                    sequence: head.sequence,
                    idempotency_sha256:
                        head.idempotency_sha256.clone(),
                    record_sha256:
                        head.record_sha256.clone(),
                    head_sha256: head.head_sha256.clone(),
                    exact_head_bytes: bytes.clone(),
                })
            }
            _ => {
                return Err(ServiceError::Invalid(
                    "journal terminal head object and exact bytes differ",
                ))
            }
        };
        Ok(VerifiedJournalChainV3 {
            records,
            terminal_head,
        })
    }

    fn repair_unique_orphan_record(
        &mut self,
    ) -> Result<(), ServiceError> {
        let (_, detached) = self.load_chain_partition()?;
        if detached.is_empty() {
            return Ok(());
        }
        if matches!(self.orphan_policy,JournalOrphanPolicy::Refuse) {
            return Err(ServiceError::Invalid("strict journal has an unknown detached append"));
        }
        if detached.len() != 1 {
            return Err(ServiceError::Invalid(
                "journal contains multiple detached immutable records",
            ));
        }
        sync_fd(self.directory.as_raw_fd())?;
        self.ensure_record_is_headed(&detached[0].record)?;
        let (_, residual) = self.load_chain_partition()?;
        if !residual.is_empty() {
            return Err(ServiceError::Invalid(
                "journal orphan repair left a detached immutable record",
            ));
        }
        Ok(())
    }

    fn record_is_in_current_chain(
        &self,
        record: &JournalRecordV3,
    ) -> Result<bool, ServiceError> {
        if self.current_head.as_ref().is_some_and(|head| {
            head.record_sha256 == record.record_sha256
                && head.idempotency_sha256
                    == record.idempotency_sha256
        }) {
            return Ok(true);
        }
        let (chain, _) = self.load_chain_partition()?;
        Ok(chain.iter().any(|loaded| {
            loaded.record.record_sha256 == record.record_sha256
                && loaded.record.idempotency_sha256
                    == record.idempotency_sha256
        }))
    }

    fn load_chain_partition(
        &self,
    ) -> Result<
        (
            Vec<LoadedJournalRecordV3>,
            Vec<LoadedJournalRecordV3>,
        ),
        ServiceError,
    > {
        let loaded = read_all_journal_records(
            self.directory.as_raw_fd(),
            self.service_role,
            self.maximum_response_bytes,
        )?;
        let mut by_head = BTreeMap::new();
        for loaded_record in loaded {
            let record_head =
                JournalHeadV3::from_record(&loaded_record.record)?;
            if by_head
                .insert(
                    record_head.head_sha256.as_str().to_string(),
                    loaded_record,
                )
                .is_some()
            {
                return Err(ServiceError::Invalid(
                    "journal contains duplicate immutable record heads",
                ));
            }
        }
        let Some(terminal_head) = &self.current_head else {
            return Ok((
                Vec::new(),
                by_head.into_values().collect(),
            ));
        };
        let mut cursor =
            terminal_head.head_sha256.as_str().to_string();
        let mut expected_sequence = terminal_head.sequence;
        let mut chain = Vec::new();
        loop {
            let loaded_record =
                by_head.remove(&cursor).ok_or(
                    ServiceError::Invalid(
                        "journal chain references a missing immutable record",
                    ),
                )?;
            if loaded_record.record.sequence
                != expected_sequence
            {
                return Err(ServiceError::Invalid(
                    "journal chain sequence is not contiguous",
                ));
            }
            let derived_head =
                JournalHeadV3::from_record(&loaded_record.record)?;
            if chain.is_empty() && &derived_head != terminal_head {
                return Err(ServiceError::Invalid(
                    "journal terminal head does not exactly match its immutable record",
                ));
            }
            chain.push(loaded_record);
            expected_sequence =
                expected_sequence.checked_sub(1).ok_or(
                    ServiceError::Invalid(
                        "journal chain sequence underflowed",
                    ),
                )?;
            let previous = chain
                .last()
                .and_then(|loaded| {
                    loaded.record.previous_head_sha256.as_ref()
                });
            match previous {
                Some(previous) => {
                    if expected_sequence == 0 {
                        return Err(ServiceError::Invalid(
                            "journal genesis record unexpectedly references a predecessor",
                        ));
                    }
                    cursor = previous.as_str().to_string();
                }
                None => {
                    if expected_sequence != 0 {
                        return Err(ServiceError::Invalid(
                            "journal chain terminated before its declared sequence",
                        ));
                    }
                    break;
                }
            }
        }
        Ok((chain, by_head.into_values().collect()))
    }

    fn ensure_record_is_headed(
        &mut self,
        record: &JournalRecordV3,
    ) -> Result<(), ServiceError> {
        if self.current_head.as_ref().is_some_and(|head| {
            head.record_sha256 == record.record_sha256
                && head.idempotency_sha256
                    == record.idempotency_sha256
        }) {
            return Ok(());
        }
        let expected_sequence = self
            .current_head
            .as_ref()
            .map_or(Ok(1_u64), |head| {
                head.sequence.checked_add(1).ok_or(
                    ServiceError::Invalid(
                        "journal sequence exhausted",
                    ),
                )
            })?;
        let expected_previous = self
            .current_head
            .as_ref()
            .map(|head| head.head_sha256.clone());
        if record.sequence != expected_sequence
            || record.previous_head_sha256 != expected_previous
        {
            return Err(ServiceError::Invalid(
                "persisted journal record does not extend the current head",
            ));
        }
        let head = JournalHeadV3::from_record(record)?;
        let head_bytes = encode_canonical_value_bounded(
            &head,
            MAX_JOURNAL_METADATA_BYTES,
        )?;
        self.replace_head(&head_bytes)?;
        sync_fd(self.directory.as_raw_fd())?;
        self.current_head = Some(head);
        self.current_head_bytes = Some(head_bytes);
        Ok(())
    }

    fn install_immutable_record(
        &mut self,
        final_name: &str,
        bytes: &[u8],
    ) -> Result<(), ServiceError> {
        let temporary_name =
            self.write_unique_temporary("record", bytes)?;
        match rename_noreplace_at(
            self.directory.as_raw_fd(),
            &temporary_name,
            final_name,
        ) {
            Ok(()) => Ok(()),
            Err(ServiceError::Io(error))
                if error.raw_os_error() == Some(libc::EEXIST) =>
            {
                unlinkat_if_present(
                    self.directory.as_raw_fd(),
                    &temporary_name,
                )?;
                Err(ServiceError::Invalid(
                    "journal record appeared concurrently despite the retained writer lock",
                ))
            }
            Err(error) => {
                unlinkat_if_present(
                    self.directory.as_raw_fd(),
                    &temporary_name,
                )?;
                Err(error)
            }
        }
    }

    fn replace_head(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), ServiceError> {
        let temporary_name =
            self.write_unique_temporary("head", bytes)?;
        let old = cstring_name(&temporary_name)?;
        let new = cstring_name(JOURNAL_HEAD_NAME)?;
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                old.as_ptr(),
                self.directory.as_raw_fd(),
                new.as_ptr(),
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            unlinkat_if_present(
                self.directory.as_raw_fd(),
                &temporary_name,
            )?;
            return Err(error.into());
        }
        Ok(())
    }

    fn write_unique_temporary(
        &mut self,
        purpose: &'static str,
        bytes: &[u8],
    ) -> Result<String, ServiceError> {
        for _ in 0..64 {
            let name = self.next_temporary_name(purpose)?;
            match write_new_synced_file(
                self.directory.as_raw_fd(),
                &name,
                bytes,
            ) {
                Ok(()) => return Ok(name),
                Err(ServiceError::Io(error))
                    if error.raw_os_error()
                        == Some(libc::EEXIST) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ServiceError::Invalid(
            "journal could not allocate a unique bounded temporary entry",
        ))
    }

    fn next_temporary_name(
        &mut self,
        purpose: &'static str,
    ) -> Result<String, ServiceError> {
        self.temporary_sequence = self
            .temporary_sequence
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "journal temporary sequence exhausted",
            ))?;
        Ok(format!(
            ".{}.{}.{}.{}.tmp",
            self.service_role.journal_label(),
            purpose,
            std::process::id(),
            self.temporary_sequence,
        ))
    }
}

fn read_record_by_idempotency(
    directory_fd: RawFd,
    service_role: TrustedHostServiceRoleV3,
    maximum_response_bytes: usize,
    idempotency_sha256: &Sha256Digest,
) -> Result<Option<JournalRecordV3>, ServiceError> {
    Ok(read_record_by_idempotency_with_bytes(
        directory_fd,
        service_role,
        maximum_response_bytes,
        idempotency_sha256,
    )?
    .map(|loaded| loaded.record))
}

fn read_record_by_idempotency_with_bytes(
    directory_fd: RawFd,
    service_role: TrustedHostServiceRoleV3,
    maximum_response_bytes: usize,
    idempotency_sha256: &Sha256Digest,
) -> Result<Option<LoadedJournalRecordV3>, ServiceError> {
    let name = record_name(idempotency_sha256)?;
    let loaded: Option<(JournalRecordV3, Vec<u8>)> =
        read_optional_canonical_file_with_bytes(
            directory_fd,
            &name,
            MAX_JOURNAL_METADATA_BYTES,
        )?;
    let Some((record, exact_record_bytes)) = loaded else {
        return Ok(None);
    };
    {
        record.validate(service_role, maximum_response_bytes)?;
        if &record.idempotency_sha256 != idempotency_sha256 {
            return Err(ServiceError::Invalid(
                "journal filename and record idempotency digest differ",
            ));
        }
    }
    Ok(Some(LoadedJournalRecordV3 {
        record,
        exact_record_bytes,
    }))
}

fn read_all_journal_records(
    directory_fd: RawFd,
    service_role: TrustedHostServiceRoleV3,
    maximum_response_bytes: usize,
) -> Result<Vec<LoadedJournalRecordV3>, ServiceError> {
    let names =
        read_journal_record_names(directory_fd, service_role)?;
    let mut records = Vec::with_capacity(names.len());
    let mut total_record_bytes = 0_usize;
    for name in names {
        let loaded: Option<(JournalRecordV3, Vec<u8>)> =
            read_optional_canonical_file_with_bytes(
                directory_fd,
                &name,
                MAX_JOURNAL_METADATA_BYTES,
            )?;
        let (record, exact_record_bytes) =
            loaded.ok_or(ServiceError::Invalid(
                "journal record disappeared while the writer lock was held",
            ))?;
        record.validate(service_role, maximum_response_bytes)?;
        if record_name(&record.idempotency_sha256)? != name {
            return Err(ServiceError::Invalid(
                "journal filename and immutable record digest differ",
            ));
        }
        total_record_bytes = total_record_bytes
            .checked_add(exact_record_bytes.len())
            .ok_or(ServiceError::Invalid(
                "journal immutable record byte count overflowed",
            ))?;
        if total_record_bytes > MAX_JOURNAL_RECOVERY_BYTES {
            return Err(ServiceError::Invalid(
                "journal immutable records exceed the hard recovery byte bound",
            ));
        }
        records.push(LoadedJournalRecordV3 {
            record,
            exact_record_bytes,
        });
    }
    Ok(records)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
}

fn read_journal_record_names(
    directory_fd: RawFd,
    service_role: TrustedHostServiceRoleV3,
) -> Result<Vec<String>, ServiceError> {
    let duplicate = loop {
        let result = unsafe {
            libc::fcntl(
                directory_fd,
                libc::F_DUPFD_CLOEXEC,
                0,
            )
        };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    };
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(duplicate);
        }
        return Err(error.into());
    }
    let stream = DirectoryStream(stream);
    let temporary_prefix =
        format!(".{}.", service_role.journal_label());
    let mut names = Vec::new();
    let mut scanned_entries = 0_usize;
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno).into());
            }
            break;
        }
        let name = unsafe {
            CStr::from_ptr((*entry).d_name.as_ptr())
        }
        .to_str()
        .map_err(|_| {
            ServiceError::Invalid(
                "journal directory contains a non-UTF-8 entry",
            )
        })?;
        scanned_entries = scanned_entries
            .checked_add(1)
            .ok_or(ServiceError::Invalid(
                "journal directory entry count overflowed",
            ))?;
        if scanned_entries
            > MAX_JOURNAL_RECOVERY_RECORDS.saturating_add(128)
        {
            return Err(ServiceError::Invalid(
                "journal directory entry count exceeds its hard recovery bound",
            ));
        }
        if matches!(
            name,
            "." | ".." | JOURNAL_HEAD_NAME | JOURNAL_LOCK_NAME
        ) {
            continue;
        }
        if is_record_name(name) {
            if names.len() >= MAX_JOURNAL_RECOVERY_RECORDS {
                return Err(ServiceError::Invalid(
                    "journal record count exceeds its hard recovery bound",
                ));
            }
            names.push(name.to_string());
            continue;
        }
        if name.starts_with(&temporary_prefix)
            && name.ends_with(".tmp")
        {
            require_secure_named_regular_file(
                directory_fd,
                name,
            )?;
            continue;
        }
        return Err(ServiceError::Invalid(
            "journal directory contains an unexpected entry",
        ));
    }
    names.sort_unstable();
    Ok(names)
}

fn is_record_name(name: &str) -> bool {
    let Some(hexadecimal) = name
        .strip_prefix("record.")
        .and_then(|name| name.strip_suffix(".v3.json"))
    else {
        return false;
    };
    hexadecimal.len() == 64
        && hexadecimal.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
}

fn record_name(
    digest: &Sha256Digest,
) -> Result<String, ServiceError> {
    require_nonzero_digest("journalRecordName.digest", digest)?;
    let hexadecimal =
        digest.as_str().strip_prefix("sha256:").ok_or(
            ServiceError::Invalid(
                "journal digest lacks its canonical prefix",
            ),
        )?;
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_digit()
                || (b'a'..=b'f').contains(&byte))
    {
        return Err(ServiceError::Invalid(
            "journal digest is not canonical lowercase SHA-256",
        ));
    }
    Ok(format!("record.{hexadecimal}.v3.json"))
}

fn require_directory(fd: RawFd) -> Result<(), ServiceError> {
    let mut metadata: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_nlink == 0
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(ServiceError::Invalid(
            "journal descriptor is not a linked, owner-only directory owned by the service uid",
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
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_mode & 0o7777 != 0o600
    {
        return Err(ServiceError::Invalid(
            "journal entry is not a singly linked owner-only regular file owned by the service uid",
        ));
    }
    Ok(())
}

fn openat_owned(
    directory_fd: RawFd,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<OwnedFd, ServiceError> {
    let name = cstring_name(name)?;
    let raw = unsafe {
        libc::openat(directory_fd, name.as_ptr(), flags, mode)
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn write_new_synced_file(
    directory_fd: RawFd,
    name: &str,
    bytes: &[u8],
) -> Result<(), ServiceError> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_METADATA_BYTES {
        return Err(ServiceError::Invalid(
            "journal entry exceeds its fixed bound",
        ));
    }
    let descriptor = openat_owned(
        directory_fd,
        name,
        libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK,
        0o600,
    )?;
    require_regular_file(descriptor.as_raw_fd())?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_optional_canonical_file<T>(
    directory_fd: RawFd,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<T>, ServiceError>
where
    T: DeserializeOwned + Serialize,
{
    Ok(read_optional_canonical_file_with_bytes(
        directory_fd,
        name,
        maximum_bytes,
    )?
    .map(|(value, _)| value))
}

pub(super) fn read_optional_canonical_file_with_bytes<T>(
    directory_fd: RawFd,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<(T, Vec<u8>)>, ServiceError>
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
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    require_regular_file(descriptor.as_raw_fd())?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    let read_limit = u64::try_from(maximum_bytes)
        .map_err(|_| {
            ServiceError::Invalid(
                "journal read bound cannot be represented",
            )
        })?
        .checked_add(1)
        .ok_or(ServiceError::Invalid(
            "journal read bound overflow",
        ))?;
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(ServiceError::Invalid(
            "journal entry is empty or exceeds its fixed bound",
        ));
    }
    let value =
        decode_canonical_value_bounded(&bytes, maximum_bytes)?;
    Ok(Some((value, bytes)))
}

fn require_secure_named_regular_file(
    directory_fd: RawFd,
    name: &str,
) -> Result<(), ServiceError> {
    let descriptor = openat_owned(
        directory_fd,
        name,
        libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK,
        0,
    )?;
    require_regular_file(descriptor.as_raw_fd())
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

fn rename_noreplace_at(
    directory_fd: RawFd,
    old_name: &str,
    new_name: &str,
) -> Result<(), ServiceError> {
    let old = cstring_name(old_name)?;
    let new = cstring_name(new_name)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory_fd,
            old.as_ptr(),
            directory_fd,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn unlinkat_if_present(
    directory_fd: RawFd,
    name: &str,
) -> Result<(), ServiceError> {
    let name = cstring_name(name)?;
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

fn cstring_name(name: &str) -> Result<CString, ServiceError> {
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || name == "."
        || name == ".."
        || name.contains('/')
        || Path::new(name).components().count() != 1
    {
        return Err(ServiceError::Invalid(
            "journal entry name is not a single safe component",
        ));
    }
    CString::new(name).map_err(|_| {
        ServiceError::Invalid(
            "journal entry name contains an interior NUL",
        )
    })
}
