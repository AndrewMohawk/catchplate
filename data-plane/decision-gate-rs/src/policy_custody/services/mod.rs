//! TrustedHostNoTee policy-custody service bootstrap and serving loops.
//!
//! Host runners accept only systemd-owned inputs: one named,
//! inherited AF_UNIX SOCK_SEQPACKET listener, named retained capability FDs,
//! and read-only credentials beneath CREDENTIALS_DIRECTORY. They never bind or
//! connect a socket path and never accept an ambient secret-path override.
//! The separate guest delivery owner supplies held signed originals to the same
//! real constructors; it does not relabel their trust reports as measured.

pub(super) mod bounded_cleanup_helper;
pub(super) mod cleanup_authorization_consumer;
pub(super) mod common;
pub(super) mod current_signature_authority;
pub(super) mod durable_recovery_store;
pub(super) mod production;
pub(super) mod recovery_target_provider;
pub(super) mod wire;
pub(super) mod guest;
pub(super) mod generation_service;
pub(super) mod generation_service_client;
mod guest_original;
use guest::Bootstrap;

use self::bounded_cleanup_helper::{
    CleanupHelperServerProgress, CleanupHelperSigningAuthorityV3,
    TrustedHostCleanupEffectOperationV3,
    TrustedHostNoTeeBoundedCleanupHelperClient,
    TrustedHostNoTeeBoundedCleanupHelperServer,
    ValidatedCleanupHelperHandshakeV3,
};
use self::cleanup_authorization_consumer::{
    TrustedHostNoTeeCleanupAuthorizationConsumerClient,
    TrustedHostNoTeeCleanupAuthorizationConsumerServer,
    TrustedHostNoTeeCleanupAuthorizationVerifier,
    TrustedHostNoTeeCleanupConsumerSigningIdentity,
    TrustedHostNoTeeCurrentHeadVerifier,
};
use self::common::{
    perform_client_handshake, ReceivedSeqpacket,
    ServiceRequestFrameV3, ServiceResponseFrameV3,
    TrustedHostNoTeeServiceReportV3, MAX_SERVICE_FRAME_BYTES,
    MAX_SERVICE_RIGHTS,
};
pub(super) use self::common::{
    decode_canonical_frame, encode_canonical_frame,
    AuthenticatedInheritedSeqpacket, ExpectedPeerCredentials,
    ServiceError, ServiceHandshakeReplyV3, ServiceHandshakeRequestV3,
    TrustedHostServiceRoleV3,
};
use self::current_signature_authority::{
    SharedCurrentSignatureAuthorityClient,
    TrustedHostNoTeeCurrentSignatureAuthorityClient,
    TrustedHostNoTeeCurrentSignatureAuthorityServer,
};
use self::durable_recovery_store::{
    recovery_material_to_runtime, wire_owner_to_runtime,
    DurableRecoveryStoreSeedV3,
    RecoveryStoreCurrentHeadRequestBindingV3,
    TrustedHostNoTeeDurableRecoveryStoreServer,
    TrustedHostNoTeeRecoveryStoreSigningAuthority,
    VerifiedRecoveryStoreCurrentHeadProvider,
};
pub(super) use self::durable_recovery_store::{
    RecoveryRuntimeMaterialV3,
    TrustedHostNoTeeDurableRecoveryStoreClient,
};
use self::production::{
    authenticate_production_rpc_session,
    run_production_rpc_service,
    ExistingFiveServiceProductionAuthoritiesV4,
    ProductionPrimitiveRejectionV4,
    ProductionParentSignerEndpointConfigV4,
    ProductionProofEndpointConfigV4,
    ProductionProofEndpointKindV4,
    ProductionRpcServiceBridgeV4,
    ProductionServiceHistoricalKeyringsV4,
};
pub(super) use self::production::run_production_rpc_service_from_env;
use self::recovery_target_provider::{
    SignedDurableReapLineageProofV3,
    TrustedHostNoTeeRecoveryTargetProviderClient,
    TrustedHostNoTeeRecoveryTargetProviderServer,
};
use self::wire::{
    CleanupEffectIntentV3, CurrentAuthoritySubjectV3,
    DurableOwnershipRecordV3, RecoveryMaterialV3,
};
use super::boottime::{boottime_now_nanos, BoottimeDomain};
use super::authority_history::{
    AuthorityHistoryManifestV3, BoundedAuthorityHistoryV3,
    HistoricalAuthorityRoleV3, HistoricalServiceRoleV3,
    MAX_AUTHORITY_COMPACTION_ANCHORS, MAX_AUTHORITY_HISTORY_EPOCHS,
    MAX_AUTHORITY_REPLAY_TOMBSTONES,
};
use super::endpoint_clients::{
    CurrentKeyAuthorizationPin, EndpointConsumeCursor,
    EndpointTrustPin,
};
use super::protocol::{
    EndpointProcessIdentity, PolicyCustodyEndpointRole,
    SignedEndpointKeyAuthorizationCheckpoint,
};
use super::production_dispatch::
    production_dispatch_protocol_set_sha256;
use super::super::{canonical_json_bytes, Sha256Digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd,
};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::mpsc::{
    sync_channel, SyncSender, TrySendError,
};
use std::sync::atomic::{
    AtomicBool, AtomicU64, AtomicU8, Ordering,
};
use std::sync::{Arc, Mutex};
use std::thread;

const SERVICE_RUNTIME_CONFIG_VERSION: &str =
    "serverware.policyCustodyServiceRuntimeConfig/v4";
const DURABLE_RECOVERY_STORE_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-durable-recovery-store.json";
const CLEANUP_AUTHORIZATION_CONSUMER_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-cleanup-authorization-consumer.json";
const RECOVERY_TARGET_PROVIDER_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-recovery-target-provider.json";
const CURRENT_SIGNATURE_AUTHORITY_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-current-signature-authority.json";
const BOUNDED_CLEANUP_HELPER_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-bounded-cleanup-helper.json";
const LISTENER_FD_NAME: &str = "listener";
const JOURNAL_FD_NAME: &str = "journal";
const STATE_FD_NAME: &str = "state";
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_STARTUP_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_ACTIVATION_FDS: usize = 64;
const MAX_CURRENT_SUBJECTS: usize = 64;
const MAX_READINESS_REAP_WORKERS: usize = 64;
const POLL_SLICE_MILLIS: i32 = 1_000;
const DURABILITY_WORK_QUEUE_DEPTH: usize = 8;
const DURABILITY_WORK_QUEUED: u8 = 0;
const DURABILITY_WORK_RUNNING: u8 = 1;
const DURABILITY_WORK_CANCELLED: u8 = 2;
const DURABILITY_WORK_COMPLETED: u8 = 3;
const DURABILITY_WORK_LATE: u8 = 4;

type RuntimeAuthorityHistory = BoundedAuthorityHistoryV3<
    MAX_AUTHORITY_HISTORY_EPOCHS,
    MAX_AUTHORITY_COMPACTION_ANCHORS,
    MAX_AUTHORITY_REPLAY_TOMBSTONES,
>;

#[derive(Debug)]
pub(crate) struct ServiceRunnerError {
    message: String,
}

impl ServiceRunnerError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ServiceRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ServiceRunnerError {}

impl From<io::Error> for ServiceRunnerError {
    fn from(error: io::Error) -> Self {
        Self::invalid(error.to_string())
    }
}

impl From<ServiceError> for ServiceRunnerError {
    fn from(error: ServiceError) -> Self {
        Self::invalid(error.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedPeerCredentialV3 {
    uid: u32,
    gid: u32,
    pid: i32,
    process_identity_sha256: Sha256Digest,
    start_time_ticks: u64,
    executable_device: u64,
    executable_inode: u64,
    executable_length: u64,
    executable_sha256: Sha256Digest,
    cgroup_path_sha256: Sha256Digest,
    cgroup_mount_id: u64,
    cgroup_inode: u64,
    security_label_sha256: Sha256Digest,
    configuration_generation_sha256: Sha256Digest,
}

impl ExpectedPeerCredentialV3 {
    fn checked(&self) -> Result<ExpectedPeerCredentials, ServiceRunnerError> {
        if self.pid <= 0
            || self.process_identity_sha256
                == Sha256Digest::compute(&[])
            || self.start_time_ticks == 0
            || self.executable_device == 0
            || self.executable_inode == 0
            || self.executable_length == 0
            || self.executable_length > 256 * 1024 * 1024
            || self.executable_sha256 == Sha256Digest::compute(&[])
        {
            return Err(ServiceRunnerError::invalid(
                "configured service peer PID and process identity must be exact and nonzero",
            ));
        }
        Ok(ExpectedPeerCredentials {
            pid: self.pid,
            uid: self.uid,
            gid: self.gid,
            process_identity_sha256:
                self.process_identity_sha256.clone(),
            start_time_ticks: self.start_time_ticks,
            executable_device: self.executable_device,
            executable_inode: self.executable_inode,
            executable_length: self.executable_length,
            executable_sha256: self
                .executable_sha256
                .raw_bytes()
                .map_err(|_| {
                    ServiceRunnerError::invalid(
                        "configured peer executable digest is invalid",
                    )
                })?,
            cgroup_path_sha256:
                self.cgroup_path_sha256.clone(),
            cgroup_mount_id: self.cgroup_mount_id,
            cgroup_inode: self.cgroup_inode,
            security_label_sha256:
                self.security_label_sha256.clone(),
            configuration_generation_sha256:
                self.configuration_generation_sha256.clone(),
        })
        .and_then(|expected| {
            expected.validate_claim()?;
            Ok(expected)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeConfigHeaderV3 {
    api_version: String,
    startup_timeout_millis: u64,
    operation_generation: u64,
    service_restart_epoch: u64,
    readiness_epoch: u64,
    durability_worker_queue_depth: u16,
    maximum_durability_worker_nanos: u64,
    authority_history_manifest_sha256: Sha256Digest,
    authority_history_manifest_credential: String,
    authority_history_root_key_id: Sha256Digest,
    authority_history_root_key_spki_sha256: Sha256Digest,
    production_dispatch_protocol_set_sha256: Sha256Digest,
    deployment_generation_sha256: Sha256Digest,
    shared_configuration_sha256: Sha256Digest,
    listener_socket_path: PathBuf,
    expected_peer: ExpectedPeerCredentialV3,
    activation_directory_identities:
        BTreeMap<String, ActivationDirectoryIdentityV3>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    generation_admission:Option<generation_service::Selection>,
}

impl RuntimeConfigHeaderV3 {
    fn validate(&self) -> Result<(), ServiceRunnerError> {
        self.expected_peer.checked()?;
        if !matches!((self.api_version.as_str(),self.generation_admission.as_ref()),
                (SERVICE_RUNTIME_CONFIG_VERSION,None)|(generation_service::RUNTIME,Some(_)))
            || self.startup_timeout_millis == 0
            || self.startup_timeout_millis
                > MAX_STARTUP_TIMEOUT_MILLIS
            || self.operation_generation == 0
            || self.service_restart_epoch == 0
            || self.readiness_epoch < self.service_restart_epoch
            || usize::from(self.durability_worker_queue_depth)
                != DURABILITY_WORK_QUEUE_DEPTH
            || self.maximum_durability_worker_nanos == 0
            || self.maximum_durability_worker_nanos
                > 1_000_000_000
            || self.authority_history_manifest_sha256
                == Sha256Digest::compute(&[])
            || self.authority_history_root_key_id
                == Sha256Digest::compute(&[])
            || self.authority_history_root_key_spki_sha256
                == Sha256Digest::compute(&[])
            || self.production_dispatch_protocol_set_sha256
                == Sha256Digest::compute(&[])
            || production_dispatch_protocol_set_sha256()
                .map_or(true, |expected| {
                    expected
                        != self
                            .production_dispatch_protocol_set_sha256
                })
            || self.deployment_generation_sha256
                == Sha256Digest::compute(&[])
            || self.shared_configuration_sha256
                == Sha256Digest::compute(&[])
            || !self.listener_socket_path.is_absolute()
            || self.listener_socket_path.as_os_str().is_empty()
            || self
                .listener_socket_path
                .as_os_str()
                .as_bytes()
                .contains(&0)
            || self.activation_directory_identities.len() > if self.generation_admission.is_some(){3}else{2}
        {
            return Err(ServiceRunnerError::invalid(
                "service runtime config header is incomplete or invalid",
            ));
        }
        validate_credential_name(
            &self.authority_history_manifest_credential,
        )?;
        if let Some(selection)=&self.generation_admission {
            if selection.grant_fd_name!=generation_service::GRANT_FD {
                return Err(ServiceRunnerError::invalid("generation grant descriptor name changed"));
            }
            self.activation_directory_identity(generation_service::DIRECTORY)?;
        }
        for (name, identity) in
            &self.activation_directory_identities
        {
            validate_fd_name(name)?;
            identity.validate()?;
        }
        Ok(())
    }

    fn observed_service_invocation_id_sha256(
        &self,
    ) -> Result<Sha256Digest, ServiceRunnerError> {
        let invocation_id = env::var("INVOCATION_ID").map_err(|_| {
            ServiceRunnerError::invalid(
                "systemd INVOCATION_ID is required",
            )
        })?;
        if invocation_id.len() != 32
            || !invocation_id.bytes().all(|byte| {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
        {
            return Err(ServiceRunnerError::invalid(
                "systemd INVOCATION_ID is not one canonical 128-bit lowercase hexadecimal identifier",
            ));
        }
        Ok(Sha256Digest::compute(invocation_id.as_bytes()))
    }

    fn load_authority_history(
        &self,
        credentials: &CredentialDirectory,
        expected_role: TrustedHostServiceRoleV3,
    ) -> Result<RuntimeAuthorityHistory, ServiceRunnerError> {
        let bytes = credentials.read(
            &self.authority_history_manifest_credential,
            MAX_CONFIG_BYTES,
        )?;
        if Sha256Digest::compute(&bytes)
            != self.authority_history_manifest_sha256
        {
            return Err(ServiceRunnerError::invalid(
                "authority-history credential differs from its startup-pinned manifest digest",
            ));
        }
        let manifest: AuthorityHistoryManifestV3 =
            common::decode_canonical_frame(&bytes)?;
        let history = RuntimeAuthorityHistory::from_manifest(
            manifest,
            &self.authority_history_root_key_id,
            &self.authority_history_root_key_spki_sha256,
        )
        .map_err(|error| {
            ServiceRunnerError::invalid(error.to_string())
        })?;
        let expected_historical_role =
            HistoricalAuthorityRoleV3::IsolatedService(
                historical_service_role(expected_role),
            );
        if history.authority_role() != expected_historical_role
            || history.manifest_sha256()
                != &self.authority_history_manifest_sha256
        {
            return Err(ServiceRunnerError::invalid(
                "authority-history credential binds another service role or manifest",
            ));
        }
        Ok(history)
    }

    fn activation_directory_identity(
        &self,
        name: &str,
    ) -> Result<
        &ActivationDirectoryIdentityV3,
        ServiceRunnerError,
    > {
        self.activation_directory_identities
            .get(name)
            .ok_or_else(|| {
                ServiceRunnerError::invalid(format!(
                    "configured activation directory identity {name} is absent"
                ))
            })
    }
}

fn historical_service_role(
    role: TrustedHostServiceRoleV3,
) -> HistoricalServiceRoleV3 {
    match role {
        TrustedHostServiceRoleV3::DurableRecoveryStore => {
            HistoricalServiceRoleV3::DurableRecoveryStore
        }
        TrustedHostServiceRoleV3::
            CleanupAuthorizationConsumer =>
        {
            HistoricalServiceRoleV3::
                CleanupAuthorizationConsumer
        }
        TrustedHostServiceRoleV3::RecoveryTargetProvider => {
            HistoricalServiceRoleV3::RecoveryTargetProvider
        }
        TrustedHostServiceRoleV3::
            CurrentSignatureAuthority =>
        {
            HistoricalServiceRoleV3::
                CurrentSignatureAuthority
        }
        TrustedHostServiceRoleV3::BoundedCleanupHelper => {
            HistoricalServiceRoleV3::BoundedCleanupHelper
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationDirectoryIdentityV3 {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl ActivationDirectoryIdentityV3 {
    fn validate(&self) -> Result<(), ServiceRunnerError> {
        if self.mount_id == 0
            || self.inode == 0
            || self.mode & libc::S_IFMT
                != libc::S_IFDIR
            || self.mode & 0o7777 != 0o700
        {
            return Err(ServiceRunnerError::invalid(
                "activation directory identity is incomplete or not an owner-only directory",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EndpointConsumeCursorCredentialV3 {
    sequence_high_water: u64,
    expected_next_sequence: u64,
    expected_predecessor_receipt_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EndpointTrustPinCredentialV3 {
    declared_socket_path: PathBuf,
    endpoint_process_identity: EndpointProcessIdentity,
    signed_current_key_authorization:
        SignedEndpointKeyAuthorizationCheckpoint,
    endpoint_verifying_key_credential: String,
    checkpoint_authority_verifying_key_credential: String,
    consume_cursor: EndpointConsumeCursorCredentialV3,
    consume_head_observed_at_boottime_nanos: u64,
}

impl EndpointTrustPinCredentialV3 {
    fn build(
        &self,
        credentials: &CredentialDirectory,
    ) -> Result<EndpointTrustPin, ServiceRunnerError> {
        self.build_inner(credentials, true)
    }

    fn build_historical(
        &self,
        credentials: &CredentialDirectory,
    ) -> Result<EndpointTrustPin, ServiceRunnerError> {
        self.build_inner(credentials, false)
    }

    fn build_inner(
        &self,
        credentials: &CredentialDirectory,
        require_current: bool,
    ) -> Result<EndpointTrustPin, ServiceRunnerError> {
        if !self.declared_socket_path.is_absolute()
            || self
                .declared_socket_path
                .as_os_str()
                .as_bytes()
                .contains(&0)
        {
            return Err(ServiceRunnerError::invalid(
                "declared endpoint socket identity is not an absolute path",
            ));
        }
        let endpoint_verifying_key = credentials
            .read_verifying_key(&self.endpoint_verifying_key_credential)?;
        let checkpoint_authority_verifying_key = credentials
            .read_verifying_key(
                &self.checkpoint_authority_verifying_key_credential,
            )?;
        let checkpoint = &self.signed_current_key_authorization;
        let payload = &checkpoint.payload;
        let process = &self.endpoint_process_identity;
        let pin = EndpointTrustPin {
            endpoint_role: payload.endpoint_role,
            socket_path: self.declared_socket_path.clone(),
            endpoint_uid: process.endpoint_uid,
            endpoint_gid: process.endpoint_gid,
            endpoint_process_identity: process.clone(),
            endpoint_process_identity_sha256:
                process.identity_sha256.clone(),
            exact_endpoint_generation:
                payload.exact_endpoint_generation,
            boottime_domain: BoottimeDomain::current().map_err(|error| {
                ServiceRunnerError::invalid(error.to_string())
            })?,
            current_key_authorization: CurrentKeyAuthorizationPin {
                endpoint_role: payload.endpoint_role,
                endpoint_process_identity_sha256:
                    payload.endpoint_process_identity_sha256.clone(),
                exact_endpoint_generation:
                    payload.exact_endpoint_generation,
                signing_key_id:
                    payload.authorized_signing_key_id.clone(),
                signing_key_spki_sha256:
                    payload
                        .authorized_signing_key_spki_sha256
                        .clone(),
                verifying_key: endpoint_verifying_key,
                signed_current_key_authorization: checkpoint.clone(),
                exact_checkpoint_sha256:
                    checkpoint.checkpoint_sha256.clone(),
                exact_predecessor_checkpoint_sha256:
                    payload.predecessor_checkpoint_sha256.clone(),
                exact_checkpoint_sequence:
                    payload.checkpoint_sequence,
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
                checkpoint_authority_verifying_key,
            },
            consume_cursor: EndpointConsumeCursor {
                sequence_high_water:
                    self.consume_cursor.sequence_high_water,
                expected_next_sequence:
                    self.consume_cursor.expected_next_sequence,
                expected_predecessor_receipt_sha256: self
                    .consume_cursor
                    .expected_predecessor_receipt_sha256
                    .clone(),
            },
            consume_head_observed_at_boottime_nanos:
                self.consume_head_observed_at_boottime_nanos,
        };
        if require_current {
            pin.validate().map_err(|error| {
                ServiceRunnerError::invalid(error.to_string())
            })?;
        }
        Ok(pin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableRecoveryStoreRuntimeConfigV3 {
    runtime: RuntimeConfigHeaderV3,
    signing_key_credential: String,
    signing_key_id: Sha256Digest,
    endpoint_process_identity: EndpointProcessIdentity,
    endpoint_generation: u64,
    checkpoint_sequence: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    current_head_authority_verifying_key_credential: String,
    current_head_authority_key_id: Sha256Digest,
    ownership_seed: Vec<DurableOwnershipRecordV3>,
    recovery_material_seed: Vec<RecoveryMaterialV3>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CleanupAuthorizationConsumerRuntimeConfigV3 {
    runtime: RuntimeConfigHeaderV3,
    signing_key_credential: String,
    endpoint_process_identity: EndpointProcessIdentity,
    endpoint_generation: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    current_head_authority_verifying_key_credential: String,
    current_head_authority_key_id: Sha256Digest,
    checkpoint_sequence: u64,
    minimum_checkpoint_sequence: u64,
    minimum_revocation_generation: u64,
    cleanup_authority_verifying_key_credential: String,
    cleanup_authority_key_id: Sha256Digest,
    cleanup_authority_current_key_authorization_checkpoint_sha256:
        Sha256Digest,
    cleanup_authority_revocation_generation: u64,
    cleanup_authority_revocation_root_sha256: Sha256Digest,
    genesis_predecessor_receipt_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryTargetProviderRuntimeConfigV3 {
    runtime: RuntimeConfigHeaderV3,
    signing_key_credential: String,
    service_signing_pin: EndpointTrustPinCredentialV3,
    maximum_registrations: usize,
    lineage_authority_key_id: Sha256Digest,
    lineage_authority_key_spki_sha256: Sha256Digest,
    lineage_authority_verifying_key_credential: String,
    durable_reap_lineage_proofs:
        Vec<SignedDurableReapLineageProofV3>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentSignatureSubjectCredentialV3 {
    subject: CurrentAuthoritySubjectV3,
    pin: EndpointTrustPinCredentialV3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentSignatureAuthorityRuntimeConfigV3 {
    runtime: RuntimeConfigHeaderV3,
    service_signing_key_credential: String,
    service_signing_pin: EndpointTrustPinCredentialV3,
    current_subjects: Vec<CurrentSignatureSubjectCredentialV3>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoundedCleanupHelperRuntimeConfigV3 {
    runtime: RuntimeConfigHeaderV3,
    signing_key_credential: String,
    current_head_authority_verifying_key_credential: String,
    current_head_authority_key_id: Sha256Digest,
    endpoint_process_identity_sha256: Sha256Digest,
    endpoint_generation: u64,
    helper_generation: u64,
    signing_key_id: Sha256Digest,
    checkpoint_sequence: u64,
    current_key_authorization_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

struct LoadedConfig<T> {
    value: T,
    exact_sha256: Sha256Digest,
    credentials: CredentialDirectory,
}

struct HandshakeCurrentHeadPin {
    verifying_key: VerifyingKey,
    authority_key_id: Sha256Digest,
    authority_key_spki_sha256: Sha256Digest,
    endpoint_role: PolicyCustodyEndpointRole,
    endpoint_generation: u64,
    checkpoint_sequence: u64,
    checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl HandshakeCurrentHeadPin {
    fn from_endpoint_pin(pin: &EndpointTrustPin) -> Self {
        Self {
            verifying_key: pin
                .current_key_authorization
                .checkpoint_authority_verifying_key
                .clone(),
            authority_key_id: pin
                .current_key_authorization
                .checkpoint_authority_key_id
                .clone(),
            authority_key_spki_sha256: pin
                .current_key_authorization
                .checkpoint_authority_key_spki_sha256
                .clone(),
            endpoint_role: pin.endpoint_role,
            endpoint_generation: pin.exact_endpoint_generation,
            checkpoint_sequence: pin
                .current_key_authorization
                .exact_checkpoint_sequence,
            checkpoint_sha256: pin
                .current_key_authorization
                .exact_checkpoint_sha256
                .clone(),
            revocation_generation: pin
                .current_key_authorization
                .exact_revocation_generation_high_water,
            revocation_root_sha256: pin
                .current_key_authorization
                .exact_revocation_root_sha256
                .clone(),
        }
    }

    fn verify(
        &self,
        request: &ServiceHandshakeRequestV3,
    ) -> Result<(), ServiceRunnerError> {
        let signed =
            &request.expected_current_head.signed_current_head;
        let statement = &signed.statement;
        let now = boottime_now_nanos().map_err(|error| {
            ServiceRunnerError::invalid(error.to_string())
        })?;
        if signed.authority_key_id != self.authority_key_id
            || signed.authority_key_spki_sha256
                != self.authority_key_spki_sha256
            || statement.endpoint_role != self.endpoint_role
            || statement.endpoint_generation
                != self.endpoint_generation
            || statement.checkpoint_sequence
                != self.checkpoint_sequence
            || statement.checkpoint_sha256
                != self.checkpoint_sha256
            || statement.revocation_generation_high_water
                != self.revocation_generation
            || statement.revocation_root_sha256
                != self.revocation_root_sha256
            || statement.issued_at_boottime_nanos > now
            || statement.deadline != request.deadline
        {
            return Err(ServiceRunnerError::invalid(
                "service handshake current head does not match the configured current authority",
            ));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&signed.authority_signature_base64)
            .map_err(|_| {
                ServiceRunnerError::invalid(
                    "service handshake current-head signature is not base64url",
                )
            })?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| {
                ServiceRunnerError::invalid(
                    "service handshake current-head signature has an invalid size",
                )
            })?;
        self.verifying_key
            .verify_strict(
                &signed
                    .authority_signature_preimage()
                    .map_err(|error| {
                        ServiceRunnerError::invalid(
                            error.to_string(),
                        )
                    })?,
                &signature,
            )
            .map_err(|_| {
                ServiceRunnerError::invalid(
                    "service handshake current-head signature is invalid",
                )
            })
    }
}

enum CredentialDirectory {
    Host { descriptor: OwnedFd },
    Guest(Arc<guest::Delivery>),
}

impl CredentialDirectory {
    fn open_systemd() -> Result<Self, ServiceRunnerError> {
        let directory = env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or_else(|| {
                ServiceRunnerError::invalid(
                    "CREDENTIALS_DIRECTORY is required",
                )
            })?;
        if directory.as_bytes().is_empty()
            || directory.as_bytes().contains(&0)
            || directory.as_bytes().first() != Some(&b'/')
        {
            return Err(ServiceRunnerError::invalid(
                "CREDENTIALS_DIRECTORY is not an absolute systemd path",
            ));
        }
        let path = CString::new(directory.as_bytes()).map_err(|_| {
            ServiceRunnerError::invalid(
                "CREDENTIALS_DIRECTORY contains NUL",
            )
        })?;
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        validate_credential_directory(descriptor.as_fd())?;
        Ok(Self::Host { descriptor })
    }

    fn read(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, ServiceRunnerError> {
        validate_credential_name(name)?;
        let descriptor = match self {
            Self::Guest(owner) => return owner.read(name, maximum_bytes),
            Self::Host { descriptor } => descriptor,
        };
        if maximum_bytes == 0 {
            return Err(ServiceRunnerError::invalid(
                "credential byte bound must be nonzero",
            ));
        }
        let name = CString::new(name).map_err(|_| {
            ServiceRunnerError::invalid(
                "systemd credential name contains NUL",
            )
        })?;
        let raw = unsafe {
            libc::openat(
                descriptor.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        let stat = descriptor_stat(descriptor.as_fd())?;
        let effective_uid = unsafe { libc::geteuid() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || (stat.st_uid != 0 && stat.st_uid != effective_uid)
            || stat.st_mode & 0o222 != 0
            || stat.st_size <= 0
        {
            return Err(ServiceRunnerError::invalid(
                "systemd credential is not an immutable read-only regular file",
            ));
        }
        let length = usize::try_from(stat.st_size).map_err(|_| {
            ServiceRunnerError::invalid(
                "systemd credential length is not representable",
            )
        })?;
        if length > maximum_bytes {
            return Err(ServiceRunnerError::invalid(
                "systemd credential exceeds its fixed byte bound",
            ));
        }
        let mut bytes = vec![0_u8; length];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = unsafe {
                libc::pread(
                    descriptor.as_raw_fd(),
                    bytes[offset..].as_mut_ptr().cast(),
                    bytes.len() - offset,
                    offset as libc::off_t,
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error.into());
            }
            if read == 0 {
                return Err(ServiceRunnerError::invalid(
                    "systemd credential was truncated while read",
                ));
            }
            offset = offset
                .checked_add(usize::try_from(read).map_err(|_| {
                    ServiceRunnerError::invalid(
                        "systemd credential read length is invalid",
                    )
                })?)
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "systemd credential read offset overflowed",
                    )
                })?;
        }
        let after = descriptor_stat(descriptor.as_fd())?;
        if stat.st_dev != after.st_dev
            || stat.st_ino != after.st_ino
            || stat.st_size != after.st_size
            || stat.st_mode != after.st_mode
            || stat.st_mtime != after.st_mtime
            || stat.st_mtime_nsec != after.st_mtime_nsec
        {
            return Err(ServiceRunnerError::invalid(
                "systemd credential metadata changed while read",
            ));
        }
        Ok(bytes)
    }

    fn read_signing_key(
        &self,
        name: &str,
        expected_key_id: &Sha256Digest,
    ) -> Result<(SigningKey, Sha256Digest), ServiceRunnerError> {
        let mut bytes = self.read(name, 32)?;
        if bytes.len() != 32 {
            bytes.fill(0);
            return Err(ServiceRunnerError::invalid(
                "Ed25519 signing credential must contain exactly 32 raw bytes",
            ));
        }
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&bytes);
        let credential_sha256 = Sha256Digest::compute(&bytes);
        bytes.fill(0);
        let key = SigningKey::from_bytes(&secret);
        secret.fill(0);
        if let Self::Guest(owner) = self {
            owner.signing(name, &key, expected_key_id)?;
        }
        Ok((key, credential_sha256))
    }

    fn read_verifying_key(
        &self,
        name: &str,
    ) -> Result<VerifyingKey, ServiceRunnerError> {
        let bytes = self.read(name, 32)?;
        let exact: [u8; 32] = bytes.try_into().map_err(|_| {
            ServiceRunnerError::invalid(
                "Ed25519 verification credential must contain exactly 32 raw bytes",
            )
        })?;
        VerifyingKey::from_bytes(&exact).map_err(|_| {
            ServiceRunnerError::invalid(
                "Ed25519 verification credential is invalid",
            )
        })
    }
}

fn load_config<T>(
    credential_name: &str,
) -> Result<LoadedConfig<T>, ServiceRunnerError>
where
    T: DeserializeOwned + Serialize,
{
    let credentials = CredentialDirectory::open_systemd()?;
    let bytes = credentials.read(credential_name, MAX_CONFIG_BYTES)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|error| {
        ServiceRunnerError::invalid(format!(
            "systemd service config is invalid: {error}"
        ))
    })?;
    let canonical = canonical_json_bytes(&value).map_err(|_| {
        ServiceRunnerError::invalid(
            "systemd service config is outside canonical JSON",
        )
    })?;
    if canonical != bytes {
        return Err(ServiceRunnerError::invalid(
            "systemd service config is not exact canonical JSON",
        ));
    }
    Ok(LoadedConfig {
        value,
        exact_sha256: Sha256Digest::compute(&canonical),
        credentials,
    })
}

pub(crate) fn run_durable_recovery_store_from_env(
) -> Result<(), ServiceRunnerError> {
    close_unlisted_ambient_descriptors()?;
    let loaded: LoadedConfig<DurableRecoveryStoreRuntimeConfigV3> =
        load_config(DURABLE_RECOVERY_STORE_CONFIG_CREDENTIAL)?;
    loaded.value.runtime.observed_service_invocation_id_sha256()?;
    let activation = take_activation_fds()?;
    run_durable_recovery_store_loaded(loaded, Bootstrap::Host, activation)
}

fn run_durable_recovery_store_loaded(
    loaded: LoadedConfig<DurableRecoveryStoreRuntimeConfigV3>,
    bootstrap: Bootstrap, mut activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.runtime.validate()?;
    let mut generation=generation_service::Gate::open(&loaded,&loaded.value.runtime,&bootstrap,&mut activation,
        TrustedHostServiceRoleV3::DurableRecoveryStore)?;
    let _authority_history =
        loaded.value.runtime.load_authority_history(
            &loaded.credentials,
            TrustedHostServiceRoleV3::DurableRecoveryStore,
        )?;
    let startup_deadline = bootstrap.deadline(
        loaded.value.runtime.startup_timeout_millis,
    )?;
    let expected_peer = loaded.value.runtime.expected_peer.checked()?;
    require_exact_activation_names(
        &activation,
        &[LISTENER_FD_NAME, JOURNAL_FD_NAME],
    )?;
    require_exact_directory_identity_names(
        &loaded.value.runtime,
        &[JOURNAL_FD_NAME],
    )?;
    let listener = take_activation_fd(
        &mut activation,
        LISTENER_FD_NAME,
    )?;
    let journal = take_activation_fd(
        &mut activation,
        JOURNAL_FD_NAME,
    )?;
    validate_listener(
        listener.as_fd(),
        &loaded.value.runtime.listener_socket_path,
    )?;
    validate_directory_capability(
        journal.as_fd(),
        JOURNAL_FD_NAME,
        loaded
            .value
            .runtime
            .activation_directory_identity(JOURNAL_FD_NAME)?,
    )?;

    let (signing_key, signing_credential_sha256) = loaded
        .credentials
        .read_signing_key(&loaded.value.signing_key_credential, &loaded.value.signing_key_id)?;
    let current_head_authority = loaded
        .credentials
        .read_verifying_key(
            &loaded
                .value
                .current_head_authority_verifying_key_credential,
        )?;
    let endpoint_role =
        loaded.value.endpoint_process_identity.endpoint_role;
    let process_identity_sha256 = loaded
        .value
        .endpoint_process_identity
        .identity_sha256
        .clone();
    let signer = TrustedHostNoTeeRecoveryStoreSigningAuthority::new(
        signing_key,
        loaded.value.signing_key_id,
        loaded.value.endpoint_process_identity,
        loaded.value.endpoint_generation,
        loaded
            .value
            .current_key_authorization_checkpoint_sha256
            .clone(),
        loaded.value.revocation_generation,
        loaded.value.revocation_root_sha256.clone(),
    )?;
    let handshake_pin = HandshakeCurrentHeadPin {
        authority_key_spki_sha256:
            verifying_key_spki_sha256(&current_head_authority)?,
        verifying_key: current_head_authority,
        authority_key_id:
            loaded.value.current_head_authority_key_id,
        endpoint_role,
        endpoint_generation: loaded.value.endpoint_generation,
        checkpoint_sequence: loaded.value.checkpoint_sequence,
        checkpoint_sha256: loaded
            .value
            .current_key_authorization_checkpoint_sha256
            .clone(),
        revocation_generation:
            loaded.value.revocation_generation,
        revocation_root_sha256:
            loaded.value.revocation_root_sha256.clone(),
    };
    let report = TrustedHostNoTeeServiceReportV3::new(
        TrustedHostServiceRoleV3::DurableRecoveryStore,
        loaded.value.runtime.operation_generation,
        loaded.value.runtime.service_restart_epoch,
        bootstrap.invocation(&loaded.value.runtime)?,
        loaded.value.runtime.readiness_epoch,
        loaded.value.runtime.durability_worker_queue_depth,
        loaded
            .value
            .runtime
            .maximum_durability_worker_nanos,
        loaded
            .value
            .runtime
            .authority_history_manifest_sha256
            .clone(),
        loaded
            .value
            .runtime
            .production_dispatch_protocol_set_sha256
            .clone(),
        loaded
            .value
            .runtime
            .shared_configuration_sha256
            .clone(),
        loaded
            .value
            .runtime
            .deployment_generation_sha256
            .clone(),
        loaded.exact_sha256,
        process_identity_sha256,
        Some(signing_credential_sha256),
    )?;
    let mut server =
        TrustedHostNoTeeDurableRecoveryStoreServer::
            from_recovered_journal(
                journal,
                DurableRecoveryStoreSeedV3 {
                    ownership: loaded.value.ownership_seed,
                    recovery_material:
                        loaded.value.recovery_material_seed,
                },
                signer,
            )?;
    let connection = accept_authenticated_peer(
        listener.as_fd(),
        &expected_peer,
        startup_deadline,
    )?;
    let authenticated = authenticated_capability(
        connection.as_fd(),
        &expected_peer,
    )?;
    perform_handshake(
        connection.as_raw_fd(),
        &authenticated,
        TrustedHostServiceRoleV3::DurableRecoveryStore,
        endpoint_role,
        &report,
        &handshake_pin,
        &loaded
            .value
            .runtime
            .expected_peer
            .process_identity_sha256,
        0,
        0,
        startup_deadline,
    )?;
    serve_exact_frame_authority(
        connection.as_fd(),
        &authenticated,
        bootstrap,
        TrustedHostServiceRoleV3::DurableRecoveryStore,
        loaded
            .value
            .runtime
            .maximum_durability_worker_nanos,
        move |request: Vec<u8>| {
            if let Some(gate)=&mut generation {
                if let Some(reply)=gate.handle(&request,&server)? {return Ok(reply);}
            }
            server.handle_exact_request_frame(&request)
        },
    )
}

pub(crate) fn run_cleanup_authorization_consumer_from_env(
) -> Result<(), ServiceRunnerError> {
    close_unlisted_ambient_descriptors()?;
    let loaded: LoadedConfig<
        CleanupAuthorizationConsumerRuntimeConfigV3,
    > = load_config(CLEANUP_AUTHORIZATION_CONSUMER_CONFIG_CREDENTIAL)?;
    loaded.value.runtime.observed_service_invocation_id_sha256()?;
    let activation = take_activation_fds()?;
    run_cleanup_authorization_consumer_loaded(loaded, Bootstrap::Host, activation)
}

fn run_cleanup_authorization_consumer_loaded(
    loaded: LoadedConfig<CleanupAuthorizationConsumerRuntimeConfigV3>,
    bootstrap: Bootstrap, mut activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.runtime.validate()?;
    let mut generation=generation_service::Gate::open(&loaded,&loaded.value.runtime,&bootstrap,&mut activation,
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer)?;
    let _authority_history =
        loaded.value.runtime.load_authority_history(
            &loaded.credentials,
            TrustedHostServiceRoleV3::
                CleanupAuthorizationConsumer,
        )?;
    let startup_deadline = bootstrap.deadline(
        loaded.value.runtime.startup_timeout_millis,
    )?;
    let expected_peer = loaded.value.runtime.expected_peer.checked()?;
    require_exact_activation_names(
        &activation,
        &[LISTENER_FD_NAME, STATE_FD_NAME, JOURNAL_FD_NAME],
    )?;
    require_exact_directory_identity_names(
        &loaded.value.runtime,
        &[STATE_FD_NAME, JOURNAL_FD_NAME],
    )?;
    let listener = take_activation_fd(
        &mut activation,
        LISTENER_FD_NAME,
    )?;
    let state = take_activation_fd(&mut activation, STATE_FD_NAME)?;
    let journal = take_activation_fd(
        &mut activation,
        JOURNAL_FD_NAME,
    )?;
    validate_listener(
        listener.as_fd(),
        &loaded.value.runtime.listener_socket_path,
    )?;
    validate_directory_capability(
        state.as_fd(),
        STATE_FD_NAME,
        loaded
            .value
            .runtime
            .activation_directory_identity(STATE_FD_NAME)?,
    )?;
    validate_directory_capability(
        journal.as_fd(),
        JOURNAL_FD_NAME,
        loaded
            .value
            .runtime
            .activation_directory_identity(JOURNAL_FD_NAME)?,
    )?;

    let (signing_key, signing_credential_sha256) = loaded
        .credentials
        .read_signing_key(&loaded.value.signing_key_credential, &loaded.value.signing_key_id)?;
    let signing_spki_sha256 =
        verifying_key_spki_sha256(&signing_key.verifying_key())?;
    let current_head_authority = loaded
        .credentials
        .read_verifying_key(
            &loaded
                .value
                .current_head_authority_verifying_key_credential,
        )?;
    let current_head_authority_spki_sha256 =
        verifying_key_spki_sha256(&current_head_authority)?;
    let cleanup_authority = loaded
        .credentials
        .read_verifying_key(
            &loaded
                .value
                .cleanup_authority_verifying_key_credential,
        )?;
    let cleanup_authority_spki_sha256 =
        verifying_key_spki_sha256(&cleanup_authority)?;
    let identity = TrustedHostNoTeeCleanupConsumerSigningIdentity {
        endpoint_process_identity:
            loaded.value.endpoint_process_identity,
        endpoint_generation: loaded.value.endpoint_generation,
        current_key_authorization_checkpoint_sha256: loaded
            .value
            .current_key_authorization_checkpoint_sha256
            .clone(),
        revocation_generation: loaded.value.revocation_generation,
        revocation_root_sha256:
            loaded.value.revocation_root_sha256.clone(),
        signing_key_id: loaded.value.signing_key_id.clone(),
        signing_key_spki_sha256: signing_spki_sha256,
    };
    let endpoint_role =
        identity.endpoint_process_identity.endpoint_role;
    let current_head_verifier =
        TrustedHostNoTeeCurrentHeadVerifier::new(
            current_head_authority,
            loaded.value.current_head_authority_key_id.clone(),
            current_head_authority_spki_sha256.clone(),
            loaded.value.minimum_checkpoint_sequence,
            loaded.value.minimum_revocation_generation,
        )?;
    let handshake_pin = HandshakeCurrentHeadPin {
        verifying_key: loaded
            .credentials
            .read_verifying_key(
                &loaded
                    .value
                    .current_head_authority_verifying_key_credential,
            )?,
        authority_key_id:
            loaded.value.current_head_authority_key_id.clone(),
        authority_key_spki_sha256:
            current_head_authority_spki_sha256.clone(),
        endpoint_role,
        endpoint_generation: loaded.value.endpoint_generation,
        checkpoint_sequence: loaded.value.checkpoint_sequence,
        checkpoint_sha256: loaded
            .value
            .current_key_authorization_checkpoint_sha256
            .clone(),
        revocation_generation:
            loaded.value.revocation_generation,
        revocation_root_sha256:
            loaded.value.revocation_root_sha256.clone(),
    };
    let cleanup_authorization_verifier =
        TrustedHostNoTeeCleanupAuthorizationVerifier::new(
            cleanup_authority,
            loaded.value.cleanup_authority_key_id,
            cleanup_authority_spki_sha256,
            loaded
                .value
                .cleanup_authority_current_key_authorization_checkpoint_sha256,
            loaded
                .value
                .cleanup_authority_revocation_generation,
            loaded
                .value
                .cleanup_authority_revocation_root_sha256,
        )?;
    let mut server =
        TrustedHostNoTeeCleanupAuthorizationConsumerServer::new(
            signing_key,
            identity,
            current_head_verifier,
            cleanup_authorization_verifier,
            state,
            journal,
            loaded.value.genesis_predecessor_receipt_sha256,
            loaded.value.runtime.operation_generation,
            loaded.value.runtime.service_restart_epoch,
            bootstrap.invocation(&loaded.value.runtime)?,
            loaded.value.runtime.readiness_epoch,
            loaded.value.runtime.durability_worker_queue_depth,
            loaded
                .value
                .runtime
                .maximum_durability_worker_nanos,
            loaded
                .value
                .runtime
                .authority_history_manifest_sha256
                .clone(),
            loaded
                .value
                .runtime
                .production_dispatch_protocol_set_sha256
                .clone(),
            loaded
                .value
                .runtime
                .shared_configuration_sha256
                .clone(),
            loaded
                .value
                .runtime
                .deployment_generation_sha256
                .clone(),
            loaded.exact_sha256,
            signing_credential_sha256,
        )?;
    let report = server.security_report().clone();
    let connection = accept_authenticated_peer(
        listener.as_fd(),
        &expected_peer,
        startup_deadline,
    )?;
    let authenticated = authenticated_capability(
        connection.as_fd(),
        &expected_peer,
    )?;
    perform_handshake(
        connection.as_raw_fd(),
        &authenticated,
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,
        endpoint_role,
        &report,
        &handshake_pin,
        &loaded
            .value
            .runtime
            .expected_peer
            .process_identity_sha256,
        0,
        0,
        startup_deadline,
    )?;
    serve_exact_frame_authority(
        connection.as_fd(),
        &authenticated,
        bootstrap,
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,
        loaded
            .value
            .runtime
            .maximum_durability_worker_nanos,
        move |request: Vec<u8>| {
            if let Some(gate)=&mut generation {
                if let Some(reply)=gate.handle(&request,&server)? {return Ok(reply);}
            }
            server.handle_exact_request_frame(&request)
        },
    )
}

pub(crate) fn run_recovery_target_provider_from_env(
) -> Result<(), ServiceRunnerError> {
    close_unlisted_ambient_descriptors()?;
    let loaded: LoadedConfig<RecoveryTargetProviderRuntimeConfigV3> =
        load_config(RECOVERY_TARGET_PROVIDER_CONFIG_CREDENTIAL)?;
    loaded.value.runtime.observed_service_invocation_id_sha256()?;
    let activation = take_activation_fds()?;
    run_recovery_target_provider_loaded(loaded, Bootstrap::Host, activation)
}

fn run_recovery_target_provider_loaded(
    loaded: LoadedConfig<RecoveryTargetProviderRuntimeConfigV3>,
    bootstrap: Bootstrap, mut activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.runtime.validate()?;
    let mut generation=generation_service::Gate::open(&loaded,&loaded.value.runtime,&bootstrap,&mut activation,
        TrustedHostServiceRoleV3::RecoveryTargetProvider)?;
    let _authority_history =
        loaded.value.runtime.load_authority_history(
            &loaded.credentials,
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
        )?;
    let startup_deadline = bootstrap.deadline(
        loaded.value.runtime.startup_timeout_millis,
    )?;
    let expected_peer = loaded.value.runtime.expected_peer.checked()?;
    require_exact_activation_names(
        &activation,
        &[LISTENER_FD_NAME, JOURNAL_FD_NAME],
    )?;
    require_exact_directory_identity_names(
        &loaded.value.runtime,
        &[JOURNAL_FD_NAME],
    )?;
    let listener = take_activation_fd(
        &mut activation,
        LISTENER_FD_NAME,
    )?;
    let journal = take_activation_fd(
        &mut activation,
        JOURNAL_FD_NAME,
    )?;
    validate_listener(
        listener.as_fd(),
        &loaded.value.runtime.listener_socket_path,
    )?;
    validate_directory_capability(
        journal.as_fd(),
        JOURNAL_FD_NAME,
        loaded
            .value
            .runtime
            .activation_directory_identity(JOURNAL_FD_NAME)?,
    )?;
    let signing_pin = loaded
        .value
        .service_signing_pin
        .build(&loaded.credentials)?;
    let endpoint_role = signing_pin.endpoint_role;
    let handshake_pin =
        HandshakeCurrentHeadPin::from_endpoint_pin(&signing_pin);
    let (signing_key, signing_credential_sha256) = loaded
        .credentials
        .read_signing_key(&loaded.value.signing_key_credential, &signing_pin.current_key_authorization.signing_key_id)?;
    let lineage_authority_verifying_key = loaded
        .credentials
        .read_verifying_key(
            &loaded
                .value
                .lineage_authority_verifying_key_credential,
        )?;
    let mut server =
        TrustedHostNoTeeRecoveryTargetProviderServer::
            from_recovered_journal(
            journal,
            loaded.value.runtime.operation_generation,
            loaded.value.runtime.service_restart_epoch,
            bootstrap.invocation(&loaded.value.runtime)?,
            loaded.value.runtime.readiness_epoch,
            loaded.value.runtime.durability_worker_queue_depth,
            loaded
                .value
                .runtime
                .maximum_durability_worker_nanos,
            loaded
                .value
                .runtime
                .authority_history_manifest_sha256
                .clone(),
            loaded
                .value
                .runtime
                .production_dispatch_protocol_set_sha256
                .clone(),
            loaded
                .value
                .runtime
                .shared_configuration_sha256
                .clone(),
            signing_pin,
            signing_key,
            signing_credential_sha256,
            loaded
                .value
                .runtime
                .deployment_generation_sha256
                .clone(),
            loaded.exact_sha256,
            loaded.value.maximum_registrations,
            loaded.value.lineage_authority_key_id,
            loaded.value.lineage_authority_key_spki_sha256,
            lineage_authority_verifying_key,
            loaded.value.durable_reap_lineage_proofs,
        )?;
    let report = server.trusted_host_report().clone();
    let connection = accept_authenticated_peer(
        listener.as_fd(),
        &expected_peer,
        startup_deadline,
    )?;
    let authenticated = authenticated_capability(
        connection.as_fd(),
        &expected_peer,
    )?;
    while !server.bootstrap_is_sealed() {
        authenticated.revalidate_peer()?;
        let packet =
            receive_packet(connection.as_raw_fd(), Some(startup_deadline))?;
        let response = server.handle_authenticated_bootstrap_packet(
            &authenticated,
            ReceivedSeqpacket {
                frame: packet.frame,
                rights: packet.rights,
            },
        )?;
        send_packet_until(
            connection.as_raw_fd(),
            &response,
            &[],
            Some(startup_deadline),
        )?;
        authenticated.revalidate_peer()?;
    }
    server.readiness_seal()?;
    perform_handshake(
        connection.as_raw_fd(),
        &authenticated,
        TrustedHostServiceRoleV3::RecoveryTargetProvider,
        endpoint_role,
        &report,
        &handshake_pin,
        &loaded
            .value
            .runtime
            .expected_peer
            .process_identity_sha256,
        6,
        2,
        startup_deadline,
    )?;
    let worker = BoundedServiceWorker::start(
        "policy-custody-recovery-target-durability",
        loaded
            .value
            .runtime
            .maximum_durability_worker_nanos,
        move |packet: ReceivedSeqpacket,
              fence: &BoundedDurabilityFence| {
            fence.require_open()?;
            if let Some(gate)=&mut generation {
                if !packet.rights.is_empty() && generation_service::is_command(&packet.frame)? {
                    return Err(ServiceError::Invalid("generation request carried descriptors"));
                }
                if let Some(reply)=gate.handle(&packet.frame,&server)? {
                    fence.require_open()?;
                    return Ok((reply,Vec::new(),generation_service::frame_deadline(&packet.frame)?));
                }
            }
            let prepared = server.handle_authenticated_packet(
                &authenticated,
                packet,
            )?;
            fence.require_open()?;
            Ok((encode_canonical_frame(&prepared.frame)?,prepared.rights,
                prepared.frame.request_binding.deadline.absolute_boottime_nanos()))
        },
    )?;
    bootstrap.ready(
        TrustedHostServiceRoleV3::RecoveryTargetProvider,
    )?;
    loop {
        bootstrap.check()?;
        let packet = receive_packet(connection.as_raw_fd(), bootstrap.receive_deadline())?;
        let deadline = generation_service::frame_deadline(&packet.frame)?;
        bootstrap.require_deadline(deadline)?;
        let (exact,rights,response_deadline) = worker.execute(
            ReceivedSeqpacket {
                frame: packet.frame,
                rights: packet.rights,
            },
            deadline,
        )?;
        if response_deadline != deadline {
            return Err(ServiceRunnerError::invalid(
                "recovery-target response changed the exact request deadline",
            ));
        }
        send_packet_until(
            connection.as_raw_fd(),
            &exact,
            &rights,
            Some(response_deadline),
        )?;
    }
}

pub(crate) fn run_current_signature_authority_from_env(
) -> Result<(), ServiceRunnerError> {
    close_unlisted_ambient_descriptors()?;
    let loaded: LoadedConfig<
        CurrentSignatureAuthorityRuntimeConfigV3,
    > = load_config(CURRENT_SIGNATURE_AUTHORITY_CONFIG_CREDENTIAL)?;
    loaded.value.runtime.observed_service_invocation_id_sha256()?;
    let activation = take_activation_fds()?;
    run_current_signature_authority_loaded(loaded, Bootstrap::Host, activation)
}

fn run_current_signature_authority_loaded(
    loaded: LoadedConfig<CurrentSignatureAuthorityRuntimeConfigV3>,
    bootstrap: Bootstrap, mut activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.runtime.validate()?;
    let mut generation=generation_service::Gate::open(&loaded,&loaded.value.runtime,&bootstrap,&mut activation,
        TrustedHostServiceRoleV3::CurrentSignatureAuthority)?;
    let _authority_history =
        loaded.value.runtime.load_authority_history(
            &loaded.credentials,
            TrustedHostServiceRoleV3::
                CurrentSignatureAuthority,
        )?;
    if loaded.value.current_subjects.is_empty()
        || loaded.value.current_subjects.len() > MAX_CURRENT_SUBJECTS
    {
        return Err(ServiceRunnerError::invalid(
            "current-signature subject count is outside its fixed bound",
        ));
    }
    let startup_deadline = bootstrap.deadline(
        loaded.value.runtime.startup_timeout_millis,
    )?;
    let expected_peer = loaded.value.runtime.expected_peer.checked()?;
    require_exact_activation_names(
        &activation,
        &[LISTENER_FD_NAME],
    )?;
    require_exact_directory_identity_names(
        &loaded.value.runtime,
        &[],
    )?;
    let listener = take_activation_fd(
        &mut activation,
        LISTENER_FD_NAME,
    )?;
    validate_listener(
        listener.as_fd(),
        &loaded.value.runtime.listener_socket_path,
    )?;
    let service_signing_pin = loaded
        .value
        .service_signing_pin
        .build(&loaded.credentials)?;
    let endpoint_role = service_signing_pin.endpoint_role;
    let handshake_pin = HandshakeCurrentHeadPin::from_endpoint_pin(
        &service_signing_pin,
    );
    let (
        service_signing_key,
        service_signing_credential_sha256,
    ) = loaded
        .credentials
        .read_signing_key(
            &loaded.value.service_signing_key_credential,
            &service_signing_pin.current_key_authorization.signing_key_id,
        )?;
    let mut current_subjects =
        Vec::with_capacity(loaded.value.current_subjects.len());
    for subject in &loaded.value.current_subjects {
        current_subjects.push((
            subject.subject.clone(),
            subject.pin.build(&loaded.credentials)?,
        ));
    }
    let server =
        TrustedHostNoTeeCurrentSignatureAuthorityServer::new(
            service_signing_pin,
            service_signing_key,
            service_signing_credential_sha256,
            loaded.value.runtime.operation_generation,
            loaded.value.runtime.service_restart_epoch,
            bootstrap.invocation(&loaded.value.runtime)?,
            loaded.value.runtime.readiness_epoch,
            loaded.value.runtime.durability_worker_queue_depth,
            loaded
                .value
                .runtime
                .maximum_durability_worker_nanos,
            loaded
                .value
                .runtime
                .authority_history_manifest_sha256
                .clone(),
            loaded
                .value
                .runtime
                .production_dispatch_protocol_set_sha256
                .clone(),
            loaded
                .value
                .runtime
                .shared_configuration_sha256
                .clone(),
            loaded
                .value
                .runtime
                .deployment_generation_sha256
                .clone(),
            loaded.exact_sha256,
            current_subjects,
        )?;
    let report = server.trusted_host_report().clone();
    let connection = accept_authenticated_peer(
        listener.as_fd(),
        &expected_peer,
        startup_deadline,
    )?;
    let authenticated = authenticated_capability(
        connection.as_fd(),
        &expected_peer,
    )?;
    perform_handshake(
        connection.as_raw_fd(),
        &authenticated,
        TrustedHostServiceRoleV3::CurrentSignatureAuthority,
        endpoint_role,
        &report,
        &handshake_pin,
        &loaded
            .value
            .runtime
            .expected_peer
            .process_identity_sha256,
        0,
        0,
        startup_deadline,
    )?;
    bootstrap.ready(
        TrustedHostServiceRoleV3::CurrentSignatureAuthority,
    )?;
    loop {
        bootstrap.check()?;
        authenticated.revalidate_peer()?;
        let packet = receive_packet(connection.as_raw_fd(), bootstrap.receive_deadline())?;
        if !packet.rights.is_empty() {
            return Err(ServiceRunnerError::invalid(
                "current-signature request carried SCM_RIGHTS",
            ));
        }
        if let Some(gate)=&mut generation {
            if let Some(reply)=gate.handle(&packet.frame,&server)? {
                let deadline=generation_service::frame_deadline(&packet.frame)?;
                bootstrap.require_deadline(deadline)?;
                send_packet_until(connection.as_raw_fd(),&reply,&[],Some(deadline))?;
                authenticated.revalidate_peer()?;
                continue;
            }
        }
        let request: ServiceRequestFrameV3 = decode_canonical_frame(&packet.frame)?;
        bootstrap.require_deadline(request.binding.deadline.absolute_boottime_nanos())?;
        let prepared = server.handle_authenticated_packet(
            &authenticated,
            ReceivedSeqpacket {
                frame: packet.frame,
                rights: packet.rights,
            },
        )?;
        let exact = encode_canonical_frame(&prepared.frame)?;
        let deadline = prepared
            .frame
            .request_binding
            .deadline
            .absolute_boottime_nanos();
        send_packet_until(
            connection.as_raw_fd(),
            &exact,
            &prepared.rights,
            Some(deadline),
        )?;
        authenticated.revalidate_peer()?;
    }
}

pub(crate) fn run_bounded_cleanup_helper_from_env(
) -> Result<(), ServiceRunnerError> {
    close_unlisted_ambient_descriptors()?;
    let loaded: LoadedConfig<BoundedCleanupHelperRuntimeConfigV3> =
        load_config(BOUNDED_CLEANUP_HELPER_CONFIG_CREDENTIAL)?;
    loaded.value.runtime.observed_service_invocation_id_sha256()?;
    let activation = take_activation_fds()?;
    run_bounded_cleanup_helper_loaded(loaded, Bootstrap::Host, activation)
}

fn run_bounded_cleanup_helper_loaded(
    loaded: LoadedConfig<BoundedCleanupHelperRuntimeConfigV3>,
    bootstrap: Bootstrap, mut activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.runtime.validate()?;
    let mut generation=generation_service::Gate::open(&loaded,&loaded.value.runtime,&bootstrap,&mut activation,
        TrustedHostServiceRoleV3::BoundedCleanupHelper)?;
    let _authority_history =
        loaded.value.runtime.load_authority_history(
            &loaded.credentials,
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
        )?;
    let startup_deadline = bootstrap.deadline(
        loaded.value.runtime.startup_timeout_millis,
    )?;
    let expected_peer = loaded.value.runtime.expected_peer.checked()?;
    require_exact_activation_names(
        &activation,
        &[LISTENER_FD_NAME, JOURNAL_FD_NAME],
    )?;
    require_exact_directory_identity_names(
        &loaded.value.runtime,
        &[JOURNAL_FD_NAME],
    )?;
    let listener = take_activation_fd(
        &mut activation,
        LISTENER_FD_NAME,
    )?;
    let journal = take_activation_fd(
        &mut activation,
        JOURNAL_FD_NAME,
    )?;
    validate_listener(
        listener.as_fd(),
        &loaded.value.runtime.listener_socket_path,
    )?;
    validate_directory_capability(
        journal.as_fd(),
        JOURNAL_FD_NAME,
        loaded
            .value
            .runtime
            .activation_directory_identity(JOURNAL_FD_NAME)?,
    )?;
    let connection = accept_peer(
        listener.as_fd(),
        startup_deadline,
    )?;

    let (signing_key, signing_credential_sha256) = loaded
        .credentials
        .read_signing_key(&loaded.value.signing_key_credential, &loaded.value.signing_key_id)?;
    let current_head_authority = loaded
        .credentials
        .read_verifying_key(
            &loaded
                .value
                .current_head_authority_verifying_key_credential,
        )?;
    let signer = CleanupHelperSigningAuthorityV3::new(
        signing_key,
        current_head_authority,
        loaded.value.current_head_authority_key_id,
        loaded.value.endpoint_process_identity_sha256.clone(),
        loaded.value.endpoint_generation,
        loaded.value.helper_generation,
        loaded.value.signing_key_id,
        loaded.value.checkpoint_sequence,
        loaded
            .value
            .current_key_authorization_checkpoint_sha256,
        loaded.value.revocation_generation,
        loaded.value.revocation_root_sha256,
    )?;
    let report = TrustedHostNoTeeServiceReportV3::new(
        TrustedHostServiceRoleV3::BoundedCleanupHelper,
        loaded.value.runtime.operation_generation,
        loaded.value.runtime.service_restart_epoch,
        bootstrap.invocation(&loaded.value.runtime)?,
        loaded.value.runtime.readiness_epoch,
        loaded.value.runtime.durability_worker_queue_depth,
        loaded
            .value
            .runtime
            .maximum_durability_worker_nanos,
        loaded
            .value
            .runtime
            .authority_history_manifest_sha256
            .clone(),
        loaded
            .value
            .runtime
            .production_dispatch_protocol_set_sha256
            .clone(),
        loaded
            .value
            .runtime
            .shared_configuration_sha256
            .clone(),
        loaded
            .value
            .runtime
            .deployment_generation_sha256
            .clone(),
        loaded.exact_sha256,
        loaded.value.endpoint_process_identity_sha256,
        Some(signing_credential_sha256),
    )?;
    let handshake_transport = duplicate_fd(connection.as_fd())?;
    let mut server =
        TrustedHostNoTeeBoundedCleanupHelperServer::
            from_inherited_socket(
                connection,
                expected_peer,
                journal,
                signer,
                report,
                loaded
                    .value
                    .runtime
                    .maximum_durability_worker_nanos,
                loaded.value.runtime.operation_generation,
                loaded
                    .value
                    .runtime
                    .shared_configuration_sha256
                    .clone(),
            )?;
    if !activation.is_empty() {
        return Err(ServiceRunnerError::invalid(
            "cleanup-helper retained an unexpected activation descriptor",
        ));
    }
    while !server.bootstrap_is_sealed() {
        let packet = receive_packet(
            handshake_transport.as_raw_fd(),
            Some(startup_deadline),
        )?;
        let response = server.handle_authenticated_bootstrap_packet(
            ReceivedSeqpacket {
                frame: packet.frame,
                rights: packet.rights,
            },
            startup_deadline,
        )?;
        send_packet_until(
            handshake_transport.as_raw_fd(),
            &response,
            &[],
            Some(startup_deadline),
        )?;
    }
    server.readiness_seal()?;
    perform_bounded_cleanup_handshakes(
        handshake_transport.as_raw_fd(),
        &server,
        &loaded
            .value
            .runtime
            .expected_peer
            .process_identity_sha256,
        &loaded
            .value
            .runtime
            .expected_peer
            .configuration_generation_sha256,
        startup_deadline,
    )?;
    drop(handshake_transport);
    bootstrap.ready(
        TrustedHostServiceRoleV3::BoundedCleanupHelper,
    )?;

    loop {
        bootstrap.check()?;
        match server.try_serve_one_generation_scoped(&bootstrap,&mut generation)? {
            CleanupHelperServerProgress::ReplySent => {}
            CleanupHelperServerProgress::Idle => {
                wait_for_fd(
                    server.progress_fd().as_raw_fd(),
                    libc::POLLIN,
                    server.next_deadline_boottime_nanos()?.or(bootstrap.receive_deadline()),
                )?;
            }
            CleanupHelperServerProgress::ReplyPending => {
                wait_for_fd(
                    server.progress_fd().as_raw_fd(),
                    libc::POLLOUT,
                    server.next_deadline_boottime_nanos()?.or(bootstrap.receive_deadline()),
                )?;
            }
            CleanupHelperServerProgress::EffectPending => {
                let deadline =
                    server.next_deadline_boottime_nanos()?.or(bootstrap.receive_deadline());
                if let Some(progress) = server.effect_progress_fd() {
                    wait_for_fd(
                        progress.as_raw_fd(),
                        libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                        deadline,
                    )?;
                } else {
                    continue;
                }
            }
        }
    }
}

struct BoundedServiceWork<I, O> {
    input: I,
    completion: Arc<BoundedServiceCompletion<O>>,
    fence: Arc<BoundedDurabilityFence>,
}

struct BoundedDurabilityFence {
    state: AtomicU8,
    deadline_boottime_nanos: u64,
    worker_healthy: Arc<AtomicBool>,
}

impl BoundedDurabilityFence {
    fn new(
        deadline_boottime_nanos: u64,
        worker_healthy: Arc<AtomicBool>,
    ) -> Self {
        Self {
            state: AtomicU8::new(DURABILITY_WORK_QUEUED),
            deadline_boottime_nanos,
            worker_healthy,
        }
    }

    fn begin(&self) -> Result<(), ServiceError> {
        if !self.worker_healthy.load(Ordering::Acquire)
            || boottime_now_nanos().map_or(true, |now| {
                now >= self.deadline_boottime_nanos
            })
            || self
                .state
                .compare_exchange(
                    DURABILITY_WORK_QUEUED,
                    DURABILITY_WORK_RUNNING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            self.state.store(
                DURABILITY_WORK_CANCELLED,
                Ordering::Release,
            );
            return Err(ServiceError::Invalid(
                "durable authority work was cancelled before mutation",
            ));
        }
        Ok(())
    }

    fn require_open(&self) -> Result<(), ServiceError> {
        if self.state.load(Ordering::Acquire)
                != DURABILITY_WORK_RUNNING
            || !self.worker_healthy.load(Ordering::Acquire)
            || boottime_now_nanos().map_or(true, |now| {
                now >= self.deadline_boottime_nanos
            })
        {
            return Err(ServiceError::Invalid(
                "durable authority mutation fence is closed",
            ));
        }
        Ok(())
    }

    fn finish(&self) -> Result<u64, ServiceError> {
        let finished = boottime_now_nanos().map_err(|_| {
            ServiceError::Invalid(
                "durable authority completion BOOTTIME is unavailable",
            )
        })?;
        if finished >= self.deadline_boottime_nanos
            || self
                .state
                .compare_exchange(
                    DURABILITY_WORK_RUNNING,
                    DURABILITY_WORK_COMPLETED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            self.state
                .store(DURABILITY_WORK_LATE, Ordering::Release);
            self.worker_healthy.store(false, Ordering::Release);
            return Err(ServiceError::Invalid(
                "durable authority work completed after cancellation or deadline",
            ));
        }
        Ok(finished)
    }

    fn cancel_waiter(&self) {
        let previous = self.state.swap(
            DURABILITY_WORK_CANCELLED,
            Ordering::AcqRel,
        );
        if previous == DURABILITY_WORK_RUNNING
            || previous == DURABILITY_WORK_COMPLETED
            || previous == DURABILITY_WORK_LATE
        {
            self.worker_healthy.store(false, Ordering::Release);
        }
    }
}

struct BoundedServiceCompletion<O> {
    event: OwnedFd,
    result: Mutex<Option<Result<O, ServiceError>>>,
}

impl<O> BoundedServiceCompletion<O> {
    fn new() -> Result<Self, ServiceRunnerError> {
        let raw = unsafe {
            libc::eventfd(
                0,
                libc::EFD_CLOEXEC | libc::EFD_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self {
            event: unsafe { OwnedFd::from_raw_fd(raw) },
            result: Mutex::new(None),
        })
    }

    fn complete(
        &self,
        result: Result<O, ServiceError>,
    ) -> Result<(), ServiceError> {
        let mut slot = self.result.lock().map_err(|_| {
            ServiceError::Invalid(
                "bounded service completion lock is poisoned",
            )
        })?;
        if slot.is_some() {
            return Err(ServiceError::Invalid(
                "bounded service work completed more than once",
            ));
        }
        *slot = Some(result);
        drop(slot);
        let signal = 1_u64.to_ne_bytes();
        loop {
            let written = unsafe {
                libc::write(
                    self.event.as_raw_fd(),
                    signal.as_ptr().cast(),
                    signal.len(),
                )
            };
            if written == signal.len() as isize {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        }
    }

    fn wait(
        &self,
        deadline_boottime_nanos: u64,
    ) -> Result<O, ServiceRunnerError> {
        wait_for_fd(
            self.event.as_raw_fd(),
            libc::POLLIN,
            Some(deadline_boottime_nanos),
        )?;
        let mut signal = [0_u8; size_of::<u64>()];
        loop {
            let read = unsafe {
                libc::read(
                    self.event.as_raw_fd(),
                    signal.as_mut_ptr().cast(),
                    signal.len(),
                )
            };
            if read == signal.len() as isize {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        }
        self.result
            .lock()
            .map_err(|_| {
                ServiceRunnerError::invalid(
                    "bounded service completion lock is poisoned",
                )
            })?
            .take()
            .ok_or_else(|| {
                ServiceRunnerError::invalid(
                    "bounded service completion was signaled without an exact result",
                )
            })?
            .map_err(Into::into)
    }
}

struct BoundedServiceWorker<I, O> {
    sender: SyncSender<BoundedServiceWork<I, O>>,
    healthy: Arc<AtomicBool>,
    last_completed_boottime_nanos: Arc<AtomicU64>,
    maximum_work_nanos: u64,
    _worker: thread::JoinHandle<()>,
}

impl<I, O> BoundedServiceWorker<I, O>
where
    I: Send + 'static,
    O: Send + 'static,
{
    fn start<F>(
        name: &'static str,
        maximum_work_nanos: u64,
        mut handle: F,
    ) -> Result<Self, ServiceRunnerError>
    where
        F: FnMut(I, &BoundedDurabilityFence) -> Result<O, ServiceError>
            + Send
            + 'static,
    {
        if maximum_work_nanos == 0
            || maximum_work_nanos > 1_000_000_000
        {
            return Err(ServiceRunnerError::invalid(
                "bounded service worker maximum duration is outside its fixed bound",
            ));
        }
        let (sender, receiver) =
            sync_channel::<BoundedServiceWork<I, O>>(
                DURABILITY_WORK_QUEUE_DEPTH,
            );
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = Arc::clone(&healthy);
        let last_completed_boottime_nanos =
            Arc::new(AtomicU64::new(0));
        let worker_last_completed =
            Arc::clone(&last_completed_boottime_nanos);
        let worker = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    let result = match work.fence.begin() {
                        Ok(()) => {
                            let handled =
                                handle(work.input, &work.fence);
                            match (
                                handled,
                                work.fence.finish(),
                            ) {
                                (Ok(value), Ok(finished)) => {
                                    worker_last_completed.store(
                                        finished,
                                        Ordering::Release,
                                    );
                                    Ok(value)
                                }
                                (Err(error), Ok(finished)) => {
                                    worker_last_completed.store(
                                        finished,
                                        Ordering::Release,
                                    );
                                    Err(error)
                                }
                                (_, Err(error)) => Err(error),
                            }
                        }
                        Err(error) => Err(error),
                    };
                    if work.completion.complete(result).is_err() {
                        worker_health.store(false, Ordering::Release);
                        break;
                    }
                }
                worker_health.store(false, Ordering::Release);
            })
            .map_err(|error| {
                ServiceRunnerError::invalid(format!(
                    "cannot start fixed bounded service worker: {error}"
                ))
            })?;
        Ok(Self {
            sender,
            healthy,
            last_completed_boottime_nanos,
            maximum_work_nanos,
            _worker: worker,
        })
    }

    fn execute(
        &self,
        input: I,
        deadline_boottime_nanos: u64,
    ) -> Result<O, ServiceRunnerError> {
        let now = boottime_now_nanos().map_err(|error| {
            ServiceRunnerError::invalid(error.to_string())
        })?;
        if !self.healthy.load(Ordering::Acquire)
            || deadline_boottime_nanos == 0
            || now >= deadline_boottime_nanos
            || deadline_boottime_nanos
                .checked_sub(now)
                .is_none_or(|remaining| {
                    remaining > self.maximum_work_nanos
                })
        {
            return Err(ServiceRunnerError::invalid(
                "bounded service worker is unhealthy or the BOOTTIME deadline expired",
            ));
        }
        let completion =
            Arc::new(BoundedServiceCompletion::new()?);
        let fence = Arc::new(BoundedDurabilityFence::new(
            deadline_boottime_nanos,
            Arc::clone(&self.healthy),
        ));
        let work = BoundedServiceWork {
            input,
            completion: Arc::clone(&completion),
            fence: Arc::clone(&fence),
        };
        match self.sender.try_send(work) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(ServiceRunnerError::invalid(
                    "bounded service work queue is full",
                ))
            }
            Err(TrySendError::Disconnected(_)) => {
                self.healthy.store(false, Ordering::Release);
                return Err(ServiceRunnerError::invalid(
                    "bounded service worker is unavailable",
                ))
            }
        }
        match completion.wait(deadline_boottime_nanos) {
            Ok(result) => {
                if fence.state.load(Ordering::Acquire)
                        != DURABILITY_WORK_COMPLETED
                    || self
                        .last_completed_boottime_nanos
                        .load(Ordering::Acquire)
                        == 0
                {
                    self.healthy.store(false, Ordering::Release);
                    return Err(ServiceRunnerError::invalid(
                        "bounded service completion lacks a current durability fence",
                    ));
                }
                Ok(result)
            }
            Err(error) => {
                fence.cancel_waiter();
                Err(error)
            }
        }
    }
}

fn serve_exact_frame_authority<F>(
    connection: BorrowedFd<'_>,
    authenticated: &AuthenticatedInheritedSeqpacket,
    bootstrap: Bootstrap,
    service_role: TrustedHostServiceRoleV3,
    maximum_work_nanos: u64,
    mut handle: F,
) -> Result<(), ServiceRunnerError>
where
    F: FnMut(Vec<u8>) -> Result<Vec<u8>, ServiceError>
        + Send
        + 'static,
{
    let worker = BoundedServiceWorker::start(
        "policy-custody-durability",
        maximum_work_nanos,
        move |frame, fence: &BoundedDurabilityFence| {
            fence.require_open()?;
            let response = handle(frame)?;
            fence.require_open()?;
            Ok(response)
        },
    )?;
    bootstrap.ready(service_role)?;
    loop {
        bootstrap.check()?;
        authenticated.revalidate_peer()?;
        let packet = receive_packet(connection.as_raw_fd(), bootstrap.receive_deadline())?;
        if !packet.rights.is_empty() {
            return Err(ServiceRunnerError::invalid(
                "descriptor-free authority request carried SCM_RIGHTS",
            ));
        }
        let request_deadline = generation_service::frame_deadline(&packet.frame)?;
        bootstrap.require_deadline(request_deadline)?;
        let response = worker.execute(
            packet.frame,
            request_deadline,
        )?;
        generation_service::check_response_deadline(&response,request_deadline)?;
        let deadline = request_deadline;
        send_packet_until(
            connection.as_raw_fd(),
            &response,
            &[],
            Some(deadline),
        )?;
        authenticated.revalidate_peer()?;
    }
}

fn perform_handshake(
    socket_fd: RawFd,
    authenticated: &AuthenticatedInheritedSeqpacket,
    service_role: TrustedHostServiceRoleV3,
    endpoint_role: PolicyCustodyEndpointRole,
    report: &TrustedHostNoTeeServiceReportV3,
    current_head_pin: &HandshakeCurrentHeadPin,
    expected_client_process_identity_sha256: &Sha256Digest,
    maximum_request_rights: u8,
    maximum_reply_rights: u8,
    startup_deadline: u64,
) -> Result<(), ServiceRunnerError> {
    authenticated.revalidate_peer()?;
    if authenticated.peer_process_identity_sha256()
        != expected_client_process_identity_sha256
    {
        return Err(ServiceRunnerError::invalid(
            "retained kernel peer identity differs from the configured handshake identity",
        ));
    }
    let packet = receive_packet(
        socket_fd,
        Some(startup_deadline),
    )?;
    if !packet.rights.is_empty() {
        return Err(ServiceRunnerError::invalid(
            "service handshake carried SCM_RIGHTS",
        ));
    }
    let request: ServiceHandshakeRequestV3 =
        decode_canonical_frame(&packet.frame)?;
    if &request.client_process_identity_sha256
            != expected_client_process_identity_sha256
        || &request.client_configuration_generation_sha256
            != authenticated
                .peer_configuration_generation_sha256()
    {
        return Err(ServiceRunnerError::invalid(
            "service handshake client identity or configuration generation differs from the configured peer",
        ));
    }
    request.validate(service_role, endpoint_role)?;
    current_head_pin.verify(&request)?;
    validate_handshake_bounds(
        &request,
        maximum_request_rights,
        maximum_reply_rights,
        startup_deadline,
    )?;
    let reply = ServiceHandshakeReplyV3::for_request(
        &request,
        report.service_process_identity_sha256.clone(),
        report.clone(),
    )?;
    reply.validate_for_request(&request, endpoint_role)?;
    let exact = encode_canonical_frame(&reply)?;
    send_packet_until(
        socket_fd,
        &exact,
        &[],
        Some(request.deadline.absolute_boottime_nanos()),
    )?;
    authenticated.revalidate_peer()?;
    Ok(())
}

fn perform_bounded_cleanup_handshakes(
    socket_fd: RawFd,
    server: &TrustedHostNoTeeBoundedCleanupHelperServer,
    expected_client_process_identity_sha256: &Sha256Digest,
    expected_client_configuration_generation_sha256:
        &Sha256Digest,
    startup_deadline: u64,
) -> Result<(), ServiceRunnerError> {
    let expected_roles = server.expected_handshake_roles()?;
    let mut observed_roles = BTreeSet::new();
    for expected_role in expected_roles {
        let packet = receive_packet(
            socket_fd,
            Some(startup_deadline),
        )?;
        if !packet.rights.is_empty() {
            return Err(ServiceRunnerError::invalid(
                "cleanup-helper handshake carried SCM_RIGHTS",
            ));
        }
        let request: ServiceHandshakeRequestV3 =
            decode_canonical_frame(&packet.frame)?;
        if &request.client_process_identity_sha256
                != expected_client_process_identity_sha256
            || &request.client_configuration_generation_sha256
                != expected_client_configuration_generation_sha256
        {
            return Err(ServiceRunnerError::invalid(
                "cleanup-helper handshake client identity or configuration generation differs from the configured peer",
            ));
        }
        let endpoint_role = request
            .expected_current_head
            .signed_current_head
            .statement
            .endpoint_role;
        if endpoint_role != *expected_role
            || !observed_roles.insert(endpoint_role)
        {
            return Err(ServiceRunnerError::invalid(
                "cleanup-helper handshake role set is out of order, duplicate, or differs from the sealed effect manifest",
            ));
        }
        validate_handshake_bounds(
            &request,
            2,
            0,
            startup_deadline,
        )?;
        let reply =
            server.handshake_reply(&request, endpoint_role)?;
        reply.validate_for_request(&request, endpoint_role)?;
        let exact = encode_canonical_frame(&reply)?;
        send_packet_until(
            socket_fd,
            &exact,
            &[],
            Some(request.deadline.absolute_boottime_nanos()),
        )?;
    }
    if observed_roles.len() != expected_roles.len() {
        return Err(ServiceRunnerError::invalid(
            "cleanup-helper did not complete its exact sealed role handshake set",
        ));
    }
    Ok(())
}

fn validate_handshake_bounds(
    request: &ServiceHandshakeRequestV3,
    maximum_request_rights: u8,
    maximum_reply_rights: u8,
    startup_deadline: u64,
) -> Result<(), ServiceRunnerError> {
    request
        .deadline
        .to_runtime()
        .map_err(|error| {
            ServiceRunnerError::invalid(error.to_string())
        })?
        .require_live()
        .map_err(|error| {
            ServiceRunnerError::invalid(error.to_string())
        })?;
    if request.deadline.absolute_boottime_nanos()
            > startup_deadline
        || request.request_rights_count != maximum_request_rights
        || request.reply_rights_count != maximum_reply_rights
    {
        return Err(ServiceRunnerError::invalid(
            "service handshake exceeds its startup deadline or differs from its exact SCM_RIGHTS contract",
        ));
    }
    Ok(())
}

fn startup_deadline(
    timeout_millis: u64,
) -> Result<u64, ServiceRunnerError> {
    let now = boottime_now_nanos().map_err(|error| {
        ServiceRunnerError::invalid(error.to_string())
    })?;
    let timeout_nanos = timeout_millis
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            ServiceRunnerError::invalid(
                "startup timeout nanoseconds overflowed",
            )
        })?;
    now.checked_add(timeout_nanos).ok_or_else(|| {
        ServiceRunnerError::invalid(
            "startup BOOTTIME deadline overflowed",
        )
    })
}

fn notify_systemd_ready(
    service_role: TrustedHostServiceRoleV3,
) -> Result<(), ServiceRunnerError> {
    let role = match service_role {
        TrustedHostServiceRoleV3::DurableRecoveryStore => {
            "durable-recovery-store"
        }
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer => {
            "cleanup-authorization-consumer"
        }
        TrustedHostServiceRoleV3::RecoveryTargetProvider => {
            "recovery-target-provider"
        }
        TrustedHostServiceRoleV3::CurrentSignatureAuthority => {
            "current-signature-authority"
        }
        TrustedHostServiceRoleV3::BoundedCleanupHelper => {
            "bounded-cleanup-helper"
        }
    };
    notify_systemd_ready_status(&format!(
        "{role} mutation and recovery paths ready"
    ))
}

fn notify_systemd_ready_status(
    status: &str,
) -> Result<(), ServiceRunnerError> {
    let notify_socket = env::var_os("NOTIFY_SOCKET").ok_or_else(|| {
        ServiceRunnerError::invalid(
            "NOTIFY_SOCKET is required for fail-closed readiness",
        )
    })?;
    let configured = notify_socket.as_bytes();
    if configured.len() < 2
        || configured.contains(&0)
        || (configured[0] != b'/' && configured[0] != b'@')
    {
        return Err(ServiceRunnerError::invalid(
            "NOTIFY_SOCKET is not an absolute or abstract UNIX address",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let abstract_address = configured[0] == b'@';
    let address_length = if abstract_address {
        configured.len()
    } else {
        configured.len().checked_add(1).ok_or_else(|| {
            ServiceRunnerError::invalid(
                "NOTIFY_SOCKET length overflowed",
            )
        })?
    };
    if address_length > address.sun_path.len() {
        return Err(ServiceRunnerError::invalid(
            "NOTIFY_SOCKET exceeds sockaddr_un.sun_path",
        ));
    }
    let mut encoded = configured.to_vec();
    if abstract_address {
        encoded[0] = 0;
    } else {
        encoded.push(0);
    }
    unsafe {
        ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            encoded.len(),
        );
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_DGRAM
                | libc::SOCK_CLOEXEC
                | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let message = format!("READY=1\nSTATUS={status}");
    let sockaddr_length = size_of::<libc::sa_family_t>()
        .checked_add(address_length)
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or_else(|| {
            ServiceRunnerError::invalid(
                "NOTIFY_SOCKET sockaddr length overflowed",
            )
        })?;
    loop {
        let sent = unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                libc::MSG_NOSIGNAL,
                (&address as *const libc::sockaddr_un)
                    .cast::<libc::sockaddr>(),
                sockaddr_length,
            )
        };
        if sent == message.len() as isize {
            return Ok(());
        }
        if sent >= 0 {
            return Err(ServiceRunnerError::invalid(
                "systemd readiness datagram was truncated",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
}

fn verifying_key_spki_sha256(
    key: &VerifyingKey,
) -> Result<Sha256Digest, ServiceRunnerError> {
    let spki = key.to_public_key_der().map_err(|_| {
        ServiceRunnerError::invalid(
            "Ed25519 verification key has no canonical SPKI",
        )
    })?;
    Ok(Sha256Digest::compute(spki.as_bytes()))
}

fn take_activation_fds(
) -> Result<BTreeMap<String, OwnedFd>, ServiceRunnerError> {
    let listen_pid = parse_decimal_environment("LISTEN_PID")?;
    if listen_pid != i64::from(unsafe { libc::getpid() }) {
        return Err(ServiceRunnerError::invalid(
            "LISTEN_PID does not identify this service process",
        ));
    }
    let count = usize::try_from(parse_decimal_environment(
        "LISTEN_FDS",
    )?)
    .map_err(|_| {
        ServiceRunnerError::invalid(
            "LISTEN_FDS is not representable",
        )
    })?;
    if count == 0 || count > MAX_ACTIVATION_FDS {
        return Err(ServiceRunnerError::invalid(
            "LISTEN_FDS is outside its fixed bound",
        ));
    }
    let names = env::var("LISTEN_FDNAMES").map_err(|_| {
        ServiceRunnerError::invalid(
            "LISTEN_FDNAMES is required",
        )
    })?;
    let names: Vec<&str> = names.split(':').collect();
    if names.len() != count {
        return Err(ServiceRunnerError::invalid(
            "LISTEN_FDNAMES count differs from LISTEN_FDS",
        ));
    }
    let mut descriptors = BTreeMap::new();
    for (index, name) in names.into_iter().enumerate() {
        validate_fd_name(name)?;
        let raw = 3_i32
            .checked_add(i32::try_from(index).map_err(|_| {
                ServiceRunnerError::invalid(
                    "activation descriptor index overflowed",
                )
            })?)
            .ok_or_else(|| {
                ServiceRunnerError::invalid(
                    "activation descriptor number overflowed",
                )
            })?;
        set_cloexec(raw)?;
        let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
        if descriptors
            .insert(name.to_string(), descriptor)
            .is_some()
        {
            return Err(ServiceRunnerError::invalid(
                "LISTEN_FDNAMES contains a duplicate",
            ));
        }
    }
    Ok(descriptors)
}

fn close_unlisted_ambient_descriptors(
) -> Result<(), ServiceRunnerError> {
    let listen_pid = parse_decimal_environment("LISTEN_PID")?;
    if listen_pid != i64::from(unsafe { libc::getpid() }) {
        return Err(ServiceRunnerError::invalid(
            "LISTEN_PID does not identify this service process",
        ));
    }
    let count = u32::try_from(parse_decimal_environment(
        "LISTEN_FDS",
    )?)
    .map_err(|_| {
        ServiceRunnerError::invalid(
            "LISTEN_FDS is not representable",
        )
    })?;
    if count == 0
        || usize::try_from(count)
            .map_or(true, |count| count > MAX_ACTIVATION_FDS)
    {
        return Err(ServiceRunnerError::invalid(
            "LISTEN_FDS is outside its fixed bound",
        ));
    }
    let first_unlisted = 3_u32.checked_add(count).ok_or_else(|| {
        ServiceRunnerError::invalid(
            "activation descriptor range overflowed",
        )
    })?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first_unlisted,
            u32::MAX,
            0_u32,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn parse_decimal_environment(
    name: &str,
) -> Result<i64, ServiceRunnerError> {
    let value = env::var(name).map_err(|_| {
        ServiceRunnerError::invalid(format!(
            "{name} is required"
        ))
    })?;
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ServiceRunnerError::invalid(format!(
            "{name} is not strict decimal"
        )));
    }
    value.parse::<i64>().map_err(|_| {
        ServiceRunnerError::invalid(format!(
            "{name} is outside its integer range"
        ))
    })
}

fn validate_fd_name(name: &str) -> Result<(), ServiceRunnerError> {
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ServiceRunnerError::invalid(
            "activation descriptor name is invalid",
        ));
    }
    Ok(())
}

fn require_exact_activation_names(
    descriptors: &BTreeMap<String, OwnedFd>,
    required: &[&str],
) -> Result<(), ServiceRunnerError> {
    let required_names: BTreeSet<&str> =
        required.iter().copied().collect();
    if required_names.len() != required.len() {
        return Err(ServiceRunnerError::invalid(
            "activation descriptor requirement contains duplicates",
        ));
    }
    let observed: BTreeSet<&str> =
        descriptors.keys().map(String::as_str).collect();
    if observed != required_names {
        return Err(ServiceRunnerError::invalid(
            "systemd activation descriptors do not exactly match the role contract",
        ));
    }
    Ok(())
}

fn require_exact_directory_identity_names(
    runtime: &RuntimeConfigHeaderV3,
    required: &[&str],
) -> Result<(), ServiceRunnerError> {
    let mut required_names: BTreeSet<&str> =
        required.iter().copied().collect();
    let unique=required_names.len()==required.len();
    if runtime.generation_admission.is_some() {required_names.insert(generation_service::DIRECTORY);}
    if !unique
        || runtime
            .activation_directory_identities
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != required_names
    {
        return Err(ServiceRunnerError::invalid(
            "configured activation directory identities do not exactly match the role contract",
        ));
    }
    Ok(())
}

fn take_activation_fd(
    descriptors: &mut BTreeMap<String, OwnedFd>,
    name: &str,
) -> Result<OwnedFd, ServiceRunnerError> {
    descriptors.remove(name).ok_or_else(|| {
        ServiceRunnerError::invalid(format!(
            "required activation descriptor {name} is missing"
        ))
    })
}

fn validate_listener(
    listener: BorrowedFd<'_>,
    expected_path: &std::path::Path,
) -> Result<(), ServiceRunnerError> {
    set_nonblocking_cloexec(listener.as_raw_fd())?;
    let socket_type =
        get_socket_int(listener.as_raw_fd(), libc::SO_TYPE)?;
    let accepting =
        get_socket_int(listener.as_raw_fd(), libc::SO_ACCEPTCONN)?;
    let expected = expected_path.as_os_str().as_bytes();
    if !expected_path.is_absolute()
        || expected.is_empty()
        || expected.contains(&0)
    {
        return Err(ServiceRunnerError::invalid(
            "configured listener pathname is not an absolute pathname socket identity",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut address_length =
        size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            listener.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut address_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let base = (&address as *const libc::sockaddr_un) as usize;
    let path_start = (&address.sun_path as *const _) as usize;
    let path_offset = path_start.checked_sub(base).ok_or_else(|| {
        ServiceRunnerError::invalid(
            "sockaddr_un pathname offset is invalid",
        )
    })?;
    let expected_address_length = path_offset
        .checked_add(expected.len())
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            ServiceRunnerError::invalid(
                "configured listener pathname length overflowed",
            )
        })?;
    if expected.len() >= address.sun_path.len()
        || socket_type != libc::SOCK_SEQPACKET
        || accepting != 1
        || address.sun_family as i32 != libc::AF_UNIX
        || address_length as usize != expected_address_length
        || address.sun_path[0] == 0
    {
        return Err(ServiceRunnerError::invalid(
            "inherited listener is not the exact configured pathname AF_UNIX SOCK_SEQPACKET socket",
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
        return Err(ServiceRunnerError::invalid(
            "inherited listener pathname is unnamed, abstract, truncated, or different from the configured pathname",
        ));
    }
    Ok(())
}

fn validate_directory_capability(
    descriptor: BorrowedFd<'_>,
    label: &str,
    expected: &ActivationDirectoryIdentityV3,
) -> Result<(), ServiceRunnerError> {
    expected.validate()?;
    const STATX_MNT_ID_MASK: libc::c_uint = 0x0000_1000;
    let mut observed: libc::statx = unsafe { zeroed() };
    let empty_path = b"\0";
    if unsafe {
        libc::statx(
            descriptor.as_raw_fd(),
            empty_path.as_ptr().cast(),
            libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT,
            libc::STATX_BASIC_STATS | STATX_MNT_ID_MASK,
            &mut observed,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if observed.stx_mask & libc::STATX_BASIC_STATS
            != libc::STATX_BASIC_STATS
        || observed.stx_mask & STATX_MNT_ID_MASK == 0
        || observed.stx_nlink == 0
        || u32::from(observed.stx_mode)
            & libc::S_IFMT
            != libc::S_IFDIR
        || observed.stx_mnt_id != expected.mount_id
        || observed.stx_dev_major != expected.device_major
        || observed.stx_dev_minor != expected.device_minor
        || observed.stx_ino != expected.inode
        || observed.stx_uid != expected.uid
        || observed.stx_gid != expected.gid
        || u32::from(observed.stx_mode) != expected.mode
    {
        return Err(ServiceRunnerError::invalid(format!(
            "{label} activation descriptor does not match its exact configured mount, device, inode, owner, or mode"
        )));
    }
    set_cloexec(descriptor.as_raw_fd())
}

fn validate_credential_directory(
    descriptor: BorrowedFd<'_>,
) -> Result<(), ServiceRunnerError> {
    let stat = descriptor_stat(descriptor)?;
    let effective_uid = unsafe { libc::geteuid() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_nlink == 0
        || (stat.st_uid != 0 && stat.st_uid != effective_uid)
        || stat.st_mode & 0o022 != 0
    {
        return Err(ServiceRunnerError::invalid(
            "systemd credential directory ownership or mode is unsafe",
        ));
    }
    Ok(())
}

fn validate_credential_name(
    name: &str,
) -> Result<(), ServiceRunnerError> {
    if name.is_empty()
        || name.len() > 128
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(ServiceRunnerError::invalid(
            "systemd credential name is invalid",
        ));
    }
    Ok(())
}

fn accept_authenticated_peer(
    listener: BorrowedFd<'_>,
    expected_peer: &ExpectedPeerCredentials,
    deadline: u64,
) -> Result<OwnedFd, ServiceRunnerError> {
    let connection = accept_peer(listener, deadline)?;
    let authentication =
        authenticated_capability(connection.as_fd(), expected_peer)?;
    drop(authentication);
    Ok(connection)
}

fn accept_peer(
    listener: BorrowedFd<'_>,
    deadline: u64,
) -> Result<OwnedFd, ServiceRunnerError> {
    loop {
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                ptr::null_mut(),
                ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if raw >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => {
                wait_for_fd(
                    listener.as_raw_fd(),
                    libc::POLLIN,
                    Some(deadline),
                )?;
            }
            _ => return Err(error.into()),
        }
    }
}

fn authenticated_capability(
    connection: BorrowedFd<'_>,
    expected_peer: &ExpectedPeerCredentials,
) -> Result<AuthenticatedInheritedSeqpacket, ServiceRunnerError> {
    AuthenticatedInheritedSeqpacket::from_inherited(
        duplicate_fd(connection)?,
        expected_peer.clone(),
    )
    .map_err(Into::into)
}

fn duplicate_fd(
    descriptor: BorrowedFd<'_>,
) -> Result<OwnedFd, ServiceRunnerError> {
    let raw = unsafe {
        libc::fcntl(
            descriptor.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            3,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

struct LocalPacket {
    frame: Vec<u8>,
    rights: Vec<OwnedFd>,
}

#[repr(align(16))]
struct AncillaryBuffer([u8; 512]);

fn receive_packet(
    socket_fd: RawFd,
    deadline: Option<u64>,
) -> Result<LocalPacket, ServiceRunnerError> {
    let expected_credentials =
        socket_peer_credentials(socket_fd)?;
    loop {
        if let Some(packet) = try_receive_packet(
            socket_fd,
            expected_credentials,
        )? {
            return Ok(packet);
        }
        wait_for_fd(socket_fd, libc::POLLIN, deadline)?;
    }
}

fn try_receive_packet(
    socket_fd: RawFd,
    expected_credentials: (i32, u32, u32),
) -> Result<Option<LocalPacket>, ServiceRunnerError> {
    let mut frame = vec![0_u8; MAX_SERVICE_FRAME_BYTES];
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
        return Err(ServiceRunnerError::invalid(
            "authenticated service peer closed",
        ));
    }
    let rights =
        received_rights(&message, expected_credentials)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(ServiceRunnerError::invalid(
            "service packet or ancillary data was truncated",
        ));
    }
    let received = usize::try_from(received).map_err(|_| {
        ServiceRunnerError::invalid(
            "service packet length is not representable",
        )
    })?;
    if received == 0 || received > MAX_SERVICE_FRAME_BYTES {
        return Err(ServiceRunnerError::invalid(
            "service packet length is outside its fixed bound",
        ));
    }
    frame.truncate(received);
    Ok(Some(LocalPacket { frame, rights }))
}

fn received_rights(
    message: &libc::msghdr,
    expected_credentials: (i32, u32, u32),
) -> Result<Vec<OwnedFd>, ServiceRunnerError> {
    let control_start = message.msg_control as usize;
    let control_end = control_start
        .checked_add(message.msg_controllen)
        .ok_or_else(|| {
            ServiceRunnerError::invalid(
                "ancillary buffer range overflowed",
            )
        })?;
    let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut rights = Vec::new();
    let mut message_count = 0_usize;
    let mut credentials_seen = false;
    let mut invalid = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        message_count = message_count.checked_add(1).ok_or_else(|| {
            ServiceRunnerError::invalid(
                "ancillary message count overflowed",
            )
        })?;
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
            let byte_length =
                header_length.checked_sub(minimum);
            let data_start =
                unsafe { libc::CMSG_DATA(header) } as usize;
            let data_end = byte_length
                .and_then(|length| data_start.checked_add(length));
            if let Some(byte_length) = byte_length.filter(|length| {
                length % size_of::<RawFd>() == 0
                    && data_start >= control_start
                    && data_end.is_some_and(|end| end <= control_end)
            }) {
                let raw_rights = unsafe {
                    std::slice::from_raw_parts(
                        libc::CMSG_DATA(header).cast::<RawFd>(),
                        byte_length / size_of::<RawFd>(),
                    )
                };
                for raw in raw_rights {
                    if *raw < 0 {
                        invalid = true;
                    } else {
                        rights.push(unsafe {
                            OwnedFd::from_raw_fd(*raw)
                        });
                    }
                }
            } else {
                invalid = true;
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
                invalid = true;
            } else {
                let credentials = unsafe {
                    ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::ucred>(),
                    )
                };
                if (
                    credentials.pid,
                    credentials.uid,
                    credentials.gid,
                ) != expected_credentials
                {
                    invalid = true;
                }
                credentials_seen = true;
            }
        } else {
            invalid = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if invalid
        || !credentials_seen
        || message_count > 2
        || rights.len() > MAX_SERVICE_RIGHTS
    {
        return Err(ServiceRunnerError::invalid(
            "service packet ancillary data violates its closed SCM_RIGHTS contract",
        ));
    }
    Ok(rights)
}

fn socket_peer_credentials(
    socket_fd: RawFd,
) -> Result<(i32, u32, u32), ServiceRunnerError> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length =
        size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(ServiceRunnerError::invalid(
            "service socket lacks exact SO_PEERCRED identity",
        ));
    }
    Ok((
        credentials.pid,
        credentials.uid,
        credentials.gid,
    ))
}

fn send_packet_until(
    socket_fd: RawFd,
    frame: &[u8],
    rights: &[OwnedFd],
    deadline: Option<u64>,
) -> Result<(), ServiceRunnerError> {
    loop {
        if try_send_packet(socket_fd, frame, rights)? {
            return Ok(());
        }
        wait_for_fd(socket_fd, libc::POLLOUT, deadline)?;
    }
}

fn try_send_packet(
    socket_fd: RawFd,
    frame: &[u8],
    rights: &[OwnedFd],
) -> Result<bool, ServiceRunnerError> {
    if frame.is_empty()
        || frame.len() > MAX_SERVICE_FRAME_BYTES
        || rights.len() > MAX_SERVICE_RIGHTS
    {
        return Err(ServiceRunnerError::invalid(
            "outbound service packet violates its fixed bounds",
        ));
    }
    let raw_rights: Vec<RawFd> =
        rights.iter().map(AsRawFd::as_raw_fd).collect();
    let mut vector = libc::iovec {
        iov_base: frame.as_ptr() as *mut libc::c_void,
        iov_len: frame.len(),
    };
    let mut ancillary = AncillaryBuffer([0; 512]);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !raw_rights.is_empty() {
        let byte_length = raw_rights
            .len()
            .checked_mul(size_of::<RawFd>())
            .ok_or_else(|| {
                ServiceRunnerError::invalid(
                    "outbound SCM_RIGHTS length overflowed",
                )
            })?;
        let byte_length_u32 =
            libc::c_uint::try_from(byte_length).map_err(|_| {
                ServiceRunnerError::invalid(
                    "outbound SCM_RIGHTS length is invalid",
                )
            })?;
        let control_length =
            unsafe { libc::CMSG_SPACE(byte_length_u32) } as usize;
        if control_length > ancillary.0.len() {
            return Err(ServiceRunnerError::invalid(
                "outbound SCM_RIGHTS exceeds its ancillary buffer",
            ));
        }
        message.msg_control = ancillary.0.as_mut_ptr().cast();
        message.msg_controllen = control_length;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(ServiceRunnerError::invalid(
                "outbound SCM_RIGHTS header is unavailable",
            ));
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(byte_length_u32) as usize;
            ptr::copy_nonoverlapping(
                raw_rights.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                byte_length,
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
            return Err(ServiceRunnerError::invalid(
                "SOCK_SEQPACKET response was not atomic",
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

fn wait_for_fd(
    fd: RawFd,
    events: libc::c_short,
    deadline: Option<u64>,
) -> Result<(), ServiceRunnerError> {
    loop {
        let timeout = match deadline {
            None => POLL_SLICE_MILLIS,
            Some(deadline) => {
                let now = boottime_now_nanos().map_err(|error| {
                    ServiceRunnerError::invalid(error.to_string())
                })?;
                if now >= deadline {
                    return Err(ServiceRunnerError::invalid(
                        "service operation crossed its absolute BOOTTIME deadline",
                    ));
                }
                let remaining_millis =
                    (deadline - now).saturating_add(999_999)
                        / 1_000_000;
                i32::try_from(remaining_millis)
                    .unwrap_or(i32::MAX)
                    .min(POLL_SLICE_MILLIS)
            }
        };
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(&mut poll, 1, timeout)
        };
        if ready > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(ServiceRunnerError::invalid(
                    "service poll observed an invalid descriptor",
                ));
            }
            if poll.revents
                & (events | libc::POLLERR | libc::POLLHUP)
                != 0
            {
                return Ok(());
            }
            return Err(ServiceRunnerError::invalid(
                "service poll returned an unexpected event set",
            ));
        }
        if ready == 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error.into());
        }
    }
}

fn descriptor_stat(
    descriptor: BorrowedFd<'_>,
) -> Result<libc::stat, ServiceRunnerError> {
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(stat)
}

fn get_socket_int(
    fd: RawFd,
    option: libc::c_int,
) -> Result<libc::c_int, ServiceRunnerError> {
    let mut value: libc::c_int = 0;
    let mut length =
        size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(ServiceRunnerError::invalid(
            "socket option length is invalid",
        ));
    }
    Ok(value)
}

fn set_nonblocking_cloexec(
    fd: RawFd,
) -> Result<(), ServiceRunnerError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
        } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    set_cloexec(fd)
}

fn set_cloexec(fd: RawFd) -> Result<(), ServiceRunnerError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                fd,
                libc::F_SETFD,
                flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
