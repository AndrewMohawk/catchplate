//! Compatibility facade for the extracted policy-custody authority.
//!
//! The facade constructs only extracted concrete adapters. Operation-specific
//! authority remains in the extracted modules. Stronger production authorities
//! are separate processes speaking the canonical v3 protocol over authenticated
//! local sockets; private Rust traits are not an external plugin ABI.

use super::super::{
    canonical_json_bytes, hash_domain_frames,
    verify_production_activation_publication_receipt,
    verify_production_active_effect_barrier,
    verify_production_active_effect_commit,
    verify_production_custody_trusted_host_attestation,
    verify_production_ingress_custody_admission,
    verify_production_publication_reconciliation_receipt,
    verify_production_reconciled_active_effect_commit,
    verify_production_shadow_spill_receipt,
    verify_production_spool_append_reservation_receipt,
    verify_production_spool_compaction_receipt,
    verify_production_terminal_slot_append_outcome,
    ActivationPublicationReceiptWire, AuthorityRole,
    ActivationPublicationTransaction, ActiveEffectBarrierReceiptWire,
    ActiveEffectCommitReceiptWire, ActiveEffectCommitState,
    ActiveEffectPreparation, AuthenticatedSpoolCompactionReceipt,
    AuthenticatedSpoolCompactionRequest,
    CustodyTrustedHostVerifierResultWire, EnvelopeKeyTrust,
    IngressCustodyAdmissionWire,
    PolicyShadowCustodySignerRole,
    PolicyShadowPersistenceProofVerifier,
    ProductionCustodyConfiguration,
    ProductionCustodyDispatchManifest,
    ProductionCustodyDispatchRequest,
    ProductionCustodyDispatchResponse,
    ProductionCustodyExecutionClosureManifest,
    ProductionCustodyGenerationInstallAttestation,
    ProductionCustodyGenerationInstallReceiptPayload,
    ProductionCustodyGenerationTransitionPreparation,
    ProductionCustodyKernelDriverIdentity,
    ProductionCustodyMutationPermit,
    ProductionCustodyProofScope,
    ProductionCustodyResultDisposition,
    ProductionCustodyStableReaperIdentity,
    ProductionCustodyTerminalCleanupAttestation,
    ProductionCustodyTerminalCleanupReceiptPayload,
    ProductionCustodyTerminationProof,
    PolicyShadowCustodyOperation,
    ProductionPolicyShadowCustodyProcess,
    ProductionPolicyShadowCustodyRpcSupervisor, Sha256Digest,
    PreparedGenerationPublication, PublicationReconciliationReceiptWire,
    PublicationReconciliationState, VerifiedPublicationReconciliationReceipt,
    RequestCommitment, ShadowError, ShadowSpoolEvent, ShadowGenerationIdentity,
    SignedEnvelope, SignedShadowSpillReceipt,
    SpoolAppendReservationReceiptWire, TerminalSlotAppendRequest, TerminalSlotAppendOutcomeWire,
    TrustedTime, VerifiedActiveEffectPermit, VerifiedAssignment,
};
use super::boottime::{BoottimeDeadline, BoottimeDomain};
use super::endpoint_clients::{
    CurrentEndpointTrustProvider, TrustedHostNoTeeEndpointTrustProvider,
};
use super::operation_driver::{
    PolicyCustodyOperationDriver,
    PolicyCustodyRecoveryReadiness,
};
use super::protocol::{
    PolicyCustodyEndpointRole, PolicyCustodyOperation,
};
use super::production_dispatch::{
    CanonicalProductionArtifactV4,
    ClosedProductionDispatchRequestV4,
    ClosedProductionDispatchResultV4,
    ClosedProductionGenerationRequestV4,
    ClosedProductionGenerationResponseV4,
    ExactSignedProductionGenerationInstallEnvelopeWireV4,
    MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES,
    PRODUCTION_RPC_PROTOCOL_VERSION,
    PRODUCTION_GENERATION_PROTOCOL_VERSION,
    ProductionArtifactKindV4, ProductionDispatchBindingV4,
    ProductionGenerationAbortResultWireV4,
    ProductionGenerationInstallContextWireV4,
    ProductionGenerationInstallEnvelopeRoleV4,
    ProductionGenerationPreparationResultWireV4,
    ProductionGenerationRecoveredResultWireV4,
    ProductionGenerationTransitionV4,
    ProductionRpcRequestBodyV4, ProductionRpcRequestV4,
    ProductionRpcRejectionCodeV4,
    ProductionRpcResponseBodyV4, ProductionRpcResponseV4,
    production_dispatch_protocol_set_sha256,
    PRODUCTION_DISPATCH_PROTOCOL_VERSION,
    SealedProductionArtifactReferenceV4,
};
use super::services::{
    decode_canonical_frame, encode_canonical_frame,
    AuthenticatedInheritedSeqpacket, ExpectedPeerCredentials,
};
use super::watchdog_recovery::{
    BoottimeWatchdogPoller, BoundedCleanupHelper,
    CleanupAuthorizationConsumer, CurrentSignatureAuthority,
    HeartbeatEvent, LinuxBoottimeWatchdogPoller,
    LinuxHeartbeatEvent, RecoveryRuntimeMaterialStore,
    RecoveryTargetProvider, TrustedHostNoTeeReport,
};
use super::ExtractedPolicyCustodyAuthority;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

const PRODUCTION_PROCESS_CONFIG_VERSION: &str =
    "serverware.policyCustodyProcess/v4";
const MAX_PRODUCTION_PROCESS_CONFIG_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedHostAttestationConfigV4 {
    host_evidence_sha256: Sha256Digest,
    host_evidence_profile_sha256: Sha256Digest,
    host_evidence_policy_sha256: Sha256Digest,
    host_measurement_sha256: Sha256Digest,
    production_configuration_binding_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    asserted_custody_key_set_root_sha256: Sha256Digest,
    verified_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    trust_checkpoint_id: Sha256Digest,
    trust_revocation_generation: u64,
    trust_revocation_root_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature_base64: String,
}

impl TrustedHostAttestationConfigV4 {
    fn into_wire(
        self,
    ) -> Result<CustodyTrustedHostVerifierResultWire, ShadowError> {
        CustodyTrustedHostVerifierResultWire::
            from_verifier_with_execution_closure(
                self.host_evidence_sha256,
                self.host_evidence_profile_sha256,
                self.host_evidence_policy_sha256,
                self.host_measurement_sha256,
                self.production_configuration_binding_sha256,
                self.worker_executable_sha256,
                self.execution_closure_manifest_sha256,
                self.structurally_verified_seccomp_policy_sha256,
                self.asserted_custody_key_set_root_sha256,
                self.verified_at_unix_nanos,
                self.expires_at_unix_nanos,
                self.trust_checkpoint_id,
                self.trust_revocation_generation,
                self.trust_revocation_root_sha256,
                self.signing_key_id,
                self.signing_key_spki_sha256,
                self.signature_base64,
            )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcPeerConfigV4 {
    pid: i32,
    uid: u32,
    gid: u32,
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

impl RpcPeerConfigV4 {
    fn checked(&self) -> Result<ExpectedPeerCredentials, ShadowError> {
        let expected = ExpectedPeerCredentials {
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
                .map_err(|_| ShadowError::CustodyUnavailable)?,
            cgroup_path_sha256: self.cgroup_path_sha256.clone(),
            cgroup_mount_id: self.cgroup_mount_id,
            cgroup_inode: self.cgroup_inode,
            security_label_sha256:
                self.security_label_sha256.clone(),
            configuration_generation_sha256:
                self.configuration_generation_sha256.clone(),
        };
        expected
            .validate_claim()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        Ok(expected)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionProcessConfigV4 {
    api_version: String,
    supervisor_instance_sha256: Sha256Digest,
    supervisor_boot_id_sha256: Sha256Digest,
    execution_closure_manifest:
        ProductionCustodyExecutionClosureManifest,
    signer_backend_sha256: Sha256Digest,
    persistence_backend_sha256: Sha256Digest,
    retrieval_backend_sha256: Sha256Digest,
    dispatcher_protocol_set_sha256: Sha256Digest,
    kernel_driver_identity: ProductionCustodyKernelDriverIdentity,
    stable_reaper_identity: ProductionCustodyStableReaperIdentity,
    driver_generation_receipt_sha256: Sha256Digest,
    maximum_rpc_nanos: u64,
    cleanup_reserve_nanos: u64,
    maximum_in_flight_calls: u16,
    maximum_async_durability_nanos: u64,
    rpc_worker_count: u16,
    rpc_queue_depth: u16,
    rpc_socket_path: PathBuf,
    rpc_peer: RpcPeerConfigV4,
    trusted_host_attestation: TrustedHostAttestationConfigV4,
}

impl ProductionProcessConfigV4 {
    fn validate(&self) -> Result<(), ShadowError> {
        if self.api_version != PRODUCTION_PROCESS_CONFIG_VERSION
            || self.rpc_worker_count == 0
            || self.rpc_worker_count > 64
            || self.rpc_queue_depth < self.rpc_worker_count
            || self.rpc_queue_depth > 256
            || !self.rpc_socket_path.is_absolute()
            || self.driver_generation_receipt_sha256
                == Sha256Digest::compute(&[])
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }

    fn production_configuration(
        &self,
        assignment: &VerifiedAssignment,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<ProductionCustodyConfiguration, ShadowError> {
        let configuration = ProductionCustodyConfiguration::
            from_verified_assignment_with_settlement_authority(
                assignment,
                key_trust,
                trusted_time,
                self.supervisor_instance_sha256.clone(),
                self.supervisor_boot_id_sha256.clone(),
                self.execution_closure_manifest.clone(),
                self.signer_backend_sha256.clone(),
                self.persistence_backend_sha256.clone(),
                self.retrieval_backend_sha256.clone(),
                self.dispatcher_protocol_set_sha256.clone(),
                self.kernel_driver_identity.clone(),
                self.maximum_rpc_nanos,
                self.cleanup_reserve_nanos,
                self.maximum_in_flight_calls,
                self.maximum_async_durability_nanos,
            )?;
        let attestation =
            verify_production_custody_trusted_host_attestation(
                &configuration,
                self.trusted_host_attestation.clone().into_wire()?,
                key_trust,
                trusted_time,
            )?;
        configuration.activate_with_verified_attestation(attestation)
    }
}

struct InstalledProductionSupervisor {
    source_config_sha256: Sha256Digest,
    process_config: ProductionProcessConfigV4,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    supervisor: Arc<ProductionPolicyShadowCustodyRpcSupervisor>,
}
struct InstalledNativeSupervisor {
    source:Sha256Digest,owner:Arc<super::services::NativeCustodyLifecycleOwner>,factory:Arc<super::native_remote_factory::Factory>,
    assignment:Sha256Digest,supervisor:Arc<ProductionPolicyShadowCustodyRpcSupervisor>,
}
static INSTALLED_NATIVE_SUPERVISOR:OnceLock<Mutex<Option<InstalledNativeSupervisor>>>=OnceLock::new();

static INSTALLED_PRODUCTION_SUPERVISOR:
    OnceLock<Mutex<Option<InstalledProductionSupervisor>>> =
    OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionTerminationProofWireV4 {
    operation_id_sha256: Sha256Digest,
    termination_fence_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    kernel_retained_descriptor_set_sha256: Sha256Digest,
    driver_generation_receipt_sha256: Sha256Digest,
    worker_terminated_at_unix_nanos: i64,
    worker_terminated_at_boottime_nanos: u64,
    process_reaped: bool,
    late_mutation_fence_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionTerminalCleanupResultWireV4 {
    api_version: String,
    process_termination: ProductionTerminationProofWireV4,
    exact_signed_settlement_envelope_bytes: Vec<u8>,
    exact_signed_settlement_envelope_sha256: Sha256Digest,
}

struct RpcJob {
    exact_request: Vec<u8>,
    deadline_boottime_nanos: u64,
    completion: SyncSender<Result<Vec<u8>, ShadowError>>,
}

struct BoundedCanonicalRpcClient {
    queue: SyncSender<RpcJob>,
}
#[derive(Clone)]
struct NativeRpcGuard {factory:Arc<super::native_remote_factory::Factory>,trust:Arc<dyn EnvelopeKeyTrust+Send+Sync>,time:Arc<dyn TrustedTime+Send+Sync>}
impl NativeRpcGuard {
    fn check(&self,deadline:u64)->Result<(),ShadowError>{self.factory.check(self.trust.as_ref(),self.time.as_ref())?;
        self.factory.require_deadline(deadline)?;Ok(())}
}

impl BoundedCanonicalRpcClient {
    fn connect(
        config: &ProductionProcessConfigV4,
    ) -> Result<Arc<Self>, ShadowError> {
        let worker_count = usize::from(config.rpc_worker_count);
        let mut sessions = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let socket = connect_unix_seqpacket(&config.rpc_socket_path)?;
            sessions.push(
                AuthenticatedInheritedSeqpacket::from_inherited(
                    socket,
                    config.rpc_peer.checked()?,
                )
                .map_err(|_| ShadowError::CustodyUnavailable)?,
            );
        }
        Self::from_sessions(sessions,usize::from(config.rpc_queue_depth),None)
    }
    fn from_sessions(sessions:Vec<AuthenticatedInheritedSeqpacket>,queue_depth:usize,native:Option<NativeRpcGuard>)->Result<Arc<Self>,ShadowError>{
        if sessions.is_empty() || sessions.len()>64 || queue_depth<sessions.len() || queue_depth>256 {
            return Err(ShadowError::CustodyUnavailable);
        }
        let (queue, receiver) =
            mpsc::sync_channel::<RpcJob>(queue_depth);
        let receiver = Arc::new(Mutex::new(receiver));
        for (ordinal, session) in sessions.into_iter().enumerate() {
            let receiver = Arc::clone(&receiver);
            let native=native.clone();
            thread::Builder::new()
                .name(format!("policy-custody-rpc-{ordinal}"))
                .spawn(move || loop {
                    let job = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let Ok(job) = job else {
                        return;
                    };
                    let result=(||{
                        if let Some(guard)=&native{guard.check(job.deadline_boottime_nanos)?;}
                        let result=rpc_exchange(&session,&job.exact_request,job.deadline_boottime_nanos)?;
                        if let Some(guard)=&native{guard.check(job.deadline_boottime_nanos)?;}
                        Ok(result)
                    })();
                    let _ = job.completion.send(result);
                })
                .map_err(|_| ShadowError::CustodyUnavailable)?;
        }
        Ok(Arc::new(Self { queue }))
    }

    fn call(
        &self,
        request: &ProductionRpcRequestV4,
    ) -> Result<ProductionRpcResponseV4, ShadowError> {
        request
            .validate()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let exact_request = encode_canonical_frame(request)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let (completion, completed) = mpsc::sync_channel(1);
        self.queue
            .try_send(RpcJob {
                exact_request,
                deadline_boottime_nanos:
                    request.deadline_boottime_nanos,
                completion,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) | TrySendError::Disconnected(_) => {
                    ShadowError::CustodyUnavailable
                }
            })?;
        loop {
            match completed.try_recv() {
                Ok(result) => {
                    let response: ProductionRpcResponseV4 = decode_canonical_frame(&result?)
                        .map_err(|_| ShadowError::CustodyUnavailable)?;
                    response
                        .validate_for_request(request)
                        .map_err(|_| ShadowError::CustodyUnavailable)?;
                    return Ok(response);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(ShadowError::CustodyUnavailable)
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if super::boottime::boottime_now_nanos()
                .map_err(|_| ShadowError::CustodyUnavailable)?
                >= request.deadline_boottime_nanos
            {
                return Err(ShadowError::CustodyUnavailable);
            }
            thread::park_timeout(Duration::from_micros(250));
        }
    }
}

fn rpc_exchange(
    session: &AuthenticatedInheritedSeqpacket,
    exact_request: &[u8],
    deadline_boottime_nanos: u64,
) -> Result<Vec<u8>, ShadowError> {
    session
        .revalidate_peer()
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    loop {
        if session
            .try_send(exact_request, &[], 0)
            .map_err(|_| ShadowError::CustodyUnavailable)?
        {
            session
                .revalidate_peer()
                .map_err(|_| ShadowError::CustodyUnavailable)?;
            break;
        }
        wait_for_rpc_fd(
            session.progress_fd().as_raw_fd(),
            libc::POLLOUT,
            deadline_boottime_nanos,
        )?;
    }
    loop {
        if let Some(packet) = session
            .try_receive(0)
            .map_err(|_| ShadowError::CustodyUnavailable)?
        {
            session
                .revalidate_peer()
                .map_err(|_| ShadowError::CustodyUnavailable)?;
            return Ok(packet.frame);
        }
        wait_for_rpc_fd(
            session.progress_fd().as_raw_fd(),
            libc::POLLIN,
            deadline_boottime_nanos,
        )?;
    }
}

fn wait_for_rpc_fd(
    descriptor: i32,
    events: i16,
    deadline_boottime_nanos: u64,
) -> Result<(), ShadowError> {
    loop {
        let now = super::boottime::boottime_now_nanos()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if now >= deadline_boottime_nanos {
            return Err(ShadowError::CustodyUnavailable);
        }
        let remaining = deadline_boottime_nanos - now;
        let timeout_millis = i32::try_from(
            remaining.saturating_add(999_999) / 1_000_000,
        )
        .unwrap_or(i32::MAX)
        .max(1);
        let mut poll = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, timeout_millis) };
        if result > 0
            && poll.revents
                & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                == 0
            && poll.revents & events != 0
        {
            return Ok(());
        }
        if result == 0 {
            continue;
        }
        if result < 0
            && std::io::Error::last_os_error().raw_os_error()
                == Some(libc::EINTR)
        {
            continue;
        }
        return Err(ShadowError::CustodyUnavailable);
    }
}

fn connect_unix_seqpacket(path: &PathBuf) -> Result<OwnedFd, ShadowError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty()
        || bytes[0] != b'/'
        || bytes.contains(&0)
        || bytes.len() >= address.sun_path.len()
    {
        return Err(ShadowError::CustodyUnavailable);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(ShadowError::CustodyUnavailable);
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let length = std::mem::size_of::<libc::sa_family_t>()
        .checked_add(bytes.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| libc::socklen_t::try_from(value).ok())
        .ok_or(ShadowError::CustodyUnavailable)?;
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(ShadowError::CustodyUnavailable);
    }
    Ok(socket)
}

struct RpcPersistenceVerifier {
    rpc: Arc<BoundedCanonicalRpcClient>,
    maximum_rpc_nanos: u64,
    generation_ambiguous: Arc<AtomicBool>,
}

fn exact_rpc_request(
    request: ProductionRpcRequestBodyV4,
    replay_id_sha256: Sha256Digest,
    deadline_boottime_nanos: u64,
) -> Result<ProductionRpcRequestV4, ShadowError> {
    let request_id_sha256 = Sha256Digest::compute(
        &canonical_json_bytes(&(
            PRODUCTION_RPC_PROTOCOL_VERSION,
            &replay_id_sha256,
            deadline_boottime_nanos,
            &request,
        ))?,
    );
    let mut envelope = ProductionRpcRequestV4 {
        api_version: PRODUCTION_RPC_PROTOCOL_VERSION.to_owned(),
        request_id_sha256,
        replay_id_sha256,
        deadline_boottime_nanos,
        request,
        request_sha256: Sha256Digest::compute(&[]),
    };
    envelope.request_sha256 = envelope
        .computed_request_sha256()
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    envelope
        .validate()
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    Ok(envelope)
}

struct PreparedGenerationRpcState {
    preparation: ProductionCustodyGenerationTransitionPreparation,
    request: ClosedProductionGenerationRequestV4,
    successor: ProductionCustodyConfiguration,
    remote_committed_or_recovered: bool,
}

enum DispatchResponseContext {
    None,
    RecoverPublication(u64),
    PreparePublication(IngressPublicationPreparation),
    CommitPublication(RetainedIngressPublication),
    AbortPublication(RetainedIngressPublication),
    BeginIngress {
        request_binding_sha256: Sha256Digest,
        published: Option<RetainedIngressPublication>,
    },
    ReserveSpool(ShadowSpoolEvent),
    AppendSpool(ShadowSpoolEvent),
    CompactSpool(AuthenticatedSpoolCompactionRequest),
    ActiveEffectBarrier(ActiveEffectPreparation),
    ActiveEffectCommit {
        permit: VerifiedActiveEffectPermit,
        terminal_state: ActiveEffectCommitState,
        result_sha256: Sha256Digest,
    },
    ReconcileActiveEffect(Sha256Digest),
    AppendTerminal(TerminalSlotAppendRequest),
    PublishActivation(ActivationPublicationTransaction),
}

#[derive(Clone, PartialEq, Eq)]
struct IngressPublicationPreparation {
    configuration_binding_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    successor: Arc<ShadowGenerationIdentity>,
    predecessor: Option<Sha256Digest>,
    expected_publication_revision: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct RetainedIngressPublication {
    context: IngressPublicationPreparation,
    prepared: PreparedGenerationPublication,
}

/// One publication may be prepared at a time; ingress holds only an Arc to
/// the previously authenticated immutable identity. No identity is learned
/// from an ingress response. An ambiguous preparation stays reserved until an
/// authenticated abort/recovery or configuration transition invalidates it.
#[derive(Clone, Default)]
struct IngressPublicationState {
    revision: u64,
    pending: Option<(IngressPublicationPreparation, Option<PreparedGenerationPublication>)>,
    published: Option<RetainedIngressPublication>,
}

impl IngressPublicationState {
    fn next_revision(&self) -> Result<u64, ShadowError> {
        self.revision.checked_add(1).ok_or(ShadowError::CounterOverflow)
    }

    fn invalidate(&mut self) -> Result<(), ShadowError> {
        let revision = self.next_revision()?;
        self.pending = None;
        self.published = None;
        self.revision = revision;
        Ok(())
    }

    fn reserve(&mut self, context: &IngressPublicationPreparation) -> Result<(), ShadowError> {
        if let Some((existing, _)) = &self.pending {
            if existing != context {
                return Err(ShadowError::CustodyUnavailable);
            }
        } else {
            let revision = self.next_revision()?;
            self.pending = Some((context.clone(), None));
            self.revision = revision;
        }
        Ok(())
    }

    fn accept_prepared(
        &mut self,
        context: &IngressPublicationPreparation,
        prepared: &PreparedGenerationPublication,
    ) -> Result<(), ShadowError> {
        prepared.validate_for_successor(context.predecessor.as_ref(), &context.successor)?;
        let revision = self.next_revision()?;
        let (reserved, stored) = self.pending.as_mut().ok_or(ShadowError::BindingDrift)?;
        if reserved != context || stored.as_ref().is_some_and(|value| value != prepared) {
            return Err(ShadowError::BindingDrift);
        }
        *stored = Some(prepared.clone());
        self.revision = revision;
        Ok(())
    }

    fn retained(&self, prepared: &PreparedGenerationPublication) -> Result<RetainedIngressPublication, ShadowError> {
        if let Some((context, Some(stored))) = &self.pending {
            if stored == prepared {
                return Ok(RetainedIngressPublication { context: context.clone(), prepared: stored.clone() });
            }
        }
        self.published.as_ref().filter(|value| value.prepared == *prepared)
            .cloned().ok_or(ShadowError::BindingDrift)
    }

    fn receipt_matches(
        retained: &RetainedIngressPublication,
        receipt: &VerifiedPublicationReconciliationReceipt,
    ) -> bool {
        receipt.state() == PublicationReconciliationState::Published
            && receipt.published_generation_sha256() == Some(retained.context.successor.generation_id())
            && receipt.predecessor_generation_sha256() == retained.context.predecessor.as_ref()
            && receipt.publication_revision() == retained.context.expected_publication_revision
            && receipt.sequence_bounds() == Some(retained.prepared.sequence_bounds())
            && receipt.prepared_publication_sha256() == Some(retained.prepared.preparation_receipt_sha256())
    }

    fn commit(
        &mut self,
        retained: &RetainedIngressPublication,
        receipt: &VerifiedPublicationReconciliationReceipt,
    ) -> Result<(), ShadowError> {
        if self.retained(&retained.prepared)? != *retained || !Self::receipt_matches(retained, receipt) {
            return Err(ShadowError::BindingDrift);
        }
        // A delayed retry of an older publication must not erase a newer
        // pending publication or replace its context.
        if self.pending.as_ref().is_some_and(|(context, _)| context != &retained.context) {
            return Err(ShadowError::BindingDrift);
        }
        let revision = self.next_revision()?;
        self.published = Some(retained.clone());
        self.pending = None;
        self.revision = revision;
        Ok(())
    }

    fn abort(&mut self, retained: &RetainedIngressPublication) -> Result<(), ShadowError> {
        if self.retained(&retained.prepared)? != *retained {
            return Err(ShadowError::BindingDrift);
        }
        let revision = self.next_revision()?;
        if self.pending.as_ref().is_some_and(|(context, _)| context == &retained.context) {
            self.pending = None;
        }
        if self.published.as_ref() == Some(retained) {
            self.published = None;
        }
        self.revision = revision;
        Ok(())
    }

    fn recover(&mut self, expected_revision: u64, receipt: &VerifiedPublicationReconciliationReceipt) -> Result<(), ShadowError> {
        if self.revision != expected_revision {
            return Err(ShadowError::BindingDrift);
        }
        let revision = self.next_revision()?;
        self.pending = None;
        if !self.published.as_ref().is_some_and(|retained| Self::receipt_matches(retained, receipt)) {
            self.published = None;
        }
        self.revision = revision;
        // A digest-only recovered publication cannot seed an absent identity.
        // Startup must replay the ordinary verified prepare/commit chain with
        // its locally verified assignment/load successor before Assigned can
        // be accepted. A recovery receipt alone intentionally remains closed.
        Ok(())
    }
}

enum ProcessAuthority {
    Host(ProductionProcessConfigV4),
    Native(Arc<super::native_remote_factory::Factory>),
}
struct RetainedProcessSettings {
    authority:ProcessAuthority,kernel_driver_identity:ProductionCustodyKernelDriverIdentity,
    driver_generation_receipt_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    maximum_rpc_nanos:u64,maximum_in_flight_calls:u16,
}
impl RetainedProcessSettings {
    fn host(value:ProductionProcessConfigV4)->Self {
        Self{kernel_driver_identity:value.kernel_driver_identity.clone(),driver_generation_receipt_sha256:value.driver_generation_receipt_sha256.clone(),
            worker_executable_sha256:value.execution_closure_manifest.worker_executable_sha256().clone(),
            maximum_rpc_nanos:value.maximum_rpc_nanos,maximum_in_flight_calls:value.maximum_in_flight_calls,authority:ProcessAuthority::Host(value)}
    }
    fn native(owner:Arc<super::native_remote_factory::Factory>)->Self {
        Self{kernel_driver_identity:owner.driver.clone(),driver_generation_receipt_sha256:owner.prior_admission_sha256.clone(),
            worker_executable_sha256:owner.configuration.worker_executable_sha256().clone(),
            maximum_rpc_nanos:owner.settings.maximum_rpc_nanos,maximum_in_flight_calls:owner.settings.maximum_in_flight_calls,
            authority:ProcessAuthority::Native(owner)}
    }
    fn validate(&self,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<(),ShadowError>{
        match &self.authority {ProcessAuthority::Host(value)=>value.validate(),ProcessAuthority::Native(owner)=>owner.check(trust,time)}
    }
    fn deadline(&self,value:u64)->Result<u64,ShadowError>{match &self.authority{
        ProcessAuthority::Host(_)=>Ok(value),ProcessAuthority::Native(owner)=>owner.require_deadline(value)}}
}

struct RpcProductionPolicyShadowCustodyProcess {
    active_configuration: RwLock<ProductionCustodyConfiguration>,
    manifest: ProductionCustodyDispatchManifest,
    process_config: RetainedProcessSettings,
    rpc: Arc<BoundedCanonicalRpcClient>,
    key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
    trusted_time: Arc<dyn TrustedTime + Send + Sync>,
    persistence_verifier: RpcPersistenceVerifier,
    sealed_references:
        Mutex<BTreeMap<String, SealedProductionArtifactReferenceV4>>,
    prepared_generations: Mutex<Vec<PreparedGenerationRpcState>>,
    ingress_publication: Mutex<IngressPublicationState>,
    generation_ambiguous: Arc<AtomicBool>,
}

impl RpcProductionPolicyShadowCustodyProcess {
    fn deadline(&self) -> Result<u64, ShadowError> {
        self.process_config.deadline(super::boottime::boottime_now_nanos()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .checked_add(self.process_config.maximum_rpc_nanos)
            .ok_or(ShadowError::CounterOverflow)?)
    }

    fn call_body(
        &self,
        request: ProductionRpcRequestBodyV4,
        replay_id_sha256: Sha256Digest,
        deadline_boottime_nanos: u64,
    ) -> Result<ProductionRpcResponseBodyV4, ShadowError> {
        self.process_config.validate(self.key_trust.as_ref(),self.trusted_time.as_ref())?;
        self.process_config.deadline(deadline_boottime_nanos)?;
        if self.generation_ambiguous.load(Ordering::Acquire)
            && !matches!(request, ProductionRpcRequestBodyV4::Generation(_))
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let envelope = exact_rpc_request(
            request,
            replay_id_sha256,
            deadline_boottime_nanos,
        )?;
        let response = self.rpc.call(&envelope)?;
        match response.response {
            ProductionRpcResponseBodyV4::Rejected(_) => {
                Err(ShadowError::CustodyUnavailable)
            }
            response => Ok(response),
        }
    }

    fn generation_call(
        &self,
        request: ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ShadowError> {
        let deadline = request.deadline_boottime_nanos();
        let replay = request.replay_id_sha256().clone();
        match self.call_body(
            ProductionRpcRequestBodyV4::Generation(request.clone()),
            replay,
            deadline,
        )? {
            ProductionRpcResponseBodyV4::Generation(response)
                if response.api_version
                        == PRODUCTION_GENERATION_PROTOCOL_VERSION
                    && response.request_sha256
                        == request
                            .request_sha256()
                            .map_err(|_| ShadowError::CustodyUnavailable)?
                    && response.replay_id_sha256
                        == *request.replay_id_sha256()
                    && response.service_transitions.len() == 5 => Ok(response),
            _ => Err(ShadowError::CustodyUnavailable),
        }
    }

    fn prepared_request(
        &self,
        preparation: &ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<ClosedProductionGenerationRequestV4, ShadowError> {
        self.prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .iter()
            .find(|entry| entry.preparation == *preparation)
            .map(|entry| entry.request.clone())
            .ok_or(ShadowError::CustodyUnavailable)
    }

    fn generation_install_context(
        &self,
        successor: &ProductionCustodyConfiguration,
    ) -> Result<ProductionGenerationInstallContextWireV4, ShadowError> {
        let authority = successor
            .authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        let checkpoint = successor.authority_trust_checkpoint();
        let issued_at_unix_nanos =
            self.trusted_time.now_unix_nanos()?;
        let expires_at_unix_nanos = issued_at_unix_nanos
            .checked_add(
                successor.maximum_authority_evidence_age_nanos(),
            )
            .ok_or(ShadowError::CounterOverflow)?;
        Ok(ProductionGenerationInstallContextWireV4 {
            assignment_id: successor.assignment_id().clone(),
            assignment_payload_sha256:
                successor.assignment_payload_sha256().clone(),
            assignment_revision: successor.assignment_revision(),
            operation_coverage_root_sha256: successor
                .operation_coverage_root_sha256()
                .clone(),
            five_service_protocol_set_sha256: successor
                .dispatcher_protocol_set_sha256()
                .clone(),
            envelope_authority_role:
                ProductionGenerationInstallEnvelopeRoleV4::
                    CustodyResultEnvelope,
            envelope_authority_key_id: authority.key_id().clone(),
            envelope_authority_key_spki_sha256:
                authority.key_spki_sha256().clone(),
            trusted_time_checkpoint_sha256:
                checkpoint.checkpoint_id.clone(),
            trusted_time_revocation_generation:
                checkpoint.revocation_generation,
            trusted_time_revocation_root_sha256:
                checkpoint.revocation_root_sha256.clone(),
            issued_at_unix_nanos,
            expires_at_unix_nanos,
        })
    }

    fn generation_deadline(&self) -> Result<u64, ShadowError> {
        let window = self
            .process_config
            .maximum_rpc_nanos
            .checked_mul(2)
            .ok_or(ShadowError::CounterOverflow)?;
        self.process_config.deadline(super::boottime::boottime_now_nanos()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .checked_add(window)
            .ok_or(ShadowError::CounterOverflow)?)
    }

    fn generation_transition_id(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        install_context: &ProductionGenerationInstallContextWireV4,
    ) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyCustodyProductionGenerationIntent/v4",
            &[&canonical_json_bytes(&(
                previous.map(|value| {
                    value.production_configuration_binding_sha256()
                }),
                successor.production_configuration_binding_sha256(),
                self.manifest.manifest_sha256(),
                self.process_config
                    .kernel_driver_identity
                    .identity_sha256(),
                &self.process_config
                    .kernel_driver_identity
                    .retained_descriptor_manifest_sha256,
                &self.process_config.driver_generation_receipt_sha256,
                install_context,
            ))?],
        ))
    }

    fn generation_replay_id(
        transition: ProductionGenerationTransitionV4,
        transition_id_sha256: &Sha256Digest,
        preparation_receipt_sha256: Option<&Sha256Digest>,
    ) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyCustodyProductionGenerationReplay/v4",
            &[&canonical_json_bytes(&(
                transition,
                transition_id_sha256,
                preparation_receipt_sha256,
            ))?],
        ))
    }

    fn preparation_from_wire(
        wire: ProductionGenerationPreparationResultWireV4,
    ) -> Result<ProductionCustodyGenerationTransitionPreparation, ShadowError>
    {
        let five_service_preparation_receipts_root_sha256 =
            super::super::production_custody_five_service_receipts_root(
                &wire
                    .durable_recovery_store_prepare_receipt_sha256,
                &wire
                    .cleanup_authorization_prepare_receipt_sha256,
                &wire.recovery_target_prepare_receipt_sha256,
                &wire.bounded_cleanup_prepare_receipt_sha256,
                &wire.current_signature_prepare_receipt_sha256,
            )?;
        Ok(ProductionCustodyGenerationTransitionPreparation {
            transition_id_sha256: wire.transition_id_sha256,
            previous_configuration_binding_sha256:
                wire.previous_configuration_binding_sha256,
            successor_configuration_binding_sha256:
                wire.successor_configuration_binding_sha256,
            dispatch_manifest_sha256: wire.dispatch_manifest_sha256,
            kernel_driver_identity_sha256:
                wire.kernel_driver_identity_sha256,
            kernel_retained_descriptor_set_sha256:
                wire.retained_descriptor_set_sha256,
            driver_generation_receipt_sha256:
                wire.driver_generation_receipt_sha256,
            durable_recovery_store_prepare_receipt_sha256:
                wire.durable_recovery_store_prepare_receipt_sha256,
            cleanup_authorization_prepare_receipt_sha256:
                wire.cleanup_authorization_prepare_receipt_sha256,
            recovery_target_prepare_receipt_sha256:
                wire.recovery_target_prepare_receipt_sha256,
            bounded_cleanup_prepare_receipt_sha256:
                wire.bounded_cleanup_prepare_receipt_sha256,
            current_signature_prepare_receipt_sha256:
                wire.current_signature_prepare_receipt_sha256,
            five_service_preparation_receipts_root_sha256,
            durable_intent_receipt_sha256:
                wire.durable_intent_receipt_sha256,
            prepared_at_boottime_nanos:
                wire.prepared_at_boottime_nanos,
            commit_deadline_boottime_nanos:
                wire.commit_deadline_boottime_nanos,
        })
    }

    fn install_attestation_from_wire(
        &self,
        wire: ExactSignedProductionGenerationInstallEnvelopeWireV4,
    ) -> Result<ProductionCustodyGenerationInstallAttestation, ShadowError>
    {
        wire.validate()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let signed: SignedEnvelope<
            ProductionCustodyGenerationInstallReceiptPayload,
        > = serde_json::from_slice(
            &wire.exact_signed_install_envelope_bytes,
        )
        .map_err(|_| ShadowError::CustodyUnavailable)?;
        if canonical_json_bytes(&signed)?
            != wire.exact_signed_install_envelope_bytes
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(ProductionCustodyGenerationInstallAttestation::
            from_external_installation(self.manifest.clone(), signed))
    }

    fn recover_generation(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
    ) -> Result<
        Option<(
            ProductionCustodyGenerationTransitionPreparation,
            ProductionCustodyGenerationInstallAttestation,
        )>,
        ShadowError,
    > {
        let install_context =
            self.generation_install_context(successor)?;
        let transition_id_sha256 = self.generation_transition_id(
            previous,
            successor,
            &install_context,
        )?;
        let replay_id_sha256 = Self::generation_replay_id(
            ProductionGenerationTransitionV4::Recover,
            &transition_id_sha256,
            None,
        )?;
        let request = ClosedProductionGenerationRequestV4::Recover {
            transition_id_sha256,
            previous_configuration_binding_sha256: previous.map(
                |value| {
                    value
                        .production_configuration_binding_sha256()
                        .clone()
                },
            ),
            successor_configuration_binding_sha256: successor
                .production_configuration_binding_sha256()
                .clone(),
            dispatch_manifest_sha256:
                self.manifest.manifest_sha256().clone(),
            kernel_driver_identity_sha256: self
                .process_config
                .kernel_driver_identity
                .identity_sha256()
                .clone(),
            retained_descriptor_set_sha256: self
                .process_config
                .kernel_driver_identity
                .retained_descriptor_manifest_sha256
                .clone(),
            driver_generation_receipt_sha256: self
                .process_config
                .driver_generation_receipt_sha256
                .clone(),
            install_context,
            deadline_boottime_nanos: self.generation_deadline()?,
            replay_id_sha256,
        };
        let envelope = exact_rpc_request(
            ProductionRpcRequestBodyV4::Generation(request.clone()),
            request.replay_id_sha256().clone(),
            request.deadline_boottime_nanos(),
        )?;
        let response = self.rpc.call(&envelope)?;
        let response = match response.response {
            ProductionRpcResponseBodyV4::Rejected(rejection)
                if rejection.code
                    == ProductionRpcRejectionCodeV4::RecoveryNotReady =>
            {
                return Ok(None)
            }
            ProductionRpcResponseBodyV4::Generation(response) => response,
            _ => return Err(ShadowError::CustodyUnavailable),
        };
        let recovered = if response.api_version==super::services::generation_recovery::RESPONSE_API {
            // The actual selected bridge has independently verified both the
            // native signature and all five current service observations. This
            // exact variant does not turn a rejection into an empty state.
            let evidence=Self::decode_artifact::<super::services::generation_recovery::Evidence>(
                &response.result,ProductionArtifactKindV4::NativeGenerationRecovery)?;
            if evidence.payload.request!=request || response.request_sha256!=request.request_sha256().map_err(|_|ShadowError::CustodyUnavailable)?
                || response.replay_id_sha256!=*request.replay_id_sha256() || !response.service_transitions.is_empty() {
                return Err(ShadowError::CustodyUnavailable);
            }
            let Some(installed)=evidence.payload.installed else{return Ok(None);};
            super::services::generation_recovery::same_scope(&request,&installed.prepare_request).map_err(|_|ShadowError::CustodyUnavailable)?;
            let preparation=Self::decode_artifact::<ProductionGenerationPreparationResultWireV4>(&installed.preparation.result,
                ProductionArtifactKindV4::GenerationTransitionPreparation)?;
            preparation.validate_for_request(&installed.prepare_request).map_err(|_|ShadowError::CustodyUnavailable)?;
            let installation=Self::decode_artifact::<ExactSignedProductionGenerationInstallEnvelopeWireV4>(&installed.installation.result,
                ProductionArtifactKindV4::GenerationInstallAttestation)?;
            installation.validate_for_request(&installed.commit_request).map_err(|_|ShadowError::CustodyUnavailable)?;
            ProductionGenerationRecoveredResultWireV4{preparation,installation}
        } else {
            let recovered=Self::decode_artifact::<ProductionGenerationRecoveredResultWireV4>(&response.result,
                ProductionArtifactKindV4::GenerationInstallAttestation)?;
            recovered.validate_for_request(&request).map_err(|_|ShadowError::CustodyUnavailable)?;recovered
        };
        let preparation = Self::preparation_from_wire(
            recovered.preparation,
        )?;
        let installation = self.install_attestation_from_wire(
            recovered.installation,
        )?;
        self.generation_ambiguous.store(true, Ordering::Release);
        let mut prepared = self
            .prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if prepared.len()
            >= usize::from(self.process_config.maximum_in_flight_calls)
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        prepared.push(PreparedGenerationRpcState {
            preparation: preparation.clone(),
            request,
            successor: successor.clone(),
            remote_committed_or_recovered: true,
        });
        Ok(Some((preparation, installation)))
    }

    fn prepare_generation(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
    ) -> Result<
        ProductionCustodyGenerationTransitionPreparation,
        ShadowError,
    > {
        let install_context =
            self.generation_install_context(successor)?;
        let transition_id_sha256 = self.generation_transition_id(
            previous,
            successor,
            &install_context,
        )?;
        let replay_id_sha256 = Self::generation_replay_id(
            ProductionGenerationTransitionV4::Prepare,
            &transition_id_sha256,
            None,
        )?;
        let request = ClosedProductionGenerationRequestV4::Prepare {
            transition_id_sha256,
            previous_configuration_binding_sha256: previous.map(
                |value| {
                    value
                        .production_configuration_binding_sha256()
                        .clone()
                },
            ),
            successor_configuration_binding_sha256: successor
                .production_configuration_binding_sha256()
                .clone(),
            dispatch_manifest_sha256:
                self.manifest.manifest_sha256().clone(),
            kernel_driver_identity_sha256: self
                .process_config
                .kernel_driver_identity
                .identity_sha256()
                .clone(),
            retained_descriptor_set_sha256: self
                .process_config
                .kernel_driver_identity
                .retained_descriptor_manifest_sha256
                .clone(),
            driver_generation_receipt_sha256: self
                .process_config
                .driver_generation_receipt_sha256
                .clone(),
            install_context,
            deadline_boottime_nanos: self.generation_deadline()?,
            replay_id_sha256,
        };
        let response = self.generation_call(request.clone())?;
        let wire = Self::decode_artifact::<
            ProductionGenerationPreparationResultWireV4,
        >(
            &response.result,
            ProductionArtifactKindV4::GenerationTransitionPreparation,
        )?;
        wire.validate_for_request(&request)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let preparation = Self::preparation_from_wire(wire)?;
        let mut prepared = self
            .prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if prepared.len()
            >= usize::from(self.process_config.maximum_in_flight_calls)
            || prepared
                .iter()
                .any(|entry| entry.preparation == preparation)
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        prepared.push(PreparedGenerationRpcState {
            preparation: preparation.clone(),
            request,
            successor: successor.clone(),
            remote_committed_or_recovered: false,
        });
        Ok(preparation)
    }

    fn commit_generation(
        &self,
        preparation: &ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<
        ProductionCustodyGenerationInstallAttestation,
        ShadowError,
    > {
        let _prepared_request = self.prepared_request(preparation)?;
        let preparation_receipt_sha256 = preparation.receipt_sha256()?;
        let replay_id_sha256 = Self::generation_replay_id(
            ProductionGenerationTransitionV4::Commit,
            &preparation.transition_id_sha256,
            Some(&preparation_receipt_sha256),
        )?;
        let request = ClosedProductionGenerationRequestV4::Commit {
            transition_id_sha256:
                preparation.transition_id_sha256.clone(),
            preparation_receipt_sha256,
            deadline_boottime_nanos:
                preparation.commit_deadline_boottime_nanos,
            replay_id_sha256,
        };
        self.generation_ambiguous.store(true, Ordering::Release);
        let response = self.generation_call(request)?;
        let wire = Self::decode_artifact::<
            ExactSignedProductionGenerationInstallEnvelopeWireV4,
        >(
            &response.result,
            ProductionArtifactKindV4::GenerationInstallAttestation,
        )?;
        let installation = self.install_attestation_from_wire(wire)?;
        let mut prepared = self
            .prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let entry = prepared
            .iter_mut()
            .find(|entry| entry.preparation == *preparation)
            .ok_or(ShadowError::CustodyUnavailable)?;
        entry.remote_committed_or_recovered = true;
        Ok(installation)
    }

    fn abort_generation(
        &self,
        preparation: &ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<Sha256Digest, ShadowError> {
        let _prepared_request = self.prepared_request(preparation)?;
        let preparation_receipt_sha256 = preparation.receipt_sha256()?;
        let replay_id_sha256 = Self::generation_replay_id(
            ProductionGenerationTransitionV4::Abort,
            &preparation.transition_id_sha256,
            Some(&preparation_receipt_sha256),
        )?;
        let request = ClosedProductionGenerationRequestV4::Abort {
            transition_id_sha256:
                preparation.transition_id_sha256.clone(),
            preparation_receipt_sha256,
            deadline_boottime_nanos: self.deadline()?,
            replay_id_sha256,
        };
        self.generation_ambiguous.store(true, Ordering::Release);
        let response = self.generation_call(request.clone())?;
        let wire = Self::decode_artifact::<
            ProductionGenerationAbortResultWireV4,
        >(
            &response.result,
            ProductionArtifactKindV4::GenerationAbortSettlement,
        )?;
        wire.validate_for_request(&request)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let settlement = wire.durable_abort_settlement_sha256;
        self.prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .retain(|entry| entry.preparation != *preparation);
        self.generation_ambiguous.store(false, Ordering::Release);
        Ok(settlement)
    }

    fn artifact<T: Serialize>(
        kind: ProductionArtifactKindV4,
        value: &T,
    ) -> Result<CanonicalProductionArtifactV4, ShadowError> {
        CanonicalProductionArtifactV4::from_serializable(kind, value)
            .map_err(|_| ShadowError::CustodyUnavailable)
    }

    fn decode_artifact<T>(
        artifact: &CanonicalProductionArtifactV4,
        expected_kind: ProductionArtifactKindV4,
    ) -> Result<T, ShadowError>
    where
        T: for<'de> Deserialize<'de> + Serialize,
    {
        if artifact.kind != expected_kind {
            return Err(ShadowError::CustodyUnavailable);
        }
        let exact = artifact
            .exact_bytes()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let value: T = serde_json::from_slice(&exact)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if canonical_json_bytes(&value)? != exact {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(value)
    }

    fn reconstruct_dispatch_response(
        &self,
        operation: PolicyShadowCustodyOperation,
        context: DispatchResponseContext,
        result: ClosedProductionDispatchResultV4,
        expected_configuration_binding_sha256: &Sha256Digest,
    ) -> Result<ProductionCustodyDispatchResponse, ShadowError> {
        let configuration = self
            .active_configuration
            .read()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if configuration.production_configuration_binding_sha256() != expected_configuration_binding_sha256 {
            return Err(ShadowError::BindingDrift);
        }
        match (operation, context, result) {
            (
                PolicyShadowCustodyOperation::VerifyCheckpointSuccessor,
                DispatchResponseContext::None,
                ClosedProductionDispatchResultV4::Verified,
            ) => Ok(ProductionCustodyDispatchResponse::
                CheckpointSuccessorVerified),
            (
                PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead,
                DispatchResponseContext::None,
                ClosedProductionDispatchResultV4::Verified,
            ) => Ok(ProductionCustodyDispatchResponse::
                CurrentCheckpointHeadVerified),
            (
                PolicyShadowCustodyOperation::VerifyObservationEvidence,
                DispatchResponseContext::None,
                ClosedProductionDispatchResultV4::Verified,
            ) => Ok(ProductionCustodyDispatchResponse::
                ObservationEvidenceVerified),
            (
                PolicyShadowCustodyOperation::AbortGenerationPublication,
                DispatchResponseContext::AbortPublication(retained),
                ClosedProductionDispatchResultV4::Verified,
            ) => {
                self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.abort(&retained)?;
                Ok(ProductionCustodyDispatchResponse::GenerationPublicationAborted)
            }
            (
                PolicyShadowCustodyOperation::PrepareGenerationPublication,
                DispatchResponseContext::PreparePublication(context),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let prepared = Self::decode_artifact::<PreparedGenerationPublication>(
                    &artifact,
                    ProductionArtifactKindV4::PreparedGenerationPublication,
                )?;
                self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?
                    .accept_prepared(&context, &prepared)?;
                Ok(ProductionCustodyDispatchResponse::GenerationPublicationPrepared(prepared))
            }
            (
                PolicyShadowCustodyOperation::BeginIngress,
                DispatchResponseContext::BeginIngress { request_binding_sha256, published },
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<IngressCustodyAdmissionWire>(
                    &artifact, ProductionArtifactKindV4::IngressCustodyAdmission)?;
                if published.as_ref().is_some_and(|value|
                    value.context.configuration_binding_sha256 != *expected_configuration_binding_sha256)
                {
                    return Err(ShadowError::BindingDrift);
                }
                let verified = verify_production_ingress_custody_admission(
                    wire, published.as_ref().map(|value| value.context.successor.as_ref()),
                    published.as_ref().map(|value| value.prepared.sequence_bounds()),
                    &request_binding_sha256, &configuration, self.key_trust.as_ref(),
                    self.trusted_time.as_ref(), &self.persistence_verifier,
                )?;
                Ok(ProductionCustodyDispatchResponse::IngressBegun(verified))
            }
            (
                PolicyShadowCustodyOperation::AppendTerminal,
                DispatchResponseContext::AppendTerminal(request),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<TerminalSlotAppendOutcomeWire>(
                    &artifact, ProductionArtifactKindV4::TerminalSlotAppendOutcome)?;
                let verified = verify_production_terminal_slot_append_outcome(
                    wire, &request, &configuration, self.key_trust.as_ref(),
                    self.trusted_time.as_ref(), &self.persistence_verifier,
                )?;
                Ok(ProductionCustodyDispatchResponse::TerminalAppended(verified))
            }
            (
                PolicyShadowCustodyOperation::CommitRequest,
                DispatchResponseContext::None,
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => Ok(ProductionCustodyDispatchResponse::RequestCommitted(
                Self::decode_artifact::<RequestCommitment>(
                    &artifact,
                    ProductionArtifactKindV4::RequestCommitment,
                )?,
            )),
            (
                PolicyShadowCustodyOperation::AppendSpoolEvent,
                DispatchResponseContext::AppendSpool(event),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<
                    SignedShadowSpillReceipt,
                >(
                    &artifact,
                    ProductionArtifactKindV4::ShadowSpillReceipt,
                )?;
                let verified = verify_production_shadow_spill_receipt(
                    wire,
                    &event,
                    &configuration,
                    self.key_trust.as_ref(),
                    self.trusted_time.as_ref(),
                    &self.persistence_verifier,
                )?;
                Ok(ProductionCustodyDispatchResponse::
                    SpoolEventAppended(verified))
            }
            (
                PolicyShadowCustodyOperation::CompactSpool,
                DispatchResponseContext::CompactSpool(request),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<
                    AuthenticatedSpoolCompactionReceipt,
                >(
                    &artifact,
                    ProductionArtifactKindV4::SpoolCompactionReceipt,
                )?;
                let verified = verify_production_spool_compaction_receipt(
                    wire,
                    &request,
                    &configuration,
                    self.key_trust.as_ref(),
                    self.trusted_time.as_ref(),
                    &self.persistence_verifier,
                )?;
                Ok(ProductionCustodyDispatchResponse::
                    SpoolCompacted(verified))
            }
            (
                PolicyShadowCustodyOperation::CommitActiveEffect,
                DispatchResponseContext::ActiveEffectCommit {
                    permit,
                    terminal_state,
                    result_sha256,
                },
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<
                    ActiveEffectCommitReceiptWire,
                >(
                    &artifact,
                    ProductionArtifactKindV4::ActiveEffectCommitReceipt,
                )?;
                let verified = verify_production_active_effect_commit(
                    wire,
                    &permit,
                    terminal_state,
                    &result_sha256,
                    &configuration,
                    self.key_trust.as_ref(),
                    self.trusted_time.as_ref(),
                    &self.persistence_verifier,
                )?;
                Ok(ProductionCustodyDispatchResponse::
                    ActiveEffectCommitted(verified))
            }
            (
                PolicyShadowCustodyOperation::ReconcileActiveEffect,
                DispatchResponseContext::ReconcileActiveEffect(
                    effect_id_sha256,
                ),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<
                    ActiveEffectCommitReceiptWire,
                >(
                    &artifact,
                    ProductionArtifactKindV4::ActiveEffectCommitReceipt,
                )?;
                let verified =
                    verify_production_reconciled_active_effect_commit(
                        wire,
                        &effect_id_sha256,
                        &configuration,
                        self.key_trust.as_ref(),
                        self.trusted_time.as_ref(),
                        &self.persistence_verifier,
                    )?;
                Ok(ProductionCustodyDispatchResponse::
                    ActiveEffectReconciled(verified))
            }
            (
                PolicyShadowCustodyOperation::ConsumeAndPublishActivation,
                DispatchResponseContext::PublishActivation(transaction),
                ClosedProductionDispatchResultV4::Artifact(artifact),
            ) => {
                let wire = Self::decode_artifact::<
                    ActivationPublicationReceiptWire,
                >(
                    &artifact,
                    ProductionArtifactKindV4::ActivationPublicationReceipt,
                )?;
                let verified =
                    verify_production_activation_publication_receipt(
                        wire,
                        &transaction,
                        &configuration,
                        self.key_trust.as_ref(),
                        self.trusted_time.as_ref(),
                        &self.persistence_verifier,
                    )?;
                Ok(ProductionCustodyDispatchResponse::
                    ActivationConsumedAndPublished(verified))
            }
            (
                PolicyShadowCustodyOperation::RecoverCurrentState,
                DispatchResponseContext::RecoverPublication(revision),
                ClosedProductionDispatchResultV4::SealedArtifact {
                    reference,
                    exact_signed_artifact,
                },
            ) => {
                let wire = Self::decode_artifact::<
                    PublicationReconciliationReceiptWire,
                >(
                    &exact_signed_artifact.artifact,
                    ProductionArtifactKindV4::
                        PublicationReconciliationReceipt,
                )?;
                let verified =
                    verify_production_publication_reconciliation_receipt(
                        wire,
                        &configuration,
                        self.key_trust.as_ref(),
                        self.trusted_time.as_ref(),
                        &self.persistence_verifier,
                    )?;
                let mut state = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?;
                let mut next = state.clone();
                next.recover(revision, &verified)?;
                self.retain_sealed_reference(reference, &verified)?;
                *state = next;
                Ok(ProductionCustodyDispatchResponse::CurrentStateRecovered(verified))
            }
            (
                PolicyShadowCustodyOperation::CommitGenerationPublication,
                DispatchResponseContext::CommitPublication(retained),
                ClosedProductionDispatchResultV4::SealedArtifact { reference, exact_signed_artifact },
            ) => {
                let wire = Self::decode_artifact::<PublicationReconciliationReceiptWire>(
                    &exact_signed_artifact.artifact, ProductionArtifactKindV4::PublicationReconciliationReceipt)?;
                let verified = verify_production_publication_reconciliation_receipt(
                    wire, &configuration, self.key_trust.as_ref(), self.trusted_time.as_ref(), &self.persistence_verifier)?;
                let mut state = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?;
                let mut next = state.clone();
                next.commit(&retained, &verified)?;
                self.retain_sealed_reference(reference, &verified)?;
                *state = next;
                Ok(ProductionCustodyDispatchResponse::GenerationPublicationCommitted(verified))
            }
            (
                PolicyShadowCustodyOperation::ReserveSpoolAppend,
                DispatchResponseContext::ReserveSpool(event),
                ClosedProductionDispatchResultV4::SealedArtifact {
                    reference,
                    exact_signed_artifact,
                },
            ) => {
                let artifact=&exact_signed_artifact.artifact;
                let value=Self::decode_artifact::<serde_json::Value>(artifact,
                    ProductionArtifactKindV4::SpoolAppendReservationOutcome)?;
                let wire=if value.get("apiVersion").is_some() {
                    if !configuration.retains_native_closure_owner(){return Err(ShadowError::CustodyUnavailable);}
                    let original=Self::decode_artifact::<super::super::NativeSpoolReservationOutcomeWire>(
                        artifact,ProductionArtifactKindV4::SpoolAppendReservationOutcome)?;
                    if original.api_version!="serverware.nativeSpoolReservationOutcome/v1" {
                        return Err(ShadowError::CustodyUnavailable);
                    }
                    match original.result {
                        super::super::NativeSpoolReservationResultWire::Reserved(value)=>value,
                        super::super::NativeSpoolReservationResultWire::Unavailable(value)=>{
                            let verified=verify_production_shadow_spill_receipt(value,&event,&configuration,
                                self.key_trust.as_ref(),self.trusted_time.as_ref(),&self.persistence_verifier)?;
                            if verified.disposition()!=super::super::ShadowSpoolDisposition::Unavailable {
                                return Err(ShadowError::CustodyUnavailable);
                            }
                            // A definite, durably verified refusal is not a
                            // reservation and never creates an append capability.
                            return Ok(ProductionCustodyDispatchResponse::SpoolAppendReserved(
                                super::super::SpoolAppendReservationOutcome::Unavailable(verified)));
                        },
                    }
                }else{Self::decode_artifact::<SpoolAppendReservationReceiptWire>(artifact,
                    ProductionArtifactKindV4::SpoolAppendReservationOutcome)?};
                let verified =
                    verify_production_spool_append_reservation_receipt(
                        wire,
                        &event,
                        &configuration,
                        self.key_trust.as_ref(),
                        self.trusted_time.as_ref(),
                        &self.persistence_verifier,
                    )?;
                self.retain_sealed_reference(reference, &verified)?;
                Ok(ProductionCustodyDispatchResponse::SpoolAppendReserved(
                    super::super::SpoolAppendReservationOutcome::Reserved(
                        verified,
                    ),
                ))
            }
            (
                PolicyShadowCustodyOperation::AppendActiveEffectBarrier,
                DispatchResponseContext::ActiveEffectBarrier(preparation),
                ClosedProductionDispatchResultV4::SealedArtifact {
                    reference,
                    exact_signed_artifact,
                },
            ) => {
                let wire = Self::decode_artifact::<
                    ActiveEffectBarrierReceiptWire,
                >(
                    &exact_signed_artifact.artifact,
                    ProductionArtifactKindV4::ActiveEffectPermit,
                )?;
                let verified = verify_production_active_effect_barrier(
                    wire,
                    &preparation,
                    &configuration,
                    self.key_trust.as_ref(),
                    self.trusted_time.as_ref(),
                    &self.persistence_verifier,
                )?;
                self.retain_sealed_reference(reference, &verified)?;
                Ok(ProductionCustodyDispatchResponse::
                    ActiveEffectBarrierAppended(verified))
            }
            _ => Err(ShadowError::CustodyUnavailable),
        }
    }

    fn protocol_operation(
        operation: PolicyShadowCustodyOperation,
    ) -> PolicyCustodyOperation {
        match operation {
            PolicyShadowCustodyOperation::RecoverCurrentState => {
                PolicyCustodyOperation::RecoverCurrentState
            }
            PolicyShadowCustodyOperation::VerifyCheckpointSuccessor => {
                PolicyCustodyOperation::VerifyCheckpointSuccessor
            }
            PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead => {
                PolicyCustodyOperation::VerifyCurrentCheckpointHead
            }
            PolicyShadowCustodyOperation::VerifyObservationEvidence => {
                PolicyCustodyOperation::VerifyObservationEvidence
            }
            PolicyShadowCustodyOperation::PrepareGenerationPublication => {
                PolicyCustodyOperation::PrepareGenerationPublication
            }
            PolicyShadowCustodyOperation::CommitGenerationPublication => {
                PolicyCustodyOperation::CommitGenerationPublication
            }
            PolicyShadowCustodyOperation::AbortGenerationPublication => {
                PolicyCustodyOperation::AbortGenerationPublication
            }
            PolicyShadowCustodyOperation::BeginIngress => {
                PolicyCustodyOperation::BeginIngress
            }
            PolicyShadowCustodyOperation::ReserveSpoolAppend => {
                PolicyCustodyOperation::ReserveSpoolAppend
            }
            PolicyShadowCustodyOperation::AppendSpoolEvent => {
                PolicyCustodyOperation::AppendSpoolEvent
            }
            PolicyShadowCustodyOperation::CompactSpool => {
                PolicyCustodyOperation::CompactSpool
            }
            PolicyShadowCustodyOperation::CommitRequest => {
                PolicyCustodyOperation::CommitRequest
            }
            PolicyShadowCustodyOperation::AppendActiveEffectBarrier => {
                PolicyCustodyOperation::AppendActiveEffectBarrier
            }
            PolicyShadowCustodyOperation::CommitActiveEffect => {
                PolicyCustodyOperation::CommitActiveEffect
            }
            PolicyShadowCustodyOperation::ReconcileActiveEffect => {
                PolicyCustodyOperation::ReconcileActiveEffect
            }
            PolicyShadowCustodyOperation::AppendTerminal => {
                PolicyCustodyOperation::AppendTerminal
            }
            PolicyShadowCustodyOperation::ConsumeAndPublishActivation => {
                PolicyCustodyOperation::ConsumeAndPublishActivation
            }
        }
    }

    fn consume_sealed_reference<T: Serialize>(
        &self,
        kind: ProductionArtifactKindV4,
        capability: &T,
    ) -> Result<SealedProductionArtifactReferenceV4, ShadowError> {
        let identity = Sha256Digest::compute(
            &canonical_json_bytes(capability)?,
        );
        let reference = self
            .sealed_references
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .remove(identity.as_str())
            .ok_or(ShadowError::CustodyUnavailable)?;
        if reference.kind != kind {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(reference)
    }

    fn retain_sealed_reference<T: Serialize>(
        &self,
        reference: SealedProductionArtifactReferenceV4,
        capability: &T,
    ) -> Result<(), ShadowError> {
        let identity = Sha256Digest::compute(
            &canonical_json_bytes(capability)?,
        );
        let mut references = self
            .sealed_references
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if references.len()
                >= usize::from(self.process_config.maximum_in_flight_calls)
            || references.contains_key(identity.as_str())
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        references.insert(identity.as_str().to_owned(), reference);
        Ok(())
    }

    fn dispatch_binding(
        &self,
        permit: &ProductionCustodyMutationPermit,
    ) -> Result<ProductionDispatchBindingV4, ShadowError> {
        let configuration = self
            .active_configuration
            .read()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let deadline = permit.operation_deadline();
        ProductionDispatchBindingV4::from_verified_parent_permit(
            Self::protocol_operation(permit.operation()),
            permit.operation_id_sha256().clone(),
            permit.request_sha256().clone(),
            permit.durable_request_sha256().clone(),
            permit.termination_fence_sha256().clone(),
            configuration
                .production_configuration_binding_sha256()
                .clone(),
            self.process_config
                .kernel_driver_identity
                .identity_sha256()
                .clone(),
            self.process_config
                .kernel_driver_identity
                .retained_descriptor_manifest_sha256
                .clone(),
            self.process_config
                .driver_generation_receipt_sha256
                .clone(),
            deadline.opened_at_boottime_nanos(),
            deadline.operation_deadline_boottime_nanos(),
            deadline.cleanup_deadline_boottime_nanos(),
        )
        .map_err(|_| ShadowError::CustodyUnavailable)
    }

    fn settle_operation(
        &self,
        permit: &ProductionCustodyMutationPermit,
        result_disposition: ProductionCustodyResultDisposition,
    ) -> Result<ProductionCustodyTerminalCleanupAttestation, ShadowError> {
        permit.authorize_cleanup(
            permit.operation(),
            permit.operation_id_sha256(),
        )?;
        let cleanup_deadline_boottime_nanos = permit
            .operation_deadline()
            .cleanup_deadline_boottime_nanos();
        let replay_id_sha256 = hash_domain_frames(
            b"serverware.policyCustodyProductionSettlementReplay/v4",
            &[&canonical_json_bytes(&(
                permit.operation_id_sha256(),
                permit.termination_fence_sha256(),
                result_disposition,
                cleanup_deadline_boottime_nanos,
            ))?],
        );
        let response = self.call_body(
            ProductionRpcRequestBodyV4::Settle {
                operation_id_sha256:
                    permit.operation_id_sha256().clone(),
                termination_fence_sha256:
                    permit.termination_fence_sha256().clone(),
                result_disposition,
                cleanup_deadline_boottime_nanos,
            },
            replay_id_sha256,
            cleanup_deadline_boottime_nanos,
        )?;
        let artifact = match response {
            ProductionRpcResponseBodyV4::Settlement(artifact) => artifact,
            _ => return Err(ShadowError::CustodyUnavailable),
        };
        let wire = Self::decode_artifact::<
            ProductionTerminalCleanupResultWireV4,
        >(
            &artifact,
            ProductionArtifactKindV4::TerminalCleanupAttestation,
        )?;
        let termination = wire.process_termination;
        if wire.api_version
                != "serverware.policyCustodyProductionTerminalCleanupResult/v4"
            || termination.operation_id_sha256
                != *permit.operation_id_sha256()
            || termination.termination_fence_sha256
                != *permit.termination_fence_sha256()
            || termination.worker_executable_sha256
                != self.process_config.worker_executable_sha256
            || termination.kernel_driver_identity_sha256
                != *self
                    .process_config
                    .kernel_driver_identity
                    .identity_sha256()
            || termination.kernel_retained_descriptor_set_sha256
                != self
                    .process_config
                    .kernel_driver_identity
                    .retained_descriptor_manifest_sha256
            || termination.driver_generation_receipt_sha256
                != self.process_config.driver_generation_receipt_sha256
            || wire.exact_signed_settlement_envelope_bytes.is_empty()
            || wire.exact_signed_settlement_envelope_bytes.len()
                > MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES
            || Sha256Digest::compute(
                &wire.exact_signed_settlement_envelope_bytes,
            ) != wire.exact_signed_settlement_envelope_sha256
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let process_termination =
            ProductionCustodyTerminationProof::from_process_supervisor(
                termination.operation_id_sha256,
                termination.termination_fence_sha256,
                termination.worker_executable_sha256,
                termination.kernel_driver_identity_sha256,
                termination.kernel_retained_descriptor_set_sha256,
                termination.driver_generation_receipt_sha256,
                termination.worker_terminated_at_unix_nanos,
                termination.worker_terminated_at_boottime_nanos,
                termination.process_reaped,
                termination.late_mutation_fence_closed,
            )?;
        let signed_settlement: SignedEnvelope<
            ProductionCustodyTerminalCleanupReceiptPayload,
        > = serde_json::from_slice(
            &wire.exact_signed_settlement_envelope_bytes,
        )
        .map_err(|_| ShadowError::CustodyUnavailable)?;
        if canonical_json_bytes(&signed_settlement)?
            != wire.exact_signed_settlement_envelope_bytes
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(ProductionCustodyTerminalCleanupAttestation::
            from_external_settlement(
                process_termination,
                signed_settlement,
            ))
    }

    fn dispatch_operation(
        &self,
        permit: &ProductionCustodyMutationPermit,
        request: ProductionCustodyDispatchRequest,
    ) -> Result<ProductionCustodyDispatchResponse, ShadowError> {
        let parent_operation = request.operation();
        permit.authorize(
            parent_operation,
            permit.operation_id_sha256(),
        )?;
        let binding = self.dispatch_binding(permit)?;
        let expected_configuration_binding_sha256 = binding.production_configuration_binding_sha256.clone();
        // Keep local publication capture/reservation in the same configuration
        // epoch as the request. Reconfiguration must not clear this state and
        // then let a stale request repopulate its pending slot.
        let configuration_guard = self.active_configuration.read()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if configuration_guard.production_configuration_binding_sha256()
            != &expected_configuration_binding_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        let mut response_context = DispatchResponseContext::None;
        let closed = match request {
            ProductionCustodyDispatchRequest::RecoverCurrentState => {
                response_context = DispatchResponseContext::RecoverPublication(
                    self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.revision);
                ClosedProductionDispatchRequestV4::RecoverCurrentState {
                    binding,
                }
            }
            ProductionCustodyDispatchRequest::VerifyCheckpointSuccessor {
                generation,
                checkpoint_sequence,
                previous_checkpoint_sha256,
                checkpoint_payload_sha256,
            } => ClosedProductionDispatchRequestV4::VerifyCheckpointSuccessor {
                binding,
                generation: Self::artifact(
                    ProductionArtifactKindV4::ShadowGenerationIdentity,
                    &generation,
                )?,
                checkpoint_sequence,
                previous_checkpoint_sha256,
                checkpoint_payload_sha256,
            },
            ProductionCustodyDispatchRequest::VerifyCurrentCheckpointHead {
                generation,
                checkpoint_sequence,
                checkpoint_sha256,
            } => ClosedProductionDispatchRequestV4::VerifyCurrentCheckpointHead {
                binding,
                generation: Self::artifact(
                    ProductionArtifactKindV4::ShadowGenerationIdentity,
                    &generation,
                )?,
                checkpoint_sequence,
                checkpoint_sha256,
            },
            ProductionCustodyDispatchRequest::VerifyObservationEvidence {
                evidence,
                ingress,
                active_decision,
            } => ClosedProductionDispatchRequestV4::VerifyObservationEvidence {
                binding,
                evidence_tuple: Self::artifact(
                    ProductionArtifactKindV4::ObservationEvidenceTuple,
                    &(evidence, ingress, active_decision),
                )?,
            },
            ProductionCustodyDispatchRequest::PrepareGenerationPublication {
                recovered,
                previous,
                successor,
            } => {
                let recovering_same = recovered.published_generation_sha256()
                    .or_else(|| recovered.committed_generation_sha256()) == Some(successor.generation_id());
                let context = IngressPublicationPreparation {
                    configuration_binding_sha256: expected_configuration_binding_sha256.clone(),
                    request_sha256: binding.request_sha256.clone(),
                    successor: Arc::new(successor.clone()),
                    predecessor: if recovering_same {
                        recovered.predecessor_generation_sha256().cloned()
                    } else {
                        previous.as_ref().map(|value| value.generation_id().clone())
                    },
                    expected_publication_revision: if recovering_same { recovered.publication_revision() }
                        else { recovered.publication_revision().checked_add(1).ok_or(ShadowError::CounterOverflow)? },
                };
                let previous_artifact = previous
                    .as_ref()
                    .map(|value| {
                        Self::artifact(
                            ProductionArtifactKindV4::ShadowGenerationIdentity,
                            value,
                        )
                    })
                    .transpose()?;
                let successor_artifact = Self::artifact(
                    ProductionArtifactKindV4::ShadowGenerationIdentity,
                    &successor,
                )?;
                let mut state = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?;
                let mut next = state.clone();
                next.reserve(&context)?;
                let recovered_reference = self.consume_sealed_reference(
                    ProductionArtifactKindV4::PublicationReconciliationReceipt, &recovered)?;
                *state = next;
                drop(state);
                response_context = DispatchResponseContext::PreparePublication(context);
                ClosedProductionDispatchRequestV4::PrepareGenerationPublication {
                    binding, recovered: recovered_reference, previous: previous_artifact, successor: successor_artifact,
                }
            }
            ProductionCustodyDispatchRequest::CommitGenerationPublication {
                prepared,
            } => {
                let retained = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.retained(&prepared)?;
                if retained.context.configuration_binding_sha256 != expected_configuration_binding_sha256 {
                    return Err(ShadowError::BindingDrift);
                }
                response_context = DispatchResponseContext::CommitPublication(retained);
                ClosedProductionDispatchRequestV4::CommitGenerationPublication { binding, prepared: Self::artifact(
                    ProductionArtifactKindV4::PreparedGenerationPublication,
                    &prepared,
                )? }
            }
            ProductionCustodyDispatchRequest::AbortGenerationPublication {
                prepared,
            } => {
                let retained = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.retained(&prepared)?;
                if retained.context.configuration_binding_sha256 != expected_configuration_binding_sha256 {
                    return Err(ShadowError::BindingDrift);
                }
                response_context = DispatchResponseContext::AbortPublication(retained);
                ClosedProductionDispatchRequestV4::AbortGenerationPublication { binding, prepared: Self::artifact(
                    ProductionArtifactKindV4::PreparedGenerationPublication,
                    &prepared,
                )? }
            }
            ProductionCustodyDispatchRequest::BeginIngress {
                request_binding_sha256,
            } => {
                let published = self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.published.clone();
                if published.as_ref().is_some_and(|value|
                    value.context.configuration_binding_sha256 != expected_configuration_binding_sha256)
                {
                    return Err(ShadowError::BindingDrift);
                }
                response_context = DispatchResponseContext::BeginIngress {
                    request_binding_sha256: request_binding_sha256.clone(), published,
                };
                ClosedProductionDispatchRequestV4::BeginIngress { binding, request_binding_sha256 }
            }
            ProductionCustodyDispatchRequest::ReserveSpoolAppend { event } => {
                let event_artifact = Self::artifact(
                    ProductionArtifactKindV4::ShadowSpoolEvent,
                    &event,
                )?;
                response_context =
                    DispatchResponseContext::ReserveSpool(event);
                ClosedProductionDispatchRequestV4::ReserveSpoolAppend {
                    binding,
                    event: event_artifact,
                }
            }
            ProductionCustodyDispatchRequest::AppendSpoolEvent {
                reservation,
                event,
            } => {
                let reservation = self.consume_sealed_reference(
                    ProductionArtifactKindV4::SpoolAppendReservationOutcome,
                    &reservation,
                )?;
                let event_artifact = Self::artifact(
                    ProductionArtifactKindV4::ShadowSpoolEvent,
                    &event,
                )?;
                response_context =
                    DispatchResponseContext::AppendSpool(event);
                ClosedProductionDispatchRequestV4::AppendSpoolEvent {
                    binding,
                    reservation,
                    event: event_artifact,
                }
            }
            ProductionCustodyDispatchRequest::CompactSpool { request } => {
                let request_artifact = Self::artifact(
                    ProductionArtifactKindV4::
                        AuthenticatedSpoolCompactionRequest,
                    &request,
                )?;
                response_context =
                    DispatchResponseContext::CompactSpool(request);
                ClosedProductionDispatchRequestV4::CompactSpool {
                    binding,
                    request: request_artifact,
                }
            }
            ProductionCustodyDispatchRequest::CommitRequest {
                facts,
                context,
            } => ClosedProductionDispatchRequestV4::CommitRequest {
                binding,
                facts: Self::artifact(
                    ProductionArtifactKindV4::ProtectedRequestFacts,
                    &facts,
                )?,
                context: Self::artifact(
                    ProductionArtifactKindV4::RequestCommitmentContext,
                    &context,
                )?,
            },
            ProductionCustodyDispatchRequest::AppendActiveEffectBarrier {
                preparation,
            } => {
                let preparation_artifact = Self::artifact(
                    ProductionArtifactKindV4::ActiveEffectPreparation,
                    &preparation,
                )?;
                response_context =
                    DispatchResponseContext::ActiveEffectBarrier(
                        preparation,
                    );
                ClosedProductionDispatchRequestV4::
                    AppendActiveEffectBarrier {
                        binding,
                        preparation: preparation_artifact,
                    }
            }
            ProductionCustodyDispatchRequest::CommitActiveEffect {
                effect_permit,
                terminal_state,
                result_sha256,
            } => {
                let sealed_permit = self.consume_sealed_reference(
                    ProductionArtifactKindV4::ActiveEffectPermit,
                    &effect_permit,
                )?;
                let terminal_state_artifact = Self::artifact(
                    ProductionArtifactKindV4::ActiveEffectCommitState,
                    &terminal_state,
                )?;
                response_context =
                    DispatchResponseContext::ActiveEffectCommit {
                        permit: effect_permit,
                        terminal_state,
                        result_sha256: result_sha256.clone(),
                    };
                ClosedProductionDispatchRequestV4::CommitActiveEffect {
                    binding,
                    effect_permit: sealed_permit,
                    terminal_state: terminal_state_artifact,
                    result_sha256,
                }
            }
            ProductionCustodyDispatchRequest::ReconcileActiveEffect {
                generation_id,
                ingress_sequence,
                effect_id_sha256,
            } => {
                response_context =
                    DispatchResponseContext::ReconcileActiveEffect(
                        effect_id_sha256.clone(),
                    );
                ClosedProductionDispatchRequestV4::ReconcileActiveEffect {
                    binding,
                    generation_id,
                    ingress_sequence,
                    effect_id_sha256,
                }
            }
            ProductionCustodyDispatchRequest::AppendTerminal { request } => {
                let request_artifact = Self::artifact(
                    ProductionArtifactKindV4::TerminalSlotAppendRequest,
                    &request,
                )?;
                response_context =
                    DispatchResponseContext::AppendTerminal(request);
                ClosedProductionDispatchRequestV4::AppendTerminal {
                    binding,
                    request: request_artifact,
                }
            }
            ProductionCustodyDispatchRequest::ConsumeAndPublishActivation {
                transaction,
            } => {
                let transaction_artifact = Self::artifact(
                    ProductionArtifactKindV4::ActivationPublicationTransaction,
                    &transaction,
                )?;
                response_context =
                    DispatchResponseContext::PublishActivation(
                        transaction,
                    );
                ClosedProductionDispatchRequestV4::
                    ConsumeAndPublishActivation {
                        binding,
                        transaction: transaction_artifact,
                    }
            }
        };
        closed
            .validate()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let replay = closed.binding().replay_id_sha256.clone();
        let deadline = closed
            .binding()
            .operation_deadline_boottime_nanos;
        drop(configuration_guard);
        let (response,native_computation) = match self.call_body(
            ProductionRpcRequestBodyV4::Dispatch(closed.clone()),
            replay,
            deadline,
        )? {
            ProductionRpcResponseBodyV4::Dispatch(response) => (response,None),
            ProductionRpcResponseBodyV4::NativeCommitRequest{dispatch,computation}
                if parent_operation==PolicyShadowCustodyOperation::CommitRequest => (dispatch,Some(computation)),
            _ => return Err(ShadowError::CustodyUnavailable),
        };
        if response.api_version != PRODUCTION_DISPATCH_PROTOCOL_VERSION
            || response.operation != closed.operation()
            || response.operation_id_sha256
                != closed.binding().operation_id_sha256
            || response.request_sha256
                != closed.binding().request_sha256
            || response.replay_id_sha256
                != closed.binding().replay_id_sha256
            || Sha256Digest::compute(
                &canonical_json_bytes(&response.result)?,
            ) != response.result_sha256
            || response.service_transitions.is_empty()
            || response.service_transitions.len() > 5
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let native_original=if let Some(original)=native_computation {
            let configuration=self.active_configuration.read().map_err(|_|ShadowError::CustodyUnavailable)?;
            super::native_request_commitment::verify_computation(&original,&closed,&response,
                &configuration,self.key_trust.as_ref(),self.trusted_time.as_ref())?;
            Some(original)
        }else{None};
        let result=self.reconstruct_dispatch_response(
            parent_operation,
            response_context,
            response.result,
            &expected_configuration_binding_sha256,
        )?;
        match result {
            ProductionCustodyDispatchResponse::RequestCommitted(mut commitment)=>{
                commitment.native_computation=native_original;
                Ok(ProductionCustodyDispatchResponse::RequestCommitted(commitment))
            },
            other if native_original.is_none()=>Ok(other),
            _=>Err(ShadowError::CustodyUnavailable),
        }
    }
}

impl ProductionPolicyShadowCustodyProcess
    for RpcProductionPolicyShadowCustodyProcess
{
    fn dispatch_manifest(
        &self,
    ) -> Result<ProductionCustodyDispatchManifest, ShadowError> {
        Ok(self.manifest.clone())
    }

    fn recover_generation_configuration(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        _key_trust: &dyn EnvelopeKeyTrust,
        _trusted_time: &dyn TrustedTime,
    ) -> Result<
        Option<(
            ProductionCustodyGenerationTransitionPreparation,
            ProductionCustodyGenerationInstallAttestation,
        )>,
        ShadowError,
    > {
        self.recover_generation(previous, successor)
    }

    fn prepare_generation_configuration(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        _key_trust: &dyn EnvelopeKeyTrust,
        _trusted_time: &dyn TrustedTime,
    ) -> Result<
        ProductionCustodyGenerationTransitionPreparation,
        ShadowError,
    > {
        self.prepare_generation(previous, successor)
    }

    fn commit_generation_configuration(
        &self,
        preparation: &ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<
        ProductionCustodyGenerationInstallAttestation,
        ShadowError,
    > {
        self.commit_generation(preparation)
    }

    fn abort_generation_configuration(
        &self,
        preparation: ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<Sha256Digest, ShadowError> {
        self.abort_generation(&preparation)
    }

    fn validate_production_configuration(
        &self,
        configuration: &ProductionCustodyConfiguration,
    ) -> Result<(), ShadowError> {
        self.process_config.validate(self.key_trust.as_ref(),self.trusted_time.as_ref())?;
        let mut prepared = self
            .prepared_generations
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        let committed = prepared.iter().position(|entry| {
            entry.remote_committed_or_recovered
                && entry.successor == *configuration
        });
        if let Some(index) = committed {
            let mut active = self
                .active_configuration
                .write()
                .map_err(|_| ShadowError::CustodyUnavailable)?;
            self.ingress_publication.lock().map_err(|_| ShadowError::CustodyUnavailable)?.invalidate()?;
            *active = configuration.clone();
            prepared.remove(index);
            self.generation_ambiguous
                .store(false, Ordering::Release);
            return Ok(());
        }
        if !self.generation_ambiguous.load(Ordering::Acquire)
            && self
                .active_configuration
                .read()
                .map_err(|_| ShadowError::CustodyUnavailable)?
                .eq(configuration)
        {
            return Ok(());
        }
        Err(ShadowError::BindingDrift)
    }

    fn persistence_proof_verifier(
        &self,
    ) -> &dyn PolicyShadowPersistenceProofVerifier {
        &self.persistence_verifier
    }

    fn request_worker_termination(
        &self,
        operation_id_sha256: &Sha256Digest,
        termination_fence_sha256: &Sha256Digest,
    ) {
        let Ok(deadline) = self.deadline() else {
            return;
        };
        let Ok(replay_material) = canonical_json_bytes(&(
            operation_id_sha256,
            termination_fence_sha256,
            "request-termination",
        )) else {
            return;
        };
        let replay = Sha256Digest::compute(&replay_material);
        let _ = self.call_body(
            ProductionRpcRequestBodyV4::RequestTermination {
                operation_id_sha256: operation_id_sha256.clone(),
                termination_fence_sha256:
                    termination_fence_sha256.clone(),
            },
            replay,
            deadline,
        );
    }

    fn terminate_reap_fence_and_settle(
        &self,
        permit: &ProductionCustodyMutationPermit,
        result_disposition: ProductionCustodyResultDisposition,
    ) -> Result<ProductionCustodyTerminalCleanupAttestation, ShadowError> {
        self.settle_operation(permit, result_disposition)
    }

    fn dispatch(
        &self,
        permit: &ProductionCustodyMutationPermit,
        request: ProductionCustodyDispatchRequest,
    ) -> Result<ProductionCustodyDispatchResponse, ShadowError> {
        self.dispatch_operation(permit, request)
    }
}

impl RpcPersistenceVerifier {
    fn deadline(&self) -> Result<u64, ShadowError> {
        super::boottime::boottime_now_nanos()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .checked_add(self.maximum_rpc_nanos)
            .ok_or(ShadowError::CounterOverflow)
    }

    fn require_verified(
        &self,
        request: ProductionRpcRequestBodyV4,
    ) -> Result<(), ShadowError> {
        if self.generation_ambiguous.load(Ordering::Acquire) {
            return Err(ShadowError::CustodyUnavailable);
        }
        let deadline = self.deadline()?;
        let replay = Sha256Digest::compute(&canonical_json_bytes(&request)?);
        let envelope = exact_rpc_request(request, replay, deadline)?;
        match self.rpc.call(&envelope)?.response {
            ProductionRpcResponseBodyV4::Verified => Ok(()),
            _ => Err(ShadowError::CustodyUnavailable),
        }
    }
}

impl PolicyShadowPersistenceProofVerifier for RpcPersistenceVerifier {
    fn verify_persistence_receipt(
        &self,
        role: PolicyShadowCustodySignerRole,
        persistence_receipt_sha256: &Sha256Digest,
        canonical_payload: &[u8],
    ) -> Result<(), ShadowError> {
        self.require_verified(
            ProductionRpcRequestBodyV4::VerifyPersistence {
                signer_role: role,
                persistence_receipt_sha256:
                    persistence_receipt_sha256.clone(),
                canonical_payload: canonical_payload.to_vec(),
            },
        )
    }

    fn verify_immutable_retrieval(
        &self,
        role: PolicyShadowCustodySignerRole,
        retrieval_id_sha256: &Sha256Digest,
        retrieval_proof_sha256: &Sha256Digest,
        canonical_payload: &[u8],
    ) -> Result<(), ShadowError> {
        self.require_verified(ProductionRpcRequestBodyV4::VerifyRetrieval {
            signer_role: role,
            retrieval_id_sha256: retrieval_id_sha256.clone(),
            retrieval_proof_sha256: retrieval_proof_sha256.clone(),
            canonical_payload: canonical_payload.to_vec(),
        })
    }

    fn verify_assignment_bound_persistence_receipt(
        &self,
        scope: &ProductionCustodyProofScope,
        role: PolicyShadowCustodySignerRole,
        persistence_receipt_sha256: &Sha256Digest,
        canonical_receipt_payload: &[u8],
        signed_authority_payload: &[u8],
    ) -> Result<(), ShadowError> {
        self.require_verified(
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence {
                proof_scope_canonical_bytes:
                    canonical_json_bytes(scope)?,
                signer_role: role,
                persistence_receipt_sha256:
                    persistence_receipt_sha256.clone(),
                canonical_receipt_payload:
                    canonical_receipt_payload.to_vec(),
                signed_authority_payload:
                    signed_authority_payload.to_vec(),
            },
        )
    }

    fn verify_assignment_bound_immutable_retrieval(
        &self,
        scope: &ProductionCustodyProofScope,
        role: PolicyShadowCustodySignerRole,
        retrieval_id_sha256: &Sha256Digest,
        retrieval_proof_sha256: &Sha256Digest,
        canonical_receipt_payload: &[u8],
        signed_authority_payload: &[u8],
    ) -> Result<(), ShadowError> {
        self.require_verified(
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval {
                proof_scope_canonical_bytes:
                    canonical_json_bytes(scope)?,
                signer_role: role,
                retrieval_id_sha256: retrieval_id_sha256.clone(),
                retrieval_proof_sha256:
                    retrieval_proof_sha256.clone(),
                canonical_receipt_payload:
                    canonical_receipt_payload.to_vec(),
                signed_authority_payload:
                    signed_authority_payload.to_vec(),
            },
        )
    }
}

#[derive(Debug)]
pub(crate) enum CustodyProcessError {
    Unready(&'static str),
    Invalid(String),
}

impl fmt::Display for CustodyProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unready(message) => formatter.write_str(message),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CustodyProcessError {}

pub(crate) struct PolicyShadowCustodyProcessClient {
    endpoint_trust: TrustedHostNoTeeEndpointTrustProvider,
    watchdog_poller: LinuxBoottimeWatchdogPoller,
    heartbeat: LinuxHeartbeatEvent,
    heartbeat_capability: OwnedFd,
    deployment_report: TrustedHostNoTeeReport,
}

impl fmt::Debug for PolicyShadowCustodyProcessClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyShadowCustodyProcessClient")
            .field(
                "attestation_mode",
                &self
                    .endpoint_trust
                    .trust_report()
                    .attestation_mode(),
            )
            .field(
                "authority_scope",
                &self
                    .endpoint_trust
                    .trust_report()
                    .authority_scope(),
            )
            .field(
                "hardware_proof",
                &self
                    .endpoint_trust
                    .trust_report()
                    .hardware_proof(),
            )
            .finish_non_exhaustive()
    }
}

impl PolicyShadowCustodyProcessClient {
    fn from_systemd_environment(
    ) -> Result<Self, CustodyProcessError> {
        let startup_deadline = startup_deadline_from_environment()?;
        let credential_name = env::var(
            serverware_decision_gate::
                POLICY_SHADOW_CUSTODY_ENDPOINT_CONFIG_CREDENTIAL_ENV,
        )
        .unwrap_or_else(|_| {
            serverware_decision_gate::
                POLICY_SHADOW_CUSTODY_DEFAULT_ENDPOINT_CONFIG_CREDENTIAL
                .to_owned()
        });
        let mut endpoint_trust =
            TrustedHostNoTeeEndpointTrustProvider::
                from_systemd_credentials(
                    &credential_name,
                    startup_deadline,
                )
                .map_err(|error| {
                    CustodyProcessError::Invalid(format!(
                        "trusted-host endpoint bootstrap failed: {error}"
                    ))
                })?;

        for role in [
            PolicyCustodyEndpointRole::SignerHsm,
            PolicyCustodyEndpointRole::SettlementStore,
            PolicyCustodyEndpointRole::FenceAuthority,
            PolicyCustodyEndpointRole::CleanupWatchdog,
            PolicyCustodyEndpointRole::CgroupExecutor,
            PolicyCustodyEndpointRole::TerminationLedger,
        ] {
            endpoint_trust
                .signed_endpoint_client_until(role, startup_deadline)
                .map_err(|error| {
                    CustodyProcessError::Invalid(format!(
                        "trusted-host endpoint role {role:?} is not current: {error}"
                    ))
                })?;
        }

        let endpoint_report = endpoint_trust.trust_report();
        if endpoint_report.attestation_mode()
                != "trusted-host-no-tee"
            || endpoint_report.authority_scope()
                != "co-located-host-local"
            || !endpoint_report.co_located()
            || endpoint_report.hardware_proof()
        {
            return Err(CustodyProcessError::Unready(
                "trusted-host endpoint report overclaims its trust boundary",
            ));
        }
        let deployment_report = TrustedHostNoTeeReport::local_systemd(
            endpoint_report.configuration_sha256().clone(),
        )
        .map_err(|error| {
            CustodyProcessError::Invalid(format!(
                "trusted-host deployment report is invalid: {error}"
            ))
        })?;
        let watchdog_poller =
            LinuxBoottimeWatchdogPoller::new().map_err(|error| {
                CustodyProcessError::Invalid(format!(
                    "watchdog BOOTTIME poller bootstrap failed: {error}"
                ))
            })?;
        let heartbeat = LinuxHeartbeatEvent::new().map_err(|error| {
            CustodyProcessError::Invalid(format!(
                "watchdog heartbeat bootstrap failed: {error}"
            ))
        })?;
        let heartbeat_capability =
            LinuxHeartbeatEvent::create_counter(0).map_err(|error| {
                CustodyProcessError::Invalid(format!(
                    "watchdog heartbeat capability bootstrap failed: {error}"
                ))
            })?;
        startup_deadline.require_live().map_err(|error| {
            CustodyProcessError::Invalid(format!(
                "policy-custody bootstrap crossed its absolute deadline: {error}"
            ))
        })?;
        let client = Self {
            endpoint_trust,
            watchdog_poller,
            heartbeat,
            heartbeat_capability,
            deployment_report,
        };
        client.validate_startup()?;
        Ok(client)
    }

    fn validate_startup(&self) -> Result<(), CustodyProcessError> {
        if self.endpoint_trust.progress_fd().as_raw_fd() < 0
            || self.watchdog_poller.progress_fd().as_raw_fd() < 0
            || self.heartbeat.progress_fd().as_raw_fd() < 0
            || self.heartbeat_capability.as_raw_fd() < 0
            || self.deployment_report.profile != "TrustedHostNoTee"
            || !self.deployment_report.authority_is_co_located
            || self.deployment_report.hardware_key_protection
            || self.deployment_report.hardware_attestation
        {
            return Err(CustodyProcessError::Unready(
                "trusted-host concrete adapter set is incomplete or overclaims isolation",
            ));
        }
        Ok(())
    }

    pub(super) fn reconcile_recovery_startup<
        S,
        A,
        T,
        H,
        V,
        B,
        E,
    >(
        &self,
        driver: &mut PolicyCustodyOperationDriver<
            S,
            A,
            T,
            H,
            V,
            B,
            E,
        >,
        startup_deadline: &BoottimeDeadline,
    ) -> Result<
        PolicyCustodyRecoveryReadiness,
        CustodyProcessError,
    >
    where
        S: RecoveryRuntimeMaterialStore,
        A: CleanupAuthorizationConsumer,
        T: RecoveryTargetProvider,
        H: BoundedCleanupHelper,
        V: CurrentSignatureAuthority,
        B: BoottimeWatchdogPoller,
        E: HeartbeatEvent,
    {
        self.validate_startup()?;
        let readiness = driver
            .reconcile_startup(startup_deadline)
            .map_err(|error| {
                CustodyProcessError::Invalid(format!(
                    "five-service recovery reconciliation failed: {error}"
                ))
            })?;
        startup_deadline.require_live().map_err(|error| {
            CustodyProcessError::Invalid(format!(
                "five-service recovery readiness crossed its startup deadline: {error}"
            ))
        })?;
        Ok(readiness)
    }
}

pub(super) fn install_retained_generation(
    mut retained_config: File,
    expected_config_sha256: Sha256Digest,
    assignment: VerifiedAssignment,
    key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
    trusted_time: Arc<dyn TrustedTime + Send + Sync>,
) -> Result<
    Arc<ProductionPolicyShadowCustodyRpcSupervisor>,
    ShadowError,
> {
    let metadata = retained_config
        .metadata()
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    let expected_length = usize::try_from(metadata.len())
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    if !metadata.file_type().is_file()
        || expected_length == 0
        || expected_length > MAX_PRODUCTION_PROCESS_CONFIG_BYTES
    {
        return Err(ShadowError::CustodyUnavailable);
    }
    retained_config
        .seek(SeekFrom::Start(0))
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    let mut exact_config = Vec::with_capacity(expected_length);
    retained_config
        .take(
            u64::try_from(MAX_PRODUCTION_PROCESS_CONFIG_BYTES)
                .map_err(|_| ShadowError::CustodyUnavailable)?
                .saturating_add(1),
        )
        .read_to_end(&mut exact_config)
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    if exact_config.len() != expected_length
        || Sha256Digest::compute(&exact_config)
            != expected_config_sha256
    {
        return Err(ShadowError::CustodyUnavailable);
    }
    let process_config: ProductionProcessConfigV4 =
        serde_json::from_slice(&exact_config)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
    if canonical_json_bytes(&process_config)? != exact_config {
        return Err(ShadowError::CustodyUnavailable);
    }
    process_config.validate()?;
    if production_dispatch_protocol_set_sha256()
        .map_err(|_| ShadowError::CustodyUnavailable)?
        != process_config.dispatcher_protocol_set_sha256
    {
        return Err(ShadowError::BindingDrift);
    }

    let configuration = process_config.production_configuration(
        &assignment,
        key_trust.as_ref(),
        trusted_time.as_ref(),
    )?;
    let assignment_payload_sha256 =
        configuration.assignment_payload_sha256().clone();
    let assignment_revision = configuration.assignment_revision();
    let installed = INSTALLED_PRODUCTION_SUPERVISOR
        .get_or_init(|| Mutex::new(None));
    let mut installed = installed
        .lock()
        .map_err(|_| ShadowError::CustodyUnavailable)?;
    if INSTALLED_NATIVE_SUPERVISOR.get_or_init(||Mutex::new(None)).lock().map_err(|_|ShadowError::CustodyUnavailable)?.is_some(){
        return Err(ShadowError::CustodyUnavailable);
    }
    if let Some(current) = installed.as_mut() {
        if current.source_config_sha256 != expected_config_sha256
            || current.process_config.api_version
                != process_config.api_version
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        if current.assignment_payload_sha256
            == assignment_payload_sha256
            && current.assignment_revision == assignment_revision
        {
            return Ok(Arc::clone(&current.supervisor));
        }
        if assignment_revision <= current.assignment_revision {
            return Err(ShadowError::BindingDrift);
        }
        current
            .supervisor
            .install_verified_generation_configuration(configuration)?;
        current.assignment_payload_sha256 = assignment_payload_sha256;
        current.assignment_revision = assignment_revision;
        return Ok(Arc::clone(&current.supervisor));
    }

    let manifest = ProductionCustodyDispatchManifest::
        from_verified_external_dispatcher(
            &configuration,
            process_config.kernel_driver_identity.clone(),
            process_config.stable_reaper_identity.clone(),
            process_config.dispatcher_protocol_set_sha256.clone(),
            u64::try_from(MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES)
                .map_err(|_| ShadowError::CustodyUnavailable)?,
            u64::try_from(MAX_PRODUCTION_DISPATCH_ARTIFACT_BYTES)
                .map_err(|_| ShadowError::CustodyUnavailable)?,
            process_config.maximum_async_durability_nanos,
        )?;
    let rpc = BoundedCanonicalRpcClient::connect(&process_config)?;
    let generation_ambiguous = Arc::new(AtomicBool::new(false));
    let process = Arc::new(RpcProductionPolicyShadowCustodyProcess {
        active_configuration: RwLock::new(configuration.clone()),
        manifest,
        process_config: RetainedProcessSettings::host(process_config.clone()),
        rpc: Arc::clone(&rpc),
        key_trust: Arc::clone(&key_trust),
        trusted_time: Arc::clone(&trusted_time),
        persistence_verifier: RpcPersistenceVerifier {
            rpc,
            maximum_rpc_nanos: process_config.maximum_rpc_nanos,
            generation_ambiguous: Arc::clone(&generation_ambiguous),
        },
        sealed_references: Mutex::new(BTreeMap::new()),
        prepared_generations: Mutex::new(Vec::new()),
        ingress_publication: Mutex::new(IngressPublicationState::default()),
        generation_ambiguous,
    });
    let supervisor = ProductionPolicyShadowCustodyRpcSupervisor::install(
        configuration,
        process,
        key_trust,
        trusted_time,
    )?;
    *installed = Some(InstalledProductionSupervisor {
        source_config_sha256: expected_config_sha256,
        process_config,
        assignment_payload_sha256,
        assignment_revision,
        supervisor: Arc::clone(&supervisor),
    });
    Ok(supervisor)
}

pub(crate) fn install_policy_shadow_custody_generation_from_retained_file(
    retained_config: File,
    expected_config_sha256: super::super::Sha256Digest,
    assignment: VerifiedAssignment,
    key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
    trusted_time: Arc<dyn TrustedTime + Send + Sync>,
) -> Result<
    Arc<ProductionPolicyShadowCustodyRpcSupervisor>,
    ShadowError,
> {
    ExtractedPolicyCustodyAuthority::install_generation_from_retained_file(
        retained_config,
        expected_config_sha256,
        assignment,
        key_trust,
        trusted_time,
    )
}

/// Explicit native receiver/v3 only. Sessions and originals come from the same
/// actual root-admitted owner, never from a serialized bridge Arc or host DTO.
pub(crate) fn install_native_custody_generation_from_retained_owner(
    owner:Arc<super::services::NativeCustodyLifecycleOwner>,source:Sha256Digest,assignment:VerifiedAssignment,
    key_trust:Arc<dyn EnvelopeKeyTrust+Send+Sync>,trusted_time:Arc<dyn TrustedTime+Send+Sync>)
    ->Result<Arc<ProductionPolicyShadowCustodyRpcSupervisor>,ShadowError>{
    owner.check(&source).map_err(|_|ShadowError::CustodyUnavailable)?;
    let host=INSTALLED_PRODUCTION_SUPERVISOR.get_or_init(||Mutex::new(None)).lock().map_err(|_|ShadowError::CustodyUnavailable)?;
    if host.is_some(){return Err(ShadowError::CustodyUnavailable);}
    let mut installed=INSTALLED_NATIVE_SUPERVISOR.get_or_init(||Mutex::new(None)).lock().map_err(|_|ShadowError::CustodyUnavailable)?;
    if let Some(current)=installed.as_ref(){
        if current.source!=source || !Arc::ptr_eq(&current.owner,&owner) || &current.assignment!=assignment.payload_sha256(){
            return Err(ShadowError::BindingDrift);
        }
        current.factory.check(key_trust.as_ref(),trusted_time.as_ref())?;return Ok(Arc::clone(&current.supervisor));
    }
    let factory=Arc::new(super::native_remote_factory::Factory::open(&owner,&source,assignment.clone(),key_trust.as_ref(),trusted_time.as_ref())?);
    if factory.settings.dispatcher_protocol_set_sha256!=production_dispatch_protocol_set_sha256().map_err(|_|ShadowError::BindingDrift)?{
        return Err(ShadowError::BindingDrift);
    }
    let sessions=factory.take_sessions()?;
    if sessions.len()!=4{return Err(ShadowError::CustodyUnavailable);}
    let rpc=BoundedCanonicalRpcClient::from_sessions(sessions,32,Some(NativeRpcGuard{factory:Arc::clone(&factory),
        trust:Arc::clone(&key_trust),time:Arc::clone(&trusted_time)}))?;
    let generation_ambiguous=Arc::new(AtomicBool::new(false));
    let process=Arc::new(RpcProductionPolicyShadowCustodyProcess{
        active_configuration:RwLock::new(factory.configuration.clone()),manifest:factory.manifest.clone(),
        process_config:RetainedProcessSettings::native(Arc::clone(&factory)),rpc:Arc::clone(&rpc),
        key_trust:Arc::clone(&key_trust),trusted_time:Arc::clone(&trusted_time),
        persistence_verifier:RpcPersistenceVerifier{rpc,maximum_rpc_nanos:factory.settings.maximum_rpc_nanos,
            generation_ambiguous:Arc::clone(&generation_ambiguous)},
        sealed_references:Mutex::new(BTreeMap::new()),prepared_generations:Mutex::new(Vec::new()),
        ingress_publication:Mutex::new(IngressPublicationState::default()),generation_ambiguous});
    // This invokes the same real generation recovery/prepare/commit authorities;
    // constructed admission is not substituted for their actual signed result.
    let supervisor=ProductionPolicyShadowCustodyRpcSupervisor::install(factory.configuration.clone(),process,key_trust,trusted_time)?;
    *installed=Some(InstalledNativeSupervisor{source,owner,factory,assignment:assignment.payload_sha256().clone(),supervisor:Arc::clone(&supervisor)});
    Ok(supervisor)
}

pub(crate) fn run_policy_shadow_custody_server_from_env(
) -> Result<(), CustodyProcessError> {
    let runtime =
        PolicyShadowCustodyProcessClient::from_systemd_environment()?;
    runtime.validate_startup()?;
    super::run_production_rpc_service_from_env()
        .map_err(|error| {
            CustodyProcessError::Invalid(format!(
                "production policy-custody RPC service failed closed: {error}"
            ))
        })
}

fn startup_deadline_from_environment(
) -> Result<BoottimeDeadline, CustodyProcessError> {
    let raw = env::var(
        serverware_decision_gate::
            POLICY_SHADOW_CUSTODY_STARTUP_DEADLINE_BOOTTIME_NANOS_ENV,
    )
    .map_err(|_| {
        CustodyProcessError::Unready(
            "absolute policy-custody startup BOOTTIME deadline is absent",
        )
    })?;
    let absolute_nanos = raw.parse::<u64>().map_err(|_| {
        CustodyProcessError::Unready(
            "absolute policy-custody startup BOOTTIME deadline is invalid",
        )
    })?;
    let domain = BoottimeDomain::current().map_err(|error| {
        CustodyProcessError::Invalid(format!(
            "current BOOTTIME domain is unavailable: {error}"
        ))
    })?;
    BoottimeDeadline::from_absolute_in_expected_domain(
        domain,
        absolute_nanos,
    )
    .map_err(|error| {
        CustodyProcessError::Invalid(format!(
            "absolute policy-custody startup deadline is unavailable: {error}"
        ))
    })
}

#[cfg(test)]
mod custody_response_context_tests {
    use super::*;
    use crate::policy_shadow::{custody_response_fixture as fixture, terminal_receipt_fixture};

    fn context() -> IngressPublicationPreparation {
        IngressPublicationPreparation {
            configuration_binding_sha256: Sha256Digest::compute(b"local fixture configuration"),
            request_sha256: Sha256Digest::compute(b"local fixture prepare request"),
            successor: Arc::new(fixture::generation()), predecessor: None, expected_publication_revision: 2,
        }
    }

    #[test]
    fn custody_publication_context_requires_exact_preparation_and_verified_commit() {
        let context = context();
        let prepared = fixture::preparation(&context.successor);
        let mut state = IngressPublicationState::default();
        state.reserve(&context).unwrap();
        let mut other = context.clone(); other.request_sha256 = Sha256Digest::compute(b"concurrent request");
        assert_eq!(state.reserve(&other).err(), Some(ShadowError::CustodyUnavailable));
        for (name, replacement, expected) in [
            ("last_ingress_sequence", serde_json::json!(0), ShadowError::InvalidField {
                field: "custody.last_ingress_sequence", reason: "must be a positive signed-schema integer",
            }),
            ("last_ingress_sequence", serde_json::json!(u64::MAX - 1), ShadowError::InvalidField {
                field: "custody.last_ingress_sequence", reason: "must be a positive signed-schema integer",
            }),
            ("persisted_sequence_range_sha256", serde_json::json!(Sha256Digest::compute(b"wrong range")), ShadowError::GenerationIdentityMismatch),
        ] {
            let mut raw = serde_json::to_value(&prepared).unwrap(); raw[name] = replacement;
            let invalid: PreparedGenerationPublication = serde_json::from_value(raw).unwrap();
            assert_eq!(state.accept_prepared(&context, &invalid).err(), Some(expected));
        }
        state.accept_prepared(&context, &prepared).unwrap();
        let retained = state.retained(&prepared).unwrap();
        let wrong = fixture::publication(&context.successor, &prepared, 3);
        assert_eq!(state.commit(&retained, &wrong).err(), Some(ShadowError::BindingDrift));
        assert!(state.published.is_none());
        let authentic = fixture::publication(&context.successor, &prepared, 2);
        state.commit(&retained, &authentic).unwrap();
        assert!(state.published.as_ref() == Some(&retained));
        assert!(state.pending.is_none());
    }

    #[test]
    fn custody_publication_context_rejects_delayed_recovery_without_erasing_new_state() {
        let context = context();
        let prepared = fixture::preparation(&context.successor);
        let authentic = fixture::publication(&context.successor, &prepared, 2);
        let mut state = IngressPublicationState::default();
        let recovery_started_at = state.revision;
        state.reserve(&context).unwrap();
        state.accept_prepared(&context, &prepared).unwrap();
        let retained = state.retained(&prepared).unwrap();
        state.commit(&retained, &authentic).unwrap();
        assert_eq!(state.recover(recovery_started_at, &authentic).err(), Some(ShadowError::BindingDrift));
        assert!(state.published.as_ref() == Some(&retained));
        let recovery_started_at = state.revision;
        let mut next = context.clone(); next.request_sha256 = Sha256Digest::compute(b"next preparation");
        state.reserve(&next).unwrap();
        assert_eq!(state.recover(recovery_started_at, &authentic).err(), Some(ShadowError::BindingDrift));
        assert!(state.pending.as_ref().is_some_and(|(pending, _)| pending == &next));
        let current_revision = state.revision;
        state.recover(current_revision, &authentic).unwrap();
        assert!(state.pending.is_none());
        assert!(state.published.as_ref() == Some(&retained));
        let mut empty = IngressPublicationState::default();
        empty.recover(0, &authentic).unwrap();
        assert!(empty.published.is_none(), "digest-only recovery must not invent a verified load identity");
    }

    #[test]
    fn custody_publication_context_abort_reconfigure_and_overflow_fail_closed() {
        let context = context();
        let prepared = fixture::preparation(&context.successor);
        let authentic = fixture::publication(&context.successor, &prepared, 2);
        let mut state = IngressPublicationState::default();
        state.reserve(&context).unwrap(); state.accept_prepared(&context, &prepared).unwrap();
        let retained = state.retained(&prepared).unwrap();
        state.commit(&retained, &authentic).unwrap();
        let captured = state.published.clone();
        state.abort(&retained).unwrap();
        assert!(state.published.is_none());
        assert!(captured.as_ref() == Some(&retained), "request context is immutable, not a later cache read");
        state.reserve(&context).unwrap(); state.accept_prepared(&context, &prepared).unwrap();
        let before = state.revision;
        state.invalidate().unwrap();
        assert!(state.revision > before && state.pending.is_none() && state.published.is_none());
        assert_eq!(state.commit(&retained, &authentic).err(), Some(ShadowError::BindingDrift));
        assert_eq!(state.recover(before, &authentic).err(), Some(ShadowError::BindingDrift));
        state.revision = u64::MAX;
        assert_eq!(state.reserve(&context).err(), Some(ShadowError::CounterOverflow));
        assert!(state.pending.is_none());
    }

    #[test]
    fn custody_response_decoder_rejects_noncanonical_nested_fields_and_wrong_kind() {
        let bytes = b"local terminal decoder fixture".to_vec();
        let event = ShadowSpoolEvent::new(Sha256Digest::compute(b"generation"), 1,
            Sha256Digest::compute(b"request"), Sha256Digest::compute(b"commitment"),
            crate::policy_shadow::ShadowSpoolPhase::PreDispatchTerminal, Sha256Digest::compute(&bytes), bytes).unwrap();
        let verified = terminal_receipt_fixture::verify(&event, crate::policy_shadow::ShadowSpoolDisposition::Appended,
            terminal_receipt_fixture::Fault::None).unwrap();
        let raw = serde_json::json!({"outcome":"committed", "receipt":verified.wire});
        let artifact = CanonicalProductionArtifactV4::from_serializable(ProductionArtifactKindV4::TerminalSlotAppendOutcome, &raw).unwrap();
        assert!(RpcProductionPolicyShadowCustodyProcess::decode_artifact::<TerminalSlotAppendOutcomeWire>(
            &artifact, ProductionArtifactKindV4::TerminalSlotAppendOutcome).is_ok());
        let mut altered = raw;
        altered["receipt"]["unexpected"] = serde_json::json!(true);
        let artifact = CanonicalProductionArtifactV4::from_serializable(ProductionArtifactKindV4::TerminalSlotAppendOutcome, &altered).unwrap();
        assert_eq!(RpcProductionPolicyShadowCustodyProcess::decode_artifact::<TerminalSlotAppendOutcomeWire>(
            &artifact, ProductionArtifactKindV4::TerminalSlotAppendOutcome).err(), Some(ShadowError::CustodyUnavailable));
        assert_eq!(RpcProductionPolicyShadowCustodyProcess::decode_artifact::<TerminalSlotAppendOutcomeWire>(
            &artifact, ProductionArtifactKindV4::IngressCustodyAdmission).err(), Some(ShadowError::CustodyUnavailable));
    }

    #[test]
    fn custody_response_source_pins_production_verifiers_and_request_captured_context() {
        // Source wiring only: these assertions are not a live RPC, production
        // assignment, peer identity, service persistence or publication proof.
        let source = include_str!("policy_shadow_custody_process.rs");
        let production = source.split_once("#[cfg(test)]\nmod custody_response_context_tests").unwrap().0;
        let reconstruction = production.split_once("    fn reconstruct_dispatch_response(").unwrap().1
            .split_once("    fn protocol_operation(").unwrap().0;
        assert!(reconstruction.contains("verify_production_ingress_custody_admission("));
        assert!(reconstruction.contains("verify_production_terminal_slot_append_outcome("));
        assert!(reconstruction.contains("configuration.production_configuration_binding_sha256() != expected_configuration_binding_sha256"));
        let dispatch = production.split_once("    fn dispatch_operation(").unwrap().1
            .split_once("impl ProductionPolicyShadowCustodyProcess").unwrap().0;
        assert!(dispatch.contains("DispatchResponseContext::BeginIngress {"));
        assert!(dispatch.contains("request_binding_sha256: request_binding_sha256.clone(), published"));
        assert!(dispatch.contains("DispatchResponseContext::RecoverPublication("));
        assert!(dispatch.find("let configuration_guard = self.active_configuration.read()").unwrap()
            < dispatch.find("let closed = match request").unwrap());
        assert!(dispatch.find("drop(configuration_guard);").unwrap()
            < dispatch.find("let response = match self.call_body(").unwrap());
        assert!(production.contains("next.recover(revision, &verified)?;\n                self.retain_sealed_reference"));
        assert!(production.contains("next.commit(&retained, &verified)?;\n                self.retain_sealed_reference"));
    }
}
