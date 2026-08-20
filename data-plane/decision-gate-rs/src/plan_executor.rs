#![cfg(target_os = "linux")]

use crate::artifact_cas::{
    ArtifactCasStore, ArtifactManifestV12, PublishedArtifactCas,
};
use crate::controller_v12::{
    sha256 as controller_sha256, ArtifactSeal,
    ControllerWorkflowInvocationV12, ExecutorLaneProxyBindingV12,
    ExecutorManifestTrustKeyV12, ExecutorTerminalEvidenceV12, LaneEvidence,
    LanePhase as ControllerLanePhase, LogicalLane as ControllerLogicalLane,
    SourceSeal, TerminalVerdict, WorkflowSelectionV12,
    CONTROLLER_EXECUTOR_PROTOCOL_V12, EXECUTOR_INVOCATION_FD_COUNT_V12,
    EXECUTOR_INVOCATION_PAYLOAD_FD_INDEX_V12,
    EXECUTOR_LANE_PROXY_FD_INDEX_V12, EXECUTOR_SOURCE_INPUT_FD_INDEX_V12,
};
use crate::plan_protocol::{
    canonical_bytes, canonical_sha256, current_boot_id_sha256, sha256_bytes,
    ArtifactCasReference, AuthoritativeLaneState, BodyContract,
    Digest, DindGenerationKind, ExactBuildTuple,
    InheritedLaneProxy, LaneProxyRequest, LaneProxyResponse,
    LogicalLane, LogicalLaneContract, LogicalPlanV12,
    OciObjectReference, PinnedPull, PlanPhase, PlanProtocolError,
    PlanResult, ProxyDisposition, ProxyOperation,
    RequiredOciImportClosureV12, RunnerIdentity,
    RuntimeTrustProfile, ServiceEndpoint, ServiceInstanceV12,
    SourceCasReference, MAX_FRAME_BYTES,
};
use crate::docker_contract::{
    DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
};
use crate::readiness::{
    ReadinessFixtureTrust, ReadinessProbe, ReadinessRequestV12,
    ReadinessResponseV12, ReadinessRunner, ReadinessTransport,
    SignedReadinessFixtureV12,
};
use crate::runtime_evidence::{
    verify_static_executable_fd, ExecutableRole,
    RunnerRuntimeEvidenceV12, StaticExecutableEvidenceV12,
    TRUSTED_HOST_CLAIM,
};
use crate::source_cas::{
    AuthenticatedDirectoryInput, AuthorizedManifestKey,
    ManifestTrustPolicy, PublishedSourceCas, SourceCasStore,
    PublicationControlV12, SourceInputKind, SourceManifestV12,
};
use crate::{plan_protocol, readiness, runtime_evidence};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const EXECUTOR_EVIDENCE_VERSION: &str =
    "serverware/controller-plan-executor-evidence/v12";
const EXECUTOR_RESULT_VERSION: &str =
    "serverware/controller-plan-executor-result/v12";
const PROXY_PAYLOAD_VERSION: &str =
    "serverware/controller-plan-proxy-payload/v12";
const EXECUTOR_RPC_FD_ENV: &str =
    "SERVERWARE_CONTROLLER_PLAN_V12_RPC_FD";
const MAX_INVOCATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_ATTACHED_FDS: usize = 8;
const F_GET_SEALS_VALUE: libc::c_int = 1034;
const F_SEAL_SEAL_VALUE: libc::c_int = 0x0001;
const F_SEAL_SHRINK_VALUE: libc::c_int = 0x0002;
const F_SEAL_GROW_VALUE: libc::c_int = 0x0004;
const F_SEAL_WRITE_VALUE: libc::c_int = 0x0008;
const REQUIRED_SEALS: libc::c_int = F_SEAL_SEAL_VALUE
    | F_SEAL_SHRINK_VALUE
    | F_SEAL_GROW_VALUE
    | F_SEAL_WRITE_VALUE;

struct ResolvedExecutorInvocationV12 {
    envelope: ControllerWorkflowInvocationV12,
    source_publication_control: PublicationControlV12,
    artifact_publication_control: PublicationControlV12,
    plan: LogicalPlanV12,
    source_manifest: SourceManifestV12,
    source_input: OwnedFd,
    lane_proxy: InheritedLaneProxy,
    lane_proxy_fd: OwnedFd,
    manifest_trust_keys: Vec<ExecutorManifestTrustKeyV12>,
    readiness_fixture: SignedReadinessFixtureV12,
}

impl ResolvedExecutorInvocationV12 {
    fn trust_policy(&self) -> PlanResult<ManifestTrustPolicy> {
        ManifestTrustPolicy::new(
            self.manifest_trust_keys
                .iter()
                .map(|key| AuthorizedManifestKey {
                    key_id: key.key_id.clone(),
                    public_key: key.public_key,
                })
                .collect(),
        )
    }

    fn readiness_trust(&self) -> PlanResult<ReadinessFixtureTrust> {
        pinned_executor_policy()
            .map_err(PlanProtocolError::InvalidOwned)?
            .readiness_trust
            .clone()
            .into_runtime()
            .map_err(|error| {
                PlanProtocolError::InvalidOwned(error.to_string())
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProxyPayloadV12 {
    version: String,
    plan_id: Digest,
    lane: LogicalLane,
    phase: PlanPhase,
    operation: ProxyOperation,
    source: SourceCasReference,
    artifact_manifest_sha256: Option<Digest>,
    prepare_sha256: Option<Digest>,
    body_sha256: Option<Digest>,
    content: ProxyPayloadContentV12,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
enum ProxyPayloadContentV12 {
    CreateBuildDind {
        generation_kind: DindGenerationKind,
        exact_build: ExactBuildTuple,
        runner: RunnerIdentity,
    },
    PullPinned {
        pull: PinnedPull,
    },
    BuildExact {
        exact_build: ExactBuildTuple,
    },
    ExportOwnedOci {
        expected_artifacts: ArtifactCasReference,
        expected_repositories: Vec<String>,
    },
    Destroy {
        reason_sha256: Digest,
        require_zero_resources: bool,
    },
    CreateNoBuildDind {
        generation_kind: DindGenerationKind,
        artifacts: ArtifactCasReference,
        required_oci_import_closure: RequiredOciImportClosureV12,
        runner: RunnerIdentity,
    },
    ImportSealedOci {
        object: OciObjectReference,
        artifact_object_sha256: Digest,
    },
    CreateRunner {
        runner: RunnerIdentity,
        command: crate::plan_protocol::ContainerCommand,
    },
    CreateServices {
        services: Vec<ServiceInstanceV12>,
    },
    RunBody {
        body: BodyContract,
        derived_service_endpoints: Vec<ServiceEndpoint>,
    },
    StopRunner {
        command_sha256: Digest,
    },
    DestroyServices {
        services_sha256: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QueryPayloadV12 {
    version: String,
    plan_id: Digest,
    lane: LogicalLane,
    original_request_sha256: Digest,
    original_operation: ProxyOperation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AppliedResultV12 {
    version: String,
    plan_id: Digest,
    lane: LogicalLane,
    operation: ProxyOperation,
    authoritative_state: AuthoritativeLaneState,
    transition_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArtifactExportResultV12 {
    version: String,
    plan_id: Digest,
    lane: LogicalLane,
    artifact_manifest: ArtifactManifestV12,
    attached_directory_fd_sha256: Digest,
    export_transcript_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BodyExecutionResultV12 {
    version: String,
    plan_id: Digest,
    lane: LogicalLane,
    body_sha256: Digest,
    command_sha256: Digest,
    exit_status: i32,
    stdout_sha256: Digest,
    stderr_sha256: Digest,
    output_manifest_sha256: Digest,
    runner_static_evidence: StaticExecutableEvidenceV12,
    courier_static_evidence: StaticExecutableEvidenceV12,
    runner_evidence: RunnerRuntimeEvidenceV12,
    terminal_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DestructionResultV12 {
    version: String,
    plan_id: Digest,
    generation_kind: DindGenerationKind,
    docker_top_level_object_count_scope: String,
    docker_internal_storage_absence_proof: String,
    drained_containers: u64,
    drained_images: u64,
    drained_networks: u64,
    drained_volumes: u64,
    containers: u64,
    images: u64,
    networks: u64,
    volumes: u64,
    docker_authority_established: bool,
    mounts: u64,
    cgroup_processes: u64,
    proxy_accepting: bool,
    ledger_terminal: bool,
    dind_reaped: bool,
    state_root_absent: bool,
    terminal_receipt_sha256: Digest,
    result_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TerminalDestructionReceiptV12 {
    version: String,
    trust_profile: String,
    plan_id: Digest,
    capability_sha256: Digest,
    profile: DindGenerationKind,
    owner_namespace: String,
    daemon_generation: String,
    network_namespace: String,
    request_sha256: Digest,
    observed_at_boottime_ns: u64,
    docker_top_level_object_count_scope: String,
    docker_internal_storage_absence_proof: String,
    drained_containers: u64,
    drained_images: u64,
    drained_networks: u64,
    drained_volumes: u64,
    containers: u64,
    images: u64,
    networks: u64,
    volumes: u64,
    docker_authority_established: bool,
    mounts: u64,
    cgroup_processes: u64,
    proxy_accepting: bool,
    ledger_terminal: bool,
    dind_reaped: bool,
    netns_absent: bool,
    socket_absent: bool,
    state_root_absent: bool,
    observed_state_sha256: Digest,
    signer_spki_sha256: Digest,
    signer_public_key_spki_der: Vec<u8>,
    signature: Vec<u8>,
    receipt_sha256: Digest,
}

impl DestructionResultV12 {
    fn validate(
        &self,
        plan_id: &Digest,
        generation_kind: DindGenerationKind,
    ) -> PlanResult<()> {
        if self.version != EXECUTOR_RESULT_VERSION
            || &self.plan_id != plan_id
            || self.generation_kind != generation_kind
            || self.docker_top_level_object_count_scope
                != DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
            || self.docker_internal_storage_absence_proof
                != DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
            || self.containers != 0
            || self.images != 0
            || self.networks != 0
            || self.volumes != 0
            || (!self.docker_authority_established
                && (self.drained_containers != 0
                    || self.drained_images != 0
                    || self.drained_networks != 0
                    || self.drained_volumes != 0))
            || self.mounts != 0
            || self.cgroup_processes != 0
            || self.proxy_accepting
            || !self.ledger_terminal
            || !self.dind_reaped
            || !self.state_root_absent
            || self.terminal_receipt_sha256 == [0; 32]
            || self.result_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "lane destruction did not prove zero retained resources",
            ));
        }
        let mut copy = self.clone();
        copy.result_sha256 = [0; 32];
        if sha256_bytes(&canonical_bytes(&copy)?)
            != self.result_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "lane destruction digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaneExecutionEvidenceV12 {
    pub lane: LogicalLane,
    pub prepare_sha256: Digest,
    pub body_sha256: Digest,
    pub command_sha256: Digest,
    pub stdout_sha256: Digest,
    pub stderr_sha256: Digest,
    pub output_manifest_sha256: Digest,
    pub runner_runtime_report_sha256: Digest,
    pub terminal_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutorEvidenceV12 {
    pub version: String,
    pub plan_id: Digest,
    pub plan_sha256: Digest,
    pub source: SourceCasReference,
    pub artifact_manifest_sha256: Digest,
    pub artifact_object_sha256: Digest,
    pub trust_profile: RuntimeTrustProfile,
    pub trust_claim: String,
    pub courier_sha256: Digest,
    pub readiness_evidence_sha256: Digest,
    pub lanes: Vec<LaneExecutionEvidenceV12>,
    pub build_dind_destroyed: bool,
    pub no_build_dind_destroyed: bool,
    pub completed_at_boottime_ns: u64,
    pub evidence_sha256: Digest,
}

struct ProxyExchange {
    response: LaneProxyResponse,
    attached_fds: Vec<OwnedFd>,
}

trait LaneProxyTransport {
fn transact(
        &mut self,
        request: &LaneProxyRequest,
        attached_fds: &[RawFd],
    ) -> PlanResult<ProxyExchange>;
}

struct SeqpacketLaneProxy {
    socket: OwnedFd,
    expected_peer_uid: u32,
    expected_peer_pid: u32,
}

impl SeqpacketLaneProxy {
    fn from_inherited(binding: &InheritedLaneProxy) -> PlanResult<Self> {
        binding.validate()?;
        let duplicate =
            duplicate_fd(binding.fd)?;
        let flags = unsafe {
            libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFL)
        };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    duplicate.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let proxy = Self {
            socket: duplicate,
            expected_peer_uid: binding.peer_uid,
            expected_peer_pid: binding.peer_pid,
        };
        proxy.verify_socket()?;
        if measure_peer_executable(binding.peer_pid)?
            != binding.peer_identity_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy executable digest differs from invocation",
            ));
        }
        Ok(proxy)
    }

    fn verify_socket(&self) -> PlanResult<()> {
        let mut socket_type = 0;
        let mut socket_type_len =
            mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut socket_type as *mut libc::c_int
                    as *mut libc::c_void,
                &mut socket_type_len,
            )
        } != 0
            || socket_type != libc::SOCK_SEQPACKET
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy FD is not a seqpacket socket",
            ));
        }
        let mut peer: libc::ucred = unsafe { mem::zeroed() };
        let mut peer_len =
            mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut peer as *mut libc::ucred as *mut libc::c_void,
                &mut peer_len,
            )
        } != 0
            || peer_len as usize != mem::size_of::<libc::ucred>()
            || peer.uid != self.expected_peer_uid
            || peer.pid <= 0
            || peer.pid as u32 != self.expected_peer_pid
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy peer identity differs from invocation",
            ));
        }
        Ok(())
    }
}

impl LaneProxyTransport for SeqpacketLaneProxy {
    fn transact(
        &mut self,
        request: &LaneProxyRequest,
        attached_fds: &[RawFd],
    ) -> PlanResult<ProxyExchange> {
        self.verify_socket()?;
        let bytes = canonical_bytes(request)?;
        send_packet_with_fds(
            self.socket.as_raw_fd(),
            &bytes,
            attached_fds,
            request.deadline_boottime_ns,
        )?;
        let (response_bytes, received_fds) = receive_packet_with_fds(
            self.socket.as_raw_fd(),
            request.deadline_boottime_ns,
        )?;
        let response: LaneProxyResponse =
            serde_json::from_slice(&response_bytes)?;
        response.validate_for(request)?;
        Ok(ProxyExchange {
            response,
            attached_fds: received_fds,
        })
    }
}

struct ProxySession<T: LaneProxyTransport> {
    transport: T,
    plan_id: Digest,
    capability_sha256: Digest,
    operation_deadline_boottime_ns: u64,
    cleanup_deadline_boottime_ns: u64,
    sequence: u64,
}

struct OperationReply {
    bytes: Vec<u8>,
    terminal_destruction_receipt: Option<Vec<u8>>,
    attached_fds: Vec<OwnedFd>,
}

impl<T: LaneProxyTransport> ProxySession<T> {
    fn call<P: Serialize>(
        &mut self,
        lane: LogicalLane,
        phase: PlanPhase,
        operation: ProxyOperation,
        expected_state: AuthoritativeLaneState,
        target_sha256: Digest,
        payload: &P,
        attached_fds: &[RawFd],
    ) -> PlanResult<OperationReply> {
        self.call_with_deadline(
            lane,
            phase,
            operation,
            expected_state,
            target_sha256,
            payload,
            attached_fds,
            self.operation_deadline_boottime_ns,
            true,
        )
    }

    fn cleanup_call<P: Serialize>(
        &mut self,
        lane: LogicalLane,
        operation: ProxyOperation,
        target_sha256: Digest,
        payload: &P,
    ) -> PlanResult<OperationReply> {
        self.call_with_deadline(
            lane,
            PlanPhase::Prepare,
            operation,
            AuthoritativeLaneState::Destroying,
            target_sha256,
            payload,
            &[],
            self.cleanup_deadline_boottime_ns,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn call_with_deadline<P: Serialize>(
        &mut self,
        lane: LogicalLane,
        phase: PlanPhase,
        operation: ProxyOperation,
        expected_state: AuthoritativeLaneState,
        target_sha256: Digest,
        payload: &P,
        attached_fds: &[RawFd],
        deadline_boottime_ns: u64,
        resolve_unknown: bool,
    ) -> PlanResult<OperationReply> {
        if boottime_ns()? >= deadline_boottime_ns {
            return Err(PlanProtocolError::Invalid(
                "lane proxy operation deadline expired",
            ));
        }
        let payload = canonical_bytes(payload)?;
        let payload_sha256 = sha256_bytes(&payload);
        self.sequence = self.sequence.checked_add(1).ok_or(
            PlanProtocolError::Invalid("lane proxy sequence overflow"),
        )?;
        let mut request = LaneProxyRequest {
            protocol:
                crate::plan_protocol::PLAN_PROXY_PROTOCOL_VERSION.to_string(),
            request_id: random_digest()?,
            plan_id: self.plan_id,
            lane,
            phase,
            sequence: self.sequence,
            boot_id_sha256: current_boot_id_sha256()?,
            deadline_boottime_ns,
            capability_sha256: self.capability_sha256,
            operation,
            expected_state,
            target_sha256,
            payload_sha256,
            payload,
            request_sha256: [0; 32],
        };
        request.request_sha256 =
            sha256_bytes(&canonical_bytes(&request)?);
        request.validate()?;
        let exchange = match self.transport.transact(&request, attached_fds) {
            Ok(exchange) => exchange,
            Err(error)
                if operation != ProxyOperation::QueryAuthoritativeState =>
            {
                return self.query_uncertain(&request).map_err(|reconcile| {
                    HARD_UNREADY.store(
                        true,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    PlanProtocolError::InvalidOwned(format!(
                        "lane proxy outcome became uncertain ({error}); durable reconciliation failed ({reconcile})"
                    ))
                });
            }
            Err(error) => {
                HARD_UNREADY.store(
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                );
                return Err(PlanProtocolError::InvalidOwned(format!(
                    "durable lane-proxy query failed: {error}"
                )));
            }
        };
        let destruction_operation = matches!(
            operation,
            ProxyOperation::DestroyBuildDind
                | ProxyOperation::DestroyNoBuildDind
        );
        if operation != ProxyOperation::QueryAuthoritativeState
            && (destruction_operation
                != exchange
                    .response
                    .terminal_destruction_receipt
                    .is_some())
        {
            close_fds(exchange.attached_fds);
            return Err(PlanProtocolError::Invalid(
                "lane proxy response terminal receipt differs from the requested operation",
            ));
        }
        match exchange.response.disposition {
            ProxyDisposition::Applied | ProxyDisposition::AlreadyApplied => {
                Ok(OperationReply {
                    bytes: exchange.response.result,
                    terminal_destruction_receipt:
                        exchange
                            .response
                            .terminal_destruction_receipt,
                    attached_fds: exchange.attached_fds,
                })
            }
            ProxyDisposition::Rejected => {
                Err(PlanProtocolError::Invalid(
                    "lane proxy rejected an exact plan operation",
                ))
            }
            ProxyDisposition::OutcomeUnknown if resolve_unknown => {
                close_fds(exchange.attached_fds);
                self.query_uncertain(&request)
            }
            ProxyDisposition::OutcomeUnknown => {
                close_fds(exchange.attached_fds);
                HARD_UNREADY.store(
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                );
                Err(PlanProtocolError::Invalid(
                    "lane proxy durable query remains unknown",
                ))
            }
        }
    }

    fn query_uncertain(
        &mut self,
        original: &LaneProxyRequest,
    ) -> PlanResult<OperationReply> {
        let payload = QueryPayloadV12 {
            version: PROXY_PAYLOAD_VERSION.to_string(),
            plan_id: self.plan_id,
            lane: original.lane,
            original_request_sha256: original.request_sha256,
            original_operation: original.operation,
        };
        self.call_with_deadline(
            original.lane,
            original.phase,
            ProxyOperation::QueryAuthoritativeState,
            original.expected_state,
            original.target_sha256,
            &payload,
            &[],
            original.deadline_boottime_ns,
            false,
        )
    }
}

struct ProxyReadinessAdapter<'a, T: LaneProxyTransport> {
    session: &'a mut ProxySession<T>,
}

impl<T: LaneProxyTransport> ReadinessTransport
    for ProxyReadinessAdapter<'_, T>
{
    fn execute(
        &mut self,
        request: &ReadinessRequestV12,
    ) -> PlanResult<ReadinessResponseV12> {
        let operation = match request.probe {
            ReadinessProbe::DockerUpgrade => {
                ProxyOperation::ReadinessDockerUpgrade
            }
            ReadinessProbe::ServiceHealth => {
                ProxyOperation::ReadinessService
            }
            ReadinessProbe::Chromium => {
                ProxyOperation::ReadinessChromium
            }
            ReadinessProbe::Teardown => {
                ProxyOperation::ReadinessTeardown
            }
        };
        let reply = self.session.call_with_deadline(
            LogicalLane::Build,
            PlanPhase::Prepare,
            operation,
            AuthoritativeLaneState::Declared,
            request.fixture_id,
            request,
            &[],
            request.deadline_boottime_ns,
            false,
        )?;
        if !reply.attached_fds.is_empty() {
            close_fds(reply.attached_fds);
            return Err(PlanProtocolError::Invalid(
                "readiness probe returned unexpected authority FDs",
            ));
        }
        Ok(serde_json::from_slice(&reply.bytes)?)
    }
}

pub fn run_cli() -> PlanResult<()> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("execute-logical-v12") if arguments.len() == 2 => {
            run_v12_rpc_from_environment(None)
        }
        Some("bootstrap-v11" | "execute-v11") => {
            legacy_v11::run(&arguments).map_err(|error| {
                PlanProtocolError::InvalidOwned(error.to_string())
            })
        }
        _ => Err(PlanProtocolError::Invalid(
            "usage: serverware-coder-plan execute-logical-v12",
        )),
    }
}

fn run_v12_rpc_from_environment(
    expected_phase: Option<WorkflowSelectionV12>,
) -> PlanResult<()> {
    let rpc_fd = std::env::var(EXECUTOR_RPC_FD_ENV)
        .map_err(|_| {
            PlanProtocolError::Invalid(
                "plan executor framed RPC FD is absent",
            )
        })?
        .parse::<RawFd>()
        .map_err(|_| {
            PlanProtocolError::Invalid(
                "plan executor framed RPC FD is invalid",
            )
        })?;
    handle_controller_rpc(rpc_fd, expected_phase)
}

fn execute_invocation(
    invocation: ResolvedExecutorInvocationV12,
) -> PlanResult<ExecutorTerminalEvidenceV12> {
    if !pinned_executor_policy()
        .map_err(PlanProtocolError::InvalidOwned)?
        .full_signed_readiness_before_repository_work_every_invocation
    {
        return Err(PlanProtocolError::Invalid(
            "executor configuration does not require full signed readiness before repository work",
        ));
    }
    let now = boottime_ns()?;
    if now >= invocation.plan.deadline_boottime_ns {
        return Err(PlanProtocolError::Invalid(
            "plan expired before executor startup",
        ));
    }
    if invocation.plan.trust_profile
        != RuntimeTrustProfile::TrustedHostNoTee
    {
        return Err(PlanProtocolError::Invalid(
            "executor cannot self-activate an IMA profile",
        ));
    }
    invocation.readiness_fixture.validate(
        &invocation.readiness_trust()?,
        now,
    )?;
    let trust = invocation.trust_policy()?;
    invocation.source_manifest.validate(
        &invocation.source_publication_control,
        &trust,
    )?;
    verify_service_instances(&invocation.plan, &trust)?;
    let artifact_store = ArtifactCasStore::open(
        Path::new(&invocation.envelope.artifact_cas_root),
        trust,
    )?;
    let courier_fd = open_self_executable()?;
    let courier = verify_static_executable_fd(
        courier_fd.as_raw_fd(),
        ExecutableRole::StaticCourier,
    )?;
    let transport =
        SeqpacketLaneProxy::from_inherited(&invocation.lane_proxy)?;
    let mut session = ProxySession {
        transport,
        plan_id: invocation.plan.plan_id,
        capability_sha256:
            invocation.lane_proxy.capability_sha256,
        operation_deadline_boottime_ns:
            invocation.plan.deadline_boottime_ns,
        cleanup_deadline_boottime_ns:
            invocation.envelope.cleanup_deadline_boottime_ns,
        sequence: 0,
    };
    let readiness = ReadinessRunner::new(
        ProxyReadinessAdapter {
            session: &mut session,
        },
        invocation.readiness_trust()?,
    )
    .run(
        &invocation.readiness_fixture,
        invocation.envelope.readiness_deadline_boottime_ns,
        invocation.envelope.cleanup_deadline_boottime_ns,
    )?;
    let source_input =
        AuthenticatedDirectoryInput::from_retained_fd(duplicate_fd(
            invocation.source_input.as_raw_fd(),
        )?)?;
    let source_store = SourceCasStore::open(
        Path::new(&invocation.envelope.source_cas_root),
        invocation.trust_policy()?,
    )?;
    let published_source: PublishedSourceCas = source_store
        .publish(
            source_input,
            invocation.source_manifest.clone(),
            &invocation.source_publication_control,
        )?;
    if published_source.reference != invocation.plan.source {
        return Err(PlanProtocolError::Invalid(
            "published source CAS differs from logical plan",
        ));
    }
    let execution = execute_plan(
        &invocation.plan,
        &published_source,
        &artifact_store,
        &invocation.artifact_publication_control,
        invocation.envelope.selection,
        &mut session,
    );
    let (artifact, lanes, build_destroyed, no_build_destroyed) =
        match execution {
            Ok(result) => result,
            Err(primary) => {
                let cleanup = force_destroy_all(
                    &invocation.plan,
                    &mut session,
                    b"executor failure",
                );
                return match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(PlanProtocolError::InvalidOwned(
                        format!(
                            "{primary}; authoritative cleanup also failed: {cleanup}",
                        ),
                    )),
                };
            }
        };
    let completed = boottime_ns()?;
    if completed >= invocation.envelope.cleanup_deadline_boottime_ns {
        return Err(PlanProtocolError::Invalid(
            "plan executor completed after cleanup deadline",
        ));
    }
    let mut evidence = ExecutorEvidenceV12 {
        version: EXECUTOR_EVIDENCE_VERSION.to_string(),
        plan_id: invocation.plan.plan_id,
        plan_sha256: invocation.plan.plan_sha256,
        source: published_source.reference,
        artifact_manifest_sha256:
            artifact.reference.manifest_sha256,
        artifact_object_sha256: artifact.reference.object_sha256,
        trust_profile: RuntimeTrustProfile::TrustedHostNoTee,
        trust_claim: TRUSTED_HOST_CLAIM.to_string(),
        courier_sha256: courier.content_sha256,
        readiness_evidence_sha256: readiness.evidence_sha256,
        lanes,
        build_dind_destroyed: build_destroyed,
        no_build_dind_destroyed: no_build_destroyed,
        completed_at_boottime_ns: completed,
        evidence_sha256: [0; 32],
    };
    evidence.evidence_sha256 =
        sha256_bytes(&canonical_bytes(&evidence)?);
    executor_terminal_evidence(&invocation, &artifact, evidence)
}

fn resolve_controller_invocation(
    envelope: ControllerWorkflowInvocationV12,
    source_input: OwnedFd,
    lane_proxy_fd: OwnedFd,
    expected_phase: Option<WorkflowSelectionV12>,
) -> PlanResult<ResolvedExecutorInvocationV12> {
    envelope.validate().map_err(|error| {
        PlanProtocolError::InvalidOwned(error.to_string())
    })?;
    if expected_phase.is_some_and(|phase| phase != envelope.selection) {
        return Err(PlanProtocolError::Invalid(
            "fixed logical phase differs from the controller invocation",
        ));
    }
    let plan: LogicalPlanV12 =
        serde_json::from_value(envelope.logical_plan.clone())?;
    let source_manifest: SourceManifestV12 =
        serde_json::from_value(envelope.source_manifest.clone())?;
    let source_publication_control: PublicationControlV12 =
        serde_json::from_value(
            envelope.source_publication_control.clone(),
        )?;
    let artifact_publication_control: PublicationControlV12 =
        serde_json::from_value(
            envelope.artifact_publication_control.clone(),
        )?;
    let readiness_fixture: SignedReadinessFixtureV12 =
        serde_json::from_value(envelope.readiness_fixture.clone())?;
    if plan.boot_id_sha256 != current_boot_id_sha256()?
        || plan.boot_id_sha256 != envelope.request.boot_id_sha256
        || plan.deadline_boottime_ns
            != envelope.execution_deadline_boottime_ns
        || source_publication_control.operation_id
            == artifact_publication_control.operation_id
        || source_publication_control.deadline_boottime_ns
            != envelope.execution_deadline_boottime_ns
        || artifact_publication_control.deadline_boottime_ns
            != envelope.execution_deadline_boottime_ns
        || source_publication_control.cleanup_deadline_boottime_ns
            != envelope.cleanup_deadline_boottime_ns
        || artifact_publication_control.cleanup_deadline_boottime_ns
            != envelope.cleanup_deadline_boottime_ns
        || readiness_fixture.signer_key_id
            != envelope.readiness_trust_key.key_id
        || readiness_fixture.expires_at_boottime_ns
            < envelope.cleanup_deadline_boottime_ns
    {
        return Err(PlanProtocolError::Invalid(
            "controller invocation typed inputs lost their request, deadline, or trust binding",
        ));
    }
    plan.validate()?;
    validate_absolute_path(&envelope.source_cas_root)?;
    validate_absolute_path(&envelope.artifact_cas_root)?;
    validate_absolute_path(&envelope.oci_cas_root)?;
    let configuration = pinned_executor_policy().map_err(
        PlanProtocolError::InvalidOwned,
    )?;
    {
        use base64::Engine as _;
        let pinned_key: [u8; 32] =
            base64::engine::general_purpose::STANDARD
                .decode(
                    configuration
                        .readiness_trust
                        .fixture_public_key_b64
                        .as_bytes(),
                )
                .map_err(|_| {
                    PlanProtocolError::Invalid(
                        "pinned readiness trust key is not base64",
                    )
                })?
                .try_into()
                .map_err(|_| {
                    PlanProtocolError::Invalid(
                        "pinned readiness trust key is not 32 bytes",
                    )
                })?;
        if envelope.readiness_trust_key.key_id
            != configuration.readiness_trust.fixture_key_id
            || envelope.readiness_trust_key.public_key != pinned_key
        {
            return Err(PlanProtocolError::Invalid(
                "controller readiness key differs from executor static policy",
            ));
        }
    }
    if envelope.lane_proxy.peer_uid != configuration.lane_proxy_uid
        || envelope.lane_proxy.peer_identity_sha256
            != configuration.inherited_proxy_executable_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "controller lane-proxy binding differs from executor static policy",
        ));
    }
    configuration
        .readiness_trust
        .verify_binding(&readiness_fixture)
        .map_err(|error| {
            PlanProtocolError::InvalidOwned(error.to_string())
        })?;
    let lane_proxy = InheritedLaneProxy {
        fd: lane_proxy_fd.as_raw_fd(),
        peer_uid: envelope.lane_proxy.peer_uid,
        peer_pid: envelope.lane_proxy.peer_pid,
        peer_identity_sha256:
            envelope.lane_proxy.peer_identity_sha256,
        capability_sha256: envelope.lane_proxy.capability_sha256,
    };
    lane_proxy.validate()?;
    Ok(ResolvedExecutorInvocationV12 {
        source_publication_control,
        artifact_publication_control,
        plan,
        source_manifest,
        source_input,
        lane_proxy,
        lane_proxy_fd,
        manifest_trust_keys: envelope.manifest_trust_keys.clone(),
        readiness_fixture,
        envelope,
    })
}

fn executor_terminal_evidence(
    invocation: &ResolvedExecutorInvocationV12,
    artifact: &PublishedArtifactCas,
    internal: ExecutorEvidenceV12,
) -> PlanResult<ExecutorTerminalEvidenceV12> {
    use base64::Engine as _;

    let canonical_bundle_sha256 = match invocation
        .source_manifest
        .provenance
        .input_kind
    {
        SourceInputKind::CanonicalBundle => invocation
            .source_manifest
            .provenance
            .canonical_bundle_sha256
            .ok_or(PlanProtocolError::Invalid(
                "canonical source provenance lacks its bundle digest",
            ))?,
        SourceInputKind::NativePointInTimeSnapshot => invocation
            .source_manifest
            .provenance
            .native_snapshot
            .as_ref()
            .ok_or(PlanProtocolError::Invalid(
                "native source provenance lacks snapshot evidence",
            ))?
            .provider_evidence_sha256,
    };
    let source = SourceSeal {
        snapshot_id: format!(
            "source-{}",
            hex::encode(
                invocation.source_manifest.source_object_sha256
            ),
        ),
        manifest_sha256:
            invocation.source_manifest.filesystem.manifest_sha256,
        canonical_bundle_sha256,
        source_root_sha256:
            invocation.source_manifest.provenance.provenance_sha256,
        immutable_object_sha256:
            invocation.source_manifest.source_object_sha256,
    };
    let exact_oci_digests = artifact
        .reference
        .oci_objects
        .iter()
        .map(|object| {
            format!(
                "sha256:{}",
                hex::encode(object.manifest_digest_sha256),
            )
        })
        .collect();
    let artifact_seal = ArtifactSeal {
        artifact_set_id: format!(
            "artifact-{}",
            hex::encode(artifact.reference.object_sha256),
        ),
        source_manifest_sha256:
            artifact.reference.source_manifest_sha256,
        filesystem_manifest_sha256:
            artifact.reference.manifest_sha256,
        oci_manifest_sha256:
            canonical_sha256(&artifact.reference.oci_objects)?,
        exact_oci_digests,
        immutable_object_sha256: artifact.reference.object_sha256,
    };
    let mut lanes = Vec::with_capacity(internal.lanes.len());
    for (index, lane) in internal.lanes.iter().enumerate() {
        let plan_lane = invocation
            .plan
            .lanes
            .iter()
            .find(|candidate| candidate.lane == lane.lane)
            .ok_or(PlanProtocolError::Invalid(
                "executor emitted evidence outside the fixed five lanes",
            ))?;
        let request_sha256 = sha256_bytes(
            &[
                invocation.envelope.invocation_sha256.as_slice(),
                lane.terminal_sha256.as_slice(),
                &[index as u8],
            ]
            .concat(),
        );
        let cleanup_intent_sha256 = sha256_bytes(
            &[
                b"serverware/executor-lane-cleanup-intent/v12\0"
                    .as_slice(),
                invocation.plan.plan_sha256.as_slice(),
                lane.terminal_sha256.as_slice(),
            ]
            .concat(),
        );
        lanes.push(LaneEvidence {
            lane: controller_lane(lane.lane),
            phase: ControllerLanePhase::Body,
            request_sha256,
            runner_identity_sha256:
                canonical_sha256(&plan_lane.prepare.runner)?,
            docker_transcript_sha256: lane.terminal_sha256,
            runtime_evidence_sha256:
                lane.runner_runtime_report_sha256,
            cleanup_intent_sha256,
            terminal_sha256: lane.terminal_sha256,
            exit_code: 0,
            artifact_seal: (lane.lane == LogicalLane::Build)
                .then(|| artifact_seal.clone()),
        });
    }
    let exact_internal = canonical_bytes(&internal)?;
    let terminal_evidence_root_sha256 = sha256_bytes(
        &[
            internal.evidence_sha256.as_slice(),
            internal.readiness_evidence_sha256.as_slice(),
            artifact.reference.manifest_sha256.as_slice(),
        ]
        .concat(),
    );
    let terminal_state_root_sha256 = sha256_bytes(
        &[
            &[u8::from(internal.build_dind_destroyed)],
            &[u8::from(internal.no_build_dind_destroyed)],
            internal.plan_sha256.as_slice(),
        ]
        .concat(),
    );
    let execution_result_sha256 =
        canonical_sha256(&internal.lanes)?;
    let mut terminal = ExecutorTerminalEvidenceV12 {
        protocol: CONTROLLER_EXECUTOR_PROTOCOL_V12.to_owned(),
        invocation_sha256: invocation.envelope.invocation_sha256,
        request_sha256:
            invocation.envelope.request.exact_request_sha256,
        terminal_evidence_root_sha256,
        terminal_state_root_sha256,
        execution_result_sha256,
        source,
        artifacts: Some(artifact_seal),
        lanes,
        verdict: TerminalVerdict::Pass,
        failure_code: None,
        executor_exact_evidence_base64url:
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&exact_internal),
        executor_exact_evidence_sha256: sha256_bytes(&exact_internal),
        completed_at_boottime_ns: internal.completed_at_boottime_ns,
        evidence_sha256: [0; 32],
    };
    let mut projection = terminal.clone();
    projection.evidence_sha256 = [0; 32];
    terminal.evidence_sha256 =
        controller_sha256(&serde_json::to_vec(&projection)?);
    terminal
        .validate_for(&invocation.envelope)
        .map_err(|error| {
            PlanProtocolError::InvalidOwned(error.to_string())
        })?;
    Ok(terminal)
}

fn controller_lane(lane: LogicalLane) -> ControllerLogicalLane {
    match lane {
        LogicalLane::Build => ControllerLogicalLane::Build,
        LogicalLane::Unit => ControllerLogicalLane::Unit,
        LogicalLane::Integration => ControllerLogicalLane::Integration,
        LogicalLane::E2e => ControllerLogicalLane::E2e,
        LogicalLane::Attestation => ControllerLogicalLane::Attestation,
    }
}

pub fn run_executor_v12_cli() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() < 3 || arguments[0] != "--config" {
        return Err(
            "usage: serverware-coder-plan-executor-v12 --config ABSOLUTE_PATH \
             <health|daemon|run-fixed-phase-v12>"
                .into(),
        );
    }
    let config_path = std::path::PathBuf::from(&arguments[1]);
    let config_digest = pin_executor_configuration(&config_path)?;
    let pinned = pinned_executor_policy()?;
    if unsafe { libc::geteuid() } != pinned.executor_uid {
        return Err(
            "plan executor UID differs from the pinned static configuration"
                .into(),
        );
    }
    pinned
        .readiness_trust
        .clone()
        .into_runtime()
        .map_err(|error| error.to_string())?;
    pinned
        .runtime_observer_policy
        .clone()
        .into_runtime()
        .map_err(|error| error.to_string())?;
    if std::env::var("SERVERWARE_CODER_REQUIRE_PER_INVOCATION_READINESS_V12")
        .as_deref()
        != Ok("1")
    {
        return Err(
            "systemd did not require full signed readiness before every repository invocation"
                .into(),
        );
    }
    match arguments[2].to_str() {
        Some("health") if arguments.len() == 3 => {
            if HARD_UNREADY.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(
                    "executor is hard-unready because cleanup or durable operation state is unknown"
                        .into(),
                );
            }
            println!(
                "{{\"version\":\"serverware/coder-plan-executor/v12\",\
                 \"config_sha256\":\"{}\",\
                 \"per_invocation_probe_order\":\"docker-upgrade,service-health,chromium,teardown\",\
                 \"readiness_before_repository_work\":true,\
                 \"status\":\"ready\"}}",
                config_digest
            );
            Ok(())
        }
        Some("daemon") if arguments.len() == 3 => {
            run_v12_systemd_daemon()
        }
        Some("run-fixed-phase-v12") if arguments.len() == 5 => {
            run_fixed_phase_v12(&arguments[3..])
        }
        _ => Err("unsupported plan executor v12 mode".into()),
    }
}

fn run_fixed_phase_v12(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let capability = arguments
        .first()
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix("--capability-fd="))
        .ok_or_else(|| {
            "run-fixed-phase-v12 requires --capability-fd=N".to_owned()
        })?
        .parse::<RawFd>()
        .map_err(|_| "capability FD is not an integer")?;
    if capability < 3 {
        return Err("capability FD must be greater than 2".into());
    }
    let phase = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .and_then(|value| value.strip_prefix("--logical-phase="))
        .and_then(parse_fixed_logical_phase)
        .ok_or_else(|| {
            "logical phase must be exactly BUILD, UNIT, INTEGRATION, E2E, or ATTESTATION"
                .to_owned()
        })?;
    validate_v12_packet_socket(capability)?;
    ACTIVE_EXECUTOR_MODE
        .set("run-fixed-phase-v12".to_owned())
        .map_err(|_| "executor mode was already selected")?;
    handle_controller_rpc(capability, Some(phase))
        .map_err(|error| error.to_string())
}

fn parse_fixed_logical_phase(
    value: &str,
) -> Option<WorkflowSelectionV12> {
    match value {
        "BUILD" => Some(WorkflowSelectionV12::Build),
        "UNIT" => Some(WorkflowSelectionV12::UnitNoBuild),
        "INTEGRATION" => {
            Some(WorkflowSelectionV12::IntegrationNoBuild)
        }
        "E2E" => Some(WorkflowSelectionV12::E2eNoBuild),
        "ATTESTATION" => {
            Some(WorkflowSelectionV12::AttestationNoBuild)
        }
        _ => None,
    }
}

fn run_v12_systemd_daemon() -> Result<(), String> {
    let listen_pid = std::env::var("LISTEN_PID")
        .map_err(|_| "daemon requires LISTEN_PID from systemd socket activation")?
        .parse::<u32>()
        .map_err(|_| "LISTEN_PID is not a u32")?;
    let listen_fds = std::env::var("LISTEN_FDS")
        .map_err(|_| "daemon requires LISTEN_FDS from systemd socket activation")?
        .parse::<u32>()
        .map_err(|_| "LISTEN_FDS is not a u32")?;
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err("daemon requires exactly one socket-activated descriptor for this PID".into());
    }
    validate_v12_packet_socket(3)?;
    crate::receipt_contract_v12::notify_systemd_v12(
        "plan-executor-v12 controller-owned socket ready",
    )
    .map_err(|error| error.to_string())?;
    loop {
        let accepted = unsafe {
            libc::accept4(
                3,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if accepted < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("accept systemd plan socket: {error}"));
        }
        let _ = ACTIVE_EXECUTOR_MODE.set("daemon".into());
        let result = handle_controller_rpc(accepted, None);
        unsafe {
            libc::close(accepted);
        }
        if let Err(error) = result {
            eprintln!(
                "serverware-coder-plan-executor-v12: rejected controller RPC: {error}"
            );
        }
    }
}

fn handle_controller_rpc(
    socket: RawFd,
    expected_phase: Option<WorkflowSelectionV12>,
) -> PlanResult<()> {
    validate_v12_packet_socket(socket)
        .map_err(PlanProtocolError::InvalidOwned)?;
    let mut peer: libc::ucred = unsafe { mem::zeroed() };
    let mut peer_len =
        mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut peer as *mut libc::ucred as *mut libc::c_void,
            &mut peer_len,
        )
    } != 0
        || peer_len as usize != mem::size_of::<libc::ucred>()
        || peer.pid <= 0
        || peer.uid
            != pinned_executor_policy()
                .map_err(PlanProtocolError::InvalidOwned)?
                .controller_uid
    {
        return Err(PlanProtocolError::Invalid(
            "executor RPC peer is not the pinned controller identity",
        ));
    }
    let receive_deadline = boottime_ns()?
        .checked_add(30_000_000_000)
        .ok_or(PlanProtocolError::Invalid(
            "executor receive deadline overflow",
        ))?;
    let (header_bytes, mut descriptors) =
        receive_packet_with_fds(socket, receive_deadline)?;
    if header_bytes.len()
        != crate::receipt_contract_v12::AUTHORITY_FRAME_BYTES
        || descriptors.len()
            != EXECUTOR_INVOCATION_FD_COUNT_V12 as usize
    {
        close_fds(descriptors);
        return Err(PlanProtocolError::Invalid(
            "executor RPC requires one frame and the exact three descriptor roles",
        ));
    }
    let header_array: [u8;
        crate::receipt_contract_v12::AUTHORITY_FRAME_BYTES] =
        header_bytes.try_into().map_err(|_| {
            PlanProtocolError::Invalid(
                "executor RPC frame length changed after validation",
            )
        })?;
    let header =
        crate::receipt_contract_v12::AuthorityFrameHeaderV12::decode(
            &header_array,
            MAX_INVOCATION_BYTES,
        )
        .map_err(|error| {
            PlanProtocolError::InvalidOwned(error.to_string())
        })?;
    if header.boottime_deadline_ns <= boottime_ns()? {
        close_fds(descriptors);
        return Err(PlanProtocolError::Invalid(
            "executor RPC frame expired before decoding",
        ));
    }
    let payload_fd = descriptors.remove(
        EXECUTOR_INVOCATION_PAYLOAD_FD_INDEX_V12 as usize,
    );
    let source_index =
        (EXECUTOR_SOURCE_INPUT_FD_INDEX_V12 - 1) as usize;
    let source_fd = descriptors.remove(source_index);
    let lane_index =
        (EXECUTOR_LANE_PROXY_FD_INDEX_V12 - 2) as usize;
    let lane_proxy_fd = descriptors.remove(lane_index);
    if !descriptors.is_empty() {
        close_fds(descriptors);
        return Err(PlanProtocolError::Invalid(
            "executor RPC retained an unassigned descriptor",
        ));
    }
    let invocation_bytes =
        read_sealed_invocation(payload_fd.as_raw_fd())?;
    if invocation_bytes.len() as u64 != header.payload_bytes
        || sha256_bytes(&invocation_bytes)
            != header.payload_sha256.decode().map_err(|error| {
                PlanProtocolError::InvalidOwned(error.to_string())
            })?
    {
        return Err(PlanProtocolError::Invalid(
            "executor invocation memfd differs from the framed digest",
        ));
    }
    let envelope: ControllerWorkflowInvocationV12 =
        serde_json::from_slice(&invocation_bytes)?;
    if canonical_bytes(&envelope)? != invocation_bytes {
        return Err(PlanProtocolError::Invalid(
            "executor invocation is not canonical JSON",
        ));
    }
    let response_deadline = envelope.cleanup_deadline_boottime_ns;
    let invocation = resolve_controller_invocation(
        envelope,
        source_fd,
        lane_proxy_fd,
        expected_phase,
    )?;
    let evidence = execute_invocation(invocation)?;
    let evidence_bytes = canonical_bytes(&evidence)?;
    let evidence_fd = create_sealed_memfd_v12(
        "serverware-plan-executor-evidence-v12",
        &evidence_bytes,
    )?;
    let response_header =
        crate::receipt_contract_v12::AuthorityFrameHeaderV12::for_payload(
            &evidence_bytes,
            response_deadline,
            MAX_INVOCATION_BYTES,
        )
        .map_err(|error| {
            PlanProtocolError::InvalidOwned(error.to_string())
        })?
        .encode(MAX_INVOCATION_BYTES)
        .map_err(|error| {
            PlanProtocolError::InvalidOwned(error.to_string())
        })?;
    send_packet_with_fds(
        socket,
        &response_header,
        &[evidence_fd.as_raw_fd()],
        response_deadline,
    )
}

fn create_sealed_memfd_v12(
    name: &str,
    bytes: &[u8],
) -> PlanResult<OwnedFd> {
    if bytes.is_empty() || bytes.len() > MAX_INVOCATION_BYTES {
        return Err(PlanProtocolError::Invalid(
            "sealed executor payload size is invalid",
        ));
    }
    let name = CString::new(name).map_err(|_| {
        PlanProtocolError::Invalid("memfd name contains NUL")
    })?;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes)?;
    file.sync_all()?;
    if unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS)
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file.into())
}

static ACTIVE_EXECUTOR_MODE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn validate_v12_packet_socket(fd: RawFd) -> Result<(), String> {
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut _ as *mut libc::c_void,
            &mut socket_type_len,
        )
    } != 0
    {
        return Err(format!(
            "fd {fd} is not the required Unix packet socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    if socket_type != libc::SOCK_SEQPACKET {
        return Err(format!("fd {fd} is not SOCK_SEQPACKET"));
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut address_len =
        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            address.as_mut_ptr() as *mut libc::sockaddr,
            &mut address_len,
        )
    } != 0
    {
        return Err(format!(
            "inspect fd {fd} socket family: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { address.assume_init() }.ss_family as libc::c_int != libc::AF_UNIX {
        return Err(format!("fd {fd} is not AF_UNIX"));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorStaticConfigurationV12 {
    pub version: String,
    pub controller_generation: u64,
    pub executor_uid: u32,
    pub controller_uid: u32,
    pub lane_proxy_uid: u32,
    pub readiness_trust: readiness::PinnedReadinessTrustV12,
    pub runtime_observer_policy: runtime_evidence::PinnedRuntimeObserverPolicyV12,
    pub inherited_proxy_executable_sha256: plan_protocol::Digest,
    pub lifecycle_root_signer_spki_sha256: String,
    pub full_signed_readiness_before_repository_work_every_invocation: bool,
    pub cleanup_reserve_alias: String,
    pub durable_operation_ledger_root: std::path::PathBuf,
    pub durable_operation_ledger_key_id: String,
    pub durable_operation_ledger_public_key_b64: String,
    pub operation_query_poll_interval_ms: u64,
}

impl ExecutorStaticConfigurationV12 {
    pub const VERSION: &'static str = "serverware/coder-plan-executor-config/v12";

    fn validate(&self) -> Result<(), String> {
        if self.version != Self::VERSION
            || self.controller_generation == 0
            || self.executor_uid == 0
            || self.controller_uid == 0
            || self.lane_proxy_uid == 0
            || self.executor_uid == self.controller_uid
            || self.executor_uid == self.lane_proxy_uid
            || self.controller_uid == self.lane_proxy_uid
            || !self
                .full_signed_readiness_before_repository_work_every_invocation
            || self.readiness_trust.controller_generation != self.controller_generation
            || !is_executor_private_alias(&self.cleanup_reserve_alias)
            || !self.durable_operation_ledger_root.is_absolute()
            || self.durable_operation_ledger_key_id.is_empty()
            || !(1..=1_000).contains(&self.operation_query_poll_interval_ms)
        {
            return Err("executor configuration header is invalid".into());
        }
        if self.inherited_proxy_executable_sha256 == [0; 32] {
            return Err("pinned inherited proxy executable digest is empty".into());
        }
        self.lifecycle_root_signer_digest()?;
        validate_durable_operation_ledger_key(self)?;
        Ok(())
    }

    fn lifecycle_root_signer_digest(
        &self,
    ) -> Result<plan_protocol::Digest, String> {
        if self.lifecycle_root_signer_spki_sha256.len() != 64
            || !self
                .lifecycle_root_signer_spki_sha256
                .bytes()
                .all(|byte| {
                    byte.is_ascii_digit()
                        || (b'a'..=b'f').contains(&byte)
                })
        {
            return Err(
                "pinned lifecycle root signer digest is invalid".into(),
            );
        }
        hex::decode(&self.lifecycle_root_signer_spki_sha256)
            .map_err(|_| {
                "decode lifecycle root signer digest".to_owned()
            })?
            .try_into()
            .map_err(|_| {
                "lifecycle root signer digest is not 32 bytes"
                    .to_owned()
            })
    }
}

fn validate_durable_operation_ledger_key(
    configuration: &ExecutorStaticConfigurationV12,
) -> Result<(), String> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(configuration.durable_operation_ledger_public_key_b64.as_bytes())
        .map_err(|_| "durable operation ledger key is not valid base64")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "durable operation ledger key is not 32 bytes")?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| "durable operation ledger key is not valid Ed25519")?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableOperationDispositionV12 {
    Applied,
    Conflict,
    Unknown,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableOperationRecordV12 {
    pub version: String,
    pub boot_id_sha256: Digest,
    pub operation_sha256: Digest,
    pub request_sha256: Digest,
    pub disposition: DurableOperationDispositionV12,
    pub sequence: u64,
    pub finalized_boottime_ns: Option<u64>,
    pub result_sha256: Option<Digest>,
    pub result_base64url: Option<String>,
    pub canonical_record_sha256: Digest,
    pub signer_key_id: String,
    pub signature_b64: String,
}

impl DurableOperationRecordV12 {
    const VERSION: &'static str = "serverware/plan-proxy-operation-ledger/v12";

    fn verify(
        &self,
        expected_operation_sha256: &Digest,
        configuration: &ExecutorStaticConfigurationV12,
    ) -> Result<(), String> {
        use base64::Engine as _;
        use sha2::Digest as _;

        if self.version != Self::VERSION
            || self.boot_id_sha256 != current_boot_id_sha256()
                .map_err(|error| error.to_string())?
            || &self.operation_sha256 != expected_operation_sha256
            || self.sequence == 0
            || self.signer_key_id != configuration.durable_operation_ledger_key_id
        {
            return Err("durable operation record header mismatch".into());
        }
        require_executor_digest(&self.operation_sha256, "durable operation digest")?;
        require_executor_digest(&self.request_sha256, "durable request digest")?;
        if let Some(result) = &self.result_sha256 {
            require_executor_digest(result, "durable operation result")?;
        }
        match self.disposition {
            DurableOperationDispositionV12::Applied
            | DurableOperationDispositionV12::Conflict => {
                if self.finalized_boottime_ns.is_none()
                    || self.result_sha256.is_none()
                    || self.result_base64url.is_none()
                {
                    return Err("terminal durable operation record is incomplete".into());
                }
            }
            DurableOperationDispositionV12::Unknown => {
                if self.finalized_boottime_ns.is_some()
                    || self.result_sha256.is_some()
                    || self.result_base64url.is_some()
                {
                    return Err("unknown durable operation record claims terminal data".into());
                }
            }
        }
        if let (Some(encoded), Some(expected)) =
            (&self.result_base64url, &self.result_sha256)
        {
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| "durable operation result is not base64url")?;
            if bytes.len() > MAX_FRAME_BYTES || sha256_bytes(&bytes) != *expected {
                return Err("durable operation result bytes differ from digest".into());
            }
        }

        let mut unsigned = self.clone();
        unsigned.canonical_record_sha256 = [0; 32];
        unsigned.signature_b64.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| format!("serialize durable operation record: {error}"))?;
        let observed: Digest = sha2::Sha256::digest(&bytes).into();
        if observed != self.canonical_record_sha256 {
            return Err("durable operation canonical digest mismatch".into());
        }

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(configuration.durable_operation_ledger_public_key_b64.as_bytes())
            .map_err(|_| "durable operation ledger key is not base64")?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "durable operation ledger key is not 32 bytes")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| "durable operation ledger key is not valid Ed25519")?;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(self.signature_b64.as_bytes())
            .map_err(|_| "durable operation signature is not base64")?;
        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|_| "durable operation signature is not valid Ed25519")?;
        let mut signed = b"serverware/plan-proxy-operation-ledger/v12\0".to_vec();
        signed.extend_from_slice(
            hex::encode(self.canonical_record_sha256).as_bytes(),
        );
        key.verify_strict(&signed, &signature)
            .map_err(|_| "durable operation signature verification failed".into())
    }
}

static HARD_UNREADY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn require_executor_digest(value: &Digest, field: &str) -> Result<(), String> {
    if *value == [0; 32] {
        Err(format!("{field} is empty"))
    } else {
        Ok(())
    }
}

fn durable_operation_query_until(
    operation_sha256: &Digest,
    deadline_boottime_ns: u64,
    cleanup_operation: bool,
) -> DurableOperationDispositionV12 {
    let outcome = durable_operation_query_until_inner(operation_sha256, deadline_boottime_ns)
        .unwrap_or(DurableOperationDispositionV12::Unknown);
    if cleanup_operation && matches!(outcome, DurableOperationDispositionV12::Unknown) {
        HARD_UNREADY.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    outcome
}

fn durable_operation_query_until_inner(
    operation_sha256: &Digest,
    deadline_boottime_ns: u64,
) -> Result<DurableOperationDispositionV12, String> {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let configuration = pinned_executor_policy()?;
    require_executor_digest(operation_sha256, "queried durable operation digest")?;
    let operation_text = hex::encode(operation_sha256);
    let root_path = std::ffi::CString::new(
        configuration
            .durable_operation_ledger_root
            .as_os_str()
            .as_bytes(),
    )
    .map_err(|_| "durable ledger path contains NUL")?;
    let root_raw = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_raw < 0 {
        return Err(format!(
            "open durable operation ledger: {}",
            std::io::Error::last_os_error()
        ));
    }
    let root = unsafe { OwnedFd::from_raw_fd(root_raw) };
    verify_root_owned_directory(root.as_raw_fd())?;
    let file_name = std::ffi::CString::new(format!("{operation_text}.json"))
        .map_err(|_| "durable operation filename contains NUL")?;

    loop {
        let now = executor_boottime_ns()?;
        if now >= deadline_boottime_ns {
            return Ok(DurableOperationDispositionV12::Unknown);
        }
        let raw = unsafe {
            libc::openat(
                root.as_raw_fd(),
                file_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw >= 0 {
            let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
            let metadata = file
                .metadata()
                .map_err(|error| format!("stat durable operation record: {error}"))?;
            if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024
            {
                HARD_UNREADY.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(
                    "durable operation journal is structurally incompatible; in-service migration is forbidden, use offline-state-quarantine-v12.sh while v12 is stopped"
                        .into(),
                );
            } else {
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                std::io::Read::read_to_end(&mut file, &mut bytes)
                    .map_err(|error| format!("read durable operation record: {error}"))?;
                match serde_json::from_slice::<DurableOperationRecordV12>(&bytes) {
                    Ok(record) if record.verify(operation_sha256, configuration).is_ok() => {
                        match record.disposition {
                            DurableOperationDispositionV12::Applied => {
                                return Ok(DurableOperationDispositionV12::Applied);
                            }
                            DurableOperationDispositionV12::Conflict => {
                                return Ok(DurableOperationDispositionV12::Conflict);
                            }
                            DurableOperationDispositionV12::Unknown => {}
                        }
                    }
                    _ => {
                        HARD_UNREADY.store(true, std::sync::atomic::Ordering::SeqCst);
                        return Err(
                            "durable operation journal is structurally incompatible; in-service migration is forbidden, use offline-state-quarantine-v12.sh while v12 is stopped"
                                .into(),
                        );
                    }
                }
            }
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                HARD_UNREADY.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(format!(
                    "open durable operation record: {error}",
                ));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(
            configuration.operation_query_poll_interval_ms,
        ));
    }
}

fn verify_root_owned_directory(fd: RawFd) -> Result<(), String> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "stat durable operation ledger root: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_nlink == 0
        || stat.st_mode & 0o022 != 0
    {
        return Err("durable operation ledger root is not root-owned and immutable".into());
    }
    Ok(())
}

fn executor_boottime_ns() -> Result<u64, String> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } != 0 {
        return Err(format!(
            "read CLOCK_BOOTTIME: {}",
            std::io::Error::last_os_error()
        ));
    }
    u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|base| u64::try_from(now.tv_nsec).ok().and_then(|ns| base.checked_add(ns)))
        .ok_or_else(|| "CLOCK_BOOTTIME overflow".into())
}

fn is_executor_private_alias(alias: &str) -> bool {
    alias.len() == 36
        && alias.starts_with("svc-")
        && alias[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !alias.contains('.')
        && !alias.contains(':')
        && alias.parse::<std::net::IpAddr>().is_err()
}

static PINNED_EXECUTOR_CONFIGURATION_BYTES: std::sync::OnceLock<Vec<u8>> =
    std::sync::OnceLock::new();
static PINNED_EXECUTOR_CONFIGURATION: std::sync::OnceLock<ExecutorStaticConfigurationV12> =
    std::sync::OnceLock::new();

pub fn pinned_executor_configuration() -> Result<&'static [u8], String> {
    PINNED_EXECUTOR_CONFIGURATION_BYTES
        .get()
        .map(Vec::as_slice)
        .ok_or_else(|| "executor configuration has not been pinned".into())
}

pub fn pinned_executor_policy() -> Result<&'static ExecutorStaticConfigurationV12, String> {
    PINNED_EXECUTOR_CONFIGURATION
        .get()
        .ok_or_else(|| "executor configuration policy has not been pinned".into())
}

fn pin_executor_configuration(path: &std::path::Path) -> Result<String, String> {
    use std::os::fd::{FromRawFd as _, RawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use sha2::Digest as _;

    if !path.is_absolute() {
        return Err("executor configuration path must be absolute".into());
    }
    let path_bytes = path.as_os_str().as_bytes();
    let path_c = std::ffi::CString::new(path_bytes)
        .map_err(|_| "executor configuration path contains NUL")?;
    let raw_fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw_fd < 0 {
        return Err(format!(
            "open executor configuration: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd as RawFd) };
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat executor configuration: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "executor configuration must be a root-owned, singly-linked, non-writable regular file"
                .into(),
        );
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|error| format!("read executor configuration: {error}"))?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("executor configuration size is outside the allowed range".into());
    }
    let digest = hex::encode(sha2::Sha256::digest(&bytes));
    let expected = std::env::var("SERVERWARE_CODER_PLAN_EXECUTOR_CONFIG_SHA256")
        .map_err(|_| "SERVERWARE_CODER_PLAN_EXECUTOR_CONFIG_SHA256 is not set")?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || expected != digest
    {
        return Err("executor configuration does not match the externally pinned digest".into());
    }
    let configuration: ExecutorStaticConfigurationV12 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse executor configuration: {error}"))?;
    configuration.validate()?;
    PINNED_EXECUTOR_CONFIGURATION
        .set(configuration)
        .map_err(|_| "executor configuration was already pinned to different bytes")?;
    PINNED_EXECUTOR_CONFIGURATION_BYTES
        .set(bytes)
        .map_err(|_| "executor configuration bytes were already pinned")?;
    Ok(digest)
}

fn pinned_readiness_trust(
    fixture: &readiness::SignedReadinessFixtureV12,
) -> Result<readiness::ReadinessFixtureTrust, String> {
    let pinned = &pinned_executor_policy()?.readiness_trust;
    pinned
        .verify_binding(fixture)
        .map_err(|error| error.to_string())?;
    pinned
        .clone()
        .into_runtime()
        .map_err(|error| error.to_string())
}

fn verify_authoritative_runtime_evidence(
    evidence: &runtime_evidence::RunnerRuntimeEvidenceV12,
    expected_runner_identity_sha256: &Digest,
    expected_command_sha256: &Digest,
    expected_namespaces: &runtime_evidence::RuntimeNamespaceIdentityV12,
) -> Result<(), String> {
    let policy = pinned_executor_policy()?
        .runtime_observer_policy
        .clone()
        .into_runtime()
        .map_err(|error| error.to_string())?;
    let proxy_digest = &pinned_executor_policy()?.inherited_proxy_executable_sha256;
    evidence
        .validate_authoritative_join(
            expected_runner_identity_sha256,
            proxy_digest,
            expected_command_sha256,
            expected_namespaces,
            &policy,
        )
        .map_err(|error| error.to_string())
}

fn verify_service_instances(
    plan: &LogicalPlanV12,
    trust: &ManifestTrustPolicy,
) -> PlanResult<()> {
    let mut instance_ids = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    for lane in &plan.lanes[1..] {
        for service in &lane.prepare.services {
            service.validate()?;
            if !instance_ids.insert(service.service_id)
                || !aliases.insert(service.private_alias.as_str())
            {
                return Err(PlanProtocolError::Invalid(
                    "service instance identity or alias is reused",
                ));
            }
            trust.verify_domain(
                b"serverware/service-instance-signature/v12\0",
                &service.signer_key_id,
                &service.instance_sha256,
                &service.signature,
            )?;
        }
    }
    Ok(())
}

type PlanExecutionResult = (
    PublishedArtifactCas,
    Vec<LaneExecutionEvidenceV12>,
    bool,
    bool,
);

fn execute_plan<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    source: &PublishedSourceCas,
    artifact_store: &ArtifactCasStore,
    artifact_publication_control: &PublicationControlV12,
    selection: WorkflowSelectionV12,
    session: &mut ProxySession<T>,
) -> PlanResult<PlanExecutionResult> {
    plan.validate()?;
    match selection {
        WorkflowSelectionV12::FullWorkflow => {
            let (artifact, build_evidence) = execute_build_phase(
                plan,
                source,
                artifact_store,
                artifact_publication_control,
                session,
            )?;
            let mut lane_evidence = vec![build_evidence];
            lane_evidence.extend(execute_no_build_phases(
                plan,
                source,
                &artifact,
                &plan.lanes[1..],
                session,
            )?);
            Ok((artifact, lane_evidence, true, true))
        }
        WorkflowSelectionV12::Build => {
            let (artifact, evidence) = execute_build_phase(
                plan,
                source,
                artifact_store,
                artifact_publication_control,
                session,
            )?;
            Ok((artifact, vec![evidence], true, false))
        }
        fixed => {
            let lane = fixed.selected_lane().ok_or(
                PlanProtocolError::Invalid(
                    "fixed executor selection has no lane",
                ),
            )?;
            let index = match lane {
                ControllerLogicalLane::Build => {
                    return Err(PlanProtocolError::Invalid(
                        "build selection was not routed to build phase",
                    ))
                }
                ControllerLogicalLane::Unit => 1,
                ControllerLogicalLane::Integration => 2,
                ControllerLogicalLane::E2e => 3,
                ControllerLogicalLane::Attestation => 4,
            };
            let expected = plan.lanes[index]
                .prepare
                .artifacts
                .as_ref()
                .ok_or(PlanProtocolError::Invalid(
                    "no-build phase lacks its pinned artifact reference",
                ))?;
            let artifact = artifact_store.load_published(
                expected,
                artifact_publication_control,
            )?;
            let evidence = execute_no_build_phases(
                plan,
                source,
                &artifact,
                &plan.lanes[index..=index],
                session,
            )?;
            Ok((artifact, evidence, false, true))
        }
    }
}

fn execute_build_phase<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    source: &PublishedSourceCas,
    artifact_store: &ArtifactCasStore,
    artifact_publication_control: &PublicationControlV12,
    session: &mut ProxySession<T>,
) -> PlanResult<(PublishedArtifactCas, LaneExecutionEvidenceV12)> {
    let build_lane = &plan.lanes[0];
    create_build_dind(plan, build_lane, source, session)?;
    let mut build_runner_active = false;
    let build_execution = (|| {
        for pull in &build_lane
            .prepare
            .exact_build
            .as_ref()
            .ok_or(PlanProtocolError::Invalid(
                "build tuple is absent",
            ))?
            .pinned_pulls
        {
            let pull_sha256 = canonical_sha256(pull)?;
            let payload = base_payload(
                plan,
                build_lane,
                ProxyOperation::PullPinned,
                ProxyPayloadContentV12::PullPinned {
                    pull: pull.clone(),
                },
            );
            require_applied(
                session.call(
                    LogicalLane::Build,
                    PlanPhase::Prepare,
                    ProxyOperation::PullPinned,
                    AuthoritativeLaneState::Preparing,
                    pull_sha256,
                    &payload,
                    &[],
                )?,
                plan,
                LogicalLane::Build,
                ProxyOperation::PullPinned,
            )?;
        }
        let build_tuple = build_lane
            .prepare
            .exact_build
            .as_ref()
            .ok_or(PlanProtocolError::Invalid(
                "build tuple is absent",
            ))?;
        let exact_build_sha256 = canonical_sha256(build_tuple)?;
        let payload = base_payload(
            plan,
            build_lane,
            ProxyOperation::BuildExact,
            ProxyPayloadContentV12::BuildExact {
                exact_build: build_tuple.clone(),
            },
        );
        require_applied(
            session.call(
                LogicalLane::Build,
                PlanPhase::Prepare,
                ProxyOperation::BuildExact,
                AuthoritativeLaneState::Preparing,
                exact_build_sha256,
                &payload,
                &[],
            )?,
            plan,
            LogicalLane::Build,
            ProxyOperation::BuildExact,
        )?;
        create_runner(plan, build_lane, session)?;
        build_runner_active = true;
        let build_evidence =
            run_body(plan, build_lane, None, session)?;
        stop_runner(plan, build_lane, session)?;
        build_runner_active = false;
        let exported =
            export_artifacts(plan, build_lane, session)?;
        let artifact_input =
            AuthenticatedDirectoryInput::from_retained_fd(
                exported.0,
            )?;
        let published = artifact_store
            .publish(
                artifact_input,
                exported.1,
                artifact_publication_control,
            )?;
        if published.reference.manifest_sha256
                != plan.expected_artifact_manifest_sha256
            || published.reference
                != plan.lanes[1]
                    .prepare
                    .artifacts
                    .as_ref()
                    .ok_or(PlanProtocolError::Invalid(
                        "expected artifact reference is absent",
                    ))?
                    .clone()
        {
            return Err(PlanProtocolError::Invalid(
                "published artifacts differ from logical plan",
            ));
        }
        Ok((published, build_evidence))
    })();
    if build_runner_active {
        let _ = stop_runner(plan, build_lane, session);
    }
    let (artifact, build_evidence) = build_execution?;
    destroy_generation(
        plan,
        LogicalLane::Build,
        DindGenerationKind::Build,
        session,
        b"build sealed",
    )?;
    Ok((artifact, build_evidence))
}

fn execute_no_build_phases<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    source: &PublishedSourceCas,
    artifact: &PublishedArtifactCas,
    lanes: &[LogicalLaneContract],
    session: &mut ProxySession<T>,
) -> PlanResult<Vec<LaneExecutionEvidenceV12>> {
    if lanes.is_empty()
        || lanes.iter().any(|lane| lane.lane == LogicalLane::Build)
    {
        return Err(PlanProtocolError::Invalid(
            "no-build executor phase set is empty or contains build",
        ));
    }
    let anchor = lanes.first().ok_or(
        PlanProtocolError::Invalid(
            "no-build phase set disappeared before preparation",
        ),
    )?;
    create_no_build_dind(plan, anchor, source, &artifact, session)?;
    import_sealed_oci(plan, anchor, &artifact, session)?;
    let mut lane_evidence = Vec::with_capacity(lanes.len());
    for lane in lanes {
        let mut services_active = false;
        let mut runner_active = false;
        let lane_result: PlanResult<LaneExecutionEvidenceV12> = (|| {
            if !lane.prepare.services.is_empty() {
                create_services(plan, lane, session)?;
                services_active = true;
            }
            create_runner(plan, lane, session)?;
            runner_active = true;
            let evidence =
                run_body(plan, lane, Some(&artifact), session)?;
            stop_runner(plan, lane, session)?;
            runner_active = false;
            if services_active {
                destroy_services(plan, lane, session)?;
                services_active = false;
            }
            Ok(evidence)
        })();
        if runner_active {
            let _ = stop_runner(plan, lane, session);
        }
        if services_active {
            let _ = destroy_services(plan, lane, session);
        }
        lane_evidence.push(lane_result?);
    }
    destroy_generation(
        plan,
        lanes
            .last()
            .ok_or(PlanProtocolError::Invalid(
                "no-build phase set disappeared",
            ))?
            .lane,
        DindGenerationKind::NoBuild,
        session,
        b"all no-build lanes terminal",
    )?;
    Ok(lane_evidence)
}

fn create_build_dind<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    source: &PublishedSourceCas,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    let exact_build_sha256 = canonical_sha256(
        lane.prepare.exact_build.as_ref().ok_or(
            PlanProtocolError::Invalid("build tuple is absent"),
        )?,
    )?;
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::CreateBuildDind,
        ProxyPayloadContentV12::CreateBuildDind {
            generation_kind: DindGenerationKind::Build,
            exact_build: lane
                .prepare
                .exact_build
                .as_ref()
                .ok_or(PlanProtocolError::Invalid(
                    "build tuple is absent",
                ))?
                .clone(),
            runner: lane.prepare.runner.clone(),
        },
    );
    require_applied(
        session.call(
            LogicalLane::Build,
            PlanPhase::Prepare,
            ProxyOperation::CreateBuildDind,
            AuthoritativeLaneState::Declared,
            source.reference.object_sha256,
            &payload,
            &[source.object_fd.as_raw_fd()],
        )?,
        plan,
        LogicalLane::Build,
        ProxyOperation::CreateBuildDind,
    )
}

fn create_no_build_dind<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    source: &PublishedSourceCas,
    artifact: &PublishedArtifactCas,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::CreateNoBuildDind,
        ProxyPayloadContentV12::CreateNoBuildDind {
            generation_kind: DindGenerationKind::NoBuild,
            artifacts: artifact.reference.clone(),
            required_oci_import_closure:
                RequiredOciImportClosureV12::new(
                    lane.prepare
                        .imported_oci_manifest_sha256
                        .clone(),
                )?,
            runner: lane.prepare.runner.clone(),
        },
    );
    require_applied(
        session.call(
            lane.lane,
            PlanPhase::Prepare,
            ProxyOperation::CreateNoBuildDind,
            AuthoritativeLaneState::Destroyed,
            artifact.reference.object_sha256,
            &payload,
            &[
                source.object_fd.as_raw_fd(),
                artifact.object_fd.as_raw_fd(),
            ],
        )?,
        plan,
        lane.lane,
        ProxyOperation::CreateNoBuildDind,
    )
}

fn import_sealed_oci<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    artifact: &PublishedArtifactCas,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    for digest in &plan.no_build_oci_import_closure_sha256 {
        let object = artifact
            .reference
            .oci_objects
            .iter()
            .find(|object| &object.manifest_digest_sha256 == digest)
            .ok_or(PlanProtocolError::Invalid(
                "sealed OCI import is absent from artifact CAS",
            ))?;
        let payload = base_payload(
            plan,
            lane,
            ProxyOperation::ImportSealedOci,
            ProxyPayloadContentV12::ImportSealedOci {
                object: object.clone(),
                artifact_object_sha256:
                    artifact.reference.object_sha256,
            },
        );
        require_applied(
            session.call(
                lane.lane,
                PlanPhase::Prepare,
                ProxyOperation::ImportSealedOci,
                AuthoritativeLaneState::Preparing,
                *digest,
                &payload,
                &[],
            )?,
            plan,
            lane.lane,
            ProxyOperation::ImportSealedOci,
        )?;
    }
    Ok(())
}

fn create_runner<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    let runner_sha256 = canonical_sha256(&lane.prepare.runner)?;
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::CreateRunner,
        ProxyPayloadContentV12::CreateRunner {
            runner: lane.prepare.runner.clone(),
            command: lane.body.command.clone(),
        },
    );
    require_applied(
        session.call(
            lane.lane,
            PlanPhase::Prepare,
            ProxyOperation::CreateRunner,
            AuthoritativeLaneState::Prepared,
            runner_sha256,
            &payload,
            &[],
        )?,
        plan,
        lane.lane,
        ProxyOperation::CreateRunner,
    )
}

fn create_services<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    if !matches!(lane.lane, LogicalLane::Integration | LogicalLane::E2e) {
        return Err(PlanProtocolError::Invalid(
            "services are restricted to integration/e2e",
        ));
    }
    let services_sha256 = canonical_sha256(&lane.prepare.services)?;
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::CreateServices,
        ProxyPayloadContentV12::CreateServices {
            services: lane.prepare.services.clone(),
        },
    );
    require_applied(
        session.call(
            lane.lane,
            PlanPhase::Prepare,
            ProxyOperation::CreateServices,
            AuthoritativeLaneState::Prepared,
            services_sha256,
            &payload,
            &[],
        )?,
        plan,
        lane.lane,
        ProxyOperation::CreateServices,
    )
}

fn run_body<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    artifact: Option<&PublishedArtifactCas>,
    session: &mut ProxySession<T>,
) -> PlanResult<LaneExecutionEvidenceV12> {
    if lane.body.docker_api_visible {
        return Err(PlanProtocolError::Invalid(
            "repository body requested Docker API visibility",
        ));
    }
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::RunRepositoryBody,
        ProxyPayloadContentV12::RunBody {
            body: lane.body.clone(),
            derived_service_endpoints:
                lane.derived_service_endpoints()?,
        },
    );
    let reply = session.call(
        lane.lane,
        PlanPhase::Body,
        ProxyOperation::RunRepositoryBody,
        AuthoritativeLaneState::Prepared,
        lane.body.body_sha256,
        &payload,
        &[],
    )?;
    if !reply.attached_fds.is_empty() {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "repository body returned unexpected authority FDs",
        ));
    }
    let result: BodyExecutionResultV12 =
        serde_json::from_slice(&reply.bytes)?;
    validate_body_result(plan, lane, artifact, &result)?;
    if result.exit_status != 0 {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{:?} repository body returned status {}",
            lane.lane, result.exit_status,
        )));
    }
    Ok(LaneExecutionEvidenceV12 {
        lane: lane.lane,
        prepare_sha256: lane.prepare.prepare_sha256,
        body_sha256: lane.body.body_sha256,
        command_sha256: lane.body.command.command_sha256,
        stdout_sha256: result.stdout_sha256,
        stderr_sha256: result.stderr_sha256,
        output_manifest_sha256: result.output_manifest_sha256,
        runner_runtime_report_sha256:
            result.runner_evidence.runtime_report_sha256,
        terminal_sha256: result.terminal_sha256,
    })
}

fn validate_body_result(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    artifact: Option<&PublishedArtifactCas>,
    result: &BodyExecutionResultV12,
) -> PlanResult<()> {
    if result.version != EXECUTOR_RESULT_VERSION
        || result.plan_id != plan.plan_id
        || result.lane != lane.lane
        || result.body_sha256 != lane.body.body_sha256
        || result.command_sha256
            != lane.body.command.command_sha256
        || result.stdout_sha256 == [0; 32]
        || result.stderr_sha256 == [0; 32]
        || result.output_manifest_sha256 == [0; 32]
        || result.terminal_sha256 == [0; 32]
    {
        return Err(PlanProtocolError::Invalid(
            "repository body result lost exact plan binding",
        ));
    }
    let allowed: BTreeSet<Digest> = lane
        .prepare
        .runner
        .executable_closure_sha256
        .iter()
        .copied()
        .collect();
    validate_static_role_evidence(
        &result.runner_static_evidence,
        ExecutableRole::ControllerOwnedRunner,
        &lane.prepare.runner.runtime_executable_sha256,
    )?;
    validate_static_role_evidence(
        &result.courier_static_evidence,
        ExecutableRole::StaticCourier,
        lane.prepare
            .runner
            .static_courier_sha256
            .as_ref()
            .ok_or(PlanProtocolError::Invalid(
                "runner static courier digest is absent",
            ))?,
    )?;
    result.runner_evidence.validate(
        &plan.source,
        artifact.map(|artifact| &artifact.reference),
        &lane.prepare.runner.image,
        &allowed,
    )?;
    verify_authoritative_runtime_evidence(
        &result.runner_evidence,
        &canonical_sha256(&lane.prepare.runner)?,
        &lane.body.command.command_sha256,
        &result.runner_evidence.namespaces,
    )
    .map_err(PlanProtocolError::InvalidOwned)?;
    let mut copy = result.clone();
    copy.terminal_sha256 = [0; 32];
    if sha256_bytes(&canonical_bytes(&copy)?)
        != result.terminal_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "repository body terminal digest is not canonical",
        ));
    }
    Ok(())
}

fn validate_static_role_evidence(
    evidence: &StaticExecutableEvidenceV12,
    role: ExecutableRole,
    expected_sha256: &Digest,
) -> PlanResult<()> {
    if evidence.role != role
        || &evidence.content_sha256 != expected_sha256
        || evidence.size == 0
        || !evidence.filesystem_immutable
        || !evidence.root_owned
        || !evidence.no_interpreter
        || !evidence.no_needed_libraries
        || !evidence.no_writable_executable_segment
    {
        return Err(PlanProtocolError::Invalid(
            "runner/courier static executable evidence is invalid",
        ));
    }
    Ok(())
}

fn stop_runner<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::StopRunner,
        ProxyPayloadContentV12::StopRunner {
            command_sha256: lane.body.command.command_sha256,
        },
    );
    require_applied(
        session.call(
            lane.lane,
            PlanPhase::Body,
            ProxyOperation::StopRunner,
            AuthoritativeLaneState::BodyTerminal,
            lane.body.command.command_sha256,
            &payload,
            &[],
        )?,
        plan,
        lane.lane,
        ProxyOperation::StopRunner,
    )
}

fn destroy_services<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    session: &mut ProxySession<T>,
) -> PlanResult<()> {
    let services_sha256 = canonical_sha256(&lane.prepare.services)?;
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::DestroyServices,
        ProxyPayloadContentV12::DestroyServices {
            services_sha256,
        },
    );
    require_applied(
        session.call(
            lane.lane,
            PlanPhase::Body,
            ProxyOperation::DestroyServices,
            AuthoritativeLaneState::BodyTerminal,
            services_sha256,
            &payload,
            &[],
        )?,
        plan,
        lane.lane,
        ProxyOperation::DestroyServices,
    )
}

fn export_artifacts<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    session: &mut ProxySession<T>,
) -> PlanResult<(OwnedFd, ArtifactManifestV12)> {
    let repositories = &lane
        .prepare
        .exact_build
        .as_ref()
        .ok_or(PlanProtocolError::Invalid(
            "build tuple is absent",
        ))?
        .expected_repositories;
    let expected_artifacts = plan.lanes[1]
        .prepare
        .artifacts
        .as_ref()
        .ok_or(PlanProtocolError::Invalid(
            "expected artifact reference is absent",
        ))?
        .clone();
    let payload = base_payload(
        plan,
        lane,
        ProxyOperation::ExportOwnedOci,
        ProxyPayloadContentV12::ExportOwnedOci {
            expected_artifacts,
            expected_repositories: repositories.clone(),
        },
    );
    let reply = session.call(
        lane.lane,
        PlanPhase::Prepare,
        ProxyOperation::ExportOwnedOci,
        AuthoritativeLaneState::BodyTerminal,
        plan.expected_artifact_manifest_sha256,
        &payload,
        &[],
    )?;
    if reply.attached_fds.len() != 1 {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "artifact export did not return one retained directory FD",
        ));
    }
    let result: ArtifactExportResultV12 =
        serde_json::from_slice(&reply.bytes)?;
    if result.version != EXECUTOR_RESULT_VERSION
        || result.plan_id != plan.plan_id
        || result.lane != LogicalLane::Build
        || result.artifact_manifest.filesystem.manifest_sha256
            != plan.expected_artifact_manifest_sha256
        || result.attached_directory_fd_sha256 == [0; 32]
        || result.export_transcript_sha256 == [0; 32]
    {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "artifact export result lost plan binding",
        ));
    }
    let mut fds = reply.attached_fds;
    let directory = fds.remove(0);
    Ok((directory, result.artifact_manifest))
}

fn destroy_generation<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    lane: LogicalLane,
    generation_kind: DindGenerationKind,
    session: &mut ProxySession<T>,
    reason: &[u8],
) -> PlanResult<()> {
    let reason_sha256 = sha256_bytes(reason);
    let lane_contract = &plan.lanes[lane.ordinal() as usize];
    let operation = match generation_kind {
        DindGenerationKind::Build => ProxyOperation::DestroyBuildDind,
        DindGenerationKind::NoBuild => ProxyOperation::DestroyNoBuildDind,
    };
    let payload = base_payload(
        plan,
        lane_contract,
        operation,
        ProxyPayloadContentV12::Destroy {
            reason_sha256,
            require_zero_resources: true,
        },
    );
    let reply = session.cleanup_call(
        lane,
        operation,
        reason_sha256,
        &payload,
    )?;
    if !reply.attached_fds.is_empty() {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "destruction result returned unexpected FDs",
        ));
    }
    let result: DestructionResultV12 =
        serde_json::from_slice(&reply.bytes)?;
    result.validate(&plan.plan_id, generation_kind)?;
    let receipt = reply.terminal_destruction_receipt.ok_or(
        PlanProtocolError::Invalid(
            "destruction result omitted its exact signed terminal receipt",
        ),
    )?;
    if sha256_bytes(&receipt) != result.terminal_receipt_sha256 {
        return Err(PlanProtocolError::Invalid(
            "destruction result differs from its exact signed terminal receipt",
        ));
    }
    let terminal_receipt = verify_terminal_destruction_receipt_v12(
        &receipt,
        &plan.plan_id,
        generation_kind,
    )?;
    if result.docker_top_level_object_count_scope
            != terminal_receipt.docker_top_level_object_count_scope
        || result.docker_internal_storage_absence_proof
            != terminal_receipt.docker_internal_storage_absence_proof
        || result.drained_containers != terminal_receipt.drained_containers
        || result.drained_images != terminal_receipt.drained_images
        || result.drained_networks != terminal_receipt.drained_networks
        || result.drained_volumes != terminal_receipt.drained_volumes
        || result.containers != terminal_receipt.containers
        || result.images != terminal_receipt.images
        || result.networks != terminal_receipt.networks
        || result.volumes != terminal_receipt.volumes
        || result.docker_authority_established
            != terminal_receipt.docker_authority_established
        || result.mounts != terminal_receipt.mounts
        || result.cgroup_processes != terminal_receipt.cgroup_processes
        || result.proxy_accepting != terminal_receipt.proxy_accepting
        || result.ledger_terminal != terminal_receipt.ledger_terminal
        || result.dind_reaped != terminal_receipt.dind_reaped
        || result.state_root_absent != terminal_receipt.state_root_absent
    {
        return Err(PlanProtocolError::Invalid(
            "destruction result fields differ from the exact signed terminal receipt",
        ));
    }
    Ok(())
}

fn verify_terminal_destruction_receipt_v12(
    exact: &[u8],
    plan_id: &Digest,
    generation_kind: DindGenerationKind,
) -> PlanResult<TerminalDestructionReceiptV12> {
    let receipt: TerminalDestructionReceiptV12 =
        serde_json::from_slice(exact)?;
    if canonical_bytes(&receipt)? != exact
        || receipt.version
            != "serverware/private-dind-terminal-destruction/v12"
        || receipt.trust_profile
            != "trusted-host-userspace-digest-no-ima"
        || &receipt.plan_id != plan_id
        || receipt.capability_sha256 == [0; 32]
        || receipt.profile != generation_kind
        || receipt.owner_namespace.is_empty()
        || receipt.daemon_generation.is_empty()
        || receipt.network_namespace.is_empty()
        || receipt.request_sha256 == [0; 32]
        || receipt.observed_at_boottime_ns == 0
        || receipt.docker_top_level_object_count_scope
            != DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
        || receipt.docker_internal_storage_absence_proof
            != DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
        || receipt.containers != 0
        || receipt.images != 0
        || receipt.networks != 0
        || receipt.volumes != 0
        || (!receipt.docker_authority_established
            && (receipt.drained_containers != 0
                || receipt.drained_images != 0
                || receipt.drained_networks != 0
                || receipt.drained_volumes != 0))
        || receipt.mounts != 0
        || receipt.cgroup_processes != 0
        || receipt.proxy_accepting
        || !receipt.ledger_terminal
        || !receipt.dind_reaped
        || !receipt.netns_absent
        || !receipt.socket_absent
        || !receipt.state_root_absent
        || receipt.observed_state_sha256 == [0; 32]
        || receipt.signer_public_key_spki_der.is_empty()
        || receipt.signer_public_key_spki_der.len() > 1024
        || receipt.signature.len() != 64
        || receipt.receipt_sha256 == [0; 32]
    {
        return Err(PlanProtocolError::Invalid(
            "terminal destruction receipt is incomplete or mismatched",
        ));
    }
    let pinned = pinned_executor_policy()
        .map_err(PlanProtocolError::InvalidOwned)?
        .lifecycle_root_signer_digest()
        .map_err(PlanProtocolError::InvalidOwned)?;
    if receipt.signer_spki_sha256 != pinned
        || sha256_bytes(&receipt.signer_public_key_spki_der)
            != pinned
    {
        return Err(PlanProtocolError::Invalid(
            "terminal destruction receipt signer differs from executor pin",
        ));
    }
    let mut digest_projection = receipt.clone();
    digest_projection.receipt_sha256 = [0; 32];
    if sha256_bytes(&canonical_bytes(&digest_projection)?)
        != receipt.receipt_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "terminal destruction receipt digest is not canonical",
        ));
    }
    let signature_bytes: [u8; 64] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            PlanProtocolError::Invalid(
                "terminal destruction receipt signature length is invalid",
            )
        })?;
    let key = VerifyingKey::from_public_key_der(
        &receipt.signer_public_key_spki_der,
    )
    .map_err(|_| {
        PlanProtocolError::Invalid(
            "terminal destruction receipt public key is invalid",
        )
    })?;
    let mut signature_projection = receipt.clone();
    signature_projection.signature.clear();
    signature_projection.receipt_sha256 = [0; 32];
    key.verify(
        &[
            b"serverware/private-dind-terminal-receipt/v12\0"
                .as_slice(),
            canonical_bytes(&signature_projection)?.as_slice(),
        ]
        .concat(),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| {
        PlanProtocolError::Invalid(
            "terminal destruction receipt signature is invalid",
        )
    })?;
    Ok(receipt)
}

fn force_destroy_all<T: LaneProxyTransport>(
    plan: &LogicalPlanV12,
    session: &mut ProxySession<T>,
    reason: &[u8],
) -> PlanResult<()> {
    let build = destroy_generation(
        plan,
        LogicalLane::Build,
        DindGenerationKind::Build,
        session,
        reason,
    );
    let no_build = destroy_generation(
        plan,
        LogicalLane::Attestation,
        DindGenerationKind::NoBuild,
        session,
        reason,
    );
    match (build, no_build) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(build), Ok(())) => Err(build),
        (Ok(()), Err(no_build)) => Err(no_build),
        (Err(build), Err(no_build)) => {
            Err(PlanProtocolError::InvalidOwned(format!(
                "build cleanup failed: {build}; no-build cleanup failed: {no_build}",
            )))
        }
    }
}

fn base_payload(
    plan: &LogicalPlanV12,
    lane: &LogicalLaneContract,
    operation: ProxyOperation,
    content: ProxyPayloadContentV12,
) -> ProxyPayloadV12 {
    ProxyPayloadV12 {
        version: PROXY_PAYLOAD_VERSION.to_string(),
        plan_id: plan.plan_id,
        lane: lane.lane,
        phase: match operation {
            ProxyOperation::RunRepositoryBody
            | ProxyOperation::StopRunner
            | ProxyOperation::DestroyServices => PlanPhase::Body,
            _ => PlanPhase::Prepare,
        },
        operation,
        source: plan.source.clone(),
        artifact_manifest_sha256: lane
            .prepare
            .artifacts
            .as_ref()
            .map(|artifact| artifact.manifest_sha256),
        prepare_sha256: Some(lane.prepare.prepare_sha256),
        body_sha256: Some(lane.body.body_sha256),
        content,
    }
}

fn require_applied(
    reply: OperationReply,
    plan: &LogicalPlanV12,
    lane: LogicalLane,
    operation: ProxyOperation,
) -> PlanResult<()> {
    if reply.terminal_destruction_receipt.is_some() {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "nonterminal plan transition returned a destruction receipt",
        ));
    }
    if !reply.attached_fds.is_empty() {
        close_fds(reply.attached_fds);
        return Err(PlanProtocolError::Invalid(
            "plan transition returned unexpected authority FDs",
        ));
    }
    let result: AppliedResultV12 =
        serde_json::from_slice(&reply.bytes)?;
    if result.version != EXECUTOR_RESULT_VERSION
        || result.plan_id != plan.plan_id
        || result.lane != lane
        || result.operation != operation
        || result.transition_sha256 == [0; 32]
    {
        return Err(PlanProtocolError::Invalid(
            "plan transition result lost exact binding",
        ));
    }
    Ok(())
}

fn read_sealed_invocation(fd: RawFd) -> PlanResult<Vec<u8>> {
    if fd < 3 {
        return Err(PlanProtocolError::Invalid(
            "plan invocation FD aliases a standard descriptor",
        ));
    }
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size <= 0
        || stat.st_size as usize > MAX_INVOCATION_BYTES
    {
        return Err(PlanProtocolError::Invalid(
            "plan invocation is not one bounded regular memfd",
        ));
    }
    let seals = unsafe { libc::fcntl(fd, F_GET_SEALS_VALUE) };
    if seals < 0 || seals & REQUIRED_SEALS != REQUIRED_SEALS {
        return Err(PlanProtocolError::Invalid(
            "plan invocation memfd is not fully sealed",
        ));
    }
    let duplicate = duplicate_fd(fd)?;
    let mut file = File::from(duplicate);
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    file.take(MAX_INVOCATION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != stat.st_size as usize {
        return Err(PlanProtocolError::Invalid(
            "plan invocation length changed during read",
        ));
    }
    Ok(bytes)
}

fn open_self_executable() -> PlanResult<OwnedFd> {
    let path = CString::new("/proc/self/exe").map_err(|_| {
        PlanProtocolError::Invalid("self executable path is invalid")
    })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_packet_with_fds(
    socket: RawFd,
    bytes: &[u8],
    attached_fds: &[RawFd],
    deadline_boottime_ns: u64,
) -> PlanResult<()> {
    if bytes.is_empty()
        || bytes.len() > MAX_FRAME_BYTES
        || attached_fds.len() > MAX_ATTACHED_FDS
        || attached_fds.iter().any(|fd| *fd < 3)
    {
        return Err(PlanProtocolError::Invalid(
            "lane proxy outbound packet is invalid",
        ));
    }
    wait_fd_boottime(socket, libc::POLLOUT, deadline_boottime_ns)?;
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let control_bytes = if attached_fds.is_empty() {
        0
    } else {
        unsafe {
            libc::CMSG_SPACE(
                (attached_fds.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        }
    };
    let mut control =
        vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    if control_bytes > 0 {
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(PlanProtocolError::Invalid(
                    "lane proxy ancillary buffer is invalid",
                ));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(
                (attached_fds.len() * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize;
            std::ptr::copy_nonoverlapping(
                attached_fds.as_ptr(),
                libc::CMSG_DATA(header) as *mut RawFd,
                attached_fds.len(),
            );
        }
    }
    let sent = unsafe {
        libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL)
    };
    if sent != bytes.len() as isize {
        return Err(if sent < 0 {
            std::io::Error::last_os_error().into()
        } else {
            PlanProtocolError::Invalid(
                "lane proxy request was not one exact packet",
            )
        });
    }
    Ok(())
}

fn receive_packet_with_fds(
    socket: RawFd,
    deadline_boottime_ns: u64,
) -> PlanResult<(Vec<u8>, Vec<OwnedFd>)> {
    wait_fd_boottime(socket, libc::POLLIN, deadline_boottime_ns)?;
    let mut bytes = vec![0u8; MAX_FRAME_BYTES];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let control_bytes = unsafe {
        libc::CMSG_SPACE(
            (MAX_ATTACHED_FDS * mem::size_of::<RawFd>())
                as libc::c_uint,
        ) as usize
    };
    let mut control =
        vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control =
        control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control_bytes;
    let count = unsafe {
        libc::recvmsg(
            socket,
            &mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
        )
    };
    if count < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let received_fds = adopt_all_scm_rights_v12(&message)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || count == 0
        || count as usize > bytes.len()
    {
        close_fds(received_fds);
        return Err(PlanProtocolError::Invalid(
            "lane proxy response packet or ancillary data was truncated",
        ));
    }
    bytes.truncate(count as usize);
    Ok((bytes, received_fds))
}

fn adopt_all_scm_rights_v12(
    message: &libc::msghdr,
) -> std::io::Result<Vec<OwnedFd>> {
    use std::os::fd::FromRawFd as _;

    let mut adopted = Vec::new();
    let mut malformed = false;
    let base = message.msg_control as usize;
    let control_len = message.msg_controllen;
    let end = base
        .checked_add(control_len)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "cmsg overflow"))?;
    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let alignment = std::mem::size_of::<usize>();
    let align = |length: usize| {
        length
            .checked_add(alignment - 1)
            .map(|value| value & !(alignment - 1))
    };

    if control_len != 0 && message.msg_control.is_null() {
        malformed = true;
    } else {
        let mut cursor = base;
        while cursor < end {
            let remaining = end - cursor;
            if remaining < std::mem::size_of::<libc::cmsghdr>() {
                malformed = true;
                break;
            }
            let header = unsafe {
                std::ptr::read_unaligned(cursor as *const libc::cmsghdr)
            };
            let claimed_len = header.cmsg_len;
            let reachable_len = claimed_len.min(remaining);
            if claimed_len < header_len || claimed_len > remaining {
                malformed = true;
            }

            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                if reachable_len < header_len {
                    malformed = true;
                } else {
                    let data_len = reachable_len - header_len;
                    if data_len % std::mem::size_of::<libc::c_int>() != 0 {
                        malformed = true;
                    }
                    let count = data_len / std::mem::size_of::<libc::c_int>();
                    let data = (cursor + header_len) as *const libc::c_int;
                    for index in 0..count {
                        let raw_fd = unsafe { std::ptr::read_unaligned(data.add(index)) };
                        if raw_fd < 0 {
                            malformed = true;
                            continue;
                        }
                        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                        if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) }
                            != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        adopted.push(owned);
                    }
                }
            } else if claimed_len != 0 {
                malformed = true;
            }

            let Some(step) = align(claimed_len.max(header_len)) else {
                malformed = true;
                break;
            };
            if step == 0 || step > remaining {
                malformed = true;
                break;
            }
            cursor += step;
        }
    }

    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        malformed = true;
    }
    if adopted.len() > 8 {
        malformed = true;
    }
    for fd in &adopted {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mode = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
        if !matches!(mode, libc::S_IFREG | libc::S_IFDIR | libc::S_IFSOCK) {
            malformed = true;
        }
    }
    if malformed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed, truncated, excessive, or unsupported SCM_RIGHTS message",
        ));
    }
    Ok(adopted)
}

fn collect_received_fds(
    message: &libc::msghdr,
) -> PlanResult<Vec<OwnedFd>> {
    let mut received = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
            {
                close_fds(received);
                return Err(PlanProtocolError::Invalid(
                    "lane proxy returned an unsupported ancillary record",
                ));
            }
            let base =
                libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_len < base {
                close_fds(received);
                return Err(PlanProtocolError::Invalid(
                    "lane proxy ancillary length is invalid",
                ));
            }
            let payload = (*header).cmsg_len - base;
            if payload % mem::size_of::<RawFd>() != 0 {
                close_fds(received);
                return Err(PlanProtocolError::Invalid(
                    "lane proxy ancillary FD payload is misaligned",
                ));
            }
            let count = payload / mem::size_of::<RawFd>();
            if received.len() + count > MAX_ATTACHED_FDS {
                close_fds(received);
                return Err(PlanProtocolError::Invalid(
                    "lane proxy returned excessive authority FDs",
                ));
            }
            let data = libc::CMSG_DATA(header) as *const RawFd;
            for index in 0..count {
                let fd = *data.add(index);
                if fd < 3 {
                    close_fds(received);
                    return Err(PlanProtocolError::Invalid(
                        "lane proxy returned a standard descriptor",
                    ));
                }
                received.push(OwnedFd::from_raw_fd(fd));
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    Ok(received)
}

fn wait_fd_boottime(
    fd: RawFd,
    events: libc::c_short,
    deadline_boottime_ns: u64,
) -> PlanResult<()> {
    if boottime_ns()? >= deadline_boottime_ns {
        return Err(PlanProtocolError::Invalid(
            "I/O deadline expired before poll",
        ));
    }
    let timer = unsafe {
        libc::timerfd_create(
            libc::CLOCK_BOOTTIME,
            libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
        )
    };
    if timer < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let timer = unsafe { OwnedFd::from_raw_fd(timer) };
    let specification = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: (deadline_boottime_ns / 1_000_000_000)
                .try_into()
                .map_err(|_| {
                    PlanProtocolError::Invalid(
                        "I/O deadline seconds exceed time_t",
                    )
                })?,
            tv_nsec: (deadline_boottime_ns % 1_000_000_000)
                as libc::c_long,
        },
    };
    if unsafe {
        libc::timerfd_settime(
            timer.as_raw_fd(),
            libc::TFD_TIMER_ABSTIME,
            &specification,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut descriptors = [
        libc::pollfd {
            fd,
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: timer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        let result =
            unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if result < 0
            && std::io::Error::last_os_error().raw_os_error()
                == Some(libc::EINTR)
        {
            continue;
        }
    if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if descriptors[1].revents & libc::POLLIN != 0 {
            return Err(PlanProtocolError::Invalid(
                "lane proxy I/O exceeded CLOCK_BOOTTIME deadline",
            ));
        }
        if descriptors[0].revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy socket entered an invalid state",
            ));
        }
        if descriptors[0].revents & events != 0 {
            return Ok(());
        }
    }
}

fn measure_peer_executable(pid: u32) -> PlanResult<Digest> {
    let path = CString::new(format!("/proc/{pid}/exe")).map_err(|_| {
        PlanProtocolError::Invalid(
            "lane proxy executable path is invalid",
        )
    })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let before = regular_fd_identity(fd.as_raw_fd())?;
    if before.2 == 0 || before.2 > 512 * 1024 * 1024 {
        return Err(PlanProtocolError::Invalid(
            "lane proxy executable size is invalid",
        ));
    }
    let duplicate = duplicate_fd(fd.as_raw_fd())?;
    let mut file = File::from(duplicate);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(
            PlanProtocolError::Invalid(
                "lane proxy executable byte count overflow",
            ),
        )?;
        if total > before.2 {
            return Err(PlanProtocolError::Invalid(
                "lane proxy executable grew while measured",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total != before.2
        || regular_fd_identity(fd.as_raw_fd())? != before
    {
        return Err(PlanProtocolError::Invalid(
            "lane proxy executable identity changed while measured",
        ));
    }
    Ok(hasher.finalize().into())
}

fn regular_fd_identity(fd: RawFd) -> PlanResult<(u64, u64, u64, i64, i64)> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size < 0
    {
        return Err(PlanProtocolError::Invalid(
            "retained executable FD is not regular",
        ));
    }
    Ok((
        stat.st_dev,
        stat.st_ino,
        stat.st_size as u64,
        stat.st_ctime,
        stat.st_ctime_nsec,
    ))
}

fn duplicate_fd(fd: RawFd) -> PlanResult<OwnedFd> {
    if fd < 3 {
        return Err(PlanProtocolError::Invalid(
            "retained FD aliases a standard descriptor",
        ));
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn close_fds(fds: Vec<OwnedFd>) {
    drop(fds);
}

fn random_digest() -> PlanResult<Digest> {
    let mut digest = [0u8; 32];
    let result = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            digest.as_mut_ptr(),
            digest.len(),
            0,
        )
    };
    if result != digest.len() as libc::c_long || digest == [0; 32] {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(digest)
}

fn boottime_ns() -> PlanResult<u64> {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(time.tv_nsec as u64))
        .ok_or(PlanProtocolError::Invalid(
            "CLOCK_BOOTTIME value overflow",
        ))
}

fn validate_absolute_path(value: &str) -> PlanResult<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(PlanProtocolError::Invalid(
            "executor CAS root path is not canonical",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod legacy_v11 {
    use crate::coder_controller_v11::{
        constant_time_eq, now_unix_ms, ControllerError, Digest, Lane,
        PlanApiModeV11, PlanApiRequestV11, PlanApiResponseV11, Result,
        CONTROLLER_PLAN_API_SOCKET_PATH, PLAN_API_RESPONSE_BYTES,
    };
    use std::io::Write;
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const CAPABILITY_ENV: &str =
        "SERVERWARE_CONTROLLER_PLAN_CAPABILITY";
    const DAEMON_IDENTITY_ENV: &str =
        "SERVERWARE_CONTROLLER_DAEMON_IDENTITY_SHA256";
    const DEADLINE_ENV: &str =
        "SERVERWARE_CONTROLLER_DEADLINE_MS";

    pub fn run(arguments: &[String]) -> Result<()> {
        if arguments.len() != 4
            || !matches!(
                arguments[1].as_str(),
                "bootstrap-v11" | "execute-v11"
            )
        {
            return Err(ControllerError::Invalid(
                "legacy v11 plan invocation is invalid",
            ));
        }
        let mode = if arguments[1] == "bootstrap-v11" {
            PlanApiModeV11::Bootstrap
        } else {
            PlanApiModeV11::Execute
        };
        let lane =
            Lane::parse_frozen_flags(&arguments[2], &arguments[3])?;
        let one_use_capability = decode_digest_env(CAPABILITY_ENV)?;
        let daemon_identity = decode_digest_env(DAEMON_IDENTITY_ENV)?;
        let deadline_unix_ms = std::env::var(DEADLINE_ENV)
            .map_err(|_| {
                ControllerError::Invalid("plan deadline is absent")
            })?
            .parse::<u64>()
            .map_err(|_| {
                ControllerError::Invalid("plan deadline is invalid")
            })?;
        let now = now_unix_ms()?;
        if deadline_unix_ms <= now {
            return Err(ControllerError::Rejected(
                "plan deadline expired before plan API connection",
            ));
        }
        let nonce = random_digest()?;
        let request = PlanApiRequestV11::new(
            mode,
            lane,
            deadline_unix_ms,
            one_use_capability,
            nonce,
            daemon_identity,
        )?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(deadline_unix_ms - now))
            .ok_or(ControllerError::Rejected(
                "plan API monotonic deadline overflow",
            ))?;
        let socket = connect_seqpacket(
            Path::new(CONTROLLER_PLAN_API_SOCKET_PATH),
            deadline,
        )?;
        require_root_peer(socket.as_raw_fd())?;
        send_exact(socket.as_raw_fd(), &request.encode(), deadline)?;
        let mut response_bytes = [0u8; PLAN_API_RESPONSE_BYTES];
        receive_exact(
            socket.as_raw_fd(),
            &mut response_bytes,
            deadline,
        )?;
        let response =
            PlanApiResponseV11::decode(&response_bytes)?;
        if response.lane != lane
            || !constant_time_eq(
                &response.request_sha256,
                &request.request_sha256,
            )
            || !constant_time_eq(&response.request_nonce, &nonce)
            || !constant_time_eq(
                &response.daemon_identity_sha256,
                &daemon_identity,
            )
        {
            return Err(ControllerError::Rejected(
                "plan API response lost request or daemon binding",
            ));
        }
        if response.exit_status != 0 {
            return Err(ControllerError::InvalidOwned(format!(
                "fixed plan returned status {} with evidence {}",
                response.exit_status,
                digest_hex(&response.evidence_sha256),
            )));
        }
        let mut output = std::io::stdout().lock();
        writeln!(
            output,
            "serverware/plan-result/v11 evidence_sha256={} response_sha256={}",
            digest_hex(&response.evidence_sha256),
            digest_hex(&response.response_sha256),
        )
        .map_err(ControllerError::Io)?;
        output.flush().map_err(ControllerError::Io)?;
        Ok(())
    }

    fn decode_digest_env(name: &str) -> Result<Digest> {
        let value = std::env::var(name).map_err(|_| {
            ControllerError::Invalid(
                "plan binding environment is absent",
            )
        })?;
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControllerError::Invalid(
                "plan binding environment is not one lowercase SHA-256",
            ));
        }
        let mut digest = [0u8; 32];
        for (index, output) in digest.iter_mut().enumerate() {
            let high = hex_nibble(value.as_bytes()[index * 2])?;
            let low = hex_nibble(value.as_bytes()[index * 2 + 1])?;
            *output = high << 4 | low;
        }
        if digest == [0; 32] {
            return Err(ControllerError::Rejected(
                "plan binding environment is empty",
            ));
        }
        Ok(digest)
    }

    fn hex_nibble(value: u8) -> Result<u8> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(ControllerError::Invalid(
                "plan binding environment is not lowercase hexadecimal",
            )),
        }
    }

    fn digest_hex(digest: &Digest) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    fn random_digest() -> Result<Digest> {
        let mut digest = [0u8; 32];
        let result = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                digest.as_mut_ptr(),
                digest.len(),
                0,
            )
        };
        if result != digest.len() as libc::c_long
            || digest == [0; 32]
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(digest)
    }

    fn connect_seqpacket(
        path: &Path,
        deadline: Instant,
    ) -> Result<OwnedFd> {
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
            return Err(std::io::Error::last_os_error().into());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_un =
            unsafe { mem::zeroed() };
        address.sun_family =
            libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty()
            || path_bytes.len() >= address.sun_path.len()
        {
            return Err(ControllerError::Invalid(
                "plan API socket path is invalid",
            ));
        }
        for (slot, value) in
            address.sun_path.iter_mut().zip(path_bytes)
        {
            *slot = *value as libc::c_char;
        }
        let length = (mem::size_of::<libc::sa_family_t>()
            + path_bytes.len()
            + 1) as libc::socklen_t;
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                &address as *const libc::sockaddr_un
                    as *const libc::sockaddr,
                length,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error.into());
            }
            poll_fd(socket.as_raw_fd(), libc::POLLOUT, deadline)?;
            let mut pending = 0;
            let mut pending_len =
                mem::size_of::<libc::c_int>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut pending as *mut libc::c_int
                        as *mut libc::c_void,
                    &mut pending_len,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if pending != 0 {
                return Err(
                    std::io::Error::from_raw_os_error(pending).into(),
                );
            }
        }
        Ok(socket)
    }

    fn require_root_peer(fd: RawFd) -> Result<()> {
        let mut peer: libc::ucred = unsafe { mem::zeroed() };
        let mut length =
            mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut peer as *mut libc::ucred as *mut libc::c_void,
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if length as usize != mem::size_of::<libc::ucred>()
            || peer.uid != 0
        {
            return Err(ControllerError::Rejected(
                "plan API peer is not the root-owned controller",
            ));
        }
        Ok(())
    }

    fn send_exact(
        fd: RawFd,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<()> {
        poll_fd(fd, libc::POLLOUT, deadline)?;
        let sent = unsafe {
            libc::send(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != bytes.len() as isize {
            return Err(if sent < 0 {
                std::io::Error::last_os_error().into()
            } else {
                ControllerError::Rejected(
                    "plan API request was not one exact packet",
                )
            });
        }
        Ok(())
    }

    fn receive_exact(
        fd: RawFd,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<()> {
        poll_fd(fd, libc::POLLIN, deadline)?;
        let count = unsafe {
            libc::recv(
                fd,
                bytes.as_mut_ptr() as *mut libc::c_void,
                bytes.len(),
                libc::MSG_TRUNC,
            )
        };
        if count != bytes.len() as isize {
            return Err(if count < 0 {
                std::io::Error::last_os_error().into()
            } else {
                ControllerError::Rejected(
                    "plan API response was not one exact packet",
                )
            });
        }
        Ok(())
    }

    fn poll_fd(
        fd: RawFd,
        events: i16,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(ControllerError::Rejected(
                    "plan API operation exceeded its deadline",
                ));
            }
            let remaining = deadline.duration_since(now);
            let timeout = remaining
                .as_millis()
                .max(1)
                .min(i32::MAX as u128)
                as i32;
            let mut descriptor = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result =
                unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result > 0
                && descriptor.revents
                    & (libc::POLLERR
                        | libc::POLLHUP
                        | libc::POLLNVAL)
                    == 0
                && descriptor.revents & events != 0
            {
                return Ok(());
            }
            if result < 0
                && std::io::Error::last_os_error().raw_os_error()
                    == Some(libc::EINTR)
            {
                continue;
            }
            if result <= 0 {
                continue;
            }
            return Err(ControllerError::Rejected(
                "plan API socket entered an invalid state",
            ));
        }
    }
}
