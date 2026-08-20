#![allow(dead_code)]

use crate::coder_controller_v11::{
    constant_time_eq, digest_hex, ed25519_spki_der_sha256_v11, sha256,
    ControllerError, Digest, Result,
};
#[path = "plan_protocol.rs"]
mod docker_plan_protocol_v12;
pub use docker_plan_protocol_v12::{
    canonical_bytes as canonical_plan_bytes, sha256_bytes as plan_sha256_bytes,
    ArtifactCasReference,
    AuthoritativeLaneState, BodyContract, ContainerCommand,
    DindGenerationKind, ExactBuildTuple, LaneProxyRequest, LogicalLane,
    OciObjectReference, PinnedPull, PlanPhase, ProxyOperation,
    RequiredOciImportClosureV12,
    EndpointProtocol, RunnerIdentity, ServiceEndpoint, ServiceInstanceV12,
    SourceCasReference,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use crate::readiness::{ReadinessProbe, ReadinessRequestV12};

pub const DOCKER_LANE_CAPABILITY_DOMAIN_V11: &str =
    "serverware/docker-lane-capability/v11";
pub const DOCKER_API_REQUEST_DOMAIN_V11: &str =
    "serverware/docker-api-request/v11";
pub const RUNNER_EXECUTION_DOMAIN_V12: &str =
    "serverware/runner-execution/v12";
pub const SERVICE_INSTANCE_DOMAIN_V12: &str =
    "serverware/service-instance/v12";
pub const NETWORK_MEMBERSHIP_DOMAIN_V12: &str =
    "serverware/docker-network-membership/v12";
pub const PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12: &str =
    "serverware/private-dind-lifecycle/v12";
pub const PRIVATE_DIND_RESULT_VERSION_V12: &str =
    "serverware/controller-plan-executor-result/v12";
pub const PRIVATE_DIND_PROXY_PAYLOAD_VERSION_V12: &str =
    "serverware/controller-plan-proxy-payload/v12";
pub const PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12: &[u8] =
    b"serverware/private-dind-root-response-signature/v12\0";
pub const DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12: &str =
    "private-daemon-top-level-api:containers,images,nondefault-networks,volumes";
pub const DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12: &str =
    "generation-state-root-absent;internal-layers-snapshots-build-cache-not-individually-counted";
pub const DOCKER_CONTRACT_MAX_BYTES_V11: usize = 1024 * 1024;
pub const DOCKER_MAX_SEQUENCE_V11: u64 = (1u64 << 53) - 1;
pub const DOCKER_MAX_DEADLINE_NS_V11: u64 = (1u64 << 53) - 1;
pub const DOCKER_API_VERSIONS_V11: &[&str] =
    &["v1.43", "v1.44", "v1.45"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivateDindProfileV12 {
    Build,
    NoBuild,
}

impl PrivateDindProfileV12 {
    pub fn for_lane(lane: LogicalLane) -> Self {
        if lane == LogicalLane::Build {
            Self::Build
        } else {
            Self::NoBuild
        }
    }

    pub fn generation_kind(self) -> DindGenerationKind {
        match self {
            Self::Build => DindGenerationKind::Build,
            Self::NoBuild => DindGenerationKind::NoBuild,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::NoBuild => "no-build",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivateDindAttachedFdRoleV12 {
    SourceCas,
    ArtifactCas,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum DockerLanePayloadContentV12 {
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
        command: ContainerCommand,
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

impl DockerLanePayloadContentV12 {
    pub fn operation(&self) -> ProxyOperation {
        match self {
            Self::CreateBuildDind { .. } => ProxyOperation::CreateBuildDind,
            Self::PullPinned { .. } => ProxyOperation::PullPinned,
            Self::BuildExact { .. } => ProxyOperation::BuildExact,
            Self::ExportOwnedOci { .. } => ProxyOperation::ExportOwnedOci,
            Self::Destroy { .. } => ProxyOperation::DestroyBuildDind,
            Self::CreateNoBuildDind { .. } => {
                ProxyOperation::CreateNoBuildDind
            }
            Self::ImportSealedOci { .. } => ProxyOperation::ImportSealedOci,
            Self::CreateRunner { .. } => ProxyOperation::CreateRunner,
            Self::CreateServices { .. } => ProxyOperation::CreateServices,
            Self::RunBody { .. } => ProxyOperation::RunRepositoryBody,
            Self::StopRunner { .. } => ProxyOperation::StopRunner,
            Self::DestroyServices { .. } => {
                ProxyOperation::DestroyServices
            }
        }
    }

    fn validate_for(&self, operation: ProxyOperation) -> Result<()> {
        let shape_matches = match (operation, self) {
            (
                ProxyOperation::CreateBuildDind,
                Self::CreateBuildDind {
                    generation_kind,
                    exact_build,
                    runner,
                },
            ) => {
                exact_build.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                runner.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                *generation_kind == DindGenerationKind::Build
            }
            (ProxyOperation::PullPinned, Self::PullPinned { pull }) => {
                pull.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                true
            }
            (
                ProxyOperation::BuildExact,
                Self::BuildExact { exact_build },
            ) => {
                exact_build.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                true
            }
            (
                ProxyOperation::ExportOwnedOci,
                Self::ExportOwnedOci {
                    expected_artifacts,
                    expected_repositories,
                },
            ) => {
                expected_artifacts.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                !expected_repositories.is_empty()
                    && expected_repositories.len() <= 256
                    && expected_repositories
                        .windows(2)
                        .all(|pair| pair[0] < pair[1])
            }
            (
                ProxyOperation::DestroyBuildDind
                    | ProxyOperation::DestroyNoBuildDind,
                Self::Destroy {
                    reason_sha256,
                    require_zero_resources,
                },
            ) => *reason_sha256 != [0; 32] && *require_zero_resources,
            (
                ProxyOperation::CreateNoBuildDind,
                Self::CreateNoBuildDind {
                    generation_kind,
                    artifacts,
                    required_oci_import_closure,
                    runner,
                },
            ) => {
                artifacts.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                required_oci_import_closure
                    .validate_against(artifacts)
                    .map_err(|error| {
                        ControllerError::InvalidOwned(error.to_string())
                    })?;
                runner.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                *generation_kind == DindGenerationKind::NoBuild
                    && required_oci_import_closure
                        .manifest_sha256
                        .binary_search(
                            &runner.image.manifest_digest_sha256,
                        )
                        .is_ok()
            }
            (
                ProxyOperation::ImportSealedOci,
                Self::ImportSealedOci {
                    object,
                    artifact_object_sha256,
                },
            ) => {
                object.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                *artifact_object_sha256 != [0; 32]
            }
            (
                ProxyOperation::CreateRunner,
                Self::CreateRunner { runner, command },
            ) => {
                runner.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                command.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                true
            }
            (
                ProxyOperation::CreateServices,
                Self::CreateServices { services },
            ) => {
                if services.is_empty() || services.len() > 64 {
                    false
                } else {
                    for service in services {
                        service.validate().map_err(|error| {
                            ControllerError::InvalidOwned(error.to_string())
                        })?;
                    }
                    true
                }
            }
            (
                ProxyOperation::RunRepositoryBody,
                Self::RunBody {
                    body,
                    derived_service_endpoints,
                },
            ) => {
                body.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                for endpoint in derived_service_endpoints {
                    endpoint.validate().map_err(|error| {
                        ControllerError::InvalidOwned(error.to_string())
                    })?;
                }
                true
            }
            (
                ProxyOperation::StopRunner,
                Self::StopRunner { command_sha256 },
            ) => *command_sha256 != [0; 32],
            (
                ProxyOperation::DestroyServices,
                Self::DestroyServices { services_sha256 },
            ) => *services_sha256 != [0; 32],
            _ => false,
        };
        if !shape_matches {
            return Err(ControllerError::Rejected(
                "private DinD payload kind differs from its proxy operation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerLanePayloadV12 {
    pub version: String,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub phase: PlanPhase,
    pub operation: ProxyOperation,
    pub source: SourceCasReference,
    pub artifact_manifest_sha256: Option<Digest>,
    pub prepare_sha256: Option<Digest>,
    pub body_sha256: Option<Digest>,
    pub content: DockerLanePayloadContentV12,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerLaneQueryPayloadV12 {
    pub version: String,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub original_request_sha256: Digest,
    pub original_operation: ProxyOperation,
}

#[derive(Clone, Debug)]
pub enum DockerLaneDecodedPayloadV12 {
    Operation(DockerLanePayloadV12),
    Query(DockerLaneQueryPayloadV12),
    Readiness(ReadinessRequestV12),
}

#[derive(Clone, Debug)]
pub struct DockerLaneOperationV12 {
    pub request: LaneProxyRequest,
    pub profile: PrivateDindProfileV12,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub decoded_payload: DockerLaneDecodedPayloadV12,
    pub attached_fd_roles: Vec<PrivateDindAttachedFdRoleV12>,
}

impl DockerLaneOperationV12 {
    pub fn from_proxy_request(
        request: LaneProxyRequest,
        attached_fd_count: usize,
    ) -> Result<Self> {
        request.validate().map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let profile = PrivateDindProfileV12::for_lane(request.lane);
        let decoded_payload = match request.operation {
            ProxyOperation::QueryAuthoritativeState => {
                let payload: DockerLaneQueryPayloadV12 =
                    serde_json::from_slice(&request.payload).map_err(|_| {
                        ControllerError::Invalid(
                            "private DinD query payload is not exact JSON",
                        )
                    })?;
                if canonical_plan_bytes(&payload).map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })? != request.payload
                    || payload.version
                        != PRIVATE_DIND_PROXY_PAYLOAD_VERSION_V12
                    || payload.plan_id != request.plan_id
                    || payload.lane != request.lane
                    || payload.original_request_sha256 == [0; 32]
                    || matches!(
                        payload.original_operation,
                        ProxyOperation::QueryAuthoritativeState
                    )
                    || attached_fd_count != 0
                {
                    return Err(ControllerError::Rejected(
                        "private DinD query lost its exact request binding",
                    ));
                }
                DockerLaneDecodedPayloadV12::Query(payload)
            }
            ProxyOperation::ReadinessDockerUpgrade
            | ProxyOperation::ReadinessService
            | ProxyOperation::ReadinessChromium
            | ProxyOperation::ReadinessTeardown => {
                let payload: ReadinessRequestV12 =
                    serde_json::from_slice(&request.payload).map_err(|_| {
                        ControllerError::Invalid(
                            "readiness operation payload is not exact JSON",
                        )
                    })?;
                payload.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                let expected_operation = match payload.probe {
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
                if canonical_plan_bytes(&payload).map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })? != request.payload
                    || expected_operation != request.operation
                    || payload.sequence != request.sequence
                    || payload.deadline_boottime_ns
                        != request.deadline_boottime_ns
                    || payload.fixture_id != request.target_sha256
                    || attached_fd_count != 0
                {
                    return Err(ControllerError::Rejected(
                        "readiness operation lost its exact signed fixture binding",
                    ));
                }
                DockerLaneDecodedPayloadV12::Readiness(payload)
            }
            _ => {
                let payload: DockerLanePayloadV12 =
                    serde_json::from_slice(&request.payload).map_err(|_| {
                        ControllerError::Invalid(
                            "private DinD operation payload is not exact JSON",
                        )
                    })?;
                if canonical_plan_bytes(&payload).map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })? != request.payload
                    || payload.version
                        != PRIVATE_DIND_PROXY_PAYLOAD_VERSION_V12
                    || payload.plan_id != request.plan_id
                    || payload.lane != request.lane
                    || payload.phase != request.phase
                    || payload.operation != request.operation
                {
                    return Err(ControllerError::Rejected(
                        "private DinD payload differs from its proxy envelope",
                    ));
                }
                payload.source.validate().map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                payload.content.validate_for(request.operation)?;
                if matches!(
                    request.operation,
                    ProxyOperation::DestroyBuildDind
                        | ProxyOperation::DestroyNoBuildDind
                ) && ((request.operation
                    == ProxyOperation::DestroyBuildDind)
                    != (profile == PrivateDindProfileV12::Build))
                {
                    return Err(ControllerError::Rejected(
                        "private DinD destruction profile differs from lane",
                    ));
                }
                DockerLaneDecodedPayloadV12::Operation(payload)
            }
        };
        let attached_fd_roles = match request.operation {
            ProxyOperation::CreateBuildDind if attached_fd_count == 1 => {
                vec![PrivateDindAttachedFdRoleV12::SourceCas]
            }
            ProxyOperation::CreateNoBuildDind if attached_fd_count == 2 => {
                vec![
                    PrivateDindAttachedFdRoleV12::SourceCas,
                    PrivateDindAttachedFdRoleV12::ArtifactCas,
                ]
            }
            ProxyOperation::CreateBuildDind
            | ProxyOperation::CreateNoBuildDind => {
                return Err(ControllerError::Rejected(
                    "private DinD creation descriptor set is incomplete",
                ))
            }
            _ if attached_fd_count == 0 => Vec::new(),
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD operation carried unexpected descriptors",
                ))
            }
        };
        let plan = digest_hex(&request.plan_id);
        let capability = digest_hex(&request.capability_sha256);
        let generation_slot = match profile {
            PrivateDindProfileV12::Build => 0,
            PrivateDindProfileV12::NoBuild => 1,
        };
        let owner_namespace =
            format!("swv12-{}-{}", &plan[..24], &capability[..24]);
        let generation_class = if request.operation.is_readiness() {
            "readiness"
        } else {
            profile.as_str()
        };
        let daemon_generation = format!(
            "{}-{}-{}-{}",
            generation_class,
            generation_slot,
            &plan[..24],
            &capability[..24],
        );
        Ok(Self {
            request,
            profile,
            owner_namespace,
            daemon_generation,
            decoded_payload,
            attached_fd_roles,
        })
    }

    pub fn lane_id(&self) -> String {
        format!(
            "{}-{}",
            self.request.lane.ordinal(),
            &digest_hex(&self.request.plan_id)[..32],
        )
    }

    pub fn generation_slot(&self) -> u8 {
        match self.profile {
            PrivateDindProfileV12::Build => 0,
            PrivateDindProfileV12::NoBuild => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivateDindOperationRequestV12 {
    pub protocol: String,
    pub operation: String,
    pub proxy_request: LaneProxyRequest,
    pub attached_fd_roles: Vec<PrivateDindAttachedFdRoleV12>,
    pub request_sha256: Digest,
}

impl PrivateDindOperationRequestV12 {
    pub fn seal(
        proxy_request: LaneProxyRequest,
        attached_fd_roles: Vec<PrivateDindAttachedFdRoleV12>,
    ) -> Result<Self> {
        let mut request = Self {
            protocol: PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12.to_owned(),
            operation: "EXECUTE_LANE_PROXY_REQUEST".to_owned(),
            proxy_request,
            attached_fd_roles,
            request_sha256: [0; 32],
        };
        request.request_sha256 = sha256(
            &canonical_plan_bytes(&request).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol != PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12
            || self.operation != "EXECUTE_LANE_PROXY_REQUEST"
            || self.request_sha256 == [0; 32]
            || self.attached_fd_roles.len() > 2
        {
            return Err(ControllerError::Rejected(
                "private DinD lifecycle request envelope is invalid",
            ));
        }
        self.proxy_request.validate().map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let mut projection = self.clone();
        projection.request_sha256 = [0; 32];
        if sha256(
            &canonical_plan_bytes(&projection).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        ) != self.request_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD lifecycle request digest is not canonical",
            ));
        }
        let decoded = DockerLaneOperationV12::from_proxy_request(
            self.proxy_request.clone(),
            self.attached_fd_roles.len(),
        )?;
        if decoded.attached_fd_roles != self.attached_fd_roles {
            return Err(ControllerError::Rejected(
                "private DinD attached descriptor roles are noncanonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivateDindOperationDispositionV12 {
    Applied,
    AlreadyApplied,
    Rejected,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivateDindOperationResponseV12 {
    pub protocol: String,
    pub request_sha256: Digest,
    pub proxy_request_sha256: Digest,
    pub disposition: PrivateDindOperationDispositionV12,
    pub authoritative_state: AuthoritativeLaneState,
    pub result_sha256: Digest,
    pub result: Vec<u8>,
    pub returned_fd_roles: Vec<String>,
    pub observed_state_sha256: Digest,
    pub terminal_destruction_receipt: Option<Vec<u8>>,
    pub root_signer_spki_sha256: Digest,
    pub root_signer_public_key_spki_der: Vec<u8>,
    pub root_signature: Vec<u8>,
    pub response_sha256: Digest,
}

impl PrivateDindOperationResponseV12 {
    pub fn seal(
        request: &PrivateDindOperationRequestV12,
        disposition: PrivateDindOperationDispositionV12,
        authoritative_state: AuthoritativeLaneState,
        result: Vec<u8>,
        returned_fd_roles: Vec<String>,
        observed_state_sha256: Digest,
    ) -> Result<Self> {
        if observed_state_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "private DinD response lacks observed state evidence",
            ));
        }
        let mut response = Self {
            protocol: PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12.to_owned(),
            request_sha256: request.request_sha256,
            proxy_request_sha256: request.proxy_request.request_sha256,
            disposition,
            authoritative_state,
            result_sha256: sha256(&result),
            result,
            returned_fd_roles,
            observed_state_sha256,
            terminal_destruction_receipt: None,
            root_signer_spki_sha256: [0; 32],
            root_signer_public_key_spki_der: Vec::new(),
            root_signature: Vec::new(),
            response_sha256: [0; 32],
        };
        Ok(response)
    }

    pub fn with_terminal_destruction_receipt(
        mut self,
        receipt: Vec<u8>,
    ) -> Result<Self> {
        if receipt.is_empty() {
            return Err(ControllerError::Rejected(
                "private DinD terminal destruction receipt is empty",
            ));
        }
        self.terminal_destruction_receipt = Some(receipt);
        Ok(self)
    }

    pub fn sign(
        mut self,
        request: &PrivateDindOperationRequestV12,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let public_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ControllerError::Invalid(
                    "private DinD root public key cannot be DER encoded",
                )
            })?
            .as_bytes()
            .to_vec();
        self.root_signer_spki_sha256 = sha256(&public_der);
        self.root_signer_public_key_spki_der = public_der;
        self.root_signature.clear();
        self.response_sha256 = [0; 32];
        let projection = canonical_plan_bytes(&self).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let mut signed = Vec::with_capacity(
            PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12.len()
                + projection.len(),
        );
        signed.extend_from_slice(
            PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12,
        );
        signed.extend_from_slice(&projection);
        self.root_signature = signing_key.sign(&signed).to_bytes().to_vec();
        self.response_sha256 = sha256(
            &canonical_plan_bytes(&self).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        self.validate_for(request)?;
        Ok(self)
    }

    pub fn validate_for(
        &self,
        request: &PrivateDindOperationRequestV12,
    ) -> Result<()> {
        if self.protocol != PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12
            || self.request_sha256 != request.request_sha256
            || self.proxy_request_sha256
                != request.proxy_request.request_sha256
            || self.result_sha256 != sha256(&self.result)
            || self.observed_state_sha256 == [0; 32]
            || self.root_signer_spki_sha256 == [0; 32]
            || self.root_signer_public_key_spki_der.is_empty()
            || self.root_signature.len() != 64
            || self.response_sha256 == [0; 32]
            || self.returned_fd_roles.len() > 1
            || ((self.authoritative_state
                == AuthoritativeLaneState::Destroyed)
                != self.terminal_destruction_receipt.is_some())
        {
            return Err(ControllerError::Rejected(
                "private DinD response lost exact request binding",
            ));
        }
        let mut projection = self.clone();
        projection.response_sha256 = [0; 32];
        if sha256(
            &canonical_plan_bytes(&projection).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        ) != self.response_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD response digest is not canonical",
            ));
        }
        let verifying_key = VerifyingKey::from_public_key_der(
            &self.root_signer_public_key_spki_der,
        )
        .map_err(|_| {
            ControllerError::Rejected(
                "private DinD root response public key is invalid",
            )
        })?;
        if sha256(&self.root_signer_public_key_spki_der)
            != self.root_signer_spki_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD root signer SPKI digest differs",
            ));
        }
        let signature_bytes: [u8; 64] = self
            .root_signature
            .as_slice()
            .try_into()
            .map_err(|_| {
                ControllerError::Rejected(
                    "private DinD root response signature length is invalid",
                )
            })?;
        let mut signed_projection = self.clone();
        signed_projection.root_signature.clear();
        signed_projection.response_sha256 = [0; 32];
        let projection =
            canonical_plan_bytes(&signed_projection).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        let mut signed = Vec::with_capacity(
            PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12.len()
                + projection.len(),
        );
        signed.extend_from_slice(
            PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12,
        );
        signed.extend_from_slice(&projection);
        verifying_key
            .verify(
                &signed,
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| {
                ControllerError::Rejected(
                    "private DinD root response signature is invalid",
                )
            })?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthorizedDockerSignerV11 {
    pub role: &'static str,
    pub principal_id: String,
    pub key_id: String,
    pub verifying_key: VerifyingKey,
    pub authorization_leaf_sha256: Digest,
    pub authorization_checkpoint_sha256: Digest,
    pub revocation_highwater: u64,
    pub not_before_boottime_ns: u64,
    pub not_after_boottime_ns: u64,
}

impl AuthorizedDockerSignerV11 {
    pub fn validate(&self, now_boottime_ns: u64) -> Result<()> {
        if identifier(&self.principal_id).is_err()
            || identifier(&self.key_id).is_err()
            || self.authorization_leaf_sha256 == [0; 32]
            || self.authorization_checkpoint_sha256 == [0; 32]
            || self.revocation_highwater == 0
            || self.not_before_boottime_ns == 0
            || self.not_before_boottime_ns >= self.not_after_boottime_ns
            || now_boottime_ns < self.not_before_boottime_ns
            || now_boottime_ns >= self.not_after_boottime_ns
        {
            return Err(ControllerError::Rejected(
                "Docker signer authorization is absent, expired, or malformed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DockerLaneProfileV11 {
    Build,
    UnitNoBuild,
    IntegrationNoBuild,
    E2eNoBuild,
    AttestationNoBuild,
}

impl DockerLaneProfileV11 {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "BUILD" => Ok(Self::Build),
            "UNIT_NO_BUILD" => Ok(Self::UnitNoBuild),
            "INTEGRATION_NO_BUILD" => Ok(Self::IntegrationNoBuild),
            "E2E_NO_BUILD" => Ok(Self::E2eNoBuild),
            "ATTESTATION_NO_BUILD" => Ok(Self::AttestationNoBuild),
            _ => Err(ControllerError::Rejected(
                "Docker lane profile is not in the v11 allowlist",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "BUILD",
            Self::UnitNoBuild => "UNIT_NO_BUILD",
            Self::IntegrationNoBuild => "INTEGRATION_NO_BUILD",
            Self::E2eNoBuild => "E2E_NO_BUILD",
            Self::AttestationNoBuild => "ATTESTATION_NO_BUILD",
        }
    }

    pub fn is_build(self) -> bool {
        self == Self::Build
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DockerStreamModeV11 {
    BoundedHttp,
    FullDuplex,
    Upgrade101,
    BuildKit,
}

impl DockerStreamModeV11 {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "BOUNDED_HTTP" => Ok(Self::BoundedHttp),
            "FULL_DUPLEX" => Ok(Self::FullDuplex),
            "UPGRADE_101" => Ok(Self::Upgrade101),
            "BUILDKIT" => Ok(Self::BuildKit),
            _ => Err(ControllerError::Rejected(
                "Docker stream mode is not in the v11 allowlist",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BoundedHttp => "BOUNDED_HTTP",
            Self::FullDuplex => "FULL_DUPLEX",
            Self::Upgrade101 => "UPGRADE_101",
            Self::BuildKit => "BUILDKIT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DockerResourceKindV11 {
    Daemon,
    Build,
    Image,
    Container,
    Network,
    Volume,
}

impl DockerResourceKindV11 {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "DAEMON" => Ok(Self::Daemon),
            "BUILD" => Ok(Self::Build),
            "IMAGE" => Ok(Self::Image),
            "CONTAINER" => Ok(Self::Container),
            "NETWORK" => Ok(Self::Network),
            "VOLUME" => Ok(Self::Volume),
            _ => Err(ControllerError::Rejected(
                "Docker target kind is not in the v11 allowlist",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "DAEMON",
            Self::Build => "BUILD",
            Self::Image => "IMAGE",
            Self::Container => "CONTAINER",
            Self::Network => "NETWORK",
            Self::Volume => "VOLUME",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DockerObjectStateV11 {
    Absent,
    Declared,
    Creating,
    Created,
    Starting,
    Running,
    Exited,
    Removing,
    Removed,
    Destroying,
    Destroyed,
    Unknown,
}

impl DockerObjectStateV11 {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "ABSENT" => Ok(Self::Absent),
            "DECLARED" => Ok(Self::Declared),
            "CREATING" => Ok(Self::Creating),
            "CREATED" => Ok(Self::Created),
            "STARTING" => Ok(Self::Starting),
            "RUNNING" => Ok(Self::Running),
            "EXITED" => Ok(Self::Exited),
            "REMOVING" => Ok(Self::Removing),
            "REMOVED" => Ok(Self::Removed),
            "DESTROYING" => Ok(Self::Destroying),
            "DESTROYED" => Ok(Self::Destroyed),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(ControllerError::Rejected(
                "Docker object state is not in the v11 allowlist",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "ABSENT",
            Self::Declared => "DECLARED",
            Self::Creating => "CREATING",
            Self::Created => "CREATED",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Exited => "EXITED",
            Self::Removing => "REMOVING",
            Self::Removed => "REMOVED",
            Self::Destroying => "DESTROYING",
            Self::Destroyed => "DESTROYED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerTransitionV11 {
    pub from: DockerObjectStateV11,
    pub to: DockerObjectStateV11,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerTargetV11 {
    pub kind: DockerResourceKindV11,
    pub logical_id: String,
    pub engine_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerBoundsV11 {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_stream_bytes: u64,
    pub max_duration_ms: u64,
    pub max_objects: Option<u32>,
}

impl DockerBoundsV11 {
    pub fn validate(&self) -> Result<()> {
        if self.max_request_bytes == 0
            || self.max_request_bytes > 8 * 1024 * 1024 * 1024
            || self.max_response_bytes == 0
            || self.max_response_bytes > 8 * 1024 * 1024 * 1024
            || self.max_stream_bytes == 0
            || self.max_stream_bytes > 16 * 1024 * 1024 * 1024
            || self.max_duration_ms == 0
            || self.max_duration_ms > 4 * 60 * 60 * 1000
            || self.max_objects.is_some_and(|count| count == 0 || count > 4096)
        {
            return Err(ControllerError::Rejected(
                "Docker authority bounds exceed the v11 ceilings",
            ));
        }
        Ok(())
    }

    pub fn contains(&self, request: &Self) -> bool {
        request.max_request_bytes <= self.max_request_bytes
            && request.max_response_bytes <= self.max_response_bytes
            && request.max_stream_bytes <= self.max_stream_bytes
            && request.max_duration_ms <= self.max_duration_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerBuildTupleV11 {
    pub context_cas_sha256: Digest,
    pub dockerfile_cas_sha256: Digest,
    pub target: String,
    pub platform: String,
    pub output: String,
    pub build_args_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerFixedHeaderV11 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerCreateAuthorityKindV12 {
    RunnerExecution,
    ServiceInstance,
}

impl DockerCreateAuthorityKindV12 {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "RUNNER_EXECUTION" => Ok(Self::RunnerExecution),
            "SERVICE_INSTANCE" => Ok(Self::ServiceInstance),
            _ => Err(ControllerError::Rejected(
                "Docker create authority kind is not registered",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunnerExecution => "RUNNER_EXECUTION",
            Self::ServiceInstance => "SERVICE_INSTANCE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEnvironmentV12 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerMountKindV12 {
    SourceCas,
    ArtifactCas,
    Tmpfs,
}

impl DockerMountKindV12 {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "SOURCE_CAS" => Ok(Self::SourceCas),
            "ARTIFACT_CAS" => Ok(Self::ArtifactCas),
            "TMPFS" => Ok(Self::Tmpfs),
            _ => Err(ControllerError::Rejected(
                "Docker mount kind is not registered",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerMountV12 {
    pub mount_id: String,
    pub kind: DockerMountKindV12,
    pub cas_sha256: Option<Digest>,
    pub subpath: String,
    pub target: String,
    pub read_only: bool,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerResourceLimitsV12 {
    pub memory_bytes: u64,
    pub nano_cpus: u64,
    pub pids_limit: u32,
    pub shm_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerHealthCheckV12 {
    pub test: Vec<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub retries: u32,
    pub start_period_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEndpointV12 {
    pub name: String,
    pub protocol: String,
    pub container_port: u16,
}

#[derive(Clone, Debug)]
pub struct DockerCreateAuthorityV12 {
    pub exact_bytes: Vec<u8>,
    pub canonical_sha256: Digest,
    pub kind: DockerCreateAuthorityKindV12,
    pub authority_id: String,
    pub request_id: String,
    pub lane_id: String,
    pub daemon_generation: String,
    pub source_seal_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub profile: DockerLaneProfileV11,
    pub owner_namespace: String,
    pub container_logical_id: String,
    pub image: String,
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    pub environment: Vec<DockerEnvironmentV12>,
    pub user: String,
    pub working_dir: String,
    pub resources: DockerResourceLimitsV12,
    pub mounts: Vec<DockerMountV12>,
    pub aliases: Vec<String>,
    pub health: Option<DockerHealthCheckV12>,
    pub endpoints: Vec<DockerEndpointV12>,
    pub signer_authorization_leaf_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct DockerNetworkMembershipV12 {
    pub exact_bytes: Vec<u8>,
    pub canonical_sha256: Digest,
    pub membership_id: String,
    pub request_id: String,
    pub lane_id: String,
    pub daemon_generation: String,
    pub owner_namespace: String,
    pub network_logical_id: String,
    pub container_logical_id: String,
    pub container_engine_id: String,
    pub endpoint_id: String,
    pub aliases: Vec<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub signer_authorization_leaf_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct DockerLaneCapabilityV11 {
    pub exact_bytes: Vec<u8>,
    pub canonical_sha256: Digest,
    pub capability_id: String,
    pub lane_id: String,
    pub daemon_generation: String,
    pub source_seal_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub profile: DockerLaneProfileV11,
    pub owner_namespace: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub deadline_boottime_ns: u64,
    pub policy_sha256: Digest,
    pub allowed_api_versions: BTreeSet<String>,
    pub build_tuple: Option<DockerBuildTupleV11>,
    pub allowed_pinned_pulls: BTreeSet<String>,
    pub allowed_image_digests: BTreeSet<String>,
    pub limits: DockerBoundsV11,
    pub signer_authorization_leaf_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct DockerApiRequestV11 {
    pub exact_bytes: Vec<u8>,
    pub canonical_sha256: Digest,
    pub request_id: String,
    pub capability_id: String,
    pub capability_sha256: Digest,
    pub lane_id: String,
    pub daemon_generation: String,
    pub source_seal_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub profile: DockerLaneProfileV11,
    pub owner_namespace: String,
    pub sequence: u64,
    pub deadline_boottime_ns: u64,
    pub api_version: String,
    pub fixed_headers: Vec<DockerFixedHeaderV11>,
    pub method: String,
    pub normalized_route: String,
    pub canonical_query: Vec<(String, String)>,
    pub body_sha256: Digest,
    pub body_bytes: u64,
    pub target: DockerTargetV11,
    pub expected_transition: DockerTransitionV11,
    pub stream_mode: DockerStreamModeV11,
    pub limits: DockerBoundsV11,
    pub create_authority: Option<DockerCreateAuthorityV12>,
    pub network_membership: Option<DockerNetworkMembershipV12>,
    pub signer_authorization_leaf_sha256: Digest,
}

impl DockerLaneCapabilityV11 {
    pub fn parse_and_verify(
        exact_bytes: &[u8],
        signer: &AuthorizedDockerSignerV11,
        now_boottime_ns: u64,
    ) -> Result<Self> {
        signer.validate(now_boottime_ns)?;
        if signer.role != "controller-plan-executor" {
            return Err(ControllerError::Rejected(
                "Docker lane capability signer has the wrong role",
            ));
        }
        let root = docker_parse_exact_canonical_json_v11(
            exact_bytes,
            DOCKER_CONTRACT_MAX_BYTES_V11,
        )?;
        require_fields(
            object(&root, "Docker lane capability is not an object")?,
            &[
                "contractVersion",
                "capabilityId",
                "laneId",
                "daemonGeneration",
                "sourceSealSha256",
                "artifactSealSha256",
                "profile",
                "ownerNamespace",
                "sequenceStart",
                "sequenceEnd",
                "deadlineBoottimeNs",
                "policySha256",
                "allowedApiVersions",
                "buildTuple",
                "allowedPinnedPulls",
                "allowedImageDigests",
                "limits",
                "signerAuthorization",
                "signature",
            ],
        )?;
        let root_object = object(&root, "Docker lane capability is not an object")?;
        if string(root_object, "contractVersion")? != "11" {
            return Err(ControllerError::Rejected(
                "Docker lane capability version is not 11",
            ));
        }
        verify_signed_document(
            &root,
            DOCKER_LANE_CAPABILITY_DOMAIN_V11,
            signer,
            now_boottime_ns,
        )?;
        let profile =
            DockerLaneProfileV11::parse(string(root_object, "profile")?)?;
        let sequence_start = integer(root_object, "sequenceStart")?;
        let sequence_end = integer(root_object, "sequenceEnd")?;
        let deadline_boottime_ns =
            integer(root_object, "deadlineBoottimeNs")?;
        if sequence_start == 0
            || sequence_start > sequence_end
            || sequence_end > DOCKER_MAX_SEQUENCE_V11
            || deadline_boottime_ns <= now_boottime_ns
            || deadline_boottime_ns > DOCKER_MAX_DEADLINE_NS_V11
        {
            return Err(ControllerError::Rejected(
                "Docker lane capability sequence or deadline is invalid",
            ));
        }
        let build_tuple =
            parse_build_tuple(field(root_object, "buildTuple")?)?;
        if profile.is_build() != build_tuple.is_some() {
            return Err(ControllerError::Rejected(
                "Docker build tuple presence differs from the lane profile",
            ));
        }
        let limits =
            parse_bounds(field(root_object, "limits")?, true)?;
        limits.validate()?;
        let allowed_pinned_pulls =
            string_set(field(root_object, "allowedPinnedPulls")?, 64)?;
        let allowed_image_digests =
            string_set(field(root_object, "allowedImageDigests")?, 256)?;
        let allowed_api_versions =
            string_set(field(root_object, "allowedApiVersions")?, 8)?;
        if allowed_pinned_pulls
            .iter()
            .any(|image| !valid_digest_image(image))
            || allowed_image_digests
                .iter()
                .any(|image| !valid_image_id(image))
            || allowed_api_versions.is_empty()
            || allowed_api_versions.iter().any(|version| {
                DOCKER_API_VERSIONS_V11
                    .binary_search(&version.as_str())
                    .is_err()
            })
            || (!profile.is_build() && !allowed_pinned_pulls.is_empty())
        {
            return Err(ControllerError::Rejected(
                "Docker image authority is not digest-pinned or profile-safe",
            ));
        }
        let capability = Self {
            exact_bytes: exact_bytes.to_vec(),
            canonical_sha256: sha256(exact_bytes),
            capability_id: identifier(
                string(root_object, "capabilityId")?,
            )?,
            lane_id: identifier(string(root_object, "laneId")?)?,
            daemon_generation: identifier(
                string(root_object, "daemonGeneration")?,
            )?,
            source_seal_sha256: hex_digest(string(
                root_object,
                "sourceSealSha256",
            )?)?,
            artifact_seal_sha256: hex_digest(string(
                root_object,
                "artifactSealSha256",
            )?)?,
            profile,
            owner_namespace: owner_namespace(string(
                root_object,
                "ownerNamespace",
            )?)?,
            sequence_start,
            sequence_end,
            deadline_boottime_ns,
            policy_sha256: hex_digest(string(
                root_object,
                "policySha256",
            )?)?,
            allowed_api_versions,
            build_tuple,
            allowed_pinned_pulls,
            allowed_image_digests,
            limits,
            signer_authorization_leaf_sha256:
                signer.authorization_leaf_sha256,
        };
        if capability.source_seal_sha256 == [0; 32]
            || capability.artifact_seal_sha256 == [0; 32]
            || capability.policy_sha256 == [0; 32]
            || capability.build_tuple.as_ref().is_some_and(|tuple| {
                tuple.context_cas_sha256 == [0; 32]
                    || tuple.dockerfile_cas_sha256 == [0; 32]
                    || tuple.build_args_sha256 == [0; 32]
            })
        {
            return Err(ControllerError::Rejected(
                "Docker capability contains an absent seal or build digest",
            ));
        }
        Ok(capability)
    }
}

impl DockerApiRequestV11 {
    pub fn parse_and_verify(
        exact_bytes: &[u8],
        signer: &AuthorizedDockerSignerV11,
        capability: &DockerLaneCapabilityV11,
        now_boottime_ns: u64,
    ) -> Result<Self> {
        signer.validate(now_boottime_ns)?;
        if signer.role != "controller-docker-request-authority" {
            return Err(ControllerError::Rejected(
                "Docker API request signer has the wrong role",
            ));
        }
        let root = docker_parse_exact_canonical_json_v11(
            exact_bytes,
            DOCKER_CONTRACT_MAX_BYTES_V11,
        )?;
        let root_object = object(&root, "Docker API request is not an object")?;
        require_fields(
            root_object,
            &[
                "contractVersion",
                "requestId",
                "capabilityId",
                "capabilitySha256",
                "laneId",
                "daemonGeneration",
                "sourceSealSha256",
                "artifactSealSha256",
                "profile",
                "ownerNamespace",
                "sequence",
                "deadlineBoottimeNs",
                "apiVersion",
                "fixedHeaders",
                "method",
                "normalizedRoute",
                "canonicalQuery",
                "bodySha256",
                "bodyBytes",
                "target",
                "expectedTransition",
                "streamMode",
                "limits",
                "createAuthority",
                "networkMembership",
                "signerAuthorization",
                "signature",
            ],
        )?;
        if string(root_object, "contractVersion")? != "11" {
            return Err(ControllerError::Rejected(
                "Docker API request version is not 11",
            ));
        }
        verify_signed_document(
            &root,
            DOCKER_API_REQUEST_DOMAIN_V11,
            signer,
            now_boottime_ns,
        )?;
        let request_id = identifier(string(root_object, "requestId")?)?;
        let request = Self {
            exact_bytes: exact_bytes.to_vec(),
            canonical_sha256: sha256(exact_bytes),
            request_id: request_id.clone(),
            capability_id: identifier(string(
                root_object,
                "capabilityId",
            )?)?,
            capability_sha256: hex_digest(string(
                root_object,
                "capabilitySha256",
            )?)?,
            lane_id: identifier(string(root_object, "laneId")?)?,
            daemon_generation: identifier(string(
                root_object,
                "daemonGeneration",
            )?)?,
            source_seal_sha256: hex_digest(string(
                root_object,
                "sourceSealSha256",
            )?)?,
            artifact_seal_sha256: hex_digest(string(
                root_object,
                "artifactSealSha256",
            )?)?,
            profile: DockerLaneProfileV11::parse(string(
                root_object,
                "profile",
            )?)?,
            owner_namespace: owner_namespace(string(
                root_object,
                "ownerNamespace",
            )?)?,
            sequence: integer(root_object, "sequence")?,
            deadline_boottime_ns: integer(
                root_object,
                "deadlineBoottimeNs",
            )?,
            api_version: docker_api_version(string(
                root_object,
                "apiVersion",
            )?)?,
            fixed_headers: parse_fixed_headers(field(
                root_object,
                "fixedHeaders",
            )?)?,
            method: docker_method(string(root_object, "method")?)?,
            normalized_route: normalized_route(string(
                root_object,
                "normalizedRoute",
            )?)?,
            canonical_query: parse_query(field(
                root_object,
                "canonicalQuery",
            )?)?,
            body_sha256: hex_digest(string(root_object, "bodySha256")?)?,
            body_bytes: integer(root_object, "bodyBytes")?,
            target: parse_target(field(root_object, "target")?)?,
            expected_transition: parse_transition(field(
                root_object,
                "expectedTransition",
            )?)?,
            stream_mode: DockerStreamModeV11::parse(string(
                root_object,
                "streamMode",
            )?)?,
            limits: parse_bounds(field(root_object, "limits")?, false)?,
            create_authority: parse_create_authority_v12(
                field(root_object, "createAuthority")?,
                signer,
                now_boottime_ns,
            )?,
            network_membership: parse_network_membership_v12(
                field(root_object, "networkMembership")?,
                signer,
                now_boottime_ns,
            )?,
            signer_authorization_leaf_sha256:
                signer.authorization_leaf_sha256,
        };
        request.validate_against(capability, now_boottime_ns)?;
        Ok(request)
    }

    pub fn validate_against(
        &self,
        capability: &DockerLaneCapabilityV11,
        now_boottime_ns: u64,
    ) -> Result<()> {
        if self.capability_id != capability.capability_id
            || !constant_time_eq(
                &self.capability_sha256,
                &capability.canonical_sha256,
            )
            || self.lane_id != capability.lane_id
            || self.daemon_generation != capability.daemon_generation
            || self.source_seal_sha256 != capability.source_seal_sha256
            || self.artifact_seal_sha256
                != capability.artifact_seal_sha256
            || self.profile != capability.profile
            || self.owner_namespace != capability.owner_namespace
            || self.sequence < capability.sequence_start
            || self.sequence > capability.sequence_end
            || self.sequence > DOCKER_MAX_SEQUENCE_V11
            || self.deadline_boottime_ns > capability.deadline_boottime_ns
            || self.deadline_boottime_ns <= now_boottime_ns
            || !capability.allowed_api_versions.contains(&self.api_version)
            || self.body_bytes > self.limits.max_request_bytes
            || !capability.limits.contains(&self.limits)
        {
            return Err(ControllerError::Rejected(
                "Docker API request exceeds or differs from its lane capability",
            ));
        }
        self.limits.validate()?;
        if self.create_authority.is_some()
            && self.network_membership.is_some()
        {
            return Err(ControllerError::Rejected(
                "Docker request cannot combine create and membership authority",
            ));
        }
        if let Some(authority) = self.create_authority.as_ref() {
            authority.validate_against(self, capability)?;
        }
        if let Some(membership) = self.network_membership.as_ref() {
            membership.validate_against(self)?;
        }
        Ok(())
    }

    pub fn verify_wire_binding(
        &self,
        method: &str,
        normalized_route: &str,
        canonical_query: &[(String, String)],
        body_sha256: Digest,
        body_bytes: u64,
    ) -> Result<()> {
        if self.method != method
            || self.normalized_route != normalized_route
            || self.canonical_query != canonical_query
            || !constant_time_eq(&self.body_sha256, &body_sha256)
            || self.body_bytes != body_bytes
        {
            return Err(ControllerError::Rejected(
                "Docker wire request differs from the signed canonical request",
            ));
        }
        Ok(())
    }

    pub fn verify_wire_binding_v12(
        &self,
        method: &str,
        api_version: &str,
        fixed_headers: &[DockerFixedHeaderV11],
        normalized_route: &str,
        canonical_query: &[(String, String)],
        body_sha256: Digest,
        body_bytes: u64,
    ) -> Result<()> {
        self.verify_wire_binding(
            method,
            normalized_route,
            canonical_query,
            body_sha256,
            body_bytes,
        )?;
        if self.api_version != api_version
            || self.fixed_headers != fixed_headers
        {
            return Err(ControllerError::Rejected(
                "Docker wire API version or fixed headers differ from the signed request",
            ));
        }
        Ok(())
    }
}

impl DockerCreateAuthorityV12 {
    fn validate_against(
        &self,
        request: &DockerApiRequestV11,
        capability: &DockerLaneCapabilityV11,
    ) -> Result<()> {
        if self.request_id != request.request_id
            || self.lane_id != request.lane_id
            || self.daemon_generation != request.daemon_generation
            || self.source_seal_sha256 != request.source_seal_sha256
            || self.artifact_seal_sha256 != request.artifact_seal_sha256
            || self.profile != request.profile
            || self.owner_namespace != request.owner_namespace
            || self.container_logical_id != request.target.logical_id
            || request.target.kind != DockerResourceKindV11::Container
            || request.method != "POST"
            || request.normalized_route != "/containers/create"
            || request.profile == DockerLaneProfileV11::Build
            || !capability.allowed_image_digests.contains(&self.image)
        {
            return Err(ControllerError::Rejected(
                "signed Docker create authority differs from its request or lane",
            ));
        }
        if self.kind == DockerCreateAuthorityKindV12::ServiceInstance
            && (self.health.is_none() || self.endpoints.is_empty())
        {
            return Err(ControllerError::Rejected(
                "signed service instance lacks health or endpoint authority",
            ));
        }
        for mount in &self.mounts {
            match mount.kind {
                DockerMountKindV12::SourceCas
                    if mount.cas_sha256
                        == Some(capability.source_seal_sha256)
                        && mount.read_only
                        && mount.size_bytes == 0 => {}
                DockerMountKindV12::ArtifactCas
                    if mount.cas_sha256
                        == Some(capability.artifact_seal_sha256)
                        && mount.read_only
                        && mount.size_bytes == 0 => {}
                DockerMountKindV12::Tmpfs
                    if mount.cas_sha256.is_none()
                        && mount.subpath.is_empty()
                        && !mount.read_only
                        && mount.size_bytes > 0 => {}
                _ => {
                    return Err(ControllerError::Rejected(
                        "Docker mount is not a retained sealed CAS or bounded tmpfs",
                    ))
                }
            }
        }
        Ok(())
    }
}

impl DockerNetworkMembershipV12 {
    fn validate_against(&self, request: &DockerApiRequestV11) -> Result<()> {
        if self.request_id != request.request_id
            || self.lane_id != request.lane_id
            || self.daemon_generation != request.daemon_generation
            || self.owner_namespace != request.owner_namespace
            || self.network_logical_id != request.target.logical_id
            || request.target.kind != DockerResourceKindV11::Network
            || request.target.engine_id.is_none()
            || request.method != "POST"
            || !matches!(
                request.normalized_route.as_str(),
                route if route.starts_with("/networks/")
                    && (route.ends_with("/connect")
                        || route.ends_with("/disconnect"))
            )
        {
            return Err(ControllerError::Rejected(
                "signed network membership differs from its request or lane",
            ));
        }
        let prefix = format!("{}:", self.owner_namespace);
        if !self.container_logical_id.starts_with(&prefix) {
            return Err(ControllerError::Rejected(
                "network membership container is outside the owner namespace",
            ));
        }
        Ok(())
    }
}

pub fn boottime_now_ns_v11() -> Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or(ControllerError::Invalid(
            "CLOCK_BOOTTIME nanoseconds overflowed",
        ))
}

fn parse_create_authority_v12(
    value: &Value,
    signer: &AuthorizedDockerSignerV11,
    now_boottime_ns: u64,
) -> Result<Option<DockerCreateAuthorityV12>> {
    if value.is_null() {
        return Ok(None);
    }
    let exact_bytes = docker_canonical_json_bytes_v11(value)?;
    if exact_bytes.len() > DOCKER_CONTRACT_MAX_BYTES_V11 {
        return Err(ControllerError::Rejected(
            "Docker create authority exceeds its canonical byte bound",
        ));
    }
    let authority =
        object(value, "Docker create authority is not an object")?;
    require_fields(
        authority,
        &[
            "contractVersion",
            "authorityKind",
            "authorityId",
            "requestId",
            "laneId",
            "daemonGeneration",
            "sourceSealSha256",
            "artifactSealSha256",
            "profile",
            "ownerNamespace",
            "containerLogicalId",
            "image",
            "entrypoint",
            "cmd",
            "env",
            "user",
            "workingDir",
            "resources",
            "mounts",
            "aliases",
            "health",
            "endpoints",
            "signerAuthorization",
            "signature",
        ],
    )?;
    if string(authority, "contractVersion")? != "12" {
        return Err(ControllerError::Rejected(
            "Docker create authority version is not 12",
        ));
    }
    let kind = DockerCreateAuthorityKindV12::parse(string(
        authority,
        "authorityKind",
    )?)?;
    let domain = match kind {
        DockerCreateAuthorityKindV12::RunnerExecution => {
            RUNNER_EXECUTION_DOMAIN_V12
        }
        DockerCreateAuthorityKindV12::ServiceInstance => {
            SERVICE_INSTANCE_DOMAIN_V12
        }
    };
    verify_signed_document(value, domain, signer, now_boottime_ns)?;
    let mounts = parse_mounts_v12(field(authority, "mounts")?)?;
    let aliases =
        sorted_string_array(field(authority, "aliases")?, 64, 253, true)?;
    let endpoints = parse_endpoints_v12(field(authority, "endpoints")?)?;
    Ok(Some(DockerCreateAuthorityV12 {
        exact_bytes: exact_bytes.clone(),
        canonical_sha256: sha256(&exact_bytes),
        kind,
        authority_id: identifier(string(authority, "authorityId")?)?,
        request_id: identifier(string(authority, "requestId")?)?,
        lane_id: identifier(string(authority, "laneId")?)?,
        daemon_generation: identifier(string(
            authority,
            "daemonGeneration",
        )?)?,
        source_seal_sha256: hex_digest(string(
            authority,
            "sourceSealSha256",
        )?)?,
        artifact_seal_sha256: hex_digest(string(
            authority,
            "artifactSealSha256",
        )?)?,
        profile: DockerLaneProfileV11::parse(string(
            authority,
            "profile",
        )?)?,
        owner_namespace: owner_namespace(string(
            authority,
            "ownerNamespace",
        )?)?,
        container_logical_id: identifier(string(
            authority,
            "containerLogicalId",
        )?)?,
        image: docker_image_id(string(authority, "image")?)?,
        entrypoint: bounded_string_array(
            field(authority, "entrypoint")?,
            64,
            8192,
        )?,
        command: bounded_string_array(
            field(authority, "cmd")?,
            256,
            8192,
        )?,
        environment: parse_environment_v12(field(authority, "env")?)?,
        user: container_user(string(authority, "user")?)?,
        working_dir: absolute_container_path(string(
            authority,
            "workingDir",
        )?)?,
        resources: parse_resources_v12(field(authority, "resources")?)?,
        mounts,
        aliases,
        health: parse_health_v12(field(authority, "health")?)?,
        endpoints,
        signer_authorization_leaf_sha256:
            signer.authorization_leaf_sha256,
    }))
}

fn parse_network_membership_v12(
    value: &Value,
    signer: &AuthorizedDockerSignerV11,
    now_boottime_ns: u64,
) -> Result<Option<DockerNetworkMembershipV12>> {
    if value.is_null() {
        return Ok(None);
    }
    let exact_bytes = docker_canonical_json_bytes_v11(value)?;
    let membership =
        object(value, "Docker network membership is not an object")?;
    require_fields(
        membership,
        &[
            "contractVersion",
            "membershipId",
            "requestId",
            "laneId",
            "daemonGeneration",
            "ownerNamespace",
            "networkLogicalId",
            "containerLogicalId",
            "containerEngineId",
            "endpointId",
            "aliases",
            "ipv4Address",
            "ipv6Address",
            "signerAuthorization",
            "signature",
        ],
    )?;
    if string(membership, "contractVersion")? != "12" {
        return Err(ControllerError::Rejected(
            "Docker network membership version is not 12",
        ));
    }
    verify_signed_document(
        value,
        NETWORK_MEMBERSHIP_DOMAIN_V12,
        signer,
        now_boottime_ns,
    )?;
    Ok(Some(DockerNetworkMembershipV12 {
        exact_bytes: exact_bytes.clone(),
        canonical_sha256: sha256(&exact_bytes),
        membership_id: identifier(string(
            membership,
            "membershipId",
        )?)?,
        request_id: identifier(string(membership, "requestId")?)?,
        lane_id: identifier(string(membership, "laneId")?)?,
        daemon_generation: identifier(string(
            membership,
            "daemonGeneration",
        )?)?,
        owner_namespace: owner_namespace(string(
            membership,
            "ownerNamespace",
        )?)?,
        network_logical_id: identifier(string(
            membership,
            "networkLogicalId",
        )?)?,
        container_logical_id: identifier(string(
            membership,
            "containerLogicalId",
        )?)?,
        container_engine_id: docker_engine_id(string(
            membership,
            "containerEngineId",
        )?)?,
        endpoint_id: identifier(string(membership, "endpointId")?)?,
        aliases: sorted_string_array(
            field(membership, "aliases")?,
            64,
            253,
            true,
        )?,
        ipv4_address: optional_ip_address(
            field(membership, "ipv4Address")?,
            false,
        )?,
        ipv6_address: optional_ip_address(
            field(membership, "ipv6Address")?,
            true,
        )?,
        signer_authorization_leaf_sha256:
            signer.authorization_leaf_sha256,
    }))
}

fn verify_signed_document(
    root: &Value,
    expected_domain: &str,
    signer: &AuthorizedDockerSignerV11,
    now_boottime_ns: u64,
) -> Result<Digest> {
    let root_object = object(root, "signed Docker document is not an object")?;
    verify_signer_authorization(
        field(root_object, "signerAuthorization")?,
        signer,
        now_boottime_ns,
    )?;
    let signature = object(
        field(root_object, "signature")?,
        "Docker signature is not an object",
    )?;
    require_fields(
        signature,
        &[
            "algorithm",
            "domain",
            "payloadSha256",
            "signatureBase64url",
        ],
    )?;
    if string(signature, "algorithm")? != "Ed25519"
        || string(signature, "domain")? != expected_domain
    {
        return Err(ControllerError::Rejected(
            "Docker signature algorithm or domain differs",
        ));
    }
    let mut payload = root.clone();
    object_mut(&mut payload, "Docker signed document is not mutable")?
        .remove("signature");
    let canonical_payload = docker_canonical_json_bytes_v11(&payload)?;
    let payload_sha256 = sha256(&canonical_payload);
    if string(signature, "payloadSha256")?
        != digest_hex(&payload_sha256)
    {
        return Err(ControllerError::Rejected(
            "Docker signature payload digest differs",
        ));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(string(signature, "signatureBase64url")?)
        .map_err(|_| ControllerError::Invalid(
            "Docker Ed25519 signature is not base64url",
        ))?;
    let signature_bytes: [u8; 64] =
        signature_bytes.try_into().map_err(|_| {
            ControllerError::Invalid(
                "Docker Ed25519 signature length is invalid",
            )
        })?;
    let mut signed = Vec::with_capacity(expected_domain.len() + 33);
    signed.extend_from_slice(expected_domain.as_bytes());
    signed.push(0);
    signed.extend_from_slice(&payload_sha256);
    signer
        .verifying_key
        .verify_strict(
            &signed,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| {
            ControllerError::Rejected(
                "Docker Ed25519 signature is invalid",
            )
        })?;
    Ok(payload_sha256)
}

fn verify_signer_authorization(
    value: &Value,
    signer: &AuthorizedDockerSignerV11,
    now_boottime_ns: u64,
) -> Result<()> {
    signer.validate(now_boottime_ns)?;
    let authority = object(
        value,
        "Docker signer authorization is not an object",
    )?;
    require_fields(
        authority,
        &[
            "role",
            "principalId",
            "keyId",
            "spkiDerSha256",
            "authorizationLeafSha256",
            "authorizationCheckpointSha256",
            "revocationHighwater",
            "notBeforeBoottimeNs",
            "notAfterBoottimeNs",
        ],
    )?;
    if string(authority, "role")? != signer.role
        || string(authority, "principalId")? != signer.principal_id
        || string(authority, "keyId")? != signer.key_id
        || hex_digest(string(authority, "spkiDerSha256")?)?
            != ed25519_spki_der_sha256_v11(&signer.verifying_key)
        || hex_digest(string(
            authority,
            "authorizationLeafSha256",
        )?)? != signer.authorization_leaf_sha256
        || hex_digest(string(
            authority,
            "authorizationCheckpointSha256",
        )?)? != signer.authorization_checkpoint_sha256
        || integer(authority, "revocationHighwater")?
            != signer.revocation_highwater
        || integer(authority, "notBeforeBoottimeNs")?
            != signer.not_before_boottime_ns
        || integer(authority, "notAfterBoottimeNs")?
            != signer.not_after_boottime_ns
    {
        return Err(ControllerError::Rejected(
            "Docker signer authorization differs from the pinned authority",
        ));
    }
    Ok(())
}

fn docker_api_version(value: &str) -> Result<String> {
    if DOCKER_API_VERSIONS_V11.binary_search(&value).is_err() {
        return Err(ControllerError::Rejected(
            "Docker API version is not in the compiled registry",
        ));
    }
    Ok(value.to_owned())
}

fn parse_fixed_headers(value: &Value) -> Result<Vec<DockerFixedHeaderV11>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker fixed headers are not an array",
    ))?;
    if values.is_empty() || values.len() > 3 {
        return Err(ControllerError::Rejected(
            "Docker fixed header set is empty or oversized",
        ));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let header = object(value, "Docker fixed header is not an object")?;
        require_fields(header, &["name", "value"])?;
        let name = string(header, "name")?;
        let value = string(header, "value")?;
        let permitted = match name {
            "accept" => matches!(
                value,
                "application/json"
                    | "application/vnd.docker.raw-stream"
                    | "*/*"
            ),
            "content-type" => matches!(
                value,
                "application/json"
                    | "application/x-tar"
                    | "application/octet-stream"
            ),
            "user-agent" => value == "serverware-controller-v12",
            _ => false,
        };
        if !permitted
            || value.is_empty()
            || value.len() > 128
            || value.bytes().any(|byte| {
                byte < 0x20 || byte == 0x7f
            })
        {
            return Err(ControllerError::Rejected(
                "Docker fixed header name or value is not registered",
            ));
        }
        let candidate = DockerFixedHeaderV11 {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        if result.last().is_some_and(|previous| {
            previous.name.as_str() >= candidate.name.as_str()
        }) {
            return Err(ControllerError::Rejected(
                "Docker fixed headers are not strictly sorted and unique",
            ));
        }
        result.push(candidate);
    }
    if !result.iter().any(|header| {
        header.name == "user-agent"
            && header.value == "serverware-controller-v12"
    }) {
        return Err(ControllerError::Rejected(
            "Docker fixed header set lacks the controller user agent",
        ));
    }
    Ok(result)
}

fn parse_environment_v12(value: &Value) -> Result<Vec<DockerEnvironmentV12>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker environment authority is not an array",
    ))?;
    if values.len() > 256 {
        return Err(ControllerError::Rejected(
            "Docker environment authority is oversized",
        ));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let item = object(value, "Docker environment item is not an object")?;
        require_fields(item, &["name", "value"])?;
        let name = string(item, "name")?;
        let value = string(item, "value")?;
        if name.is_empty()
            || name.len() > 128
            || value.len() > 8192
            || !name.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            })
            || matches!(
                name,
                "DOCKER_HOST"
                    | "DOCKER_CONTEXT"
                    | "DOCKER_CERT_PATH"
                    | "DOCKER_TLS_VERIFY"
            )
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
        {
            return Err(ControllerError::Rejected(
                "Docker environment authority contains an unsafe item",
            ));
        }
        let candidate = DockerEnvironmentV12 {
            name: name.to_owned(),
            value: value.to_owned(),
        };
        if result.last().is_some_and(|previous| {
            previous.name.as_str() >= candidate.name.as_str()
        }) {
            return Err(ControllerError::Rejected(
                "Docker environment authority is not sorted and unique",
            ));
        }
        result.push(candidate);
    }
    Ok(result)
}

fn parse_resources_v12(value: &Value) -> Result<DockerResourceLimitsV12> {
    let resources =
        object(value, "Docker resource authority is not an object")?;
    require_fields(
        resources,
        &["memoryBytes", "nanoCpus", "pidsLimit", "shmBytes"],
    )?;
    let parsed = DockerResourceLimitsV12 {
        memory_bytes: integer(resources, "memoryBytes")?,
        nano_cpus: integer(resources, "nanoCpus")?,
        pids_limit: u32::try_from(integer(resources, "pidsLimit")?)
            .map_err(|_| {
                ControllerError::Invalid(
                    "Docker pids limit exceeds its integer range",
                )
            })?,
        shm_bytes: integer(resources, "shmBytes")?,
    };
    if !(16 * 1024 * 1024..=16 * 1024 * 1024 * 1024)
        .contains(&parsed.memory_bytes)
        || !(1_000_000..=16_000_000_000).contains(&parsed.nano_cpus)
        || !(1..=4096).contains(&parsed.pids_limit)
        || !(4 * 1024 * 1024..=1024 * 1024 * 1024)
            .contains(&parsed.shm_bytes)
    {
        return Err(ControllerError::Rejected(
            "Docker resource authority exceeds the compiled bounds",
        ));
    }
    Ok(parsed)
}

fn parse_mounts_v12(value: &Value) -> Result<Vec<DockerMountV12>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker mount authority is not an array",
    ))?;
    if values.len() > 32 {
        return Err(ControllerError::Rejected(
            "Docker mount authority is oversized",
        ));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let mount = object(value, "Docker mount authority is not an object")?;
        require_fields(
            mount,
            &[
                "mountId",
                "kind",
                "casSha256",
                "subpath",
                "target",
                "readOnly",
                "sizeBytes",
            ],
        )?;
        let kind = DockerMountKindV12::parse(string(mount, "kind")?)?;
        let cas_sha256 = optional_digest(field(mount, "casSha256")?)?;
        let subpath = relative_cas_path(string(mount, "subpath")?)?;
        let target = absolute_container_path(string(mount, "target")?)?;
        let read_only = boolean_value(field(mount, "readOnly")?)?;
        let size_bytes = integer(mount, "sizeBytes")?;
        if target == "/var/run/docker.sock"
            || target == "/run/docker.sock"
            || target.starts_with("/run/serverware/")
            || result.last().is_some_and(|previous: &DockerMountV12| {
                previous.target.as_str() >= target.as_str()
            })
        {
            return Err(ControllerError::Rejected(
                "Docker mounts are not sorted or target a protected path",
            ));
        }
        result.push(DockerMountV12 {
            mount_id: identifier(string(mount, "mountId")?)?,
            kind,
            cas_sha256,
            subpath,
            target,
            read_only,
            size_bytes,
        });
    }
    Ok(result)
}

fn parse_health_v12(value: &Value) -> Result<Option<DockerHealthCheckV12>> {
    if value.is_null() {
        return Ok(None);
    }
    let health = object(value, "Docker health authority is not an object")?;
    require_fields(
        health,
        &[
            "test",
            "intervalMs",
            "timeoutMs",
            "retries",
            "startPeriodMs",
        ],
    )?;
    let test = bounded_string_array(field(health, "test")?, 32, 4096)?;
    let interval_ms = integer(health, "intervalMs")?;
    let timeout_ms = integer(health, "timeoutMs")?;
    let retries = u32::try_from(integer(health, "retries")?).map_err(
        |_| ControllerError::Invalid("Docker health retries overflowed"),
    )?;
    let start_period_ms = integer(health, "startPeriodMs")?;
    if !matches!(test.first().map(String::as_str), Some("CMD") | Some("CMD-SHELL"))
        || test.len() < 2
        || !(100..=3_600_000).contains(&interval_ms)
        || !(100..=600_000).contains(&timeout_ms)
        || timeout_ms > interval_ms
        || !(1..=100).contains(&retries)
        || start_period_ms > 3_600_000
    {
        return Err(ControllerError::Rejected(
            "Docker health authority exceeds the compiled bounds",
        ));
    }
    Ok(Some(DockerHealthCheckV12 {
        test,
        interval_ms,
        timeout_ms,
        retries,
        start_period_ms,
    }))
}

fn parse_endpoints_v12(value: &Value) -> Result<Vec<DockerEndpointV12>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker endpoint authority is not an array",
    ))?;
    if values.len() > 64 {
        return Err(ControllerError::Rejected(
            "Docker endpoint authority is oversized",
        ));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let endpoint =
            object(value, "Docker endpoint authority is not an object")?;
        require_fields(endpoint, &["name", "protocol", "containerPort"])?;
        let name = dns_name(string(endpoint, "name")?)?;
        let protocol = string(endpoint, "protocol")?;
        let container_port =
            u16::try_from(integer(endpoint, "containerPort")?).map_err(
                |_| {
                    ControllerError::Invalid(
                        "Docker endpoint port exceeds 65535",
                    )
                },
            )?;
        if container_port == 0
            || !matches!(protocol, "tcp" | "udp")
            || result.last().is_some_and(
                |previous: &DockerEndpointV12| {
                    (
                        previous.name.as_str(),
                        previous.protocol.as_str(),
                        previous.container_port,
                    ) >= (name.as_str(), protocol, container_port)
                },
            )
        {
            return Err(ControllerError::Rejected(
                "Docker endpoint authority is invalid or not sorted",
            ));
        }
        result.push(DockerEndpointV12 {
            name,
            protocol: protocol.to_owned(),
            container_port,
        });
    }
    Ok(result)
}

fn bounded_string_array(
    value: &Value,
    maximum_items: usize,
    maximum_item_bytes: usize,
) -> Result<Vec<String>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker string authority is not an array",
    ))?;
    if values.len() > maximum_items {
        return Err(ControllerError::Rejected(
            "Docker string authority has too many items",
        ));
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or(ControllerError::Invalid(
                "Docker string authority item is not a string",
            ))?;
            if value.is_empty()
                || value.len() > maximum_item_bytes
                || value.bytes().any(|byte| byte == 0)
            {
                return Err(ControllerError::Rejected(
                    "Docker string authority item is invalid",
                ));
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn sorted_string_array(
    value: &Value,
    maximum_items: usize,
    maximum_item_bytes: usize,
    require_dns: bool,
) -> Result<Vec<String>> {
    let values =
        bounded_string_array(value, maximum_items, maximum_item_bytes)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1])
        || require_dns
            && values
                .iter()
                .any(|value| dns_name(value).is_err())
    {
        return Err(ControllerError::Rejected(
            "Docker string set is not strictly sorted, unique, and valid",
        ));
    }
    Ok(values)
}

fn container_user(value: &str) -> Result<String> {
    let (uid, gid) = value.split_once(':').unwrap_or((value, value));
    let uid = uid.parse::<u32>().map_err(|_| {
        ControllerError::Invalid("Docker container UID is not numeric")
    })?;
    let gid = gid.parse::<u32>().map_err(|_| {
        ControllerError::Invalid("Docker container GID is not numeric")
    })?;
    if uid == 0 || gid == 0 || uid > 65_535 || gid > 65_535 {
        return Err(ControllerError::Rejected(
            "Docker container user must be a bounded non-root UID and GID",
        ));
    }
    Ok(format!("{uid}:{gid}"))
}

fn absolute_container_path(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 4096
        || !value.starts_with('/')
        || value.contains("//")
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(ControllerError::Rejected(
            "Docker container path is not absolute and normalized",
        ));
    }
    Ok(value.to_owned())
}

fn relative_cas_path(value: &str) -> Result<String> {
    if value.len() > 4096
        || value.starts_with('/')
        || value.contains("//")
        || value.split('/').any(|part| matches!(part, "." | ".."))
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(ControllerError::Rejected(
            "Docker retained CAS subpath is not normalized",
        ));
    }
    Ok(value.to_owned())
}

fn dns_name(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                })
        })
    {
        return Err(ControllerError::Rejected(
            "Docker DNS name is invalid",
        ));
    }
    Ok(value.to_owned())
}

fn optional_ip_address(value: &Value, ipv6: bool) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    let address = value.as_str().ok_or(ControllerError::Invalid(
        "Docker endpoint address is not a string or null",
    ))?;
    let valid = if ipv6 {
        address.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        address.parse::<std::net::Ipv4Addr>().is_ok()
    };
    if !valid {
        return Err(ControllerError::Rejected(
            "Docker endpoint address is not canonical for its family",
        ));
    }
    Ok(Some(address.to_owned()))
}

fn optional_digest(value: &Value) -> Result<Option<Digest>> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(hex_digest(value.as_str().ok_or(
            ControllerError::Invalid(
                "Docker optional digest is not a string or null",
            ),
        )?)?))
    }
}

fn boolean_value(value: &Value) -> Result<bool> {
    value.as_bool().ok_or(ControllerError::Invalid(
        "Docker contract value is not a boolean",
    ))
}

fn docker_image_id(value: &str) -> Result<String> {
    if !valid_image_id(value) {
        return Err(ControllerError::Rejected(
            "Docker create image is not an exact sha256 content ID",
        ));
    }
    Ok(value.to_owned())
}

fn docker_engine_id(value: &str) -> Result<String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ControllerError::Rejected(
            "Docker engine ID is not an exact lowercase content ID",
        ));
    }
    Ok(value.to_owned())
}

fn parse_build_tuple(value: &Value) -> Result<Option<DockerBuildTupleV11>> {
    if value.is_null() {
        return Ok(None);
    }
    let object = object(value, "Docker build tuple is not an object")?;
    require_fields(
        object,
        &[
            "contextCasSha256",
            "dockerfileCasSha256",
            "target",
            "platform",
            "output",
            "buildArgsSha256",
        ],
    )?;
    let target = string(object, "target")?;
    let platform = string(object, "platform")?;
    let output = string(object, "output")?;
    if target.is_empty()
        || target.len() > 128
        || !target.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
        })
        || !matches!(
            platform,
            "linux/amd64"
                | "linux/arm64"
                | "linux/amd64/v1"
                | "linux/amd64/v2"
                | "linux/amd64/v3"
                | "linux/amd64/v4"
                | "linux/arm64/v8"
                | "linux/arm64/v9"
        )
        || output != "oci-cas"
    {
        return Err(ControllerError::Rejected(
            "Docker build tuple is outside the fixed v11 forms",
        ));
    }
    Ok(Some(DockerBuildTupleV11 {
        context_cas_sha256: hex_digest(string(
            object,
            "contextCasSha256",
        )?)?,
        dockerfile_cas_sha256: hex_digest(string(
            object,
            "dockerfileCasSha256",
        )?)?,
        target: target.to_owned(),
        platform: platform.to_owned(),
        output: output.to_owned(),
        build_args_sha256: hex_digest(string(
            object,
            "buildArgsSha256",
        )?)?,
    }))
}

fn parse_target(value: &Value) -> Result<DockerTargetV11> {
    let target = object(value, "Docker target is not an object")?;
    require_fields(target, &["kind", "logicalId", "engineId"])?;
    let engine_id = match field(target, "engineId")? {
        Value::Null => None,
        Value::String(value)
            if !value.is_empty()
                && value.len() <= 512
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'.' | b'_' | b':' | b'@' | b'/' | b'-'
                        )
                }) =>
        {
            Some(value.clone())
        }
        _ => {
            return Err(ControllerError::Rejected(
                "Docker target engine ID is noncanonical",
            ))
        }
    };
    Ok(DockerTargetV11 {
        kind: DockerResourceKindV11::parse(string(target, "kind")?)?,
        logical_id: identifier(string(target, "logicalId")?)?,
        engine_id,
    })
}

fn parse_transition(value: &Value) -> Result<DockerTransitionV11> {
    let transition = object(
        value,
        "Docker expected transition is not an object",
    )?;
    require_fields(transition, &["from", "to"])?;
    let transition = DockerTransitionV11 {
        from: DockerObjectStateV11::parse(string(transition, "from")?)?,
        to: DockerObjectStateV11::parse(string(transition, "to")?)?,
    };
    if transition.from == DockerObjectStateV11::Unknown
        || transition.to == DockerObjectStateV11::Unknown
    {
        return Err(ControllerError::Rejected(
            "Docker requested transition must be an exact non-UNKNOWN state pair",
        ));
    }
    Ok(transition)
}

fn parse_bounds(value: &Value, capability: bool) -> Result<DockerBoundsV11> {
    let limits = object(value, "Docker limits are not an object")?;
    let expected = if capability {
        &[
            "maxRequestBytes",
            "maxResponseBytes",
            "maxStreamBytes",
            "maxDurationMs",
            "maxObjects",
        ][..]
    } else {
        &[
            "maxRequestBytes",
            "maxResponseBytes",
            "maxStreamBytes",
            "maxDurationMs",
        ][..]
    };
    require_fields(limits, expected)?;
    let bounds = DockerBoundsV11 {
        max_request_bytes: integer(limits, "maxRequestBytes")?,
        max_response_bytes: integer(limits, "maxResponseBytes")?,
        max_stream_bytes: integer(limits, "maxStreamBytes")?,
        max_duration_ms: integer(limits, "maxDurationMs")?,
        max_objects: if capability {
            Some(
                u32::try_from(integer(limits, "maxObjects")?).map_err(
                    |_| {
                        ControllerError::Invalid(
                            "Docker object bound is too large",
                        )
                    },
                )?,
            )
        } else {
            None
        },
    };
    bounds.validate()?;
    Ok(bounds)
}

fn parse_query(value: &Value) -> Result<Vec<(String, String)>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker canonical query is not an array",
    ))?;
    if values.len() > 32 {
        return Err(ControllerError::Rejected(
            "Docker canonical query has too many pairs",
        ));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let pair = object(value, "Docker query pair is not an object")?;
        require_fields(pair, &["name", "value"])?;
        let name = string(pair, "name")?;
        let value = string(pair, "value")?;
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'_' | b'-')
                }
            })
            || value.len() > 2048
        {
            return Err(ControllerError::Rejected(
                "Docker canonical query pair is invalid",
            ));
        }
        let candidate = (name.to_owned(), value.to_owned());
        if result.last().is_some_and(|previous| previous >= &candidate) {
            return Err(ControllerError::Rejected(
                "Docker canonical query is not strictly sorted and unique",
            ));
        }
        result.push(candidate);
    }
    Ok(result)
}

fn string_set(
    value: &Value,
    maximum: usize,
) -> Result<BTreeSet<String>> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker authority list is not an array",
    ))?;
    if values.len() > maximum {
        return Err(ControllerError::Rejected(
            "Docker authority list exceeds its bound",
        ));
    }
    let mut result = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(ControllerError::Invalid(
            "Docker authority list entry is not a string",
        ))?;
        if value.is_empty()
            || value.len() > 512
            || !result.insert(value.to_owned())
        {
            return Err(ControllerError::Rejected(
                "Docker authority list is duplicate or invalid",
            ));
        }
    }
    Ok(result)
}

fn valid_digest_image(value: &str) -> bool {
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty()
        && digest.len() == 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b':' | b'-')
        })
        && digest.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
}

fn valid_image_id(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
}

fn docker_method(value: &str) -> Result<String> {
    if matches!(value, "GET" | "HEAD" | "POST" | "DELETE") {
        Ok(value.to_owned())
    } else {
        Err(ControllerError::Rejected(
            "Docker method is not in the v11 allowlist",
        ))
    }
}

fn normalized_route(value: &str) -> Result<String> {
    if value.len() < 2
        || value.len() > 256
        || !value.starts_with('/')
        || value.contains("//")
        || value.contains("..")
        || value.contains('%')
        || value.contains('?')
        || value.bytes().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'/' | b'_' | b'.' | b'{' | b'}' | b':' | b'-'
                ))
        })
    {
        return Err(ControllerError::Rejected(
            "Docker normalized route is noncanonical",
        ));
    }
    Ok(value.to_owned())
}

fn identifier(value: &str) -> Result<String> {
    if value.len() < 8
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphanumeric()
            } else {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'-')
            }
        })
    {
        return Err(ControllerError::Rejected(
            "Docker authority identifier is noncanonical",
        ));
    }
    Ok(value.to_owned())
}

fn owner_namespace(value: &str) -> Result<String> {
    if value.len() < 18
        || value.len() > 63
        || !value.starts_with("serverware-")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'
        })
    {
        return Err(ControllerError::Rejected(
            "Docker owner namespace is noncanonical",
        ));
    }
    Ok(value.to_owned())
}

fn hex_digest(value: &str) -> Result<Digest> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
    {
        return Err(ControllerError::Invalid(
            "Docker digest is not lowercase SHA-256",
        ));
    }
    let decoded = hex::decode(value)
        .map_err(|_| ControllerError::Invalid("Docker digest is invalid"))?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    if digest == [0; 32] {
        return Err(ControllerError::Rejected(
            "Docker digest must not be zero",
        ));
    }
    Ok(digest)
}

fn object<'a>(
    value: &'a Value,
    message: &'static str,
) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or(ControllerError::Invalid(message))
}

fn object_mut<'a>(
    value: &'a mut Value,
    message: &'static str,
) -> Result<&'a mut Map<String, Value>> {
    value.as_object_mut().ok_or(ControllerError::Invalid(message))
}

fn field<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a Value> {
    object
        .get(name)
        .ok_or(ControllerError::Invalid(name))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str> {
    field(object, name)?
        .as_str()
        .ok_or(ControllerError::Invalid(name))
}

fn integer(
    object: &Map<String, Value>,
    name: &'static str,
) -> Result<u64> {
    field(object, name)?
        .as_u64()
        .ok_or(ControllerError::Invalid(name))
}

fn require_fields(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<()> {
    if object.len() != expected.len()
        || expected.iter().any(|field| !object.contains_key(*field))
    {
        return Err(ControllerError::Rejected(
            "Docker contract contains missing or unknown fields",
        ));
    }
    Ok(())
}

const DOCKER_JSON_MAX_DEPTH_V11: usize = 64;
const DOCKER_JSON_MAX_NODES_V11: usize = 65_536;

pub fn docker_parse_exact_canonical_json_v11(
    exact_bytes: &[u8],
    maximum_bytes: usize,
) -> Result<Value> {
    if exact_bytes.is_empty()
        || exact_bytes.len() > maximum_bytes
        || maximum_bytes > DOCKER_CONTRACT_MAX_BYTES_V11
    {
        return Err(ControllerError::Rejected(
            "Docker JSON exceeds its exact byte bound",
        ));
    }
    let mut parser = DockerJsonParserV11 {
        bytes: exact_bytes,
        offset: 0,
        nodes: 0,
        maximum_bytes,
    };
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.offset != exact_bytes.len() {
        return Err(ControllerError::Rejected(
            "Docker JSON contains trailing data",
        ));
    }
    let canonical = docker_canonical_json_bytes_v11(&value)?;
    if canonical != exact_bytes {
        return Err(ControllerError::Rejected(
            "Docker JSON is not exact RFC 8785 canonical form",
        ));
    }
    Ok(value)
}

pub fn docker_canonical_json_bytes_v11(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_docker_canonical_value_v11(value, &mut output, 0)?;
    if output.is_empty() || output.len() > DOCKER_CONTRACT_MAX_BYTES_V11 {
        return Err(ControllerError::Rejected(
            "Docker canonical JSON exceeds its bound",
        ));
    }
    Ok(output)
}

struct DockerJsonParserV11<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
    maximum_bytes: usize,
}

impl DockerJsonParserV11<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<Value> {
        self.skip_whitespace();
        if depth > DOCKER_JSON_MAX_DEPTH_V11
            || self.nodes >= DOCKER_JSON_MAX_NODES_V11
        {
            return Err(ControllerError::Rejected(
                "Docker JSON nesting or node count exceeds its bound",
            ));
        }
        self.nodes += 1;
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_integer(),
            _ => Err(ControllerError::Invalid(
                "Docker JSON value token is invalid",
            )),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut object = Map::new();
        let mut names = BTreeSet::new();
        if self.consume_if(b'}') {
            return Ok(Value::Object(object));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(ControllerError::Invalid(
                    "Docker JSON object name is absent",
                ));
            }
            let name = self.parse_string()?;
            if !names.insert(name.clone()) {
                return Err(ControllerError::Rejected(
                    "Docker JSON object contains a duplicate decoded name",
                ));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value(depth)?;
            object.insert(name, value);
            self.skip_whitespace();
            if self.consume_if(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Value::Object(object))
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume_if(b']') {
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.consume_if(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Value::Array(values))
    }

    fn parse_integer(&mut self) -> Result<Value> {
        let start = self.offset;
        let negative = self.consume_if(b'-');
        let first = self.peek().ok_or(ControllerError::Invalid(
            "Docker JSON integer is truncated",
        ))?;
        if first == b'0' {
            self.offset += 1;
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(ControllerError::Rejected(
                    "Docker JSON integer contains a leading zero",
                ));
            }
        } else if matches!(first, b'1'..=b'9') {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
        } else {
            return Err(ControllerError::Invalid(
                "Docker JSON integer token is invalid",
            ));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E' | b'+')) {
            return Err(ControllerError::Rejected(
                "Docker JSON floats and exponents are forbidden",
            ));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| {
                ControllerError::Invalid(
                    "Docker JSON integer is not ASCII",
                )
            })?;
        if negative {
            let value = text.parse::<i64>().map_err(|_| {
                ControllerError::Invalid(
                    "Docker JSON integer overflowed",
                )
            })?;
            if value == 0 || value < -(DOCKER_MAX_SEQUENCE_V11 as i64) {
                return Err(ControllerError::Rejected(
                    "Docker JSON integer is not a safe canonical integer",
                ));
            }
            Ok(Value::Number(serde_json::Number::from(value)))
        } else {
            let value = text.parse::<u64>().map_err(|_| {
                ControllerError::Invalid(
                    "Docker JSON integer overflowed",
                )
            })?;
            if value > DOCKER_MAX_SEQUENCE_V11 {
                return Err(ControllerError::Rejected(
                    "Docker JSON integer exceeds 2^53-1",
                ));
            }
            Ok(Value::Number(serde_json::Number::from(value)))
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut value = String::new();
        loop {
            let byte = self.peek().ok_or(ControllerError::Invalid(
                "Docker JSON string is truncated",
            ))?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    break;
                }
                b'\\' => {
                    self.offset += 1;
                    self.parse_escape(&mut value)?;
                }
                0x00..=0x1f => {
                    return Err(ControllerError::Rejected(
                        "Docker JSON string contains an unescaped control",
                    ));
                }
                0x20..=0x7f => {
                    self.offset += 1;
                    value.push(byte as char);
                }
                _ => {
                    let remaining = std::str::from_utf8(
                        &self.bytes[self.offset..],
                    )
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "Docker JSON string is not valid UTF-8",
                        )
                    })?;
                    let character = remaining.chars().next().ok_or(
                        ControllerError::Invalid(
                            "Docker JSON string character is absent",
                        ),
                    )?;
                    self.offset += character.len_utf8();
                    value.push(character);
                }
            }
            if value.len() > self.maximum_bytes {
                return Err(ControllerError::Rejected(
                    "Docker JSON string exceeds its bound",
                ));
            }
        }
        Ok(value)
    }

    fn parse_escape(&mut self, output: &mut String) -> Result<()> {
        let escaped = self.take().ok_or(ControllerError::Invalid(
            "Docker JSON escape is truncated",
        ))?;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.parse_hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.take() != Some(b'\\')
                        || self.take() != Some(b'u')
                    {
                        return Err(ControllerError::Rejected(
                            "Docker JSON high surrogate lacks its low surrogate",
                        ));
                    }
                    let second = self.parse_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ControllerError::Rejected(
                            "Docker JSON surrogate pair is invalid",
                        ));
                    }
                    0x10000
                        + (((first as u32 - 0xd800) << 10)
                            | (second as u32 - 0xdc00))
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ControllerError::Rejected(
                        "Docker JSON contains a lone low surrogate",
                    ));
                } else {
                    first as u32
                };
                output.push(char::from_u32(scalar).ok_or(
                    ControllerError::Invalid(
                        "Docker JSON Unicode scalar is invalid",
                    ),
                )?);
            }
            _ => {
                return Err(ControllerError::Invalid(
                    "Docker JSON escape is invalid",
                ));
            }
        }
        Ok(())
    }

    fn parse_hex_quad(&mut self) -> Result<u16> {
        let end = self.offset.checked_add(4).ok_or(
            ControllerError::Invalid(
                "Docker JSON Unicode escape overflowed",
            ),
        )?;
        let bytes = self.bytes.get(self.offset..end).ok_or(
            ControllerError::Invalid(
                "Docker JSON Unicode escape is truncated",
            ),
        )?;
        if !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ControllerError::Invalid(
                "Docker JSON Unicode escape is invalid",
            ));
        }
        self.offset = end;
        std::str::from_utf8(bytes)
            .map_err(|_| {
                ControllerError::Invalid(
                    "Docker JSON Unicode escape is not ASCII",
                )
            })
            .and_then(|value| {
                u16::from_str_radix(value, 16).map_err(|_| {
                    ControllerError::Invalid(
                        "Docker JSON Unicode escape is invalid",
                    )
                })
            })
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<()> {
        if self
            .bytes
            .get(self.offset..self.offset + literal.len())
            != Some(literal)
        {
            return Err(ControllerError::Invalid(
                "Docker JSON literal is invalid",
            ));
        }
        self.offset += literal.len();
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        if self.take() != Some(expected) {
            return Err(ControllerError::Invalid(
                "Docker JSON punctuation is invalid",
            ));
        }
        Ok(())
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.offset += 1;
        Some(byte)
    }
}

fn write_docker_canonical_value_v11(
    value: &Value,
    output: &mut Vec<u8>,
    depth: usize,
) -> Result<()> {
    if depth > DOCKER_JSON_MAX_DEPTH_V11 {
        return Err(ControllerError::Rejected(
            "Docker canonical JSON nesting exceeds its bound",
        ));
    }
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value < -(DOCKER_MAX_SEQUENCE_V11 as i64) {
                    return Err(ControllerError::Rejected(
                        "Docker canonical JSON integer is unsafe",
                    ));
                }
                output.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                if value > DOCKER_MAX_SEQUENCE_V11 {
                    return Err(ControllerError::Rejected(
                        "Docker canonical JSON integer is unsafe",
                    ));
                }
                output.extend_from_slice(value.to_string().as_bytes());
            } else {
                return Err(ControllerError::Rejected(
                    "Docker canonical JSON floats are forbidden",
                ));
            }
        }
        Value::String(value) => write_docker_canonical_string_v11(value, output),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_docker_canonical_value_v11(
                    value,
                    output,
                    depth + 1,
                )?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut names = object.keys().collect::<Vec<_>>();
            names.sort_by(|left, right| {
                left.encode_utf16()
                    .cmp(right.encode_utf16())
            });
            output.push(b'{');
            for (index, name) in names.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_docker_canonical_string_v11(name, output);
                output.push(b':');
                let child = object.get(*name).ok_or(
                    ControllerError::Invalid(
                        "Docker canonical JSON object key disappeared",
                    ),
                )?;
                write_docker_canonical_value_v11(
                    child,
                    output,
                    depth + 1,
                )?;
            }
            output.push(b'}');
        }
    }
    if output.len() > DOCKER_CONTRACT_MAX_BYTES_V11 {
        return Err(ControllerError::Rejected(
            "Docker canonical JSON exceeds its bound",
        ));
    }
    Ok(())
}

fn write_docker_canonical_string_v11(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\u{0008}' => output.extend_from_slice(br#"\b"#),
            '\u{0009}' => output.extend_from_slice(br#"\t"#),
            '\u{000a}' => output.extend_from_slice(br#"\n"#),
            '\u{000c}' => output.extend_from_slice(br#"\f"#),
            '\u{000d}' => output.extend_from_slice(br#"\r"#),
            '\u{0000}'..='\u{001f}' => {
                let escaped = format!("\\u{:04x}", character as u32);
                output.extend_from_slice(escaped.as_bytes());
            }
            _ => {
                let mut encoded = [0u8; 4];
                output.extend_from_slice(
                    character.encode_utf8(&mut encoded).as_bytes(),
                );
            }
        }
    }
    output.push(b'"');
}
