#![allow(dead_code)]

use crate::coder_controller_v11::{ControllerError, Digest, Result};
use crate::docker_contract::{
    docker_parse_exact_canonical_json_v11, DockerApiRequestV11,
    DockerBuildTupleV11, DockerCreateAuthorityV12,
    DockerLaneCapabilityV11, DockerLaneDecodedPayloadV12,
    DockerLaneOperationV12, DockerLanePayloadContentV12,
    DockerLaneProfileV11, DockerMountKindV12, DockerObjectStateV11,
    DockerResourceKindV11, DockerStreamModeV11,
    AuthoritativeLaneState, LogicalLane, PlanPhase,
    PrivateDindProfileV12, ProxyOperation,
    DOCKER_CONTRACT_MAX_BYTES_V11,
};
use serde_json::{Map, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const OWNER_LABEL_V11: &str =
    "com.serverware.controller.owner-namespace";
pub const LANE_LABEL_V11: &str = "com.serverware.controller.lane-id";
pub const GENERATION_LABEL_V11: &str =
    "com.serverware.controller.daemon-generation";
pub const LOGICAL_ID_LABEL_V11: &str =
    "com.serverware.controller.logical-id";
pub const SOURCE_SEAL_LABEL_V11: &str =
    "com.serverware.controller.source-seal-sha256";
pub const ARTIFACT_SEAL_LABEL_V11: &str =
    "com.serverware.controller.artifact-seal-sha256";
pub const OWNER_LABEL_V12: &str = "com.serverware.coder.v12.owner";
pub const LANE_LABEL_V12: &str = "com.serverware.coder.v12.lane";
pub const GENERATION_LABEL_V12: &str =
    "com.serverware.coder.v12.generation";
pub const RESOURCE_LABEL_V12: &str =
    "com.serverware.coder.v12.resource";
pub const SOURCE_SEAL_LABEL_V12: &str =
    "com.serverware.coder.v12.source-seal-sha256";
pub const ARTIFACT_SEAL_LABEL_V12: &str =
    "com.serverware.coder.v12.artifact-seal-sha256";
pub const SERVICE_ID_LABEL_V12: &str =
    "com.serverware.coder.v12.service-id";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerLaneEffectV12 {
    Read,
    CreateGeneration,
    MutateBuildImageStore,
    MutateRuntimeObjects,
    ExportSealedArtifacts,
    DestroyGeneration,
    ReadinessProbe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerLanePolicyDecisionV12 {
    pub effect: DockerLaneEffectV12,
    pub authoritative_state: AuthoritativeLaneState,
    pub owner_labels: BTreeMap<String, String>,
    pub returned_fd_count: usize,
}

pub fn authorize_lane_operation_v12(
    operation: &DockerLaneOperationV12,
) -> Result<DockerLanePolicyDecisionV12> {
    let request = &operation.request;
    let payload = match &operation.decoded_payload {
        DockerLaneDecodedPayloadV12::Operation(payload) => Some(payload),
        DockerLaneDecodedPayloadV12::Query(_) => None,
        DockerLaneDecodedPayloadV12::Readiness(_) => None,
    };
    let state_operation = match &operation.decoded_payload {
        DockerLaneDecodedPayloadV12::Query(query) => {
            query.original_operation
        }
        _ => request.operation,
    };
    let expected_state = match state_operation {
        ProxyOperation::CreateBuildDind => AuthoritativeLaneState::Declared,
        ProxyOperation::PullPinned | ProxyOperation::BuildExact => {
            AuthoritativeLaneState::Preparing
        }
        ProxyOperation::ExportOwnedOci => {
            AuthoritativeLaneState::BodyTerminal
        }
        ProxyOperation::DestroyBuildDind
        | ProxyOperation::DestroyNoBuildDind => {
            AuthoritativeLaneState::Destroying
        }
        ProxyOperation::CreateNoBuildDind => {
            AuthoritativeLaneState::Destroyed
        }
        ProxyOperation::ImportSealedOci => {
            AuthoritativeLaneState::Preparing
        }
        ProxyOperation::CreateRunner
        | ProxyOperation::CreateServices
        | ProxyOperation::RunRepositoryBody => {
            AuthoritativeLaneState::Prepared
        }
        ProxyOperation::StopRunner
        | ProxyOperation::DestroyServices => {
            AuthoritativeLaneState::BodyTerminal
        }
        ProxyOperation::QueryAuthoritativeState => request.expected_state,
        ProxyOperation::ReadinessDockerUpgrade
        | ProxyOperation::ReadinessService
        | ProxyOperation::ReadinessChromium
        | ProxyOperation::ReadinessTeardown => {
            AuthoritativeLaneState::Declared
        }
    };
    if request.expected_state != expected_state {
        return Err(ControllerError::Rejected(
            "lane proxy expected state differs from the exact operation contract",
        ));
    }
    let expected_phase = match state_operation {
        ProxyOperation::RunRepositoryBody
        | ProxyOperation::StopRunner
        | ProxyOperation::DestroyServices => PlanPhase::Body,
        _ => PlanPhase::Prepare,
    };
    if request.phase != expected_phase {
        return Err(ControllerError::Rejected(
            "lane proxy phase differs from the exact operation table",
        ));
    }
    if request.operation == ProxyOperation::CreateServices
        && !matches!(
            request.lane,
            LogicalLane::Integration | LogicalLane::E2e
        )
    {
        return Err(ControllerError::Rejected(
            "service creation is outside integration/e2e lanes",
        ));
    }
    let (effect, authoritative_state, returned_fd_count) =
        match request.operation {
            ProxyOperation::CreateBuildDind
            | ProxyOperation::CreateNoBuildDind => (
                DockerLaneEffectV12::CreateGeneration,
                AuthoritativeLaneState::Preparing,
                0,
            ),
            ProxyOperation::PullPinned => (
                DockerLaneEffectV12::MutateBuildImageStore,
                AuthoritativeLaneState::Preparing,
                0,
            ),
            ProxyOperation::BuildExact => (
                DockerLaneEffectV12::MutateBuildImageStore,
                AuthoritativeLaneState::Prepared,
                0,
            ),
            ProxyOperation::ExportOwnedOci => (
                DockerLaneEffectV12::ExportSealedArtifacts,
                AuthoritativeLaneState::Sealed,
                1,
            ),
            ProxyOperation::ImportSealedOci => (
                DockerLaneEffectV12::MutateRuntimeObjects,
                AuthoritativeLaneState::Preparing,
                0,
            ),
            ProxyOperation::CreateRunner
            | ProxyOperation::CreateServices => (
                DockerLaneEffectV12::MutateRuntimeObjects,
                AuthoritativeLaneState::Prepared,
                0,
            ),
            ProxyOperation::RunRepositoryBody => (
                DockerLaneEffectV12::MutateRuntimeObjects,
                AuthoritativeLaneState::BodyTerminal,
                0,
            ),
            ProxyOperation::StopRunner
            | ProxyOperation::DestroyServices => (
                DockerLaneEffectV12::MutateRuntimeObjects,
                AuthoritativeLaneState::BodyTerminal,
                0,
            ),
            ProxyOperation::DestroyBuildDind
            | ProxyOperation::DestroyNoBuildDind => (
                DockerLaneEffectV12::DestroyGeneration,
                AuthoritativeLaneState::Destroyed,
                0,
            ),
            ProxyOperation::QueryAuthoritativeState => (
                DockerLaneEffectV12::Read,
                AuthoritativeLaneState::OutcomeUnknown,
                0,
            ),
            ProxyOperation::ReadinessDockerUpgrade
            | ProxyOperation::ReadinessService
            | ProxyOperation::ReadinessChromium
            | ProxyOperation::ReadinessTeardown => (
                DockerLaneEffectV12::ReadinessProbe,
                AuthoritativeLaneState::Declared,
                0,
            ),
        };
    match operation.profile {
        PrivateDindProfileV12::Build => {
            if request.lane != LogicalLane::Build
                || matches!(
                    request.operation,
                    ProxyOperation::CreateNoBuildDind
                        | ProxyOperation::ImportSealedOci
                        | ProxyOperation::DestroyNoBuildDind
                        | ProxyOperation::CreateServices
                )
                || payload.is_some_and(|payload| {
                    payload.artifact_manifest_sha256.is_some()
                })
            {
                return Err(ControllerError::Rejected(
                    "build generation operation crossed the exact build-only boundary",
                ));
            }
        }
        PrivateDindProfileV12::NoBuild => {
            if request.lane == LogicalLane::Build
                || matches!(
                    request.operation,
                    ProxyOperation::CreateBuildDind
                        | ProxyOperation::PullPinned
                        | ProxyOperation::BuildExact
                        | ProxyOperation::ExportOwnedOci
                        | ProxyOperation::DestroyBuildDind
                )
                || payload.is_some_and(|payload| {
                    payload.artifact_manifest_sha256.is_none()
                })
            {
                return Err(ControllerError::Rejected(
                    "no-build generation attempted a build or unsealed operation",
                ));
            }
        }
    }
    if let Some(payload) = payload {
        if payload.source.manifest_sha256 == [0; 32]
            || payload.prepare_sha256 == Some([0; 32])
            || payload.body_sha256 == Some([0; 32])
        {
            return Err(ControllerError::Rejected(
                "lane operation omitted its signed source or lane contract binding",
            ));
        }
        match &payload.content {
            DockerLanePayloadContentV12::CreateBuildDind {
                exact_build,
                ..
            }
            | DockerLanePayloadContentV12::BuildExact {
                exact_build,
            } if exact_build.source_manifest_sha256
                != payload.source.manifest_sha256 =>
            {
                return Err(ControllerError::Rejected(
                    "exact build source differs from the retained source CAS",
                ))
            }
            DockerLanePayloadContentV12::CreateNoBuildDind {
                artifacts,
                required_oci_import_closure,
                runner,
                ..
            } if Some(artifacts.manifest_sha256)
                != payload.artifact_manifest_sha256
                || artifacts.source_manifest_sha256
                    != payload.source.manifest_sha256
                || required_oci_import_closure
                    .validate_against(artifacts)
                    .is_err()
                || required_oci_import_closure
                    .manifest_sha256
                    .binary_search(
                        &runner.image.manifest_digest_sha256,
                    )
                    .is_err() =>
            {
                return Err(ControllerError::Rejected(
                    "no-build generation differs from its sealed source, artifact, or required OCI closure",
                ))
            }
            DockerLanePayloadContentV12::ImportSealedOci {
                object,
                artifact_object_sha256,
            } if payload.artifact_manifest_sha256.is_none()
                || *artifact_object_sha256 == [0; 32]
                || object.manifest_digest_sha256
                    != request.target_sha256 =>
            {
                return Err(ControllerError::Rejected(
                    "sealed OCI import differs from its exact target",
                ))
            }
            DockerLanePayloadContentV12::RunBody { body, .. }
                if body.lane != request.lane
                    || Some(body.body_sha256)
                        != payload.body_sha256 =>
            {
                return Err(ControllerError::Rejected(
                    "repository body differs from its signed lane contract",
                ))
            }
            _ => {}
        }
    }
    let mut owner_labels = BTreeMap::new();
    owner_labels.insert(
        OWNER_LABEL_V12.to_owned(),
        operation.owner_namespace.clone(),
    );
    owner_labels.insert(LANE_LABEL_V12.to_owned(), operation.lane_id());
    owner_labels.insert(
        GENERATION_LABEL_V12.to_owned(),
        operation.daemon_generation.clone(),
    );
    owner_labels.insert(
        RESOURCE_LABEL_V12.to_owned(),
        hex_digest(&request.target_sha256),
    );
    if let Some(payload) = payload {
        owner_labels.insert(
            SOURCE_SEAL_LABEL_V12.to_owned(),
            hex_digest(&payload.source.manifest_sha256),
        );
        if let Some(artifact) = payload.artifact_manifest_sha256 {
            owner_labels.insert(
                ARTIFACT_SEAL_LABEL_V12.to_owned(),
                hex_digest(&artifact),
            );
        }
    }
    Ok(DockerLanePolicyDecisionV12 {
        effect,
        authoritative_state,
        owner_labels,
        returned_fd_count,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerPolicyOperationV11 {
    Read,
    PullPinnedImage,
    BuildExactImage,
    CreateContainer,
    StartContainer,
    StopContainer,
    KillContainer,
    WaitContainer,
    ReadContainerLogs,
    AttachContainer,
    DeleteContainer,
    CreateNetwork,
    ConnectNetwork,
    DisconnectNetwork,
    DeleteNetwork,
    CreateVolume,
    DeleteVolume,
}

impl DockerPolicyOperationV11 {
    pub fn mutates(self) -> bool {
        !matches!(
            self,
            Self::Read | Self::ReadContainerLogs | Self::AttachContainer
        )
    }

    pub fn may_return_upgrade(self) -> bool {
        self == Self::AttachContainer
    }
}

#[derive(Clone, Debug)]
pub struct DockerPolicyDecisionV11 {
    pub operation: DockerPolicyOperationV11,
    pub mutating: bool,
    pub reconcile_route: Option<String>,
    pub response_engine_id_pointer: Option<&'static str>,
    pub required_owner_labels: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerCasIdentityKindV12 {
    Source,
    Artifact,
}

pub trait DockerOwnershipViewV11 {
    fn engine_id_is_owned(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        logical_id: &str,
        engine_id: &str,
    ) -> Result<bool>;

    fn logical_id_is_available(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        logical_id: &str,
    ) -> Result<bool>;

    fn engine_id_is_owned_any(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        engine_id: &str,
    ) -> Result<bool>;

    fn retained_cas_mount_is_bound(
        &self,
        _owner_namespace: &str,
        _generation: &str,
        _kind: DockerCasIdentityKindV12,
        _mount_id: &str,
        _cas_sha256: Digest,
        _subpath: &str,
    ) -> Result<bool> {
        Ok(false)
    }

    fn image_is_oci_closed(
        &self,
        _owner_namespace: &str,
        _generation: &str,
        _image_id: &str,
        _source_seal_sha256: Digest,
        _artifact_seal_sha256: Digest,
    ) -> Result<bool> {
        Ok(false)
    }

    fn network_membership_is_connected(
        &self,
        _owner_namespace: &str,
        _generation: &str,
        _network_logical_id: &str,
        _container_logical_id: &str,
        _network_engine_id: &str,
        _container_engine_id: &str,
    ) -> Result<Option<bool>> {
        Ok(None)
    }
}

pub struct DockerPolicyContextV11<'a> {
    pub capability: &'a DockerLaneCapabilityV11,
    pub ownership: &'a dyn DockerOwnershipViewV11,
}

pub fn verify_build_context_spool_v11(
    path: &Path,
    declared_context_sha256: Digest,
    tuple: &DockerBuildTupleV11,
    allowed_pinned_pulls: &BTreeSet<String>,
) -> Result<()> {
    if declared_context_sha256 != tuple.context_cas_sha256 {
        return Err(ControllerError::Rejected(
            "Docker build context digest differs from its exact tuple",
        ));
    }
    let path_metadata = std::fs::symlink_metadata(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || metadata.len() == 0
        || metadata.len() > 8 * 1024 * 1024 * 1024
    {
        return Err(ControllerError::Rejected(
            "Docker build context spool is unsafe or outside its bound",
        ));
    }
    let actual_context_sha256 =
        crate::coder_controller_v11::sha256_exact_reader(
            &mut file,
            metadata.len(),
        )?;
    if actual_context_sha256 != declared_context_sha256 {
        return Err(ControllerError::Rejected(
            "Docker build context changed after its retained CAS binding",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 512];
    let mut zero_blocks = 0u8;
    let mut entries = 0u64;
    let mut dockerfile_sha256 = None;
    loop {
        file.read_exact(&mut header)?;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks == 2 {
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err(ControllerError::Rejected(
                "Docker build context has a nonterminal zero block",
            ));
        }
        entries = entries.saturating_add(1);
        if entries > 1_000_000 {
            return Err(ControllerError::Rejected(
                "Docker build context exceeds its entry bound",
            ));
        }
        verify_tar_checksum(&header)?;
        let name = tar_text(&header[0..100])?;
        let prefix = tar_text(&header[345..500])?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_empty()
            || path.starts_with('/')
            || path.split('/').any(|part| {
                part.is_empty() || matches!(part, "." | "..")
            })
            || path.contains('\\')
        {
            return Err(ControllerError::Rejected(
                "Docker build context path is noncanonical",
            ));
        }
        let size = tar_octal(&header[124..136])?;
        let kind = header[156];
        if !matches!(kind, 0 | b'0' | b'5') {
            return Err(ControllerError::Rejected(
                "Docker build context contains links, devices, or extensions",
            ));
        }
        if kind == b'5' && size != 0 {
            return Err(ControllerError::Rejected(
                "Docker build context directory has payload bytes",
            ));
        }
        if path == "Dockerfile" {
            if dockerfile_sha256.is_some()
                || !matches!(kind, 0 | b'0')
                || size == 0
                || size > 16 * 1024 * 1024
            {
                return Err(ControllerError::Rejected(
                    "Docker build context Dockerfile is duplicate or invalid",
                ));
            }
            let mut dockerfile = vec![
                0u8;
                usize::try_from(size).map_err(|_| {
                    ControllerError::Invalid(
                        "Dockerfile size does not fit memory",
                    )
                })?
            ];
            file.read_exact(&mut dockerfile)?;
            validate_dockerfile_sources(
                &dockerfile,
                allowed_pinned_pulls,
            )?;
            dockerfile_sha256 =
                Some(crate::coder_controller_v11::sha256(&dockerfile));
        } else {
            file.seek(SeekFrom::Current(
                i64::try_from(size).map_err(|_| {
                    ControllerError::Invalid(
                        "Docker build context entry size is too large",
                    )
                })?,
            ))?;
        }
        let padding = (512 - size % 512) % 512;
        if padding != 0 {
            let mut padding_bytes = [0u8; 512];
            file.read_exact(&mut padding_bytes[..padding as usize])?;
            if padding_bytes[..padding as usize]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ControllerError::Rejected(
                    "Docker build context padding is nonzero",
                ));
            }
        }
    }
    if dockerfile_sha256 != Some(tuple.dockerfile_cas_sha256)
        || file.stream_position()? != metadata.len()
    {
        return Err(ControllerError::Rejected(
            "Docker build context Dockerfile or terminal length differs",
        ));
    }
    Ok(())
}

impl DockerPolicyContextV11<'_> {
    pub fn authorize(
        &self,
        request: &DockerApiRequestV11,
        body: &[u8],
    ) -> Result<DockerPolicyDecisionV11> {
        request.validate_against(
            self.capability,
            crate::docker_contract::boottime_now_ns_v11()?,
        )?;
        validate_target_namespace(request)?;
        let route = parse_route(&request.normalized_route)?;
        let query = query_map(&request.canonical_query)?;
        let opaque_build_body = request.method == "POST"
            && matches!(
                route.as_slice(),
                [RoutePart::Literal("build")]
            );
        let body_json = if body.is_empty() {
            None
        } else if opaque_build_body {
            None
        } else {
            Some(parse_exact_json(body)?)
        };
        validate_signed_authority_shape(request, &route)?;
        validate_fixed_headers(request, opaque_build_body, !body.is_empty())?;
        let labels = required_labels(self.capability, request);
        let decision = match (
            request.method.as_str(),
            route.as_slice(),
        ) {
            ("GET" | "HEAD", [RoutePart::Literal("_ping")])
            | ("GET" | "HEAD", [RoutePart::Literal("version")])
            | ("GET" | "HEAD", [RoutePart::Literal("info")]) => {
                require_daemon_read(request, &query, body_json.as_ref())?;
                decision(DockerPolicyOperationV11::Read, None, None, labels)
            }
            ("GET" | "HEAD", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("json")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_empty_query_and_body(&query, body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::Read,
                    None,
                    None,
                    labels,
                )
            }
            ("GET", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("logs")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(
                    &query,
                    &[
                        "follow",
                        "stderr",
                        "stdout",
                        "timestamps",
                    ],
                )?;
                require_boolean_query(&query, "follow")?;
                require_boolean_query(&query, "stderr")?;
                require_boolean_query(&query, "stdout")?;
                require_boolean_query(&query, "timestamps")?;
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::ReadContainerLogs,
                    None,
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("attach")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(
                    &query,
                    &[
                        "logs",
                        "stderr",
                        "stdin",
                        "stdout",
                        "stream",
                    ],
                )?;
                for key in ["logs", "stderr", "stdin", "stdout", "stream"] {
                    require_boolean_query(&query, key)?;
                }
                if query.get("logs").map(String::as_str) != Some("0")
                    || query.get("stdin").map(String::as_str) != Some("0")
                    || query.get("stream").map(String::as_str) != Some("1")
                    || query.get("stdout").map(String::as_str) != Some("1")
                {
                    return Err(ControllerError::Rejected(
                        "Docker attach is not the fixed read-only output stream",
                    ));
                }
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::AttachContainer,
                    None,
                    None,
                    labels,
                )
            }
            ("GET" | "HEAD", [RoutePart::Literal("images"), RoutePart::Identifier(id), RoutePart::Literal("json")]) => {
                require_empty_query_and_body(&query, body_json.as_ref())?;
                require_allowed_image(self.capability, id)?;
                if request.target.kind != DockerResourceKindV11::Image
                    || request.target.engine_id.as_deref() != Some(id)
                {
                    return Err(ControllerError::Rejected(
                        "Docker image read target differs from its route ID",
                    ));
                }
                decision(DockerPolicyOperationV11::Read, None, None, labels)
            }
            ("POST", [RoutePart::Literal("images"), RoutePart::Literal("create")]) => {
                require_build(self.capability.profile)?;
                require_exact_keys(&query, &["fromImage"])?;
                let image = query
                    .get("fromImage")
                    .ok_or(ControllerError::Invalid(
                        "pinned pull image is absent",
                    ))?;
                if !self.capability.allowed_pinned_pulls.contains(image) {
                    return Err(ControllerError::Rejected(
                        "Docker pull is not an exact capability-pinned digest",
                    ));
                }
                self.require_available(request, DockerResourceKindV11::Image)?;
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::PullPinnedImage,
                    Some(format!("/images/{image}/json")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("build")]) => {
                require_build(self.capability.profile)?;
                let tuple = self.capability.build_tuple.as_ref().ok_or(
                    ControllerError::Rejected(
                        "build lane lacks its exact build tuple",
                    ),
                )?;
                self.require_available(request, DockerResourceKindV11::Build)?;
                validate_build_query(
                    &query,
                    tuple,
                    &labels,
                    request.body_sha256,
                )?;
                if body.is_empty() {
                    return Err(ControllerError::Rejected(
                        "Docker build context body is absent",
                    ));
                }
                if request.stream_mode != DockerStreamModeV11::BuildKit {
                    return Err(ControllerError::Rejected(
                        "Docker build must use the bounded BuildKit stream mode",
                    ));
                }
                decision(
                    DockerPolicyOperationV11::BuildExactImage,
                    None,
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Literal("create")]) => {
                require_exact_keys(&query, &["name"])?;
                require_logical_name(request, &query, "name")?;
                self.require_available(request, DockerResourceKindV11::Container)?;
                let body = body_json.as_ref().ok_or(
                    ControllerError::Rejected(
                        "container create body is absent",
                    ),
                )?;
                validate_container_create(
                    body,
                    request,
                    self.capability,
                    self.ownership,
                    &labels,
                )?;
                decision(
                    DockerPolicyOperationV11::CreateContainer,
                    None,
                    Some("/Id"),
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("start")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_empty_query_and_body(&query, body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::StartContainer,
                    Some(format!("/containers/{id}/json")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("stop")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(&query, &["t"])?;
                require_bounded_u32(&query, "t", 1, 30)?;
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::StopContainer,
                    Some(format!("/containers/{id}/json")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("kill")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(&query, &["signal"])?;
                if query.get("signal").map(String::as_str)
                    != Some("SIGKILL")
                {
                    return Err(ControllerError::Rejected(
                        "Docker kill signal is not exactly SIGKILL",
                    ));
                }
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::KillContainer,
                    Some(format!("/containers/{id}/json")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("containers"), RoutePart::Identifier(id), RoutePart::Literal("wait")]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(&query, &["condition"])?;
                if query.get("condition").map(String::as_str)
                    != Some("not-running")
                {
                    return Err(ControllerError::Rejected(
                        "Docker wait condition is not fixed",
                    ));
                }
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::WaitContainer,
                    Some(format!("/containers/{id}/json")),
                    None,
                    labels,
                )
            }
            ("DELETE", [RoutePart::Literal("containers"), RoutePart::Identifier(id)]) => {
                self.require_owned(request, DockerResourceKindV11::Container, id)?;
                require_exact_keys(&query, &["force", "v"])?;
                require_true_query(&query, "force")?;
                require_true_query(&query, "v")?;
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::DeleteContainer,
                    Some(format!("/containers/{id}/json")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("networks"), RoutePart::Literal("create")]) => {
                require_empty_query(&query)?;
                self.require_available(request, DockerResourceKindV11::Network)?;
                validate_network_create(
                    body_json.as_ref().ok_or(
                        ControllerError::Rejected(
                            "network create body is absent",
                        ),
                    )?,
                    request,
                    &labels,
                )?;
                decision(
                    DockerPolicyOperationV11::CreateNetwork,
                    None,
                    Some("/Id"),
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("networks"), RoutePart::Identifier(id), RoutePart::Literal("connect")]) => {
                self.require_owned(request, DockerResourceKindV11::Network, id)?;
                require_empty_query(&query)?;
                validate_network_membership(
                    body_json.as_ref().ok_or(
                        ControllerError::Rejected(
                            "network connect body is absent",
                        ),
                    )?,
                    request,
                    self,
                )?;
                decision(
                    DockerPolicyOperationV11::ConnectNetwork,
                    Some(format!("/networks/{id}")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("networks"), RoutePart::Identifier(id), RoutePart::Literal("disconnect")]) => {
                self.require_owned(request, DockerResourceKindV11::Network, id)?;
                require_empty_query(&query)?;
                validate_network_membership(
                    body_json.as_ref().ok_or(
                        ControllerError::Rejected(
                            "network disconnect body is absent",
                        ),
                    )?,
                    request,
                    self,
                )?;
                decision(
                    DockerPolicyOperationV11::DisconnectNetwork,
                    Some(format!("/networks/{id}")),
                    None,
                    labels,
                )
            }
            ("DELETE", [RoutePart::Literal("networks"), RoutePart::Identifier(id)]) => {
                self.require_owned(request, DockerResourceKindV11::Network, id)?;
                require_empty_query_and_body(&query, body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::DeleteNetwork,
                    Some(format!("/networks/{id}")),
                    None,
                    labels,
                )
            }
            ("POST", [RoutePart::Literal("volumes"), RoutePart::Literal("create")]) => {
                require_empty_query(&query)?;
                self.require_available(request, DockerResourceKindV11::Volume)?;
                validate_volume_create(
                    body_json.as_ref().ok_or(
                        ControllerError::Rejected(
                            "volume create body is absent",
                        ),
                    )?,
                    request,
                    &labels,
                )?;
                decision(
                    DockerPolicyOperationV11::CreateVolume,
                    None,
                    Some("/Name"),
                    labels,
                )
            }
            ("DELETE", [RoutePart::Literal("volumes"), RoutePart::Identifier(id)]) => {
                self.require_owned(request, DockerResourceKindV11::Volume, id)?;
                require_exact_keys(&query, &["force"])?;
                require_true_query(&query, "force")?;
                require_no_body(body_json.as_ref())?;
                decision(
                    DockerPolicyOperationV11::DeleteVolume,
                    Some(format!("/volumes/{id}")),
                    None,
                    labels,
                )
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker route, method, or route shape is not exactly allowlisted",
                ))
            }
        };
        validate_stream_mode(request, &decision)?;
        validate_profile_operation(self.capability.profile, decision.operation)?;
        validate_transition_shape(request, decision.operation)?;
        validate_operation_transition(request, decision.operation)?;
        Ok(decision)
    }

    fn require_owned(
        &self,
        request: &DockerApiRequestV11,
        kind: DockerResourceKindV11,
        route_id: &str,
    ) -> Result<()> {
        if request.target.kind != kind
            || request.target.engine_id.as_deref() != Some(route_id)
            || !self.ownership.engine_id_is_owned(
                &request.owner_namespace,
                &request.daemon_generation,
                kind,
                &request.target.logical_id,
                route_id,
            )?
        {
            return Err(ControllerError::Rejected(
                "Docker target ID is not owned by this exact lane generation",
            ));
        }
        Ok(())
    }

    fn require_available(
        &self,
        request: &DockerApiRequestV11,
        kind: DockerResourceKindV11,
    ) -> Result<()> {
        if request.target.kind != kind
            || request.target.engine_id.is_some()
            || !self.ownership.logical_id_is_available(
                &request.owner_namespace,
                &request.daemon_generation,
                kind,
                &request.target.logical_id,
            )?
        {
            return Err(ControllerError::Rejected(
                "Docker logical target is not available for declaration",
            ));
        }
        Ok(())
    }
}

fn decision(
    operation: DockerPolicyOperationV11,
    reconcile_route: Option<String>,
    response_engine_id_pointer: Option<&'static str>,
    required_owner_labels: BTreeMap<String, String>,
) -> DockerPolicyDecisionV11 {
    DockerPolicyDecisionV11 {
        operation,
        mutating: operation.mutates(),
        reconcile_route,
        response_engine_id_pointer,
        required_owner_labels,
    }
}

fn validate_transition_shape(
    request: &DockerApiRequestV11,
    operation: DockerPolicyOperationV11,
) -> Result<()> {
    let read_only = !operation.mutates();
    let membership_mutation = matches!(
        operation,
        DockerPolicyOperationV11::ConnectNetwork
            | DockerPolicyOperationV11::DisconnectNetwork
    );
    let stable_object_state = request.expected_transition.from
        == request.expected_transition.to;
    let valid = if read_only || membership_mutation {
        stable_object_state
    } else {
        !stable_object_state
    };
    if !valid {
        return Err(ControllerError::Rejected(
            "Docker transition mutability differs from the HTTP method",
        ));
    }
    Ok(())
}

fn validate_signed_authority_shape(
    request: &DockerApiRequestV11,
    route: &[RoutePart<'_>],
) -> Result<()> {
    let create_route = request.method == "POST"
        && matches!(
            route,
            [RoutePart::Literal("containers"), RoutePart::Literal("create")]
        );
    let membership_route = request.method == "POST"
        && matches!(
            route,
            [
                RoutePart::Literal("networks"),
                RoutePart::Identifier(_),
                RoutePart::Literal("connect" | "disconnect")
            ]
        );
    if create_route != request.create_authority.is_some()
        || membership_route != request.network_membership.is_some()
    {
        return Err(ControllerError::Rejected(
            "Docker nested signed authority is absent or used on the wrong route",
        ));
    }
    Ok(())
}

fn validate_fixed_headers(
    request: &DockerApiRequestV11,
    build_body: bool,
    has_body: bool,
) -> Result<()> {
    let headers: BTreeMap<&str, &str> = request
        .fixed_headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
        .collect();
    let content_type = headers.get("content-type").copied();
    let expected_content_type = if !has_body {
        None
    } else if build_body {
        Some("application/x-tar")
    } else {
        Some("application/json")
    };
    let expected_accept = if request.stream_mode
        == DockerStreamModeV11::Upgrade101
    {
        "application/vnd.docker.raw-stream"
    } else {
        "application/json"
    };
    if content_type != expected_content_type
        || headers.get("accept").copied() != Some(expected_accept)
        || headers.get("user-agent").copied()
            != Some("serverware-controller-v12")
        || headers.len()
            != if expected_content_type.is_some() { 3 } else { 2 }
    {
        return Err(ControllerError::Rejected(
            "Docker fixed headers differ from the exact route framing",
        ));
    }
    Ok(())
}

fn validate_target_namespace(request: &DockerApiRequestV11) -> Result<()> {
    let expected_prefix = format!("{}:", request.owner_namespace);
    if request.target.kind != DockerResourceKindV11::Daemon
        && !request.target.logical_id.starts_with(&expected_prefix)
    {
        return Err(ControllerError::Rejected(
            "Docker logical target is outside the owner namespace",
        ));
    }
    Ok(())
}

fn validate_profile_operation(
    profile: DockerLaneProfileV11,
    operation: DockerPolicyOperationV11,
) -> Result<()> {
    if profile != DockerLaneProfileV11::Build
        && matches!(
            operation,
            DockerPolicyOperationV11::PullPinnedImage
                | DockerPolicyOperationV11::BuildExactImage
        )
    {
        return Err(ControllerError::Rejected(
            "post-seal lane attempted a build or image mutation",
        ));
    }
    Ok(())
}

fn validate_operation_transition(
    request: &DockerApiRequestV11,
    operation: DockerPolicyOperationV11,
) -> Result<()> {
    use DockerObjectStateV11 as State;
    let edge = (
        request.expected_transition.from,
        request.expected_transition.to,
    );
    let valid = match operation {
        DockerPolicyOperationV11::Read
        | DockerPolicyOperationV11::ReadContainerLogs
        | DockerPolicyOperationV11::AttachContainer => edge.0 == edge.1,
        DockerPolicyOperationV11::PullPinnedImage
        | DockerPolicyOperationV11::BuildExactImage
        | DockerPolicyOperationV11::CreateContainer
        | DockerPolicyOperationV11::CreateNetwork
        | DockerPolicyOperationV11::CreateVolume => {
            matches!(edge, (State::Absent | State::Declared, State::Created))
        }
        DockerPolicyOperationV11::StartContainer => {
            edge == (State::Created, State::Running)
        }
        DockerPolicyOperationV11::StopContainer
        | DockerPolicyOperationV11::KillContainer
        | DockerPolicyOperationV11::WaitContainer => {
            edge == (State::Running, State::Exited)
        }
        DockerPolicyOperationV11::DeleteContainer => {
            matches!(
                edge,
                (State::Created | State::Exited, State::Removed)
            )
        }
        DockerPolicyOperationV11::ConnectNetwork
        | DockerPolicyOperationV11::DisconnectNetwork => {
            edge == (State::Created, State::Created)
        }
        DockerPolicyOperationV11::DeleteNetwork
        | DockerPolicyOperationV11::DeleteVolume => {
            edge == (State::Created, State::Removed)
        }
    };
    if !valid {
        return Err(ControllerError::Rejected(
            "Docker expected transition differs from the exact operation edge",
        ));
    }
    Ok(())
}

fn validate_stream_mode(
    request: &DockerApiRequestV11,
    decision: &DockerPolicyDecisionV11,
) -> Result<()> {
    match request.stream_mode {
        DockerStreamModeV11::BoundedHttp => Ok(()),
        DockerStreamModeV11::BuildKit
            if decision.operation
                == DockerPolicyOperationV11::BuildExactImage =>
        {
            Ok(())
        }
        DockerStreamModeV11::FullDuplex
        | DockerStreamModeV11::Upgrade101
            if decision.operation.may_return_upgrade() =>
        {
            Ok(())
        }
        _ => Err(ControllerError::Rejected(
            "Docker stream mode is not valid for the exact operation",
        )),
    }
}

fn required_labels(
    capability: &DockerLaneCapabilityV11,
    request: &DockerApiRequestV11,
) -> BTreeMap<String, String> {
    [
        (
            OWNER_LABEL_V11.to_owned(),
            capability.owner_namespace.clone(),
        ),
        (LANE_LABEL_V11.to_owned(), capability.lane_id.clone()),
        (
            GENERATION_LABEL_V11.to_owned(),
            capability.daemon_generation.clone(),
        ),
        (
            LOGICAL_ID_LABEL_V11.to_owned(),
            request.target.logical_id.clone(),
        ),
        (
            SOURCE_SEAL_LABEL_V11.to_owned(),
            hex_digest(&capability.source_seal_sha256),
        ),
        (
            ARTIFACT_SEAL_LABEL_V11.to_owned(),
            hex_digest(&capability.artifact_seal_sha256),
        ),
    ]
    .into_iter()
    .collect()
}

fn validate_build_query(
    query: &BTreeMap<String, String>,
    tuple: &DockerBuildTupleV11,
    required_labels: &BTreeMap<String, String>,
    context_sha256: Digest,
) -> Result<()> {
    require_exact_keys(
        query,
        &[
            "buildargs",
            "dockerfile",
            "labels",
            "networkmode",
            "outputs",
            "platform",
            "pull",
            "target",
        ],
    )?;
    let build_args = query
        .get("buildargs")
        .ok_or(ControllerError::Invalid(
            "Docker buildargs query is absent",
        ))?;
    let build_args_value: Value =
        serde_json::from_str(build_args).map_err(|_| {
            ControllerError::Invalid(
                "Docker buildargs query is not JSON",
            )
        })?;
    let canonical_build_args =
        crate::coder_controller_v11::canonical_json_bytes_v11(
            &build_args_value,
        )?;
    let labels = query
        .get("labels")
        .ok_or(ControllerError::Invalid(
            "Docker labels query is absent",
        ))?;
    let labels_value: Value =
        serde_json::from_str(labels).map_err(|_| {
            ControllerError::Invalid(
                "Docker labels query is not JSON",
            )
        })?;
    validate_labels(&labels_value, required_labels)?;
    if context_sha256 != tuple.context_cas_sha256
        || crate::coder_controller_v11::sha256(&canonical_build_args)
            != tuple.build_args_sha256
        || query.get("dockerfile").map(String::as_str)
            != Some("Dockerfile")
        || query.get("outputs").map(String::as_str)
            != Some("type=image")
        || query.get("networkmode").map(String::as_str)
            != Some("none")
        || query.get("platform") != Some(&tuple.platform)
        || query.get("pull").map(String::as_str) != Some("0")
        || query.get("target") != Some(&tuple.target)
    {
        return Err(ControllerError::Rejected(
            "Docker build query differs from the exact capability tuple",
        ));
    }
    Ok(())
}

fn validate_dockerfile_sources(
    bytes: &[u8],
    allowed_pinned_pulls: &BTreeSet<String>,
) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        ControllerError::Invalid("Dockerfile is not UTF-8")
    })?;
    if text.contains('\0') || text.contains('\r') {
        return Err(ControllerError::Rejected(
            "Dockerfile contains noncanonical line bytes",
        ));
    }
    let mut stages = BTreeSet::new();
    let mut stage_count = 0usize;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(directive) = line.strip_prefix('#') {
            let directive = directive.trim();
            if let Some((name, frontend)) = directive.split_once('=') {
                if name.trim().eq_ignore_ascii_case("syntax") {
                    require_external_image(
                        frontend.trim(),
                        allowed_pinned_pulls,
                    )?;
                }
            }
            continue;
        }
        if line.ends_with('\\') || line.contains("<<") {
            return Err(ControllerError::Rejected(
                "Dockerfile continuations and heredocs are outside the canonical build contract",
            ));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let instruction = fields
            .first()
            .ok_or(ControllerError::Invalid(
                "Dockerfile instruction is absent",
            ))?
            .to_ascii_uppercase();
        match instruction.as_str() {
            "FROM" => {
                let mut index = 1usize;
                while fields
                    .get(index)
                    .is_some_and(|field| field.starts_with("--platform="))
                {
                    index += 1;
                }
                let image = fields.get(index).ok_or(
                    ControllerError::Rejected(
                        "Dockerfile FROM image is absent",
                    ),
                )?;
                if *image != "scratch"
                    && !stage_reference(image, stage_count, &stages)
                {
                    require_external_image(
                        image,
                        allowed_pinned_pulls,
                    )?;
                }
                index += 1;
                if fields.get(index).is_some() {
                    if fields.get(index).map(|value| {
                        value.eq_ignore_ascii_case("AS")
                    }) != Some(true)
                        || fields.len() != index + 2
                    {
                        return Err(ControllerError::Rejected(
                            "Dockerfile FROM suffix is noncanonical",
                        ));
                    }
                    let alias = fields[index + 1];
                    if !valid_stage_alias(alias)
                        || !stages.insert(alias.to_owned())
                    {
                        return Err(ControllerError::Rejected(
                            "Dockerfile stage alias is invalid or duplicated",
                        ));
                    }
                }
                stage_count = stage_count.saturating_add(1);
            }
            "COPY" => {
                for field in fields.iter().skip(1) {
                    if let Some(source) = field.strip_prefix("--from=") {
                        if !stage_reference(
                            source,
                            stage_count,
                            &stages,
                        ) {
                            require_external_image(
                                source,
                                allowed_pinned_pulls,
                            )?;
                        }
                    }
                }
            }
            "ADD" => {
                return Err(ControllerError::Rejected(
                    "Dockerfile ADD is outside the no-remote-input build contract",
                ))
            }
            "RUN"
                if line.contains("--mount")
                    && line.contains("from=") =>
            {
                return Err(ControllerError::Rejected(
                    "Dockerfile RUN external mounts are outside the canonical build contract",
                ))
            }
            _ => {}
        }
    }
    if stage_count == 0 {
        return Err(ControllerError::Rejected(
            "Dockerfile has no canonical FROM stage",
        ));
    }
    Ok(())
}

fn require_external_image(
    image: &str,
    allowed_pinned_pulls: &BTreeSet<String>,
) -> Result<()> {
    if valid_digest_image(image) && allowed_pinned_pulls.contains(image) {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Dockerfile external image is not an exactly allowed digest",
        ))
    }
}

fn stage_reference(
    value: &str,
    stage_count: usize,
    aliases: &BTreeSet<String>,
) -> bool {
    aliases.contains(value)
        || value
            .parse::<usize>()
            .ok()
            .is_some_and(|index| index < stage_count)
}

fn valid_stage_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
        })
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

fn validate_container_create(
    value: &Value,
    request: &DockerApiRequestV11,
    capability: &DockerLaneCapabilityV11,
    ownership: &dyn DockerOwnershipViewV11,
    required_labels: &BTreeMap<String, String>,
) -> Result<()> {
    let authority = request.create_authority.as_ref().ok_or(
        ControllerError::Rejected(
            "container create lacks signed RunnerExecutionV12 or ServiceInstanceV12",
        ),
    )?;
    let object = object(value, "container create body is not an object")?;
    require_object_keys(
        object,
        &[
            "AttachStderr",
            "AttachStdin",
            "AttachStdout",
            "Cmd",
            "Env",
            "Entrypoint",
            "ExposedPorts",
            "Healthcheck",
            "HostConfig",
            "Image",
            "Labels",
            "OpenStdin",
            "Tty",
            "User",
            "WorkingDir",
        ],
    )?;
    let image = string(object, "Image")?;
    if image != authority.image
        || !capability.allowed_image_digests.contains(image)
        || boolean(object, "AttachStderr")?
        || boolean(object, "AttachStdin")?
        || boolean(object, "AttachStdout")?
        || boolean(object, "OpenStdin")?
        || boolean(object, "Tty")?
        || string(object, "User")? != authority.user
        || string(object, "WorkingDir")? != authority.working_dir
        || array_strings(object, "Entrypoint")?
            != authority
                .entrypoint
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        || array_strings(object, "Cmd")?
            != authority
                .command
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
    {
        return Err(ControllerError::Rejected(
            "container create body differs from its signed execution authority",
        ));
    }
    if !ownership.image_is_oci_closed(
        &request.owner_namespace,
        &request.daemon_generation,
        image,
        request.source_seal_sha256,
        request.artifact_seal_sha256,
    )? {
        return Err(ControllerError::Rejected(
            "container image is not closed over the retained source and artifact CAS identities",
        ));
    }
    validate_exact_environment(field(object, "Env")?, authority)?;
    validate_exact_health(field(object, "Healthcheck")?, authority)?;
    validate_exact_endpoints(field(object, "ExposedPorts")?, authority)?;
    validate_labels(field(object, "Labels")?, required_labels)?;
    let host = self::object(
        field(object, "HostConfig")?,
        "HostConfig is not an object",
    )?;
    require_object_keys(
        host,
        &[
            "AutoRemove",
            "CapDrop",
            "Init",
            "Memory",
            "Mounts",
            "NanoCpus",
            "NetworkMode",
            "PidsLimit",
            "ReadonlyRootfs",
            "SecurityOpt",
            "ShmSize",
            "Tmpfs",
        ],
    )?;
    if boolean(host, "AutoRemove")? != false
        || array_strings(host, "CapDrop")? != ["ALL"]
        || boolean(host, "Init")? != true
        || integer(host, "Memory")? != authority.resources.memory_bytes
        || integer(host, "NanoCpus")? != authority.resources.nano_cpus
        || integer(host, "PidsLimit")?
            != authority.resources.pids_limit as u64
        || integer(host, "ShmSize")? != authority.resources.shm_bytes
        || boolean(host, "ReadonlyRootfs")? != true
        || array_strings(host, "SecurityOpt")?
            != ["no-new-privileges"]
        || string(host, "NetworkMode")? != "none"
    {
        return Err(ControllerError::Rejected(
            "container isolation differs from the fixed lane policy",
        ));
    }
    validate_exact_mounts(
        field(host, "Mounts")?,
        field(host, "Tmpfs")?,
        authority,
        ownership,
    )
}

fn validate_exact_environment(
    value: &Value,
    authority: &DockerCreateAuthorityV12,
) -> Result<()> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "container Env is not an array",
    ))?;
    if values.len() != authority.environment.len() {
        return Err(ControllerError::Rejected(
            "container environment differs from signed authority",
        ));
    }
    for (actual, expected) in values.iter().zip(&authority.environment) {
        let expected = format!("{}={}", expected.name, expected.value);
        if actual.as_str() != Some(expected.as_str()) {
            return Err(ControllerError::Rejected(
                "container environment differs from signed authority",
            ));
        }
    }
    Ok(())
}

fn validate_exact_health(
    value: &Value,
    authority: &DockerCreateAuthorityV12,
) -> Result<()> {
    let Some(expected) = authority.health.as_ref() else {
        if !value.is_null() {
            return Err(ControllerError::Rejected(
                "container healthcheck was not signed",
            ));
        }
        return Ok(());
    };
    let health = object(value, "container Healthcheck is not an object")?;
    require_object_keys(
        health,
        &["Interval", "Retries", "StartPeriod", "Test", "Timeout"],
    )?;
    if array_strings(health, "Test")?
        != expected
            .test
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
        || integer(health, "Interval")?
            != expected.interval_ms * 1_000_000
        || integer(health, "Timeout")?
            != expected.timeout_ms * 1_000_000
        || integer(health, "Retries")? != expected.retries as u64
        || integer(health, "StartPeriod")?
            != expected.start_period_ms * 1_000_000
    {
        return Err(ControllerError::Rejected(
            "container healthcheck differs from signed authority",
        ));
    }
    Ok(())
}

fn validate_exact_endpoints(
    value: &Value,
    authority: &DockerCreateAuthorityV12,
) -> Result<()> {
    let exposed = object(value, "container ExposedPorts is not an object")?;
    if exposed.len() != authority.endpoints.len() {
        return Err(ControllerError::Rejected(
            "container endpoint count differs from signed authority",
        ));
    }
    for endpoint in &authority.endpoints {
        let key = format!("{}/{}", endpoint.container_port, endpoint.protocol);
        if exposed
            .get(&key)
            .and_then(Value::as_object)
            .is_none_or(|value| !value.is_empty())
        {
            return Err(ControllerError::Rejected(
                "container endpoint differs from signed authority",
            ));
        }
    }
    Ok(())
}

fn validate_exact_mounts(
    bind_value: &Value,
    tmpfs_value: &Value,
    authority: &DockerCreateAuthorityV12,
    ownership: &dyn DockerOwnershipViewV11,
) -> Result<()> {
    let expected_binds: Vec<_> = authority
        .mounts
        .iter()
        .filter(|mount| mount.kind != DockerMountKindV12::Tmpfs)
        .collect();
    let binds = bind_value.as_array().ok_or(ControllerError::Invalid(
        "container HostConfig.Mounts is not an array",
    ))?;
    if binds.len() != expected_binds.len() {
        return Err(ControllerError::Rejected(
            "container bind count differs from signed authority",
        ));
    }
    for (value, expected) in binds.iter().zip(expected_binds) {
        let mount = object(value, "container bind is not an object")?;
        require_object_keys(
            mount,
            &["Consistency", "ReadOnly", "Source", "Target", "Type"],
        )?;
        let source = format!(
            "/run/serverware/coder/v12/lane-inputs/{}",
            expected.mount_id
        );
        if string(mount, "Type")? != "bind"
            || string(mount, "Source")? != source
            || string(mount, "Target")? != expected.target
            || !boolean(mount, "ReadOnly")?
            || string(mount, "Consistency")? != "consistent"
        {
            return Err(ControllerError::Rejected(
                "container bind differs from retained sealed CAS authority",
            ));
        }
        let (kind, cas_sha256) = match expected.kind {
            DockerMountKindV12::SourceCas => (
                DockerCasIdentityKindV12::Source,
                expected.cas_sha256.ok_or(ControllerError::Rejected(
                    "source CAS mount lacks its digest identity",
                ))?,
            ),
            DockerMountKindV12::ArtifactCas => (
                DockerCasIdentityKindV12::Artifact,
                expected.cas_sha256.ok_or(ControllerError::Rejected(
                    "artifact CAS mount lacks its digest identity",
                ))?,
            ),
            DockerMountKindV12::Tmpfs => {
                return Err(ControllerError::Rejected(
                    "tmpfs appeared in the retained CAS mount list",
                ))
            }
        };
        if !ownership.retained_cas_mount_is_bound(
            &authority.owner_namespace,
            &authority.daemon_generation,
            kind,
            &expected.mount_id,
            cas_sha256,
            &expected.subpath,
        )? {
            return Err(ControllerError::Rejected(
                "container bind mount has no controller-owned retained CAS registration",
            ));
        }
    }
    let tmpfs =
        object(tmpfs_value, "container HostConfig.Tmpfs is not an object")?;
    let expected_tmpfs: Vec<_> = authority
        .mounts
        .iter()
        .filter(|mount| mount.kind == DockerMountKindV12::Tmpfs)
        .collect();
    if tmpfs.len() != expected_tmpfs.len() {
        return Err(ControllerError::Rejected(
            "container tmpfs count differs from signed authority",
        ));
    }
    for expected in expected_tmpfs {
        let options = format!(
            "rw,nosuid,nodev,noexec,size={}",
            expected.size_bytes
        );
        if tmpfs.get(&expected.target).and_then(Value::as_str)
            != Some(options.as_str())
        {
            return Err(ControllerError::Rejected(
                "container tmpfs differs from signed authority",
            ));
        }
    }
    Ok(())
}

fn validate_network_create(
    value: &Value,
    request: &DockerApiRequestV11,
    labels: &BTreeMap<String, String>,
) -> Result<()> {
    let object = object(value, "network create body is not an object")?;
    require_object_keys(
        object,
        &[
            "Attachable",
            "CheckDuplicate",
            "Driver",
            "EnableIPv6",
            "Internal",
            "Labels",
            "Name",
            "Options",
        ],
    )?;
    if string(object, "Name")? != request.target.logical_id
        || string(object, "Driver")? != "bridge"
        || boolean(object, "Attachable")?
        || !boolean(object, "CheckDuplicate")?
        || boolean(object, "EnableIPv6")?
        || !boolean(object, "Internal")?
        || !self::object(
            field(object, "Options")?,
            "network options are not an object",
        )?
        .is_empty()
    {
        return Err(ControllerError::Rejected(
            "network create body differs from the fixed internal bridge",
        ));
    }
    validate_labels(field(object, "Labels")?, labels)
}

fn validate_network_membership(
    value: &Value,
    request: &DockerApiRequestV11,
    context: &DockerPolicyContextV11<'_>,
) -> Result<()> {
    let object = object(value, "network membership body is not an object")?;
    let membership = request.network_membership.as_ref().ok_or(
        ControllerError::Rejected(
            "network mutation lacks signed membership authority",
        ),
    )?;
    if string(object, "Container")? != membership.container_engine_id
        || !context.ownership.engine_id_is_owned(
            &context.capability.owner_namespace,
            &context.capability.daemon_generation,
            DockerResourceKindV11::Container,
            &membership.container_logical_id,
            &membership.container_engine_id,
        )?
    {
        return Err(ControllerError::Rejected(
            "network membership does not name an owned container",
        ));
    }
    let network_engine_id = request.target.engine_id.as_deref().ok_or(
        ControllerError::Rejected(
            "network membership lacks its owned network engine ID",
        ),
    )?;
    let existing = context.ownership.network_membership_is_connected(
        &context.capability.owner_namespace,
        &context.capability.daemon_generation,
        &membership.network_logical_id,
        &membership.container_logical_id,
        network_engine_id,
        &membership.container_engine_id,
    )?;
    if request.normalized_route.ends_with("/connect") {
        if existing == Some(true) {
            return Err(ControllerError::Rejected(
                "network membership is already durably connected",
            ));
        }
        require_object_keys(object, &["Container", "EndpointConfig"])?;
        let endpoint = self::object(
            field(object, "EndpointConfig")?,
            "EndpointConfig is not an object",
        )?;
        require_object_keys(endpoint, &["Aliases", "IPAMConfig"])?;
        if array_strings(endpoint, "Aliases")?
            != membership
                .aliases
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return Err(ControllerError::Rejected(
                "network aliases differ from the signed membership",
            ));
        }
        let ipam = self::object(
            field(endpoint, "IPAMConfig")?,
            "network IPAMConfig is not an object",
        )?;
        require_object_keys(ipam, &["IPv4Address", "IPv6Address"])?;
        if string(ipam, "IPv4Address")?
            != membership.ipv4_address.as_deref().unwrap_or("")
            || string(ipam, "IPv6Address")?
                != membership.ipv6_address.as_deref().unwrap_or("")
        {
            return Err(ControllerError::Rejected(
                "network addresses differ from the signed membership",
            ));
        }
        Ok(())
    } else if request.normalized_route.ends_with("/disconnect") {
        if existing != Some(true) {
            return Err(ControllerError::Rejected(
                "network membership is not durably connected",
            ));
        }
        require_object_keys(object, &["Container", "Force"])?;
        if boolean(object, "Force")? {
            return Err(ControllerError::Rejected(
                "network disconnect cannot force an unobserved transition",
            ));
        }
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "network membership authority used on a non-membership route",
        ))
    }
}

fn validate_volume_create(
    value: &Value,
    request: &DockerApiRequestV11,
    labels: &BTreeMap<String, String>,
) -> Result<()> {
    let object = object(value, "volume create body is not an object")?;
    require_object_keys(object, &["Driver", "DriverOpts", "Labels", "Name"])?;
    if string(object, "Name")? != request.target.logical_id
        || string(object, "Driver")? != "local"
        || !self::object(
            field(object, "DriverOpts")?,
            "DriverOpts is not an object",
        )?
            .is_empty()
    {
        return Err(ControllerError::Rejected(
            "volume create body differs from the fixed local volume",
        ));
    }
    validate_labels(field(object, "Labels")?, labels)
}

fn validate_labels(
    value: &Value,
    required: &BTreeMap<String, String>,
) -> Result<()> {
    let labels = object(value, "Docker labels are not an object")?;
    if labels.len() != required.len()
        || required.iter().any(|(name, expected)| {
            labels.get(name).and_then(Value::as_str) != Some(expected)
        })
    {
        return Err(ControllerError::Rejected(
            "Docker owner labels are absent, additional, or incorrect",
        ));
    }
    Ok(())
}

fn require_allowed_image(
    capability: &DockerLaneCapabilityV11,
    image: &str,
) -> Result<()> {
    if capability.allowed_image_digests.contains(image)
        || capability.allowed_pinned_pulls.contains(image)
    {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker image ID is outside the exact lane image set",
        ))
    }
}

fn require_daemon_read(
    request: &DockerApiRequestV11,
    query: &BTreeMap<String, String>,
    body: Option<&Value>,
) -> Result<()> {
    if request.target.kind != DockerResourceKindV11::Daemon
        || request.target.engine_id.is_some()
    {
        return Err(ControllerError::Rejected(
            "Docker daemon read has a non-daemon target",
        ));
    }
    require_empty_query_and_body(query, body)
}

fn require_build(profile: DockerLaneProfileV11) -> Result<()> {
    if profile == DockerLaneProfileV11::Build {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker build mutation is unavailable after the artifact seal",
        ))
    }
}

fn require_logical_name(
    request: &DockerApiRequestV11,
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<()> {
    if query.get(key) != Some(&request.target.logical_id) {
        return Err(ControllerError::Rejected(
            "Docker create name differs from the signed logical ID",
        ));
    }
    Ok(())
}

fn require_empty_query_and_body(
    query: &BTreeMap<String, String>,
    body: Option<&Value>,
) -> Result<()> {
    require_empty_query(query)?;
    require_no_body(body)
}

fn require_empty_query(query: &BTreeMap<String, String>) -> Result<()> {
    if query.is_empty() {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker route does not permit query fields",
        ))
    }
}

fn require_no_body(body: Option<&Value>) -> Result<()> {
    if body.is_none() {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker route does not permit a request body",
        ))
    }
}

fn require_exact_keys(
    query: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<()> {
    if query.len() != expected.len()
        || expected.iter().any(|key| !query.contains_key(*key))
    {
        return Err(ControllerError::Rejected(
            "Docker query fields differ from the exact route contract",
        ));
    }
    Ok(())
}

fn require_boolean_query(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<()> {
    if matches!(query.get(key).map(String::as_str), Some("0" | "1")) {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker boolean query value is noncanonical",
        ))
    }
}

fn require_true_query(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<()> {
    if query.get(key).map(String::as_str) == Some("1") {
        Ok(())
    } else {
        Err(ControllerError::Rejected(
            "Docker destructive cleanup query must be true",
        ))
    }
}

fn require_bounded_u32(
    query: &BTreeMap<String, String>,
    key: &str,
    minimum: u32,
    maximum: u32,
) -> Result<()> {
    let value = query
        .get(key)
        .ok_or(ControllerError::Invalid(
            "Docker numeric query field is absent",
        ))?
        .parse::<u32>()
        .map_err(|_| {
            ControllerError::Invalid("Docker numeric query is invalid")
        })?;
    if value < minimum || value > maximum {
        return Err(ControllerError::Rejected(
            "Docker numeric query is outside the route bound",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum RoutePart<'a> {
    Literal(&'a str),
    Identifier(&'a str),
}

fn parse_route(route: &str) -> Result<Vec<RoutePart<'_>>> {
    let parts: Vec<&str> =
        route.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(ControllerError::Rejected(
            "Docker route depth is outside the v11 contract",
        ));
    }
    let literals: BTreeSet<&str> = [
        "_ping",
        "version",
        "info",
        "containers",
        "images",
        "networks",
        "volumes",
        "build",
        "create",
        "json",
        "logs",
        "attach",
        "start",
        "stop",
        "kill",
        "wait",
        "connect",
        "disconnect",
    ]
    .into_iter()
    .collect();
    Ok(parts
        .into_iter()
        .map(|part| {
            if literals.contains(part) {
                RoutePart::Literal(part)
            } else {
                RoutePart::Identifier(part)
            }
        })
        .collect())
}

fn query_map(
    pairs: &[(String, String)],
) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (name, value) in pairs {
        if result.insert(name.clone(), value.clone()).is_some() {
            return Err(ControllerError::Rejected(
                "Docker query contains a duplicate field",
            ));
        }
    }
    Ok(result)
}

fn parse_exact_json(bytes: &[u8]) -> Result<Value> {
    docker_parse_exact_canonical_json_v11(
        bytes,
        DOCKER_CONTRACT_MAX_BYTES_V11,
    )
}

fn object<'a>(
    value: &'a Value,
    message: &'static str,
) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or(ControllerError::Invalid(message))
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

fn boolean(
    object: &Map<String, Value>,
    name: &'static str,
) -> Result<bool> {
    field(object, name)?
        .as_bool()
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

fn array_strings<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<Vec<&'a str>> {
    field(object, name)?
        .as_array()
        .ok_or(ControllerError::Invalid(name))?
        .iter()
        .map(|value| {
            value.as_str().ok_or(ControllerError::Invalid(name))
        })
        .collect()
}

fn require_object_keys(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<()> {
    if object.len() != expected.len()
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ControllerError::Rejected(
            "Docker JSON fields differ from the exact operation contract",
        ));
    }
    Ok(())
}

fn validate_string_array(
    value: &Value,
    max_items: usize,
    max_item_bytes: usize,
) -> Result<()> {
    let values = value.as_array().ok_or(ControllerError::Invalid(
        "Docker string list is not an array",
    ))?;
    if values.len() > max_items
        || values.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|value| value.len() > max_item_bytes || value.contains('\0'))
        })
    {
        return Err(ControllerError::Rejected(
            "Docker string list exceeds its exact bound",
        ));
    }
    Ok(())
}

fn hex_digest(digest: &Digest) -> String {
    crate::coder_controller_v11::digest_hex(digest)
}

fn verify_tar_checksum(header: &[u8; 512]) -> Result<()> {
    let declared = tar_octal(&header[148..156])?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as u64
            } else {
                *byte as u64
            }
        })
        .sum::<u64>();
    if actual != declared {
        return Err(ControllerError::Rejected(
            "Docker build context tar checksum differs",
        ));
    }
    Ok(())
}

fn tar_octal(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(ControllerError::Rejected(
            "Docker build context uses unsupported base-256 tar integers",
        ));
    }
    let text = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(|byte| !matches!(byte, 0 | b' '))
        .collect::<Vec<_>>();
    if text.is_empty() {
        return Ok(0);
    }
    if !text.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(ControllerError::Rejected(
            "Docker build context tar integer is noncanonical",
        ));
    }
    text.into_iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add((byte - b'0') as u64))
            .ok_or(ControllerError::Invalid(
                "Docker build context tar integer overflowed",
            ))
    })
}

fn tar_text(field: &[u8]) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0)
        || field[..end].iter().any(|byte| {
            !byte.is_ascii() || byte.is_ascii_control()
        })
    {
        return Err(ControllerError::Rejected(
            "Docker build context tar text is noncanonical",
        ));
    }
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .map_err(|_| {
            ControllerError::Invalid(
                "Docker build context tar text is not UTF-8",
            )
        })
}

fn hash_exact_segment(reader: &mut File, mut remaining: u64) -> Result<Digest> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..wanted])?;
        if count == 0 {
            return Err(ControllerError::Rejected(
                "Docker build context entry is truncated",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let digest = hasher.finalize();
    let mut value = [0u8; 32];
    value.copy_from_slice(&digest);
    Ok(value)
}
