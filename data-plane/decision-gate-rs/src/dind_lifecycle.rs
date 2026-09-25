#![allow(dead_code)]

#[path = "dind_json_v12.rs"]
mod dind_json_v12;

#[path = "runner_isolation_v12.rs"]
mod runner_isolation_v12;

#[path = "runner_output_storage_v12.rs"]
mod runner_output_storage_v12;

#[path = "native_postgres_reports_v12.rs"]
mod native_postgres_reports_v12;

#[path = "native_postgres_output_v12.rs"]
mod native_postgres_output_v12;

#[path = "body_output_files_v12.rs"]
mod body_output_files_v12;

#[path = "body_output_v12.rs"]
mod body_output_v12;

#[cfg(test)]
#[path = "runner_output_tests_v12.rs"]
mod runner_output_tests_v12;

use self::dind_json_v12::canonical_json_bytes_v12;
use self::runner_isolation_v12::{
    execution_host_config_v12, validate_runner_inspect_v12,
};
use self::runner_output_storage_v12::RunnerOutputStorageV12;
use self::body_output_v12::CaptureOutputsV12;
use crate::plan_protocol::body_output_contract_v12::{
    native_subset_sha256, stream_byte_limit,
};
use crate::plan_protocol::RunnerExecutionBoundsV12;
use crate::runtime_evidence::body_result_v12::{
    BodyExecutionResultV12, MAX_BODY_RESULT_BYTES_V12,
};

use crate::coder_controller_v11::{
    canonical_json_bytes_v11, constant_time_eq, digest_hex, sha256,
    sha256_exact_reader, ControllerError, Digest, Result,
};
use crate::docker_contract::{
    boottime_now_ns_v11, DockerBuildTupleV11, DockerLaneCapabilityV11,
    DockerLaneDecodedPayloadV12, DockerLaneOperationV12,
    DockerLanePayloadContentV12, DockerLaneProfileV11,
    DockerStreamModeV11, ArtifactCasReference,
    AuthoritativeLaneState, BodyContract, ContainerCommand,
    DindGenerationKind, LogicalLane, OciObjectReference,
    EndpointProtocol,
    PrivateDindOperationDispositionV12,
    PrivateDindOperationRequestV12, PrivateDindOperationResponseV12,
    PrivateDindProfileV12, ProxyOperation, RunnerIdentity,
    ServiceInstanceV12, canonical_plan_bytes,
    plan_sha256_bytes, DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
    PRIVATE_DIND_RESULT_VERSION_V12,
};
use crate::docker_ledger::{
    BeginLaneOperationV12, DockerGenerationDestructionObservationV12,
    DockerGenerationRecordV12,
    DockerLaneLedgerV12, DockerLaneOperationRecordV12,
    DockerLaneOperationStatusV12, DockerOwnershipLedgerV11,
    validate_relative_cas_subpath_v12,
};
use crate::docker_policy::{
    authorize_lane_operation_v12, ARTIFACT_SEAL_LABEL_V11,
    ARTIFACT_SEAL_LABEL_V12,
    DockerLaneEffectV12, DockerLanePolicyDecisionV12,
    GENERATION_LABEL_V11, GENERATION_LABEL_V12, LANE_LABEL_V11,
    LANE_LABEL_V12, LOGICAL_ID_LABEL_V11, OWNER_LABEL_V11,
    OWNER_LABEL_V12, RESOURCE_LABEL_V12, SERVICE_ID_LABEL_V12,
    SOURCE_SEAL_LABEL_V11, SOURCE_SEAL_LABEL_V12,
};
use crate::docker_transport::{
    canonical_docker_request_head_v12, docker_http_response_body_v12,
    execute_bounded_docker_http_v12, DockerDirectHttpOutcomeV12,
    execute_bounded_docker_http_v12_with_cancellation,
    DockerHttpExchangeContractV12, DockerRequestBodyV12,
    validate_docker_json_message_sequence_v12,
};
use crate::docker_transport::docker_body_capture_v12::BodyCaptureV12;
use crate::readiness::{
    ChromiumResultV12, DockerUpgradeResultV12, ReadinessFixtureTrust,
    ReadinessProbe, ReadinessProbeResultV12, ReadinessResponseV12,
    ServiceHealthResultV12, TeardownResultV12,
};
use ed25519_dalek::{
    Signature, SigningKey, Verifier, VerifyingKey,
};
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::process::CommandExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const DIND_START_TIMEOUT_NS_V11: u64 = 120 * 1_000_000_000;
const DIND_CLEANUP_TIMEOUT_NS_V11: u64 = 60 * 1_000_000_000;
const DIND_COMMAND_OUTPUT_MAX_BYTES_V11: u64 = 256 * 1024 * 1024;
const DIND_PID_RECORD_MAX_BYTES_V11: u64 = 4096;
const DIND_MAX_RECONCILED_GENERATIONS_V12: usize = 4096;
const OCI_MANIFEST_MAX_BYTES_V11: u64 = 1024 * 1024;
static OCI_TRANSFER_SEQUENCE_V11: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct DindLifecycleConfigV11 {
    pub state_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub private_socket_root: PathBuf,
    pub oci_cas_root: PathBuf,
    pub dockerd_path: PathBuf,
    pub dockerd_sha256: Digest,
    pub docker_path: PathBuf,
    pub docker_sha256: Digest,
    pub oci_exporter_path: PathBuf,
    pub oci_exporter_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DindLanePhaseV11 {
    Starting,
    Build,
    Sealing,
    Destroying,
    NoBuild,
    Terminal,
    Failed,
}

struct DindHandleV11 {
    child: Child,
    pidfd: OwnedFd,
    pid: libc::pid_t,
    start_time_ticks: u64,
    generation: String,
    owner_namespace: String,
    socket: PathBuf,
    data_root: PathBuf,
    exec_root: PathBuf,
    cgroup: PathBuf,
    phase: DindLanePhaseV11,
}

struct DindLaneStateV11 {
    owner_namespace: String,
    build_generation: Option<String>,
    active: Option<DindHandleV11>,
    sealed_artifact_sha256: Option<Digest>,
    sealed_images: BTreeMap<String, Digest>,
}

struct LifecycleStateV11 {
    lanes: BTreeMap<String, DindLaneStateV11>,
}

struct TemporaryCasFileV11 {
    path: PathBuf,
    armed: bool,
}

impl Drop for TemporaryCasFileV11 {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct DindLifecycleV11 {
    config: DindLifecycleConfigV11,
    ledger: Arc<DockerOwnershipLedgerV11>,
    state: Mutex<LifecycleStateV11>,
}

impl DindLifecycleV11 {
    pub fn open(
        config: DindLifecycleConfigV11,
        ledger: Arc<DockerOwnershipLedgerV11>,
    ) -> Result<Self> {
        validate_config(&config)?;
        for root in [
            &config.state_root,
            &config.private_socket_root,
            &config.oci_cas_root,
        ] {
            std::fs::create_dir_all(root)?;
            std::fs::set_permissions(
                root,
                std::fs::Permissions::from_mode(0o700),
            )?;
            require_private_root(root)?;
        }
        let lifecycle = Self {
            config,
            ledger,
            state: Mutex::new(LifecycleStateV11 {
                lanes: BTreeMap::new(),
            }),
        };
        lifecycle.startup_reconcile()?;
        Ok(lifecycle)
    }

    pub fn startup_reconcile(&self) -> Result<()> {
        let mut generations = self.recorded_generations()?;
        generations.extend(self.ledger.startup_reconciliation()?);
        if generations.len() > DIND_MAX_RECONCILED_GENERATIONS_V12 {
            return Err(ControllerError::Rejected(
                "startup reconciliation generation bound exceeded",
            ));
        }
        let deadline = boottime_now_ns_v11()?
            .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
            .ok_or(ControllerError::Invalid(
                "startup reconciliation deadline overflow",
            ))?;
        for (owner, generation) in generations {
            if boottime_now_ns_v11()? >= deadline {
                return Err(ControllerError::Rejected(
                    "startup reconciliation exceeded its global deadline",
                ));
            }
            let reason =
                sha256(b"serverware/dind-startup-reconciliation/v11");
            self.ledger.begin_destroying_generation(
                &owner,
                &generation,
                reason,
            )?;
            self.cleanup_recorded_generation(
                &owner,
                &generation,
                deadline,
            )?;
            self.ledger
                .mark_generation_destroyed(&owner, &generation)?;
        }
        Ok(())
    }

    pub fn ensure_lane_generation(
        &self,
        capability: &DockerLaneCapabilityV11,
        deadline_boottime_ns: u64,
    ) -> Result<PathBuf> {
        if deadline_boottime_ns > capability.deadline_boottime_ns
            || boottime_now_ns_v11()? >= deadline_boottime_ns
        {
            return Err(ControllerError::Rejected(
                "DinD operation deadline is invalid or expired",
            ));
        }
        if self.ledger.generation_is_terminal(
            &capability.owner_namespace,
            &capability.daemon_generation,
        )? {
            return Err(ControllerError::Rejected(
                "signed DinD generation is durably terminal",
            ));
        }
        if capability.profile == DockerLaneProfileV11::Build {
            let mut state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "DinD lifecycle mutex is poisoned",
                )
            })?;
            let lane = state
                .lanes
                .entry(capability.lane_id.clone())
                .or_insert_with(|| DindLaneStateV11 {
                    owner_namespace: capability.owner_namespace.clone(),
                    build_generation: Some(
                        capability.daemon_generation.clone(),
                    ),
                    active: None,
                    sealed_artifact_sha256: None,
                    sealed_images: BTreeMap::new(),
                });
            if lane.owner_namespace != capability.owner_namespace
                || lane.build_generation.as_deref()
                    != Some(capability.daemon_generation.as_str())
            {
                return Err(ControllerError::Rejected(
                    "signed DinD lane reused a conflicting owner or build generation",
                ));
            }
            if lane.active.is_none() {
                lane.active = Some(self.start_generation_or_terminal(
                    &capability.owner_namespace,
                    &capability.daemon_generation,
                    DindLanePhaseV11::Build,
                    deadline_boottime_ns,
                )?);
            }
            let handle = lane.active.as_ref().ok_or(
                ControllerError::Rejected(
                    "DinD build generation failed to activate",
                ),
            )?;
            if handle.phase != DindLanePhaseV11::Build
                || handle.owner_namespace != capability.owner_namespace
                || handle.generation != capability.daemon_generation
            {
                return Err(ControllerError::Rejected(
                    "active DinD differs from the signed build generation",
                ));
            }
            return Ok(handle.socket.clone());
        }
        let expected_generation =
            Self::no_build_generation_for(
                capability.artifact_seal_sha256,
                &capability.lane_id,
            );
        if capability.daemon_generation != expected_generation {
            return Err(ControllerError::Rejected(
                "no-build DinD generation is not derived from its artifact seal",
            ));
        }
        let images = self.read_sealed_manifest(capability)?;
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected("DinD lifecycle mutex is poisoned")
        })?;
        let lane = state
            .lanes
            .entry(capability.lane_id.clone())
            .or_insert_with(|| DindLaneStateV11 {
                owner_namespace: capability.owner_namespace.clone(),
                build_generation: None,
                active: None,
                sealed_artifact_sha256: None,
                sealed_images: BTreeMap::new(),
            });
        if lane.owner_namespace != capability.owner_namespace
            || lane.build_generation.is_some()
        {
            return Err(ControllerError::Rejected(
                "no-build lane reused a conflicting owner or build generation",
            ));
        }
        if lane.active.is_none() {
            let mut handle = self.start_generation_or_terminal(
                &capability.owner_namespace,
                &capability.daemon_generation,
                DindLanePhaseV11::NoBuild,
                deadline_boottime_ns,
            )?;
            if let Err(error) = self.import_sealed_images(
                &mut handle,
                &images,
                deadline_boottime_ns,
            ) {
                let reason = sha256(error.to_string().as_bytes());
                let marker_result = self.ledger.begin_destroying_generation(
                    &capability.owner_namespace,
                    &capability.daemon_generation,
                    reason,
                );
                let cleanup_result = self.cleanup_recorded_generation(
                    &capability.owner_namespace,
                    &capability.daemon_generation,
                    cleanup_deadline().unwrap_or(deadline_boottime_ns),
                );
                if marker_result.is_ok() && cleanup_result.is_ok() {
                    let _ = self.ledger.mark_generation_destroyed(
                        &capability.owner_namespace,
                        &capability.daemon_generation,
                    );
                }
                return Err(error);
            }
            lane.active = Some(handle);
            lane.sealed_artifact_sha256 =
                Some(capability.artifact_seal_sha256);
            lane.sealed_images = images;
        }
        let handle = lane.active.as_ref().ok_or(
            ControllerError::Rejected(
                "fresh no-build DinD was not retained",
            ),
        )?;
        if handle.phase != DindLanePhaseV11::NoBuild
            || handle.owner_namespace != capability.owner_namespace
            || handle.generation != capability.daemon_generation
            || lane.sealed_artifact_sha256
                != Some(capability.artifact_seal_sha256)
            || lane.sealed_images.len()
                != capability.allowed_image_digests.len()
            || lane.sealed_images.keys().any(|image| {
                !capability.allowed_image_digests.contains(image)
            })
        {
            return Err(ControllerError::Rejected(
                "active no-build DinD differs from its sealed capability",
            ));
        }
        Ok(handle.socket.clone())
    }

    pub fn no_build_generation_for(
        artifact_seal_sha256: Digest,
        lane_id: &str,
    ) -> String {
        let lane_sha256 = sha256(lane_id.as_bytes());
        format!(
            "no-build-{}-{}",
            &digest_hex(&artifact_seal_sha256)[..24],
            &digest_hex(&lane_sha256)[..16],
        )
    }

    pub fn private_socket_for(
        &self,
        capability: &DockerLaneCapabilityV11,
    ) -> Result<PathBuf> {
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected("DinD lifecycle mutex is poisoned")
        })?;
        let lane = state
            .lanes
            .get(&capability.lane_id)
            .ok_or(ControllerError::Rejected(
                "DinD lane is not active",
            ))?;
        let handle = lane.active.as_ref().ok_or(
            ControllerError::Rejected("DinD generation is not active"),
        )?;
        if handle.owner_namespace != capability.owner_namespace
            || handle.generation != capability.daemon_generation
            || handle.phase == DindLanePhaseV11::Destroying
            || handle.phase == DindLanePhaseV11::Failed
        {
            return Err(ControllerError::Rejected(
                "DinD generation differs from the lane capability",
            ));
        }
        Ok(handle.socket.clone())
    }

    pub fn seal_build_to_cas(
        &self,
        capability: &DockerLaneCapabilityV11,
        deadline_boottime_ns: u64,
    ) -> Result<Digest> {
        if capability.profile != DockerLaneProfileV11::Build
            || deadline_boottime_ns > capability.deadline_boottime_ns
            || boottime_now_ns_v11()? >= deadline_boottime_ns
        {
            return Err(ControllerError::Rejected(
                "DinD build seal deadline or profile is invalid",
            ));
        }
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected("DinD lifecycle mutex is poisoned")
        })?;
        let lane = state
            .lanes
            .get_mut(&capability.lane_id)
            .ok_or(ControllerError::Rejected(
                "DinD build lane is not active",
            ))?;
        let handle = lane.active.as_mut().ok_or(
            ControllerError::Rejected(
                "DinD build daemon is not active",
            ),
        )?;
        if handle.phase != DindLanePhaseV11::Build
            || handle.owner_namespace != capability.owner_namespace
            || handle.generation != capability.daemon_generation
        {
            return Err(ControllerError::Rejected(
                "DinD active generation is not the exact build lane",
            ));
        }
        handle.phase = DindLanePhaseV11::Sealing;
        let images = self.export_owned_images(
            handle,
            capability,
            deadline_boottime_ns,
        )?;
        if images.is_empty() {
            return Err(ControllerError::Rejected(
                "DinD build produced no owner-labelled image",
            ));
        }
        let inventory_sha256 =
            image_inventory_sha256(&images, capability)?;
        self.ledger.begin_destroying_generation(
            &capability.owner_namespace,
            &capability.daemon_generation,
            sha256(b"serverware/dind-build-sealed/v11"),
        )?;
        self.destroy_handle(handle, deadline_boottime_ns)?;
        let owner = handle.owner_namespace.clone();
        let old_generation = handle.generation.clone();
        lane.active = None;
        self.ledger
            .mark_generation_destroyed(&owner, &old_generation)?;
        self.publish_sealed_manifest(&images, capability)?;
        Ok(inventory_sha256)
    }

    pub fn require_no_build_generation(
        &self,
        capability: &DockerLaneCapabilityV11,
    ) -> Result<()> {
        if capability.profile == DockerLaneProfileV11::Build {
            return Err(ControllerError::Rejected(
                "build capability cannot enter the no-build generation",
            ));
        }
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected("DinD lifecycle mutex is poisoned")
        })?;
        let lane = state
            .lanes
            .get(&capability.lane_id)
            .ok_or(ControllerError::Rejected(
                "no-build DinD lane is not active",
            ))?;
        let handle = lane.active.as_ref().ok_or(
            ControllerError::Rejected(
                "no-build DinD generation is not active",
            ),
        )?;
        if handle.phase != DindLanePhaseV11::NoBuild
            || handle.owner_namespace != capability.owner_namespace
            || handle.generation != capability.daemon_generation
            || lane.sealed_artifact_sha256
                != Some(capability.artifact_seal_sha256)
            || lane.sealed_images.len()
                != capability.allowed_image_digests.len()
            || lane.sealed_images.keys().any(|image| {
                !capability.allowed_image_digests.contains(image)
            })
        {
            return Err(ControllerError::Rejected(
                "no-build generation differs from the sealed capability",
            ));
        }
        Ok(())
    }

    fn publish_sealed_manifest(
        &self,
        images: &BTreeMap<String, Digest>,
        capability: &DockerLaneCapabilityV11,
    ) -> Result<()> {
        let tuple = capability.build_tuple.as_ref().ok_or(
            ControllerError::Rejected(
                "sealed OCI manifest lacks its build tuple",
            ),
        )?;
        let mut image_values = Map::new();
        for (image_id, archive_sha256) in images {
            image_values.insert(
                image_id.clone(),
                Value::String(digest_hex(archive_sha256)),
            );
        }
        let manifest = Value::Object(Map::from_iter([
            (
                "artifactSealSha256".to_owned(),
                Value::String(digest_hex(
                    &capability.artifact_seal_sha256,
                )),
            ),
            (
                "buildTuple".to_owned(),
                Value::Object(Map::from_iter([
                    (
                        "buildArgsSha256".to_owned(),
                        Value::String(digest_hex(
                            &tuple.build_args_sha256,
                        )),
                    ),
                    (
                        "contextCasSha256".to_owned(),
                        Value::String(digest_hex(
                            &tuple.context_cas_sha256,
                        )),
                    ),
                    (
                        "dockerfileCasSha256".to_owned(),
                        Value::String(digest_hex(
                            &tuple.dockerfile_cas_sha256,
                        )),
                    ),
                    (
                        "output".to_owned(),
                        Value::String(tuple.output.clone()),
                    ),
                    (
                        "platform".to_owned(),
                        Value::String(tuple.platform.clone()),
                    ),
                    (
                        "target".to_owned(),
                        Value::String(tuple.target.clone()),
                    ),
                ])),
            ),
            (
                "contractVersion".to_owned(),
                Value::String("11".to_owned()),
            ),
            ("images".to_owned(), Value::Object(image_values)),
            (
                "inventorySha256".to_owned(),
                Value::String(digest_hex(
                    &image_inventory_sha256(images, capability)?,
                )),
            ),
            (
                "sourceSealSha256".to_owned(),
                Value::String(digest_hex(
                    &capability.source_seal_sha256,
                )),
            ),
        ]));
        let bytes = canonical_json_bytes_v11(&manifest)?;
        let final_path = self.config.oci_cas_root.join(format!(
            "{}.manifest.json",
            digest_hex(&capability.artifact_seal_sha256)
        ));
        publish_exact_private_file(
            &self.config.oci_cas_root,
            &final_path,
            &bytes,
        )
    }

    fn read_sealed_manifest(
        &self,
        capability: &DockerLaneCapabilityV11,
    ) -> Result<BTreeMap<String, Digest>> {
        let path = self.config.oci_cas_root.join(format!(
            "{}.manifest.json",
            digest_hex(&capability.artifact_seal_sha256)
        ));
        let bytes = read_private_file(
            &path,
            OCI_MANIFEST_MAX_BYTES_V11,
        )?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            ControllerError::Invalid(
                "sealed OCI manifest is not JSON",
            )
        })?;
        if canonical_json_bytes_v11(&value)? != bytes {
            return Err(ControllerError::Rejected(
                "sealed OCI manifest is not canonical JSON",
            ));
        }
        let root = exact_manifest_object(
            &value,
            &[
                "artifactSealSha256",
                "buildTuple",
                "contractVersion",
                "images",
                "inventorySha256",
                "sourceSealSha256",
            ],
        )?;
        if manifest_text(root, "contractVersion")? != "11"
            || parse_hex_digest(manifest_text(
                root,
                "artifactSealSha256",
            )?)?
                != capability.artifact_seal_sha256
            || parse_hex_digest(manifest_text(
                root,
                "sourceSealSha256",
            )?)?
                != capability.source_seal_sha256
        {
            return Err(ControllerError::Rejected(
                "sealed OCI manifest binding differs from the capability",
            ));
        }
        let tuple_value = root.get("buildTuple").ok_or(
            ControllerError::Invalid(
                "sealed OCI manifest build tuple is absent",
            ),
        )?;
        let tuple_object = exact_manifest_object(
            tuple_value,
            &[
                "buildArgsSha256",
                "contextCasSha256",
                "dockerfileCasSha256",
                "output",
                "platform",
                "target",
            ],
        )?;
        let tuple = DockerBuildTupleV11 {
            context_cas_sha256: parse_hex_digest(manifest_text(
                tuple_object,
                "contextCasSha256",
            )?)?,
            dockerfile_cas_sha256: parse_hex_digest(manifest_text(
                tuple_object,
                "dockerfileCasSha256",
            )?)?,
            target: manifest_text(tuple_object, "target")?.to_owned(),
            platform: manifest_text(tuple_object, "platform")?.to_owned(),
            output: manifest_text(tuple_object, "output")?.to_owned(),
            build_args_sha256: parse_hex_digest(manifest_text(
                tuple_object,
                "buildArgsSha256",
            )?)?,
        };
        if tuple.context_cas_sha256 == [0; 32]
            || tuple.dockerfile_cas_sha256 == [0; 32]
            || tuple.build_args_sha256 == [0; 32]
            || tuple.target.is_empty()
            || tuple.platform.is_empty()
            || tuple.output.is_empty()
        {
            return Err(ControllerError::Rejected(
                "sealed OCI manifest build tuple is invalid",
            ));
        }
        let image_object = root
            .get("images")
            .and_then(Value::as_object)
            .ok_or(ControllerError::Invalid(
                "sealed OCI manifest image map is invalid",
            ))?;
        if image_object.is_empty() || image_object.len() > 256 {
            return Err(ControllerError::Rejected(
                "sealed OCI manifest image count is invalid",
            ));
        }
        let mut images = BTreeMap::new();
        for (image_id, archive_sha256) in image_object {
            if !valid_image_id(image_id)
                || !capability.allowed_image_digests.contains(image_id)
            {
                return Err(ControllerError::Rejected(
                    "sealed OCI manifest contains an unauthorized image ID",
                ));
            }
            let archive_sha256 = archive_sha256
                .as_str()
                .ok_or(ControllerError::Invalid(
                    "sealed OCI archive digest is not text",
                ))
                .and_then(parse_hex_digest)?;
            if archive_sha256 == [0; 32] {
                return Err(ControllerError::Rejected(
                    "sealed OCI archive digest is absent",
                ));
            }
            images.insert(image_id.clone(), archive_sha256);
        }
        if images.len() != capability.allowed_image_digests.len()
            || parse_hex_digest(manifest_text(
                root,
                "inventorySha256",
            )?)?
                != image_inventory_sha256_parts(
                &images,
                capability.source_seal_sha256,
                &tuple,
            )?
        {
            return Err(ControllerError::Rejected(
                "sealed OCI manifest differs from the complete signed image set",
            ));
        }
        Ok(images)
    }

    pub fn fail_lane(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        reason_sha256: Digest,
    ) -> Result<()> {
        let mut failures = Vec::new();
        if let Err(error) = self.ledger.begin_destroying_generation(
            owner_namespace,
            daemon_generation,
            reason_sha256,
        ) {
            failures.push(error.to_string());
        }
        let deadline = cleanup_deadline()?;
        let mut related_generations = BTreeSet::new();
        match self.state.lock() {
            Ok(mut state) => {
                for lane in state.lanes.values_mut() {
                    let related = lane.owner_namespace == owner_namespace
                        && (lane.build_generation.as_deref()
                            == Some(daemon_generation)
                            || lane.active.as_ref().is_some_and(|handle| {
                                handle.generation == daemon_generation
                            }));
                    if !related {
                        continue;
                    }
                    if let Some(handle) = lane.active.as_mut() {
                        related_generations
                            .insert(handle.generation.clone());
                        handle.phase = DindLanePhaseV11::Destroying;
                        if let Err(error) =
                            self.destroy_handle(handle, deadline)
                        {
                            failures.push(error.to_string());
                        }
                    }
                    lane.active = None;
                    lane.build_generation = None;
                    lane.sealed_artifact_sha256 = None;
                    lane.sealed_images.clear();
                }
            }
            Err(_) => failures.push(
                "DinD lifecycle mutex is poisoned during destruction"
                    .to_owned(),
            ),
        }
        if let Err(error) = self.cleanup_recorded_generation(
            owner_namespace,
            daemon_generation,
            deadline,
        ) {
            failures.push(error.to_string());
        }
        if failures.is_empty() {
            if let Err(error) = self.ledger.mark_generation_destroyed(
                owner_namespace,
                daemon_generation,
            ) {
                failures.push(error.to_string());
            }
        }
        for related in related_generations {
            if related != daemon_generation {
                let marker_result = self.ledger.begin_destroying_generation(
                    owner_namespace,
                    &related,
                    reason_sha256,
                );
                let cleanup_result = self.cleanup_recorded_generation(
                    owner_namespace,
                    &related,
                    deadline,
                );
                match (marker_result, cleanup_result) {
                    (Ok(_), Ok(())) => {
                        if let Err(error) =
                            self.ledger.mark_generation_destroyed(
                                owner_namespace,
                                &related,
                            )
                        {
                            failures.push(error.to_string());
                        }
                    }
                    (marker, cleanup) => {
                        if let Err(error) = marker {
                            failures.push(error.to_string());
                        }
                        if let Err(error) = cleanup {
                            failures.push(error.to_string());
                        }
                    }
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ControllerError::InvalidOwned(format!(
                "DinD destruction attempted every cleanup path but failed: {}",
                failures.join("; "),
            )))
        }
    }

    pub fn finish_no_build(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<()> {
        let reason = sha256(b"serverware/dind-terminal-cleanup/v11");
        self.fail_lane(owner_namespace, daemon_generation, reason)
    }

    pub fn fail_all(&self, reason_sha256: Digest) -> Result<()> {
        let mut generations = self.recorded_generations()?;
        generations.extend(self.ledger.startup_reconciliation()?);
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "DinD lifecycle mutex is poisoned during global destruction",
            )
        })?;
        for lane in state.lanes.values() {
            if let Some(handle) = &lane.active {
                generations.insert((
                    handle.owner_namespace.clone(),
                    handle.generation.clone(),
                ));
            }
        }
        drop(state);
        let mut failures = Vec::new();
        for (owner, generation) in generations {
            if let Err(error) =
                self.fail_lane(&owner, &generation, reason_sha256)
            {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ControllerError::InvalidOwned(format!(
                "global DinD destruction attempted every lane but failed: {}",
                failures.join("; "),
            )))
        }
    }

    fn start_generation_or_terminal(
        &self,
        owner_namespace: &str,
        generation: &str,
        phase: DindLanePhaseV11,
        deadline_boottime_ns: u64,
    ) -> Result<DindHandleV11> {
        match self.start_generation(
            owner_namespace,
            generation,
            phase,
            deadline_boottime_ns,
        ) {
            Ok(handle) => Ok(handle),
            Err(error) => {
                let reason = sha256(error.to_string().as_bytes());
                let marker_result = self.ledger.begin_destroying_generation(
                    owner_namespace,
                    generation,
                    reason,
                );
                let cleanup_result = self.cleanup_recorded_generation(
                    owner_namespace,
                    generation,
                    cleanup_deadline().unwrap_or(deadline_boottime_ns),
                );
                if marker_result.is_ok() && cleanup_result.is_ok() {
                    let _ = self.ledger.mark_generation_destroyed(
                        owner_namespace,
                        generation,
                    );
                }
                Err(error)
            }
        }
    }

    fn start_generation(
        &self,
        owner_namespace: &str,
        generation: &str,
        phase: DindLanePhaseV11,
        deadline_boottime_ns: u64,
    ) -> Result<DindHandleV11> {
        require_component(owner_namespace)?;
        require_component(generation)?;
        if boottime_now_ns_v11()? >= deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "DinD generation deadline expired before start",
            ));
        }
        verify_pinned_file(
            &self.config.dockerd_path,
            self.config.dockerd_sha256,
        )?;
        let generation_root = self
            .config
            .state_root
            .join(owner_namespace)
            .join(generation);
        let data_root = generation_root.join("data");
        let exec_root = generation_root.join("exec");
        let log_root = generation_root.join("logs");
        for path in [&generation_root, &data_root, &exec_root, &log_root] {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o700),
            )?;
            require_private_root(path)?;
        }
        let socket = self
            .config
            .private_socket_root
            .join(format!("{owner_namespace}--{generation}.sock"));
        require_socket_absent(&socket)?;
        let cgroup = self
            .config
            .cgroup_root
            .join(format!("{owner_namespace}--{generation}"));
        create_cgroup(&cgroup)?;
        let pidfile = generation_root.join("dockerd.pid");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log_root.join("dockerd.log"))?;
        let error_log = log.try_clone()?;
        let host = format!("unix://{}", socket.display());
        let mut child = Command::new(&self.config.dockerd_path)
            .arg("--host")
            .arg(&host)
            .arg("--data-root")
            .arg(&data_root)
            .arg("--exec-root")
            .arg(&exec_root)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--live-restore=false")
            .arg("--userland-proxy=false")
            .arg("--log-driver=local")
            .arg("--label")
            .arg(format!(
                "com.serverware.controller.owner-namespace={owner_namespace}"
            ))
            .arg("--label")
            .arg(format!(
                "com.serverware.controller.daemon-generation={generation}"
            ))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log))
            .spawn()?;
        let pid = child.id() as libc::pid_t;
        let initialized: Result<(OwnedFd, u64)> = (|| {
            attach_cgroup(&cgroup, pid)?;
            let pidfd_raw = unsafe {
                libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd
            };
            if pidfd_raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
            let start_time_ticks = process_start_time(pid)?;
            write_pid_record(
                &generation_root.join("ownership.record"),
                pid,
                start_time_ticks,
                owner_namespace,
                generation,
                &socket,
                &cgroup,
            )?;
            let start_deadline = deadline_boottime_ns.min(
                boottime_now_ns_v11()?
                    .saturating_add(DIND_START_TIMEOUT_NS_V11),
            );
            loop {
                if let Some(status) = child.try_wait()? {
                    return Err(ControllerError::InvalidOwned(format!(
                        "private DinD exited during startup: {status}",
                    )));
                }
                if docker_ping(&socket, start_deadline).is_ok() {
                    break;
                }
                if boottime_now_ns_v11()? >= start_deadline {
                    return Err(ControllerError::Rejected(
                        "private DinD did not become ready before its deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            std::fs::set_permissions(
                &socket,
                std::fs::Permissions::from_mode(0o600),
            )?;
            Ok((pidfd, start_time_ticks))
        })();
        let (pidfd, start_time_ticks) = match initialized {
            Ok(initialized) => initialized,
            Err(error) => {
                let deadline =
                    cleanup_deadline().unwrap_or(deadline_boottime_ns);
                let _ = kill_cgroup(&cgroup);
                let _ = child.kill();
                let _ = wait_child_deadline(&mut child, deadline);
                let _ = remove_socket_if_owned(&socket);
                let _ =
                    remove_cgroup(&cgroup, deadline);
                let _ = bounded_remove_tree(
                    &self.config.state_root,
                    &generation_root,
                    deadline,
                );
                return Err(error);
            }
        };
        Ok(DindHandleV11 {
            child,
            pidfd,
            pid,
            start_time_ticks,
            generation: generation.to_owned(),
            owner_namespace: owner_namespace.to_owned(),
            socket,
            data_root,
            exec_root,
            cgroup,
            phase,
        })
    }

    fn export_owned_images(
        &self,
        handle: &DindHandleV11,
        capability: &DockerLaneCapabilityV11,
        deadline: u64,
    ) -> Result<BTreeMap<String, Digest>> {
        let output = self.run_control(
            handle,
            &[
                "image",
                "ls",
                "--no-trunc",
                "--digests",
                "--filter",
                &format!(
                    "label=com.serverware.controller.owner-namespace={}",
                    handle.owner_namespace
                ),
                "--filter",
                &format!(
                    "label=com.serverware.controller.daemon-generation={}",
                    handle.generation
                ),
                "--format",
                "{{json .}}",
            ],
            deadline,
            "image-inventory",
        )?;
        let mut images = BTreeMap::new();
        for line in output.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_slice(line).map_err(|_| {
                ControllerError::Invalid(
                    "Docker image inventory is not JSON",
                )
            })?;
            let image_id = value
                .get("ID")
                .and_then(Value::as_str)
                .ok_or(ControllerError::Rejected(
                    "Docker image inventory lacks its content ID",
                ))?;
            if !valid_image_id(image_id)
                || !capability.allowed_image_digests.contains(image_id)
                || images.contains_key(image_id)
            {
                return Err(ControllerError::Rejected(
                    "build produced a duplicate or unsigned image content ID",
                ));
            }
            let inspect = self.run_control(
                handle,
                &["image", "inspect", image_id],
                deadline,
                "image-export-inspect",
            )?;
            verify_owned_image_labels(
                &inspect,
                image_id,
                capability,
            )?;
            let transfer_tag =
                local_transfer_tag("export", handle, image_id)?;
            self.run_control(
                handle,
                &["image", "tag", image_id, transfer_tag.as_str()],
                deadline,
                "image-export-tag",
            )?;
            let temporary = self.config.oci_cas_root.join(format!(
                ".export-{}-{}-{}.tar",
                unsafe { libc::getpid() },
                OCI_TRANSFER_SEQUENCE_V11.fetch_add(1, Ordering::AcqRel),
                images.len(),
            ));
            let mut temporary_cleanup = TemporaryCasFileV11 {
                path: temporary.clone(),
                armed: true,
            };
            let temporary_text =
                temporary.to_str().ok_or(ControllerError::Invalid(
                    "OCI CAS path is not UTF-8",
                ))?;
            let daemon_host =
                format!("unix://{}", handle.socket.display());
            self.run_oci_exporter(
                handle,
                &[
                    "copy",
                    "--src-daemon-host",
                    daemon_host.as_str(),
                    "--all",
                    &format!("docker-daemon:{transfer_tag}"),
                    &format!("oci-archive:{temporary_text}"),
                ],
                deadline,
                "image-export",
                Some(capability.limits.max_stream_bytes),
            )?;
            std::fs::set_permissions(
                &temporary,
                std::fs::Permissions::from_mode(0o600),
            )?;
            let temporary_bytes = temporary.metadata()?.len();
            if temporary_bytes == 0
                || temporary_bytes > capability.limits.max_stream_bytes
            {
                return Err(ControllerError::Rejected(
                    "OCI archive is empty or exceeds the signed byte bound",
                ));
            }
            let digest = digest_file(&temporary)?;
            let final_path = self
                .config
                .oci_cas_root
                .join(format!("{}.oci.tar", digest_hex(&digest)));
            publish_cas_file(&temporary, &final_path, digest)?;
            temporary_cleanup.armed = false;
            images.insert(image_id.to_owned(), digest);
        }
        if images.len() != capability.allowed_image_digests.len() {
            return Err(ControllerError::Rejected(
                "build image inventory differs from the complete signed result set",
            ));
        }
        Ok(images)
    }

    fn import_sealed_images(
        &self,
        handle: &mut DindHandleV11,
        images: &BTreeMap<String, Digest>,
        deadline: u64,
    ) -> Result<()> {
        if handle.phase != DindLanePhaseV11::NoBuild {
            return Err(ControllerError::Rejected(
                "OCI CAS import requires a fresh no-build DinD",
            ));
        }
        for (image_id, digest) in images {
            let path = self
                .config
                .oci_cas_root
                .join(format!("{}.oci.tar", digest_hex(digest)));
            verify_pinned_file(&path, *digest)?;
            let path = path.to_str().ok_or(ControllerError::Invalid(
                "OCI CAS path is not UTF-8",
            ))?;
            let daemon_host =
                format!("unix://{}", handle.socket.display());
            let transfer_tag =
                local_transfer_tag("sealed", handle, image_id)?;
            self.run_oci_exporter(
                handle,
                &[
                    "copy",
                    "--dest-daemon-host",
                    daemon_host.as_str(),
                    "--all",
                    &format!("oci-archive:{path}"),
                    &format!("docker-daemon:{transfer_tag}"),
                ],
                deadline,
                "image-import",
                None,
            )?;
            let inspect = self.run_control(
                handle,
                &["image", "inspect", transfer_tag.as_str()],
                deadline,
                "image-import-verify",
            )?;
            let value: Value =
                serde_json::from_slice(&inspect).map_err(|_| {
                    ControllerError::Invalid(
                        "imported image inspect output is not JSON",
                    )
                })?;
            let imported_id = value
                .as_array()
                .and_then(|values| {
                    (values.len() == 1).then(|| &values[0])
                })
                .and_then(|image| image.get("Id"))
                .and_then(Value::as_str)
                .ok_or(ControllerError::Rejected(
                    "imported image lacks one content ID",
                ))?;
            if imported_id != image_id {
                return Err(ControllerError::Rejected(
                    "imported image content ID differs from the signed seal",
                ));
            }
        }
        Ok(())
    }

    fn run_control(
        &self,
        handle: &DindHandleV11,
        arguments: &[&str],
        deadline: u64,
        label: &str,
    ) -> Result<Vec<u8>> {
        if process_start_time(handle.pid)? != handle.start_time_ticks
            || boottime_now_ns_v11()? >= deadline
        {
            return Err(ControllerError::Rejected(
                "DinD control lost daemon identity or deadline",
            ));
        }
        verify_pinned_file(
            &self.config.docker_path,
            self.config.docker_sha256,
        )?;
        let output_path = self
            .config
            .state_root
            .join(&handle.owner_namespace)
            .join(&handle.generation)
            .join("logs")
            .join(format!(
                "{}-{}.log",
                safe_label(label),
                boottime_now_ns_v11()?
            ));
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)?;
        let error = output.try_clone()?;
        let mut child = Command::new(&self.config.docker_path)
            .arg("--host")
            .arg(format!("unix://{}", handle.socket.display()))
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(error))
            .spawn()?;
        let status = wait_child_deadline(&mut child, deadline)?;
        if !status.success() {
            return Err(ControllerError::InvalidOwned(format!(
                "private Docker control operation {label} failed: {status}",
            )));
        }
        let length = output.metadata()?.len();
        if length > DIND_COMMAND_OUTPUT_MAX_BYTES_V11 {
            return Err(ControllerError::Rejected(
                "private Docker control output exceeded its bound",
            ));
        }
        let mut output = output;
        output.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        output.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn run_oci_exporter(
        &self,
        handle: &DindHandleV11,
        arguments: &[&str],
        deadline: u64,
        label: &str,
        file_size_limit: Option<u64>,
    ) -> Result<Vec<u8>> {
        if process_start_time(handle.pid)? != handle.start_time_ticks
            || boottime_now_ns_v11()? >= deadline
        {
            return Err(ControllerError::Rejected(
                "OCI transfer lost daemon identity or deadline",
            ));
        }
        verify_pinned_file(
            &self.config.oci_exporter_path,
            self.config.oci_exporter_sha256,
        )?;
        let output_path = self
            .config
            .state_root
            .join(&handle.owner_namespace)
            .join(&handle.generation)
            .join("logs")
            .join(format!(
                "{}-{}.log",
                safe_label(label),
                boottime_now_ns_v11()?
            ));
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)?;
        let error = output.try_clone()?;
        let mut command = Command::new(&self.config.oci_exporter_path);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", "/nonexistent")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(error));
        if let Some(limit) = file_size_limit {
            unsafe {
                command.pre_exec(move || {
                    let limit = libc::rlimit {
                        rlim_cur: limit as libc::rlim_t,
                        rlim_max: limit as libc::rlim_t,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn()?;
        let status = wait_child_deadline(&mut child, deadline)?;
        if !status.success() {
            return Err(ControllerError::InvalidOwned(format!(
                "private OCI transfer {label} failed: {status}",
            )));
        }
        let length = output.metadata()?.len();
        if length > DIND_COMMAND_OUTPUT_MAX_BYTES_V11 {
            return Err(ControllerError::Rejected(
                "private OCI transfer output exceeded its bound",
            ));
        }
        let mut output = output;
        output.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        output.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn destroy_handle(
        &self,
        handle: &mut DindHandleV11,
        deadline: u64,
    ) -> Result<()> {
        handle.phase = DindLanePhaseV11::Destroying;
        kill_cgroup(&handle.cgroup)?;
        wait_pidfd(handle.pidfd.as_raw_fd(), deadline)?;
        let _ = handle.child.try_wait()?;
        remove_socket_if_owned(&handle.socket)?;
        bounded_remove_tree(
            &self.config.state_root,
            &handle.data_root,
            deadline,
        )?;
        bounded_remove_tree(
            &self.config.state_root,
            &handle.exec_root,
            deadline,
        )?;
        remove_cgroup(&handle.cgroup, deadline)?;
        if process_start_time(handle.pid).is_ok()
            || handle.socket.exists()
            || handle.cgroup.exists()
        {
            return Err(ControllerError::Rejected(
                "DinD authoritative cleanup is incomplete",
            ));
        }
        handle.phase = DindLanePhaseV11::Terminal;
        Ok(())
    }

    fn cleanup_recorded_generation(
        &self,
        owner_namespace: &str,
        generation: &str,
        deadline: u64,
    ) -> Result<()> {
        require_component(owner_namespace)?;
        require_component(generation)?;
        let root = self
            .config
            .state_root
            .join(owner_namespace)
            .join(generation);
        let expected_socket = self
            .config
            .private_socket_root
            .join(format!("{owner_namespace}--{generation}.sock"));
        let expected_cgroup = self
            .config
            .cgroup_root
            .join(format!("{owner_namespace}--{generation}"));
        let record = root.join("ownership.record");
        let mut current_boot_record = false;
        if record.exists() {
            let parsed = read_pid_record(&record)?;
            if parsed.owner_namespace != owner_namespace
                || parsed.generation != generation
                || parsed.socket != expected_socket
                || parsed.cgroup != expected_cgroup
            {
                return Err(ControllerError::Rejected(
                    "stale DinD record differs from its generation path",
                ));
            }
            current_boot_record = parsed.boot_id == current_boot_id()?;
            if current_boot_record
                && process_start_time(parsed.pid).ok()
                    == Some(parsed.start_time_ticks)
            {
                kill_cgroup(&expected_cgroup)?;
                let raw = unsafe {
                    libc::syscall(libc::SYS_pidfd_open, parsed.pid, 0)
                        as RawFd
                };
                if raw >= 0 {
                    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        );
                    }
                    wait_pidfd(pidfd.as_raw_fd(), deadline)?;
                }
            } else if !current_boot_record && expected_cgroup.exists() {
                return Err(ControllerError::Rejected(
                    "prior-boot ownership record collides with a live cgroup",
                ));
            }
        }
        if !record.exists() || current_boot_record {
            kill_cgroup(&expected_cgroup)?;
        }
        remove_socket_if_owned(&expected_socket)?;
        remove_cgroup(&expected_cgroup, deadline)?;
        if root.exists() {
            bounded_remove_tree(
                &self.config.state_root,
                &root,
                deadline,
            )?;
        }
        Ok(())
    }

    fn recorded_generations(
        &self,
    ) -> Result<BTreeSet<(String, String)>> {
        let mut generations = BTreeSet::new();
        let mut examined = 0usize;
        for owner in std::fs::read_dir(&self.config.state_root)? {
            examined = examined.saturating_add(1);
            if examined > DIND_MAX_RECONCILED_GENERATIONS_V12 {
                return Err(ControllerError::Rejected(
                    "DinD owner enumeration exceeds startup bound",
                ));
            }
            let owner = owner?;
            let owner_path = owner.path();
            let owner_metadata = std::fs::symlink_metadata(&owner_path)?;
            if !owner_metadata.is_dir()
                || owner_metadata.file_type().is_symlink()
                || owner_metadata.uid() != 0
                || owner_metadata.mode() & 0o077 != 0
            {
                return Err(ControllerError::Rejected(
                    "DinD state root contains a foreign owner entry",
                ));
            }
            let owner_name = owner
                .file_name()
                .into_string()
                .map_err(|_| {
                    ControllerError::Invalid(
                        "DinD owner directory is not UTF-8",
                    )
                })?;
            require_component(&owner_name)?;
            for generation in std::fs::read_dir(&owner_path)? {
                examined = examined.saturating_add(1);
                if examined > DIND_MAX_RECONCILED_GENERATIONS_V12 {
                    return Err(ControllerError::Rejected(
                        "DinD generation enumeration exceeds startup bound",
                    ));
                }
                let generation = generation?;
                let generation_path = generation.path();
                let metadata =
                    std::fs::symlink_metadata(&generation_path)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(ControllerError::Rejected(
                        "DinD owner state contains a foreign generation entry",
                    ));
                }
                let generation_name = generation
                    .file_name()
                    .into_string()
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "DinD generation directory is not UTF-8",
                        )
                    })?;
                require_component(&generation_name)?;
                generations
                    .insert((owner_name.clone(), generation_name));
            }
        }
        Ok(generations)
    }
}

const PRIVATE_DIND_START_TIMEOUT_NS_V12: u64 = 120 * 1_000_000_000;
const PRIVATE_DIND_MAX_HTTP_BYTES_V12: u64 = 512 * 1024 * 1024;
const PRIVATE_DIND_MAX_GENERATIONS_V12: usize = 64;
const PRIVATE_DIND_MAX_TAR_ENTRIES_V12: usize = 1_000_000;
const PRIVATE_DIND_MAX_JSON_MESSAGES_V12: u64 = 1_000_000;
const PRIVATE_DIND_MAX_JSON_MESSAGE_BYTES_V12: u64 = 4 * 1024 * 1024;
const PRIVATE_DIND_ARTIFACT_METADATA_V12: &str =
    ".serverware-artifact-cas-v12.json";
const PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12: &str =
    "serverware/docker-image-archive-set/v12";
const PRIVATE_DIND_SOURCE_METADATA_V12: &str =
    ".serverware-source-cas-v12.json";
const PRIVATE_DIND_BODY_RESULT_V12: &str =
    ".serverware-controller-plan-executor-result-v12.json";

#[derive(Clone)]
pub struct PrivateDindConfigV12 {
    pub state_root: PathBuf,
    pub lane_ledger_root: PathBuf,
    pub network_ownership_ledger: PathBuf,
    pub terminal_receipt_root: PathBuf,
    pub dind_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub private_socket_root: PathBuf,
    pub private_mount_root: PathBuf,
    pub netns_root: PathBuf,
    pub netns_prefix: String,
    pub network_hook: PathBuf,
    pub network_hook_sha256: Digest,
    pub host_ruleset: PathBuf,
    pub host_cleanup_ruleset: PathBuf,
    pub build_lane_ruleset: PathBuf,
    pub no_build_lane_ruleset: PathBuf,
    pub lane_cleanup_ruleset: PathBuf,
    pub dockerd_binary: PathBuf,
    pub dockerd_sha256: Digest,
    pub containerd_binary: PathBuf,
    pub containerd_sha256: Digest,
    pub containerd_shim_binary: PathBuf,
    pub containerd_shim_sha256: Digest,
    pub runc_binary: PathBuf,
    pub runc_sha256: Digest,
    pub readiness_fixture_key_id: String,
    pub readiness_fixture_public_key: [u8; 32],
    pub readiness_fixture_assets_sha256: Digest,
    pub readiness_fixture_root: PathBuf,
    pub readiness_docker_client_stream: PathBuf,
    pub readiness_docker_client_stream_sha256: Digest,
    pub readiness_docker_server_stream: PathBuf,
    pub readiness_docker_server_stream_sha256: Digest,
    pub readiness_service_image_archive: PathBuf,
    pub readiness_service_image_archive_sha256: Digest,
    pub readiness_service_probe: PathBuf,
    pub readiness_service_probe_sha256: Digest,
    pub readiness_browser_image_archive: PathBuf,
    pub readiness_browser_image_archive_sha256: Digest,
    pub readiness_chromium_page: PathBuf,
    pub readiness_chromium_page_sha256: Digest,
    pub readiness_chromium_script: PathBuf,
    pub readiness_chromium_script_sha256: Digest,
    pub readiness_chromium_probe: PathBuf,
    pub readiness_chromium_probe_sha256: Digest,
    pub readiness_chromium_expected_cdp: PathBuf,
    pub readiness_chromium_expected_cdp_sha256: Digest,
    pub readiness_chromium_expected_dom: PathBuf,
    pub readiness_chromium_expected_dom_sha256: Digest,
    pub readiness_chromium_expected_js: PathBuf,
    pub readiness_chromium_expected_js_sha256: Digest,
    pub readiness_chromium_expected_fetch: PathBuf,
    pub readiness_chromium_expected_fetch_sha256: Digest,
    pub readiness_teardown_fixture: PathBuf,
    pub readiness_teardown_fixture_sha256: Digest,
    pub root_signer_spki_sha256: Digest,
}

struct PrivateDindHandleV12 {
    child: Child,
    pidfd: OwnedFd,
    pid: libc::pid_t,
    start_time_ticks: u64,
    profile: PrivateDindProfileV12,
    owner_namespace: String,
    daemon_generation: String,
    lane_slot: u8,
    netns_name: String,
    generation_root: PathBuf,
    data_root: PathBuf,
    exec_root: PathBuf,
    socket: PathBuf,
    cgroup: PathBuf,
    source_mount: PathBuf,
    artifact_mount: Option<PathBuf>,
    output_mount: PathBuf,
    runners: BTreeMap<LogicalLane, PrivateRunnerV12>,
    service_ids: BTreeMap<LogicalLane, Vec<String>>,
}

#[derive(Clone)]
struct PrivateRunnerV12 {
    id: String,
    identity: RunnerIdentity,
    expected_create: Value,
    command_sha256: Digest,
    output_mount: PathBuf,
    output_identity_sha256: Digest,
    output_storage: RunnerOutputStorageV12,
    output_storage_identity_sha256: Digest,
    uid: u32,
    gid: u32,
    created_inspect_sha256: Option<Digest>,
    prestart_inspect_sha256: Option<Digest>,
}

struct PrivateDindStateV12 {
    active: BTreeMap<String, PrivateDindHandleV12>,
}

struct AuthoritativeReplayV12 {
    state: AuthoritativeLaneState,
    result: Vec<u8>,
    returned_fd_roles: Vec<String>,
    observed_state_sha256: Digest,
    terminal_destruction_receipt: Option<Vec<u8>>,
    returned_fds: Vec<OwnedFd>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RootTerminalDestructionReceiptV12 {
    pub version: String,
    pub trust_profile: String,
    pub plan_id: Digest,
    pub capability_sha256: Digest,
    pub profile: PrivateDindProfileV12,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub network_namespace: String,
    pub request_sha256: Digest,
    pub observed_at_boottime_ns: u64,
    pub docker_top_level_object_count_scope: String,
    pub docker_internal_storage_absence_proof: String,
    pub drained_containers: u64,
    pub drained_images: u64,
    pub drained_networks: u64,
    pub drained_volumes: u64,
    pub containers: u64,
    pub images: u64,
    pub networks: u64,
    pub volumes: u64,
    pub docker_authority_established: bool,
    pub mounts: u64,
    pub cgroup_processes: u64,
    pub proxy_accepting: bool,
    pub ledger_terminal: bool,
    pub dind_reaped: bool,
    pub netns_absent: bool,
    pub socket_absent: bool,
    pub state_root_absent: bool,
    pub observed_state_sha256: Digest,
    pub signer_spki_sha256: Digest,
    pub signer_public_key_spki_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub receipt_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DockerResourceInventoryV12 {
    containers: u64,
    images: u64,
    networks: u64,
    volumes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DockerResourceDrainV12 {
    drained: DockerResourceInventoryV12,
    terminal: DockerResourceInventoryV12,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DockerOwnedObjectsV12 {
    containers: Vec<String>,
    images: Vec<String>,
    networks: Vec<String>,
    volumes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReadinessContainerProbeContractV12 {
    version: String,
    image_reference: String,
    command: Vec<String>,
    user: String,
    result_relative_path: String,
    fixture_mount: String,
    output_mount: String,
    network_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReadinessTeardownContractV12 {
    version: String,
    docker_top_level_object_count_scope: String,
    docker_internal_storage_absence_proof: String,
    require_exact_signed_fixture: bool,
    require_durable_terminal_receipt: bool,
    require_docker_authority_established: bool,
    require_zero_containers: bool,
    require_zero_images: bool,
    require_zero_networks: bool,
    require_zero_volumes: bool,
    require_zero_mounts: bool,
    require_zero_cgroup_processes: bool,
    require_state_root_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SealedDockerArchiveEntryV12 {
    reference: OciObjectReference,
    archive_relative_path: String,
    archive_bytes: u64,
    archive_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SealedDockerArtifactClosureV12 {
    version: String,
    source_manifest_sha256: Digest,
    build_plan_sha256: Digest,
    files_sha256: Digest,
    archives: Vec<SealedDockerArchiveEntryV12>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SealedDockerArtifactManifestV12 {
    version: String,
    format: String,
    artifact_object_sha256: Digest,
    artifact_manifest_sha256: Digest,
    closure_sha256: Digest,
    source_manifest_sha256: Digest,
    build_plan_sha256: Digest,
    files_sha256: Digest,
    archives: Vec<SealedDockerArchiveEntryV12>,
}

#[derive(Clone, Debug)]
pub struct ScopedTerminalDestructionV12 {
    pub plan_id: Digest,
    pub observed_terminal_sha256: Digest,
    pub exact_terminal_receipts: Vec<Vec<u8>>,
}

pub struct PrivateDindLifecycleV12 {
    config: PrivateDindConfigV12,
    ledger: DockerLaneLedgerV12,
    signing_key: SigningKey,
    state: Mutex<PrivateDindStateV12>,
    operation_gate: RwLock<()>,
}

impl PrivateDindLifecycleV12 {
    pub fn open(
        config: PrivateDindConfigV12,
        signing_key: SigningKey,
    ) -> Result<Self> {
        validate_private_dind_config_v12(&config)?;
        for root in [
            &config.state_root,
            &config.dind_root,
            &config.private_socket_root,
            &config.private_mount_root,
            &config.terminal_receipt_root,
        ] {
            std::fs::create_dir_all(root)?;
            std::fs::set_permissions(
                root,
                std::fs::Permissions::from_mode(0o700),
            )?;
            require_private_root(root)?;
        }
        let public_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| {
                ControllerError::Invalid(
                    "private DinD signer public key cannot be encoded",
                )
            })?;
        if sha256(public_der.as_bytes())
            != config.root_signer_spki_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD signer differs from release-manifest pin",
            ));
        }
        let ledger =
            DockerLaneLedgerV12::open_without_legacy_lease(
                &config.lane_ledger_root,
            )?;
        let lifecycle = Self {
            config,
            ledger,
            signing_key,
            state: Mutex::new(PrivateDindStateV12 {
                active: BTreeMap::new(),
            }),
            operation_gate: RwLock::new(()),
        };
        Ok(lifecycle)
    }

    pub fn setup_host_network(&self) -> Result<()> {
        let deadline = boottime_now_ns_v11()?
            .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
            .ok_or(ControllerError::Invalid(
                "private DinD host setup deadline overflowed",
            ))?;
        let host_ruleset = path_text_v12(&self.config.host_ruleset)?;
        let ownership_ledger =
            path_text_v12(&self.config.network_ownership_ledger)?;
        self.run_network_hook_v12(
            &[
                "setup-host",
                host_ruleset.as_str(),
                ownership_ledger.as_str(),
            ],
            deadline,
        )?;
        Ok(())
    }

    pub fn startup_reconcile_all_nonterminal(&self) -> Result<()> {
        let records = self.ledger.nonterminal_generations()?;
        if records.len() > PRIVATE_DIND_MAX_GENERATIONS_V12 {
            return Err(ControllerError::Rejected(
                "private DinD startup generation bound exceeded",
            ));
        }
        let deadline = boottime_now_ns_v11()?
            .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
            .ok_or(ControllerError::Invalid(
                "private DinD startup cleanup deadline overflowed",
            ))?;
        for record in records {
            self.destroy_generation_record_v12(
                &record,
                record.last_request_sha256,
                deadline,
            )?;
        }
        self.reject_unledgered_generation_roots_v12()?;
        Ok(())
    }

    pub fn destroy_nonterminal_for_plan(
        &self,
        plan_id: Digest,
        request_sha256_canonical: Digest,
        cleanup_deadline_boottime_ns: u64,
    ) -> Result<ScopedTerminalDestructionV12> {
        let _operation_guard =
            self.operation_gate.write().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD plan operation gate is poisoned",
                )
            })?;
        if plan_id == [0; 32] {
            return Err(ControllerError::Rejected(
                "private DinD scoped cleanup plan digest is absent",
            ));
        }
        if cleanup_deadline_boottime_ns <= boottime_now_ns_v11()? {
            return Err(ControllerError::Rejected(
                "private DinD scoped cleanup deadline expired",
            ));
        }
        self.ledger.begin_plan_cleanup(
            plan_id,
            request_sha256_canonical,
        )?;
        let records = self.ledger.generations_for_plan(plan_id)?;
        if records.len() > PRIVATE_DIND_MAX_GENERATIONS_V12 {
            return Err(ControllerError::Rejected(
                "private DinD scoped cleanup generation bound exceeded",
            ));
        }
        let deadline = cleanup_deadline_boottime_ns.min(
            boottime_now_ns_v11()?
                .saturating_add(DIND_CLEANUP_TIMEOUT_NS_V11),
        );
        for record in records {
            if record.status != DockerLaneOperationStatusV12::Destroyed
                || record.state != AuthoritativeLaneState::Destroyed
                || record.terminal_receipt_sha256.is_none()
            {
                self.destroy_generation_record_v12(
                    &record,
                    request_sha256_canonical,
                    deadline,
                )?;
            }
        }
        let terminal_records =
            self.ledger.generations_for_plan(plan_id)?;
        if terminal_records.len() > PRIVATE_DIND_MAX_GENERATIONS_V12 {
            return Err(ControllerError::Rejected(
                "private DinD terminal cleanup generation bound exceeded",
            ));
        }
        let mut exact_terminal_receipts =
            Vec::with_capacity(terminal_records.len());
        let mut aggregate =
            Vec::with_capacity(terminal_records.len());
        for record in terminal_records {
            let (terminal, exact_receipt) =
                self.terminal_receipt_for_generation_v12(
                    &record.owner_namespace,
                    &record.daemon_generation,
                )?;
            if terminal.plan_id != plan_id {
                return Err(ControllerError::Rejected(
                    "private DinD scoped cleanup crossed plan authority",
                ));
            }
            self.verify_terminal_receipt_v12(
                &terminal,
                &exact_receipt,
            )?;
            aggregate.push(json!({
                "capabilitySha256": terminal.capability_sha256,
                "daemonGeneration": terminal.daemon_generation,
                "exactReceiptBytes": exact_receipt.len(),
                "networkNamespace": terminal.network_namespace,
                "observedStateSha256": terminal.observed_state_sha256,
                "ownerNamespace": terminal.owner_namespace,
                "profile": terminal.profile,
                "receiptSha256": sha256(&exact_receipt),
            }));
            exact_terminal_receipts.push(exact_receipt);
        }
        let observed_terminal_sha256 = sha256(
            &canonical_plan_bytes(&json!({
                "planId": plan_id,
                "receipts": aggregate,
                "version": "serverware/private-dind-scoped-terminal/v12",
            }))
            .map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        self.ledger.commit_plan_cleanup(
            plan_id,
            request_sha256_canonical,
            observed_terminal_sha256,
        )?;
        Ok(ScopedTerminalDestructionV12 {
            plan_id,
            observed_terminal_sha256,
            exact_terminal_receipts,
        })
    }

    pub fn shutdown_destroy_all_owned(&self) -> Result<()> {
        self.startup_reconcile_all_nonterminal()?;
        if !self.ledger.nonterminal_generations()?.is_empty() {
            return Err(ControllerError::Rejected(
                "private DinD shutdown retained nonterminal generations",
            ));
        }
        let deadline = boottime_now_ns_v11()?
            .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
            .ok_or(ControllerError::Invalid(
                "private DinD host cleanup deadline overflowed",
            ))?;
        let host_cleanup =
            path_text_v12(&self.config.host_cleanup_ruleset)?;
        let lane_cleanup =
            path_text_v12(&self.config.lane_cleanup_ruleset)?;
        let ownership_ledger =
            path_text_v12(&self.config.network_ownership_ledger)?;
        self.run_network_hook_v12(
            &[
                "cleanup-host",
                host_cleanup.as_str(),
                lane_cleanup.as_str(),
                ownership_ledger.as_str(),
            ],
            deadline,
        )?;
        Ok(())
    }

    pub fn terminal_observation_sha256(&self) -> Result<Digest> {
        if !self.ledger.nonterminal_generations()?.is_empty() {
            return Err(ControllerError::Rejected(
                "private DinD terminal observation retained nonterminal generations",
            ));
        }
        self.reject_unledgered_generation_roots_v12()?;
        self.ledger.terminal_observation_sha256()
    }

    pub fn execute_lane_request(
        &self,
        lifecycle_request: &PrivateDindOperationRequestV12,
        attached_fds: Vec<OwnedFd>,
    ) -> Result<(PrivateDindOperationResponseV12, Vec<OwnedFd>)> {
        let _operation_guard =
            self.operation_gate.read().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD plan operation gate is poisoned",
                )
            })?;
        lifecycle_request.validate()?;
        if lifecycle_request.attached_fd_roles.len()
            != attached_fds.len()
        {
            return Err(ControllerError::Rejected(
                "private DinD lifecycle descriptor count changed in transit",
            ));
        }
        let operation = DockerLaneOperationV12::from_proxy_request(
            lifecycle_request.proxy_request.clone(),
            attached_fds.len(),
        )?;
        let policy = authorize_lane_operation_v12(&operation)?;
        match self.ledger.begin_operation(
            lifecycle_request.request_sha256,
            &operation,
        )? {
            BeginLaneOperationV12::ExactReplay {
                response,
                ..
            } => {
                let returned = self.recreate_replay_fds_v12(
                    &operation,
                    &response,
                )?;
                Ok((response, returned))
            }
            BeginLaneOperationV12::RequiresReconciliation(record) => {
                self.reconcile_uncertain_operation_v12(
                    lifecycle_request,
                    &operation,
                    &policy,
                    record,
                )
            }
            BeginLaneOperationV12::Prepared(prepared) => {
                self.execute_prepared_operation_v12(
                    lifecycle_request,
                    operation,
                    policy,
                    prepared,
                    attached_fds,
                )
            }
        }
    }

    fn execute_prepared_operation_v12(
        &self,
        lifecycle_request: &PrivateDindOperationRequestV12,
        operation: DockerLaneOperationV12,
        policy: DockerLanePolicyDecisionV12,
        prepared: DockerLaneOperationRecordV12,
        attached_fds: Vec<OwnedFd>,
    ) -> Result<(PrivateDindOperationResponseV12, Vec<OwnedFd>)> {
        if operation.request.operation
            == ProxyOperation::QueryAuthoritativeState
        {
            if !attached_fds.is_empty() {
                return Err(ControllerError::Rejected(
                    "private DinD authoritative query carried descriptors",
                ));
            }
            let replay =
                self.query_authoritative_response_v12(&operation)?;
            let mut response = PrivateDindOperationResponseV12::seal(
                lifecycle_request,
                PrivateDindOperationDispositionV12::AlreadyApplied,
                replay.state,
                replay.result,
                replay.returned_fd_roles,
                replay.observed_state_sha256,
            )?;
            if let Some(receipt) =
                replay.terminal_destruction_receipt
            {
                response = response
                    .with_terminal_destruction_receipt(receipt)?;
            }
            let response =
                response.sign(lifecycle_request, &self.signing_key)?;
            self.ledger.commit_operation(prepared, &response)?;
            return Ok((response, replay.returned_fds));
        }
        let result = self.apply_operation_v12(
            &operation,
            &policy,
            attached_fds,
        );
        match result {
            Ok((mut result, returned_fds, observed_state_sha256)) => {
                let state = self.ledger.authoritative_state_after(
                    &prepared,
                    policy.authoritative_state,
                )?;
                if operation.request.operation
                    == ProxyOperation::ImportSealedOci
                {
                    result = applied_result_v12(
                        &operation,
                        state,
                        observed_state_sha256,
                    )?;
                }
                let returned_fd_roles = if returned_fds.is_empty() {
                    Vec::new()
                } else {
                    vec!["artifactCasDirectory".to_owned()]
                };
                if returned_fds.len() != policy.returned_fd_count {
                    return Err(ControllerError::Rejected(
                        "private DinD operation returned a noncanonical descriptor set",
                    ));
                }
                let mut response = PrivateDindOperationResponseV12::seal(
                    lifecycle_request,
                    PrivateDindOperationDispositionV12::Applied,
                    state,
                    result,
                    returned_fd_roles,
                    observed_state_sha256,
                )?;
                if state == AuthoritativeLaneState::Destroyed {
                    response = response.with_terminal_destruction_receipt(
                        self.terminal_receipt_for_operation_v12(
                            &operation,
                        )?,
                    )?;
                }
                let response =
                    response.sign(lifecycle_request, &self.signing_key)?;
                self.ledger
                    .commit_operation(prepared, &response)?;
                Ok((response, returned_fds))
            }
            Err(error) => {
                let uncertainty = sha256(
                    &[
                        b"serverware/private-dind-operation-uncertain/v12\0"
                            .as_slice(),
                        operation.request.request_sha256.as_slice(),
                        error.to_string().as_bytes(),
                    ]
                    .concat(),
                );
                let marked = self
                    .ledger
                    .mark_outcome_unknown(prepared, uncertainty)?;
                let cleanup_deadline = boottime_now_ns_v11()?
                    .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
                    .ok_or(ControllerError::Invalid(
                        "private DinD failure cleanup deadline overflowed",
                    ))?;
                let _ = self.destroy_generation_by_identity_v12(
                    &marked.owner_namespace,
                    &marked.daemon_generation,
                    marked.request_sha256,
                    cleanup_deadline,
                );
                let result = canonical_plan_bytes(&json!({
                    "error": error.to_string(),
                    "operation": format!("{:?}", operation.request.operation),
                    "requestSha256": operation.request.request_sha256,
                    "version": PRIVATE_DIND_RESULT_VERSION_V12,
                }))
                .map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?;
                let response = PrivateDindOperationResponseV12::seal(
                    lifecycle_request,
                    PrivateDindOperationDispositionV12::OutcomeUnknown,
                    AuthoritativeLaneState::OutcomeUnknown,
                    result,
                    Vec::new(),
                    uncertainty,
                )?
                .sign(lifecycle_request, &self.signing_key)?;
                Ok((response, Vec::new()))
            }
        }
    }

    fn apply_operation_v12(
        &self,
        operation: &DockerLaneOperationV12,
        policy: &DockerLanePolicyDecisionV12,
        attached_fds: Vec<OwnedFd>,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>, Digest)> {
        match operation.request.operation {
            ProxyOperation::CreateBuildDind
            | ProxyOperation::CreateNoBuildDind => {
                self.create_generation_v12(operation, attached_fds)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::PullPinned => {
                self.pull_pinned_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::BuildExact => {
                self.build_exact_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::ExportOwnedOci => {
                let (result, fd, observed) =
                    self.export_owned_oci_v12(operation)?;
                Ok((result, vec![fd], observed))
            }
            ProxyOperation::ImportSealedOci => {
                self.import_sealed_oci_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::CreateRunner => {
                self.create_runner_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::CreateServices => {
                self.create_services_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::RunRepositoryBody => {
                let result = self.run_repository_body_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((result, Vec::new(), observed))
            }
            ProxyOperation::StopRunner => {
                self.stop_runner_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::DestroyServices => {
                self.destroy_services_v12(operation)?;
                let observed = self.observe_generation_v12(operation)?;
                Ok((
                    applied_result_v12(
                        operation,
                        policy.authoritative_state,
                        observed,
                    )?,
                    Vec::new(),
                    observed,
                ))
            }
            ProxyOperation::DestroyBuildDind
            | ProxyOperation::DestroyNoBuildDind => {
                if operation.request.operation
                    == ProxyOperation::DestroyNoBuildDind
                {
                    let generations =
                        self.ledger.generations_for_authority(
                            operation.request.plan_id,
                            operation.request.capability_sha256,
                            PrivateDindProfileV12::NoBuild,
                        )?;
                    if generations.is_empty() {
                        return Err(ControllerError::Rejected(
                            "private DinD no-build terminal destroy found no owned generations",
                        ));
                    }
                    for generation in generations {
                        self.destroy_generation_record_v12(
                            &generation,
                            operation.request.request_sha256,
                            operation.request.deadline_boottime_ns,
                        )?;
                    }
                } else {
                    self.destroy_generation_by_identity_v12(
                        &operation.owner_namespace,
                        &operation.daemon_generation,
                        operation.request.request_sha256,
                        operation.request.deadline_boottime_ns,
                    )?;
                }
                let (result, observed) =
                    self.destruction_result_v12(operation)?;
                Ok((result, Vec::new(), observed))
            }
            ProxyOperation::QueryAuthoritativeState => {
                Err(ControllerError::Rejected(
                    "private DinD authoritative query bypassed exact replay path",
                ))
            }
            ProxyOperation::ReadinessDockerUpgrade
            | ProxyOperation::ReadinessService
            | ProxyOperation::ReadinessChromium
            | ProxyOperation::ReadinessTeardown => {
                if !attached_fds.is_empty() {
                    return Err(ControllerError::Rejected(
                        "readiness operation accepted caller-controlled descriptors",
                    ));
                }
                self.execute_readiness_v12(operation)
            }
        }
    }

    fn execute_readiness_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>, Digest)> {
        let request = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Readiness(request) => request,
            _ => {
                return Err(ControllerError::Rejected(
                    "readiness operation lost its signed request",
                ))
            }
        };
        let key = VerifyingKey::from_bytes(
            &self.config.readiness_fixture_public_key,
        )
        .map_err(|_| {
            ControllerError::Rejected(
                "root-pinned readiness public key is invalid",
            )
        })?;
        let trust = ReadinessFixtureTrust {
            key_id: self.config.readiness_fixture_key_id.clone(),
            key,
        };
        request
            .signed_fixture
            .validate(&trust, boottime_now_ns_v11()?)
            .map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        if request.signed_fixture.fixture_assets_sha256
                != self.config.readiness_fixture_assets_sha256
            || request.fixture_id
                != request.signed_fixture.fixture_id
            || request.fixture_sha256
                != request.signed_fixture.fixture_sha256
        {
            return Err(ControllerError::Rejected(
                "readiness request differs from root-pinned fixture assets",
            ));
        }
        let result = match request.probe {
            ReadinessProbe::DockerUpgrade => {
                if !matches!(
                    operation.request.operation,
                    ProxyOperation::ReadinessDockerUpgrade
                ) {
                    return Err(ControllerError::Rejected(
                        "Docker upgrade readiness operation is mismatched",
                    ));
                }
                self.create_generation_v12(
                    operation,
                    Vec::new(),
                )?;
                ReadinessProbeResultV12::DockerUpgrade(
                    self.run_readiness_duplex_v12(operation)?,
                )
            }
            ReadinessProbe::ServiceHealth => {
                ReadinessProbeResultV12::ServiceHealth(
                    self.run_readiness_service_v12(operation)?,
                )
            }
            ReadinessProbe::Chromium => {
                ReadinessProbeResultV12::Chromium(
                    self.run_readiness_chromium_v12(operation)?,
                )
            }
            ReadinessProbe::Teardown => {
                self.validate_readiness_teardown_contract_v12()?;
                let generation = self
                    .ledger
                    .generation(
                        &operation.owner_namespace,
                        &operation.daemon_generation,
                    )?
                    .ok_or(ControllerError::Rejected(
                        "readiness teardown generation is absent",
                    ))?;
                self.destroy_generation_record_v12(
                    &generation,
                    operation.request.request_sha256,
                    operation.request.deadline_boottime_ns,
                )?;
                let (receipt, exact_receipt) =
                    self.terminal_receipt_for_generation_v12(
                        &operation.owner_namespace,
                        &operation.daemon_generation,
                    )?;
                let fixture =
                    &request.signed_fixture.teardown;
                if fixture.owner_namespace_sha256
                        != sha256(
                            operation.owner_namespace.as_bytes(),
                        )
                    || receipt.containers != 0
                    || receipt.images != 0
                    || receipt.networks != 0
                    || receipt.volumes != 0
                    || receipt.docker_top_level_object_count_scope
                        != fixture.docker_top_level_object_count_scope
                    || receipt.docker_internal_storage_absence_proof
                        != fixture.docker_internal_storage_absence_proof
                    || !receipt.docker_authority_established
                    || receipt.mounts != 0
                    || receipt.cgroup_processes != 0
                    || !receipt.ledger_terminal
                    || !receipt.dind_reaped
                    || !receipt.state_root_absent
                    || exact_receipt.is_empty()
                {
                    return Err(ControllerError::Rejected(
                        "readiness teardown differs from its signed fixture or durable receipt",
                    ));
                }
                ReadinessProbeResultV12::Teardown(
                    TeardownResultV12 {
                        owner_namespace_sha256: sha256(
                            operation.owner_namespace.as_bytes(),
                        ),
                        docker_top_level_object_count_scope:
                            receipt
                                .docker_top_level_object_count_scope
                                .clone(),
                        docker_internal_storage_absence_proof:
                            receipt
                                .docker_internal_storage_absence_proof
                                .clone(),
                        drained_containers:
                            receipt.drained_containers,
                        drained_images: receipt.drained_images,
                        drained_networks:
                            receipt.drained_networks,
                        drained_volumes: receipt.drained_volumes,
                        containers: receipt.containers,
                        images: receipt.images,
                        networks: receipt.networks,
                        volumes: receipt.volumes,
                        docker_authority_established:
                            receipt.docker_authority_established,
                        mounts: receipt.mounts,
                        cgroup_processes: receipt.cgroup_processes,
                        ledger_terminal: receipt.ledger_terminal,
                        dind_reaped: receipt.dind_reaped,
                        state_root_absent:
                            receipt.state_root_absent,
                        terminal_receipt_sha256:
                            sha256(&exact_receipt),
                    },
                )
            }
        };
        let result_sha256 = sha256(
            &canonical_plan_bytes(&result).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        let mut response = ReadinessResponseV12 {
            protocol: "serverware/controller-readiness/v12"
                .to_owned(),
            request_id: request.request_id,
            request_sha256: request.request_sha256,
            fixture_id: request.fixture_id,
            sequence: request.sequence,
            probe: request.probe,
            result,
            result_sha256,
            response_sha256: [0; 32],
        };
        response.response_sha256 = sha256(
            &canonical_plan_bytes(&response).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        let bytes = canonical_plan_bytes(&response).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        Ok((bytes, Vec::new(), response.response_sha256))
    }

    fn run_readiness_duplex_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<DockerUpgradeResultV12> {
        let request = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Readiness(request) => request,
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker readiness request is absent",
                ))
            }
        };
        let fixture = &request.signed_fixture.docker_upgrade;
        let client_stream = read_root_pinned_file_v12(
            &self.config.readiness_docker_client_stream,
            16 * 1024 * 1024,
        )?;
        let server_stream = read_root_pinned_file_v12(
            &self.config.readiness_docker_server_stream,
            16 * 1024 * 1024,
        )?;
        if sha256(&client_stream)
                != self.config.readiness_docker_client_stream_sha256
            || sha256(&client_stream)
                != fixture.client_stream_sha256
            || sha256(&server_stream)
                != self.config.readiness_docker_server_stream_sha256
            || sha256(&server_stream)
                != fixture.server_stream_sha256
        {
            return Err(ControllerError::Rejected(
                "Docker readiness stream bytes differ from root and fixture pins",
            ));
        }
        let head = canonical_docker_request_head_v12(
            "POST",
            &fixture.request_target,
            &[(
                "connection".to_owned(),
                "upgrade".to_owned(),
            )],
            client_stream.len() as u64,
        )?;
        if sha256(&head) != fixture.request_headers_sha256 {
            return Err(ControllerError::Rejected(
                "Docker readiness request header differs from signed fixture",
            ));
        }
        let (mut client, mut server) = UnixStream::pair()?;
        let now = boottime_now_ns_v11()?;
        if now >= operation.request.deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "Docker readiness deadline expired before duplex exchange",
            ));
        }
        let timeout = Duration::from_nanos(
            operation.request.deadline_boottime_ns - now,
        );
        for stream in [&client, &server] {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
        }
        let expected_client = client_stream.clone();
        let emitted_server = server_stream.clone();
        let worker = std::thread::spawn(move || -> std::result::Result<(), String> {
            let mut header = Vec::new();
            let mut byte = [0u8; 1];
            while !header.ends_with(b"\r\n\r\n") {
                server
                    .read_exact(&mut byte)
                    .map_err(|error| error.to_string())?;
                header.push(byte[0]);
                if header.len() > 64 * 1024 {
                    return Err(
                        "readiness upgrade header exceeded its bound"
                            .into(),
                    );
                }
            }
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: serverware-readiness\r\n\r\n",
                )
                .map_err(|error| error.to_string())?;
            let mut observed_client = Vec::new();
            server
                .read_to_end(&mut observed_client)
                .map_err(|error| error.to_string())?;
            if observed_client != expected_client {
                return Err(
                    "readiness upgrade client stream changed in transit"
                        .into(),
                );
            }
            server
                .write_all(&emitted_server)
                .and_then(|_| server.flush())
                .map_err(|error| error.to_string())
        });
        client.write_all(&head)?;
        let mut response_head = Vec::new();
        let mut byte = [0u8; 1];
        while !response_head.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte)?;
            response_head.push(byte[0]);
            if response_head.len() > 64 * 1024 {
                return Err(ControllerError::Rejected(
                    "readiness upgrade response header exceeded its bound",
                ));
            }
        }
        if !response_head.starts_with(
            b"HTTP/1.1 101 Switching Protocols\r\n",
        ) {
            return Err(ControllerError::Rejected(
                "readiness upgrade did not observe HTTP 101",
            ));
        }
        client.write_all(&client_stream)?;
        client.shutdown(std::net::Shutdown::Write)?;
        let mut observed_server = Vec::new();
        client.read_to_end(&mut observed_server)?;
        worker
            .join()
            .map_err(|_| {
                ControllerError::Rejected(
                    "readiness duplex fixture worker panicked",
                )
            })?
            .map_err(ControllerError::InvalidOwned)?;
        if observed_server != server_stream {
            return Err(ControllerError::Rejected(
                "readiness upgrade server stream changed in transit",
            ));
        }
        Ok(DockerUpgradeResultV12 {
            status: 101,
            full_duplex_observed: true,
            client_half_close_observed: true,
            server_after_half_close_observed: true,
            client_stream_sha256: sha256(&client_stream),
            server_stream_sha256: sha256(&observed_server),
        })
    }

    fn run_readiness_service_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<ServiceHealthResultV12> {
        let exact = self.run_readiness_container_probe_v12(
            operation,
            &self.config.readiness_service_image_archive,
            self.config.readiness_service_image_archive_sha256,
            &self.config.readiness_service_probe,
            self.config.readiness_service_probe_sha256,
            "service",
        )?;
        let result: ServiceHealthResultV12 =
            serde_json::from_slice(&exact).map_err(|_| {
                ControllerError::Invalid(
                    "service readiness result is not valid JSON",
                )
            })?;
        let request = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Readiness(request) => request,
            _ => unreachable!(),
        };
        let fixture = &request.signed_fixture.service;
        if canonical_plan_bytes(&result).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })? != exact
            || result.fixture_image_manifest_sha256
                != fixture.fixture_image.manifest_digest_sha256
            || result.service_identity_sha256
                != fixture.service_identity_sha256
            || result.status != fixture.expected_status
            || result.headers_sha256
                != fixture.expected_headers_sha256
            || result.body_sha256
                != fixture.expected_body_sha256
            || !result.healthy
        {
            return Err(ControllerError::Rejected(
                "service readiness runtime result differs from signed fixture",
            ));
        }
        Ok(result)
    }

    fn run_readiness_chromium_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<ChromiumResultV12> {
        let exact = self.run_readiness_container_probe_v12(
            operation,
            &self.config.readiness_browser_image_archive,
            self.config.readiness_browser_image_archive_sha256,
            &self.config.readiness_chromium_probe,
            self.config.readiness_chromium_probe_sha256,
            "chromium",
        )?;
        let result: ChromiumResultV12 =
            serde_json::from_slice(&exact).map_err(|_| {
                ControllerError::Invalid(
                    "Chromium readiness result is not valid JSON",
                )
            })?;
        let request = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Readiness(request) => request,
            _ => unreachable!(),
        };
        let fixture = &request.signed_fixture.chromium;
        self.validate_readiness_chromium_assets_v12(fixture)?;
        if canonical_plan_bytes(&result).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })? != exact
            || result.browser_image_manifest_sha256
                != fixture.browser_image.manifest_digest_sha256
            || result.browser_executable_sha256
                != fixture.browser_executable_sha256
            || result.browser_version != fixture.browser_version
            || result.cdp_protocol_version
                != fixture.cdp_protocol_version
            || result.dom_sha256
                != fixture.expected_dom_sha256
            || result.javascript_result_sha256
                != fixture.expected_javascript_result_sha256
            || result.fetch_response_sha256
                != fixture.expected_fetch_response_sha256
            || !result.cdp_connected
            || !result.headless
            || !result.private_network
        {
            return Err(ControllerError::Rejected(
                "Chromium readiness runtime result differs from signed fixture",
            ));
        }
        Ok(result)
    }

    fn validate_readiness_chromium_assets_v12(
        &self,
        fixture: &crate::readiness::ChromiumFixtureV12,
    ) -> Result<()> {
        let page = read_root_pinned_file_v12(
            &self.config.readiness_chromium_page,
            8 * 1024 * 1024,
        )?;
        let script = read_root_pinned_file_v12(
            &self.config.readiness_chromium_script,
            8 * 1024 * 1024,
        )?;
        let expected_dom = read_root_pinned_file_v12(
            &self.config.readiness_chromium_expected_dom,
            8 * 1024 * 1024,
        )?;
        let expected_javascript = read_root_pinned_file_v12(
            &self.config.readiness_chromium_expected_js,
            8 * 1024 * 1024,
        )?;
        let expected_fetch = read_root_pinned_file_v12(
            &self.config.readiness_chromium_expected_fetch,
            8 * 1024 * 1024,
        )?;
        if sha256(&page)
                != self.config.readiness_chromium_page_sha256
            || sha256(&page) != fixture.document_sha256
            || sha256(&script)
                != self.config.readiness_chromium_script_sha256
            || sha256(&script)
                != fixture.javascript_source_sha256
            || sha256(&expected_dom)
                != self
                    .config
                    .readiness_chromium_expected_dom_sha256
            || sha256(&expected_dom)
                != fixture.expected_dom_sha256
            || sha256(&expected_javascript)
                != self
                    .config
                    .readiness_chromium_expected_js_sha256
            || sha256(&expected_javascript)
                != fixture.expected_javascript_result_sha256
            || sha256(&expected_fetch)
                != self
                    .config
                    .readiness_chromium_expected_fetch_sha256
            || sha256(&expected_fetch)
                != fixture.expected_fetch_response_sha256
        {
            return Err(ControllerError::Rejected(
                "Chromium readiness files differ from root and signed fixture pins",
            ));
        }
        Ok(())
    }

    fn validate_readiness_teardown_contract_v12(
        &self,
    ) -> Result<()> {
        let exact = read_root_pinned_file_v12(
            &self.config.readiness_teardown_fixture,
            1024 * 1024,
        )?;
        if sha256(&exact)
            != self.config.readiness_teardown_fixture_sha256
        {
            return Err(ControllerError::Rejected(
                "readiness teardown contract differs from its root pin",
            ));
        }
        let contract: ReadinessTeardownContractV12 =
            serde_json::from_slice(&exact).map_err(|_| {
                ControllerError::Invalid(
                    "readiness teardown contract is not valid JSON",
                )
            })?;
        if canonical_plan_bytes(&contract).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })? != exact
            || contract.version
                != "serverware/readiness-teardown-contract/v12"
            || contract.docker_top_level_object_count_scope
                != DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
            || contract.docker_internal_storage_absence_proof
                != DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
            || !contract.require_exact_signed_fixture
            || !contract.require_durable_terminal_receipt
            || !contract.require_docker_authority_established
            || !contract.require_zero_containers
            || !contract.require_zero_images
            || !contract.require_zero_networks
            || !contract.require_zero_volumes
            || !contract.require_zero_mounts
            || !contract.require_zero_cgroup_processes
            || !contract.require_state_root_absent
        {
            return Err(ControllerError::Rejected(
                "readiness teardown contract is outside the closed profile",
            ));
        }
        Ok(())
    }

    fn run_readiness_container_probe_v12(
        &self,
        operation: &DockerLaneOperationV12,
        image_archive: &Path,
        image_archive_sha256: Digest,
        contract_path: &Path,
        contract_sha256: Digest,
        role: &str,
    ) -> Result<Vec<u8>> {
        let contract_bytes =
            read_root_pinned_file_v12(contract_path, 1024 * 1024)?;
        if sha256(&contract_bytes) != contract_sha256 {
            return Err(ControllerError::Rejected(
                "readiness container contract differs from its root pin",
            ));
        }
        let contract: ReadinessContainerProbeContractV12 =
            serde_json::from_slice(&contract_bytes).map_err(|_| {
                ControllerError::Invalid(
                    "readiness container contract is not valid JSON",
                )
            })?;
        if canonical_plan_bytes(&contract).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })? != contract_bytes
            || contract.version
                != "serverware/readiness-container-probe/v12"
            || contract.command.is_empty()
            || contract.command.len() > 128
            || contract
                .command
                .iter()
                .any(|part| part.is_empty() || part.len() > 4096)
            || contract.fixture_mount != "/serverware-fixtures"
            || contract.output_mount != "/serverware-output"
            || contract.network_mode != "none"
            || !valid_nonroot_container_user_v12(&contract.user)
        {
            return Err(ControllerError::Rejected(
                "readiness container contract is outside the closed profile",
            ));
        }
        validate_relative_cas_subpath_v12(
            &contract.result_relative_path,
        )?;
        let request = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Readiness(request) => request,
            _ => unreachable!(),
        };
        let expected_reference = match request.probe {
            ReadinessProbe::ServiceHealth => {
                exact_image_reference_v12(
                    &request.signed_fixture.service.fixture_image,
                )
            }
            ReadinessProbe::Chromium => {
                exact_image_reference_v12(
                    &request.signed_fixture.chromium.browser_image,
                )
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "readiness container probe used for a non-container fixture",
                ))
            }
        };
        if contract.image_reference != expected_reference {
            return Err(ControllerError::Rejected(
                "readiness container image differs from signed fixture",
            ));
        }
        let archive = read_root_pinned_file_v12(
            image_archive,
            PRIVATE_DIND_MAX_HTTP_BYTES_V12,
        )?;
        if sha256(&archive) != image_archive_sha256
            || canonicalize_docker_image_archive_v12(&archive)?
                != archive
        {
            return Err(ControllerError::Rejected(
                "readiness image archive is not the root-pinned canonical archive",
            ));
        }
        let load = self.docker_http_v12(
            operation,
            "POST",
            "/v1.45/images/load?quiet=1",
            vec![(
                "content-type".to_owned(),
                "application/x-tar".to_owned(),
            )],
            DockerRequestBodyV12::File {
                file: OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                    .open(image_archive)?,
                bytes: archive.len() as u64,
                sha256: image_archive_sha256,
            },
            DockerStreamModeV11::FullDuplex,
        )?;
        validate_docker_json_message_sequence_v12(
            &load,
            &[200],
            PRIVATE_DIND_MAX_JSON_MESSAGES_V12,
            PRIVATE_DIND_MAX_JSON_MESSAGE_BYTES_V12,
        )?;
        let (fixture_mount, output_mount) = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "readiness lifecycle mutex is poisoned",
                )
            })?;
            let handle = require_active_handle_v12(
                &state,
                operation,
            )?;
            (handle.source_mount.clone(), handle.output_mount.clone())
        };
        let result_path =
            output_mount.join(&contract.result_relative_path);
        if result_path.exists() {
            std::fs::remove_file(&result_path)?;
        }
        let (probe_uid, probe_gid) =
            parse_nonroot_container_user_v12(&contract.user)
                .ok_or(ControllerError::Rejected(
                    "readiness probe user is invalid",
                ))?;
        let output_c = c_path(&output_mount)?;
        if unsafe {
            libc::chown(
                output_c.as_ptr(),
                probe_uid,
                probe_gid,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        std::fs::set_permissions(
            &output_mount,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let container_name = format!(
            "swv12-readiness-{}-{}",
            role,
            &digest_hex(&request.request_id)[..16],
        );
        let body = json!({
            "AttachStderr": false,
            "AttachStdin": false,
            "AttachStdout": false,
            "Cmd": contract.command,
            "Env": [],
            "HostConfig": {
                "AutoRemove": false,
                "Binds": [
                    format!(
                        "{}:{}:ro",
                        fixture_mount.display(),
                        contract.fixture_mount,
                    ),
                    format!(
                        "{}:{}:rw",
                        output_mount.display(),
                        contract.output_mount,
                    ),
                ],
                "CapDrop": ["ALL"],
                "NetworkMode": contract.network_mode,
                "ReadonlyRootfs": true,
                "SecurityOpt": ["no-new-privileges:true"],
            },
            "Image": contract.image_reference,
            "Labels": owner_labels_json_v12(operation),
            "OpenStdin": false,
            "Tty": false,
            "User": contract.user,
        });
        let create = self.docker_json_v12(
            operation,
            "POST",
            &format!(
                "/v1.45/containers/create?name={}",
                percent_encode_query_v12(&container_name),
            ),
            &body,
        )?;
        let container_id = json_text_v12(
            &require_docker_success_v12(&create, &[201])?,
            "Id",
        )?
        .to_owned();
        let start = self.docker_http_v12(
            operation,
            "POST",
            &format!("/v1.45/containers/{container_id}/start"),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        require_docker_success_v12(&start, &[204])?;
        let wait = self.docker_http_v12(
            operation,
            "POST",
            &format!(
                "/v1.45/containers/{container_id}/wait?condition=not-running"
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::FullDuplex,
        )?;
        let wait = require_docker_success_v12(&wait, &[200])?;
        if wait.get("StatusCode").and_then(Value::as_i64) != Some(0) {
            return Err(ControllerError::Rejected(
                "readiness container exited unsuccessfully",
            ));
        }
        let exact_result =
            read_probe_result_file_v12(
                &result_path,
                8 * 1024 * 1024,
            )?;
        let delete = self.docker_http_v12(
            operation,
            "DELETE",
            &format!(
                "/v1.45/containers/{container_id}?force=1&v=1"
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        require_docker_success_v12(&delete, &[204, 404])?;
        let image_delete = self.docker_http_v12(
            operation,
            "DELETE",
            &format!(
                "/v1.45/images/{}?force=1&noprune=0",
                percent_encode_path_v12(
                    &contract.image_reference,
                ),
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        require_docker_success_v12(&image_delete, &[200, 404])?;
        Ok(exact_result)
    }

    fn create_generation_v12(
        &self,
        operation: &DockerLaneOperationV12,
        attached_fds: Vec<OwnedFd>,
    ) -> Result<()> {
        self.setup_host_network()?;
        let readiness = matches!(
            &operation.decoded_payload,
            DockerLaneDecodedPayloadV12::Readiness(_)
        );
        let mut attached_fds = attached_fds;
        if readiness {
            if !attached_fds.is_empty() {
                return Err(ControllerError::Rejected(
                    "readiness generation accepted caller-controlled descriptors",
                ));
            }
            self.ledger.ensure_readiness_generation(operation)?;
            attached_fds.push(open_directory_fd_v12(
                &self.config.readiness_fixture_root,
            )?);
        }
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        if state.active.contains_key(&operation.daemon_generation) {
            return Err(ControllerError::Rejected(
                "private DinD generation is already active",
            ));
        }
        if state.active.len() >= PRIVATE_DIND_MAX_GENERATIONS_V12 {
            return Err(ControllerError::Rejected(
                "private DinD active generation bound exceeded",
            ));
        }
        let expected_fds = if readiness
            || operation.profile == PrivateDindProfileV12::Build
        {
            1
        } else {
            2
        };
        if attached_fds.len() != expected_fds {
            return Err(ControllerError::Rejected(
                "private DinD generation retained the wrong CAS descriptor set",
            ));
        }
        for fd in &attached_fds {
            require_directory_fd_v12(fd.as_raw_fd())?;
        }
        let generation_root = self
            .config
            .dind_root
            .join(&operation.owner_namespace)
            .join(&operation.daemon_generation);
        let data_root = generation_root.join("data");
        let exec_root = generation_root.join("exec");
        let log_root = generation_root.join("logs");
        let source_mount = generation_root.join("mounts/source");
        let artifact_mount = (expected_fds == 2)
            .then(|| generation_root.join("mounts/artifacts"));
        let output_mount = generation_root.join("mounts/output");
        let tool_root = generation_root.join("tools");
        for path in [
            &generation_root,
            &data_root,
            &exec_root,
            &log_root,
            &source_mount,
            &output_mount,
            &tool_root,
        ] {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        if let Some(path) = &artifact_mount {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        bind_mount_fd_read_only_v12(
            attached_fds[0].as_raw_fd(),
            &source_mount,
        )?;
        if let Some(target) = &artifact_mount {
            bind_mount_fd_read_only_v12(
                attached_fds[1].as_raw_fd(),
                target,
            )?;
        }
        if !readiness {
            validate_source_cas_mount_v12(operation, &source_mount)?;
        }
        if let Some(target) = &artifact_mount {
            validate_artifact_cas_mount_v12(operation, target)?;
        }
        create_pinned_tool_links_v12(
            &tool_root,
            &self.config.containerd_binary,
            &self.config.containerd_shim_binary,
            &self.config.runc_binary,
        )?;
        let profile = operation.profile.as_str();
        let lane_slot = operation.generation_slot().to_string();
        let ruleset = if operation.profile
            == PrivateDindProfileV12::Build
        {
            &self.config.build_lane_ruleset
        } else {
            &self.config.no_build_lane_ruleset
        };
        let ruleset_text = path_text_v12(ruleset)?;
        let network_ledger_text =
            path_text_v12(&self.config.network_ownership_ledger)?;
        self.run_network_hook_v12(
            &[
                "create-lane",
                &operation.daemon_generation,
                lane_slot.as_str(),
                profile,
                ruleset_text.as_str(),
                network_ledger_text.as_str(),
            ],
            operation.request.deadline_boottime_ns,
        )?;
        let network = network_ownership_record_v12(
            &self.config.network_ownership_ledger,
            &operation.daemon_generation,
            operation.generation_slot(),
        )?
        .ok_or(ControllerError::Rejected(
            "private DinD network hook did not publish its allocation",
        ))?;
        let netns_name = network.namespace.clone();
        self.ledger.bind_generation_network_namespace(
            &operation.owner_namespace,
            &operation.daemon_generation,
            &netns_name,
        )?;
        let ownership_record = generation_root.join("ownership-v12.json");
        let record = json!({
            "cgroup": self.cgroup_path_v12(operation),
            "daemonGeneration": operation.daemon_generation,
            "hostAddress": network.host_address,
            "hostVeth": network.host_veth,
            "laneAddress": network.lane_address,
            "laneGateway": network.lane_gateway,
            "laneSlot": operation.generation_slot(),
            "netnsName": netns_name,
            "ownerNamespace": operation.owner_namespace,
            "profile": operation.profile,
            "socket": self.socket_path_v12(operation),
            "subnetIndex": network.subnet_index,
            "version": "serverware/private-dind-ownership/v12",
        });
        publish_exact_private_file(
            &generation_root,
            &ownership_record,
            &canonical_plan_bytes(&record).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        )?;
        let cgroup = self.cgroup_path_v12(operation);
        create_cgroup(&cgroup)?;
        let socket = self.socket_path_v12(operation);
        require_socket_absent(&socket)?;
        let pidfile = generation_root.join("dockerd.pid");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log_root.join("dockerd.log"))?;
        let error_log = log.try_clone()?;
        let netns = self
            .config
            .netns_root
            .join(&netns_name);
        let netns_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&netns)?;
        let tool_path = path_text_v12(&tool_root)?;
        let mut child_command = Command::new(&self.config.dockerd_binary);
        child_command
            .arg("--host")
            .arg(format!("unix://{}", socket.display()))
            .arg("--data-root")
            .arg(&data_root)
            .arg("--exec-root")
            .arg(&exec_root)
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--bridge=none")
            .arg("--iptables=false")
            .arg("--ip-forward=false")
            .arg("--ip-masq=false")
            .arg("--live-restore=false")
            .arg("--userland-proxy=false")
            .arg("--log-driver=local")
            .arg("--label")
            .arg(format!(
                "{}={}",
                OWNER_LABEL_V12, operation.owner_namespace
            ))
            .arg("--label")
            .arg(format!(
                "{}={}",
                GENERATION_LABEL_V12, operation.daemon_generation
            ))
            .env_clear()
            .env(
                "PATH",
                format!("{tool_path}:/usr/sbin:/usr/bin:/sbin:/bin"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log));
        let netns_raw = netns_fd.as_raw_fd();
        unsafe {
            child_command.pre_exec(move || {
                if libc::setns(netns_raw, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = child_command.spawn()?;
        let pid = child.id() as libc::pid_t;
        let start_time_ticks = match process_start_time(pid) {
            Ok(value) => value,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = attach_cgroup(&cgroup, pid) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) =
            self.ledger.bind_generation_process_identity(
                &operation.owner_namespace,
                &operation.daemon_generation,
                pid,
                start_time_ticks,
            )
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Err(error) = write_private_dind_pid_record_v12(
            &generation_root.join("process-v12.json"),
            pid,
            start_time_ticks,
            &operation.owner_namespace,
            &operation.daemon_generation,
            &socket,
            &cgroup,
            &netns_name,
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let pidfd_raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
        if pidfd_raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
        let deadline = operation.request.deadline_boottime_ns.min(
            boottime_now_ns_v11()?
                .saturating_add(PRIVATE_DIND_START_TIMEOUT_NS_V12),
        );
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(ControllerError::InvalidOwned(format!(
                    "private DinD v12 exited during startup: {status}",
                )));
            }
            if docker_ping(&socket, deadline).is_ok() {
                break;
            }
            if boottime_now_ns_v11()? >= deadline {
                return Err(ControllerError::Rejected(
                    "private DinD v12 startup deadline expired",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.ledger
            .mark_generation_docker_authority_established(
                &operation.owner_namespace,
                &operation.daemon_generation,
            )?;
        std::fs::set_permissions(
            &socket,
            std::fs::Permissions::from_mode(0o600),
        )?;
        state.active.insert(
            operation.daemon_generation.clone(),
            PrivateDindHandleV12 {
                child,
                pidfd,
                pid,
                start_time_ticks,
                profile: operation.profile,
                owner_namespace: operation.owner_namespace.clone(),
                daemon_generation: operation.daemon_generation.clone(),
                lane_slot: operation.generation_slot(),
                netns_name,
                generation_root,
                data_root,
                exec_root,
                socket,
                cgroup,
                source_mount,
                artifact_mount,
                output_mount,
                runners: BTreeMap::new(),
                service_ids: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn pull_pinned_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let pull = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::PullPinned { pull } => pull,
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD pull payload changed after policy",
                ))
            }
        };
        let reference = format!(
            "{}/{}@sha256:{}",
            pull.registry,
            pull.repository,
            digest_hex(&pull.manifest_digest_sha256),
        );
        let target = format!(
            "/v1.45/images/create?fromImage={}&platform={}",
            percent_encode_query_v12(&reference),
            percent_encode_query_v12(&pull.platform),
        );
        let response = self.docker_http_v12(
            operation,
            "POST",
            &target,
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::FullDuplex,
        )?;
        validate_docker_json_message_sequence_v12(
            &response,
            &[200],
            PRIVATE_DIND_MAX_JSON_MESSAGES_V12,
            PRIVATE_DIND_MAX_JSON_MESSAGE_BYTES_V12,
        )?;
        Ok(())
    }

    fn build_exact_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let exact = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::BuildExact { exact_build } => {
                exact_build
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD build payload changed after policy",
                ))
            }
        };
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = require_active_handle_v12(&state, operation)?;
        let context = handle.source_mount.join(&exact.context_relative_path);
        let tar_path = handle
            .generation_root
            .join("build-context-v12.tar");
        let (bytes, digest) =
            write_deterministic_tar_v12(&context, &tar_path)?;
        let mut query = vec![
            ("dockerfile", exact.dockerfile_relative_path.clone()),
            ("platform", exact.platform.clone()),
            ("target", exact.target.clone()),
        ];
        let build_args = Value::Object(Map::from_iter(
            exact
                .build_arguments
                .iter()
                .map(|entry| {
                    (entry.name.clone(), Value::String(entry.value.clone()))
                }),
        ));
        query.push((
            "buildargs",
            String::from_utf8(
                canonical_json_bytes_v12(&build_args)?,
            )
            .map_err(|_| {
                ControllerError::Invalid(
                    "canonical build arguments are not UTF-8",
                )
            })?,
        ));
        let labels = owner_labels_json_v12(operation);
        query.push((
            "labels",
            String::from_utf8(
                canonical_json_bytes_v12(&labels)?,
            )
            .map_err(|_| {
                ControllerError::Invalid(
                    "canonical build labels are not UTF-8",
                )
            })?,
        ));
        for repository in &exact.expected_repositories {
            query.push(("t", repository.clone()));
        }
        query.sort();
        let target = format!(
            "/v1.45/build?{}",
            query
                .iter()
                .map(|(name, value)| format!(
                    "{}={}",
                    percent_encode_query_v12(name),
                    percent_encode_query_v12(value)
                ))
                .collect::<Vec<_>>()
                .join("&"),
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tar_path)?;
        drop(state);
        let response = self.docker_http_v12(
            operation,
            "POST",
            &target,
            vec![(
                "content-type".to_owned(),
                "application/x-tar".to_owned(),
            )],
            DockerRequestBodyV12::File {
                file,
                bytes,
                sha256: digest,
            },
            DockerStreamModeV11::BuildKit,
        )?;
        validate_docker_json_message_sequence_v12(
            &response,
            &[200],
            PRIVATE_DIND_MAX_JSON_MESSAGES_V12,
            PRIVATE_DIND_MAX_JSON_MESSAGE_BYTES_V12,
        )?;
        Ok(())
    }

    fn import_sealed_oci_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let object = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::ImportSealedOci {
                object,
                ..
            } => object,
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD import payload changed after policy",
                ))
            }
        };
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = require_active_handle_v12(&state, operation)?;
        let artifact = handle.artifact_mount.as_ref().ok_or(
            ControllerError::Rejected(
                "no-build generation lacks retained artifact CAS",
            ),
        )?;
        let manifest =
            read_sealed_docker_artifact_manifest_v12(artifact)?;
        validate_sealed_docker_artifact_manifest_self_v12(&manifest)?;
        let artifact_object_sha256 =
            match operation_payload_content_v12(operation)? {
                DockerLanePayloadContentV12::ImportSealedOci {
                    artifact_object_sha256,
                    ..
                } => artifact_object_sha256,
                _ => {
                    return Err(ControllerError::Rejected(
                        "private DinD import payload changed after policy",
                    ))
                }
            };
        if manifest.artifact_object_sha256
            != artifact_object_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD import archive set differs from its signed artifact object",
            ));
        }
        let entry =
            sealed_docker_archive_entry_v12(&manifest, &object)?;
        let archive = artifact.join(&entry.archive_relative_path);
        let archive_bytes = read_sealed_cas_file_v12(
            &archive,
            PRIVATE_DIND_MAX_HTTP_BYTES_V12,
        )?;
        if archive_bytes.len() as u64 != entry.archive_bytes
            || sha256(&archive_bytes) != entry.archive_sha256
            || canonicalize_docker_image_archive_v12(
                &archive_bytes,
            )? != archive_bytes
        {
            return Err(ControllerError::Rejected(
                "private DinD import archive differs from sealed metadata",
            ));
        }
        let bytes = entry.archive_bytes;
        let digest = entry.archive_sha256;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&archive)?;
        drop(state);
        let response = self.docker_http_v12(
            operation,
            "POST",
            "/v1.45/images/load?quiet=1",
            vec![(
                "content-type".to_owned(),
                "application/x-tar".to_owned(),
            )],
            DockerRequestBodyV12::File {
                file,
                bytes,
                sha256: digest,
            },
            DockerStreamModeV11::FullDuplex,
        )?;
        validate_docker_json_message_sequence_v12(
            &response,
            &[200],
            PRIVATE_DIND_MAX_JSON_MESSAGES_V12,
            PRIVATE_DIND_MAX_JSON_MESSAGE_BYTES_V12,
        )?;
        self.verify_imported_image_v12(operation, &object)?;
        Ok(())
    }

    fn create_runner_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let (runner, command) = match operation_payload_content_v12(
            operation,
        )? {
            DockerLanePayloadContentV12::CreateRunner {
                runner,
                command,
            } => (runner, command),
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD runner payload changed after policy",
                ))
            }
        };
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = require_active_handle_mut_v12(&mut state, operation)?;
        if handle.runners.contains_key(&operation.request.lane) {
            return Err(ControllerError::Rejected(
                "private DinD lane already has a runner",
            ));
        }
        let name = container_name_v12(
            "runner",
            operation.request.lane,
            &operation.request.plan_id,
        );
        runner.validate().map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        // The privileged generation parent is never made worker-writable.
        // Each lane gets a fresh output root, separate from the OCI export
        // directory and from every other lane, even when their UIDs differ.
        let output_mount = handle.generation_root.join(format!(
            "runner-output-{}", operation.request.lane.ordinal(),
        ));
        let output_storage = create_runner_output_v12(
            &handle.generation_root, &output_mount,
            &runner.execution_bounds,
        )?;
        let output_fd = open_directory_fd_v12(&output_mount)?;
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &output_mount, &output_storage,
        )?;
        let output_identity_sha256 =
            directory_fd_identity_sha256_v12(output_fd.as_raw_fd())?;
        let output_storage_identity_sha256 = sha256(&canonical_json_bytes_v12(
            &serde_json::to_value(&output_storage).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        )?);
        drop(output_fd);
        let body = runner_create_body_v12(
            operation,
            handle,
            &runner,
            &command,
            &output_mount,
        )?;
        drop(state);
        let response = self.docker_json_v12(
            operation,
            "POST",
            &format!(
                "/v1.45/containers/create?name={}",
                percent_encode_query_v12(&name),
            ),
            &body,
        )?;
        let created = require_docker_success_v12(&response, &[201])?;
        let id = json_text_v12(&created, "Id")?.to_owned();
        if id.len() != 64 || !id.bytes().all(|byte| {
            matches!(byte, b'0'..=b'9' | b'a'..=b'f')
        }) {
            return Err(ControllerError::Rejected(
                "private DinD runner returned a noncanonical container identity",
            ));
        }
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        require_active_handle_mut_v12(&mut state, operation)?
            .runners
            .insert(operation.request.lane, PrivateRunnerV12 {
                id: id.clone(),
                identity: runner.clone(),
                expected_create: body.clone(),
                command_sha256: command.command_sha256,
                output_mount,
                output_identity_sha256,
                output_storage,
                output_storage_identity_sha256,
                uid: runner.execution_bounds.user_uid,
                gid: runner.execution_bounds.user_gid,
                created_inspect_sha256: None,
                prestart_inspect_sha256: None,
            });
        drop(state);
        // Docker may warn and discard unsupported limits. Retain the created
        // resource for cleanup, but never start it after any warning.
        if !matches!(created.get("Warnings"), Some(Value::Null))
            && !created.get("Warnings").and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return Err(ControllerError::Rejected(
                "private DinD runner create did not confirm an empty warning set",
            ));
        }
        let inspection = self.inspect_runner_before_start_v12(
            operation, &id, &body,
        )?;
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected("private DinD lifecycle mutex is poisoned")
        })?;
        let retained = require_active_handle_mut_v12(&mut state, operation)?
            .runners.get_mut(&operation.request.lane)
            .ok_or(ControllerError::Rejected("created runner was lost"))?;
        if retained.id != id || retained.expected_create != body
            || retained.created_inspect_sha256.is_some()
            || retained.prestart_inspect_sha256.is_some()
        {
            return Err(ControllerError::Rejected("created runner identity changed during inspection"));
        }
        retained.created_inspect_sha256 = Some(inspection);
        Ok(())
    }

    fn inspect_runner_before_start_v12(
        &self,
        operation: &DockerLaneOperationV12,
        id: &str,
        expected_create: &Value,
    ) -> Result<Digest> {
        let response = self.docker_http_v12(
            operation, "GET", &format!("/v1.45/containers/{id}/json"),
            Vec::new(), DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        let inspected = require_docker_success_v12(&response, &[200])?;
        validate_runner_inspect_v12(&inspected, expected_create, id)?;
        Ok(sha256(&canonical_json_bytes_v12(&inspected)?))
    }

    fn create_services_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let services = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::CreateServices { services } => {
                services
            }
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD service payload changed after policy",
                ))
            }
        };
        let network_name = network_name_v12(&operation.request.plan_id);
        let network_body = json!({
            "Attachable": false,
            "CheckDuplicate": true,
            "Driver": "bridge",
            "EnableIPv6": false,
            "Internal": true,
            "Labels": owner_labels_json_v12(operation),
            "Name": network_name,
        });
        let network_response = self.docker_json_v12(
            operation,
            "POST",
            "/v1.45/networks/create",
            &network_body,
        )?;
        require_docker_success_v12(&network_response, &[201])?;
        let mut ids = Vec::new();
        for service in services {
            let name = container_name_v12(
                "service",
                operation.request.lane,
                &service.service_id,
            );
            let body = service_create_body_v12(
                operation,
                &service,
                &network_name,
            )?;
            let response = self.docker_json_v12(
                operation,
                "POST",
                &format!(
                    "/v1.45/containers/create?name={}",
                    percent_encode_query_v12(&name),
                ),
                &body,
            )?;
            let value = require_docker_success_v12(&response, &[201])?;
            let id = json_text_v12(&value, "Id")?.to_owned();
            let start = self.docker_http_v12(
                operation,
                "POST",
                &format!("/v1.45/containers/{id}/start"),
                Vec::new(),
                DockerRequestBodyV12::Empty,
                DockerStreamModeV11::BoundedHttp,
            )?;
            require_docker_success_v12(&start, &[204, 304])?;
            ids.push(id);
        }
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        require_active_handle_mut_v12(&mut state, operation)?
            .service_ids
            .insert(operation.request.lane, ids);
        Ok(())
    }

    fn run_repository_body_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<Vec<u8>> {
        let body_contract = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::RunBody { body, .. } => body,
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD body payload changed after policy",
                ))
            }
        };
        body_contract.validate().map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let (runner, native_inputs) = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD lifecycle mutex is poisoned",
                )
            })?;
            let handle = require_active_handle_v12(&state, operation)?;
            let runner = handle.runners.get(&operation.request.lane).cloned()
                .ok_or(ControllerError::Rejected("repository body runner is absent"))?;
            let native_inputs = if body_contract.native_postgres.is_some() {
                let artifacts = handle.artifact_mount.as_ref().ok_or(
                    ControllerError::Rejected("native PostgreSQL prepared artifact mount is absent"),
                )?;
                Some((open_directory_fd_v12(artifacts)?, open_directory_fd_v12(&handle.source_mount)?))
            } else { None };
            (runner, native_inputs)
        };
        if runner.command_sha256 != body_contract.command.command_sha256
            || runner.created_inspect_sha256.is_none()
            || runner.prestart_inspect_sha256.is_some()
        {
            return Err(ControllerError::Rejected(
                "repository body differs from its unconsumed inspected runner",
            ));
        }
        if let (Some(native), Some((artifacts, source))) =
            (&body_contract.native_postgres, &native_inputs)
        {
            native_postgres_output_v12::admit_prepared(
                artifacts.as_raw_fd(), source.as_raw_fd(), native,
                operation.request.deadline_boottime_ns,
            )?;
        }
        let output_fd = open_directory_fd_v12(&runner.output_mount)?;
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
        )?;
        if directory_fd_identity_sha256_v12(output_fd.as_raw_fd())?
            != runner.output_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "repository runner output identity changed before start",
            ));
        }
        let inspected = self.inspect_runner_before_start_v12(
            operation, &runner.id, &runner.expected_create,
        )?;
        {
            let mut state = self.state.lock().map_err(|_| {
                ControllerError::Rejected("private DinD lifecycle mutex is poisoned")
            })?;
            let retained = require_active_handle_mut_v12(&mut state, operation)?
                .runners.get_mut(&operation.request.lane)
                .ok_or(ControllerError::Rejected("body runner was lost"))?;
            if retained.id != runner.id || retained.identity != runner.identity
                || retained.expected_create != runner.expected_create
                || retained.created_inspect_sha256 != runner.created_inspect_sha256
                || retained.prestart_inspect_sha256.is_some()
            {
                return Err(ControllerError::Rejected("body runner identity changed during inspection"));
            }
            retained.prestart_inspect_sha256 = Some(inspected);
        }
        // Inspect and state publication must not hide storage drift before
        // repository code starts. The mount and kernel caps are independent
        // of Docker's reported bind configuration.
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
        )?;
        let body_deadline = {
            let now = boottime_now_ns_v11()?;
            let deadline = now.checked_add(body_contract.command.timeout_ns)
                .ok_or(ControllerError::Rejected("repository body timeout overflows"))?
                .min(operation.request.deadline_boottime_ns);
            if body_contract.native_postgres.is_some()
                && deadline.saturating_sub(now)
                < crate::plan_protocol::native_postgres_contract_v12::REQUIRED_RUNTIME_NS
            {
                return Err(ControllerError::Rejected(
                    "native PostgreSQL body lacks its full original execution window",
                ));
            }
            deadline
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut captured_outputs = CaptureOutputsV12::create(
            output_fd.as_raw_fd(), runner.uid, runner.gid, body_deadline,
        )?;
        let (stdout, stderr) = captured_outputs.take_streams()?;
        let capture = BodyCaptureV12::start(
            self.connect_private_dind_v12(operation, body_deadline)?, &runner.id,
            stdout, stderr,
            stream_byte_limit(runner.identity.execution_bounds.output_bytes)
                .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?,
            body_deadline, Arc::clone(&cancelled),
        )?;
        capture.require_pending()?;
        let id = &runner.id;
        let start = self.docker_http_v12_with_cancellation(
            operation,
            "POST",
            &format!("/v1.45/containers/{id}/start"),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
            body_deadline,
            Arc::clone(&cancelled),
        )?;
        require_docker_success_v12(&start, &[204])?;
        capture.health()?;
        let wait = self.docker_http_v12_with_cancellation(
            operation,
            "POST",
            &format!(
                "/v1.45/containers/{id}/wait?condition=not-running"
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::FullDuplex,
            body_deadline,
            Arc::clone(&cancelled),
        )?;
        let wait_body = require_docker_success_v12(&wait, &[200])?;
        let exit_status = wait_body
            .get("StatusCode")
            .and_then(Value::as_i64)
            .ok_or(ControllerError::Invalid(
                "Docker wait response lacks StatusCode",
            ))?;
        // Only observed EOF on a complete framed stream can produce these
        // hashes. Any earlier error cancels the HTTP wait and Drop joins the
        // capture worker; the existing outer abort path still owns teardown.
        let captured = capture.finish()?;
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
        )?;
        if directory_fd_identity_sha256_v12(output_fd.as_raw_fd())?
            != runner.output_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "repository runner output identity changed during execution",
            ));
        }
        let result_name = format!(
            "{}-{}.json",
            PRIVATE_DIND_BODY_RESULT_V12,
            operation.request.lane.ordinal(),
        );
        let (result, terminal_name) = match read_runner_result_v12(
            output_fd.as_raw_fd(), &result_name, runner.uid, runner.gid,
            MAX_BODY_RESULT_BYTES_V12 as u64,
        ) {
            Ok(result) => (result, result_name),
            Err(ControllerError::Io(ref io_error))
                if io_error.kind() == std::io::ErrorKind::NotFound => {
                (read_runner_result_v12(
                    output_fd.as_raw_fd(), PRIVATE_DIND_BODY_RESULT_V12,
                    runner.uid, runner.gid, MAX_BODY_RESULT_BYTES_V12 as u64,
                )?, PRIVATE_DIND_BODY_RESULT_V12.to_owned())
            }
            Err(error) => return Err(error),
        };
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
        )?;
        let parsed = BodyExecutionResultV12::parse_original(&result)
            .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
        if parsed.version != PRIVATE_DIND_RESULT_VERSION_V12
            || parsed.plan_id != operation.request.plan_id
            || parsed.lane != operation.request.lane
            || parsed.body_sha256 != body_contract.body_sha256
            || parsed.command_sha256 != runner.command_sha256
            || i64::from(parsed.exit_status) != exit_status
            || parsed.runner_evidence.runner != runner.identity.image
            || parsed.runner_evidence.runtime_executable_sha256
                != runner.identity.runtime_executable_sha256
            || parsed.runner_evidence.rootfs_sha256 != runner.identity.rootfs_sha256
            || parsed.runner_evidence.runner_identity_sha256
                != plan_sha256_bytes(&canonical_plan_bytes(&runner.identity)
                    .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?)
        {
            return Err(ControllerError::Rejected(
                "repository body terminal result differs from observed execution",
            ));
        }
        // This checks original-byte commitments only. The plan executor still
        // independently authenticates the pinned observer and static roles.
        parsed.validate_terminal()
            .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
        let native_observed = match (&body_contract.native_postgres, &native_inputs) {
            (Some(native), Some((artifacts, source))) => {
                if exit_status != 0 {
                    return Err(ControllerError::Rejected(
                        "native PostgreSQL body did not exit successfully",
                    ));
                }
                native_postgres_output_v12::admit_prepared(
                    artifacts.as_raw_fd(), source.as_raw_fd(), native, body_deadline,
                )?;
                let observed = native_postgres_output_v12::collect(
                    output_fd.as_raw_fd(), runner.uid, runner.gid, native, body_deadline,
                )?;
                if parsed.native_postgres_output_sha256 != Some(observed)
                {
                    return Err(ControllerError::Rejected(
                        "native PostgreSQL original output differs from the outer terminal commitment",
                    ));
                }
                runner_output_storage_v12::verify(
                    output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
                )?;
                if boottime_now_ns_v11()? >= body_deadline {
                    return Err(ControllerError::Rejected("native PostgreSQL result deadline expired"));
                }
                Some(observed)
            }
            (None, None) if parsed.native_postgres_output_sha256.is_none() => None,
            _ => return Err(ControllerError::Rejected(
                "native PostgreSQL result was not selected by its signed body",
            )),
        };
        let outputs = captured_outputs.finish(
            &body_contract.expected_output_paths, &terminal_name,
            &runner.identity.execution_bounds,
            (captured.stdout_sha256, captured.stdout_bytes),
            (captured.stderr_sha256, captured.stderr_bytes), body_deadline,
        )?;
        if parsed.stdout_sha256 != outputs.stdout_sha256
            || parsed.stderr_sha256 != outputs.stderr_sha256
            || parsed.output_manifest_sha256 != outputs.output_manifest_sha256
            || outputs.terminal_file_sha256 != sha256(&result)
            || outputs.terminal_file_bytes != result.len() as u64
        {
            return Err(ControllerError::Rejected(
                "body result differs from actual captured streams and collected output manifest",
            ));
        }
        if let Some(native) = native_observed {
            let manifest_native = native_subset_sha256(&outputs.files)
                .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
            if manifest_native != native {
                return Err(ControllerError::Rejected(
                    "native originals changed between report reconciliation and generic collection",
                ));
            }
        }
        runner_output_storage_v12::verify(
            output_fd.as_raw_fd(), &runner.output_mount, &runner.output_storage,
        )?;
        if boottime_now_ns_v11()? >= body_deadline {
            return Err(ControllerError::Rejected("body output collection exceeded its original deadline"));
        }
        Ok(result)
    }

    fn stop_runner_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let id = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD lifecycle mutex is poisoned",
                )
            })?;
            require_active_handle_v12(&state, operation)?
                .runners
                .get(&operation.request.lane)
                .map(|runner| runner.id.clone())
                .ok_or(ControllerError::Rejected(
                    "private DinD runner is absent",
                ))?
        };
        let delete = self.docker_http_v12(
            operation,
            "DELETE",
            &format!("/v1.45/containers/{id}?force=1&v=1"),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        require_docker_success_v12(&delete, &[204, 404])?;
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        require_active_handle_mut_v12(&mut state, operation)?
            .runners
            .remove(&operation.request.lane);
        Ok(())
    }

    fn destroy_services_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<()> {
        let ids = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD lifecycle mutex is poisoned",
                )
            })?;
            require_active_handle_v12(&state, operation)?
                .service_ids
                .get(&operation.request.lane)
                .cloned()
                .unwrap_or_default()
        };
        for id in ids {
            let response = self.docker_http_v12(
                operation,
                "DELETE",
                &format!("/v1.45/containers/{id}?force=1&v=1"),
                Vec::new(),
                DockerRequestBodyV12::Empty,
                DockerStreamModeV11::BoundedHttp,
            )?;
            require_docker_success_v12(&response, &[204, 404])?;
        }
        let network = network_name_v12(&operation.request.plan_id);
        let response = self.docker_http_v12(
            operation,
            "DELETE",
            &format!(
                "/v1.45/networks/{}",
                percent_encode_path_v12(&network),
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        require_docker_success_v12(&response, &[204, 404])?;
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        require_active_handle_mut_v12(&mut state, operation)?
            .service_ids
            .remove(&operation.request.lane);
        Ok(())
    }

    fn export_owned_oci_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<(Vec<u8>, OwnedFd, Digest)> {
        let expected = match operation_payload_content_v12(operation)? {
            DockerLanePayloadContentV12::ExportOwnedOci {
                expected_artifacts,
                expected_repositories,
            } => (expected_artifacts, expected_repositories),
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD export payload changed after policy",
                ))
            }
        };
        let output_mount = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD lifecycle mutex is poisoned",
                )
            })?;
            require_active_handle_v12(&state, operation)?
                .output_mount
                .clone()
        };
        self.verify_exact_export_image_set_v12(
            operation,
            &expected.1,
        )?;
        let expected_object_repositories = expected
            .0
            .oci_objects
            .iter()
            .map(|object| object.repository.clone())
            .collect::<BTreeSet<_>>();
        let expected_export_repositories =
            expected.1.iter().cloned().collect::<BTreeSet<_>>();
        if expected_object_repositories
            != expected_export_repositories
        {
            return Err(ControllerError::Rejected(
                "private DinD signed export repositories differ from the artifact closure",
            ));
        }
        let mut objects = expected.0.oci_objects.clone();
        objects.sort_by(|left, right| {
            (
                left.repository.as_str(),
                left.platform.as_str(),
                left.manifest_digest_sha256,
            )
                .cmp(&(
                    right.repository.as_str(),
                    right.platform.as_str(),
                    right.manifest_digest_sha256,
                ))
        });
        let mut archives = Vec::with_capacity(objects.len());
        let mut aggregate_archive_bytes = 0u64;
        for object in objects {
            let exact_reference = exact_image_reference_v12(&object);
            let response = self.docker_http_v12(
                operation,
                "GET",
                &format!(
                    "/v1.45/images/get?names={}",
                    percent_encode_query_v12(&exact_reference),
                ),
                Vec::new(),
                DockerRequestBodyV12::Empty,
                DockerStreamModeV11::FullDuplex,
            )?;
            let (status, archive) =
                docker_http_response_body_v12(&response)?;
            if status != 200 || archive.is_empty() {
                return Err(ControllerError::Rejected(
                    "private DinD exact image export failed",
                ));
            }
            let archive =
                canonicalize_docker_image_archive_v12(&archive)?;
            aggregate_archive_bytes = aggregate_archive_bytes
                .checked_add(archive.len() as u64)
                .ok_or(ControllerError::Invalid(
                    "private DinD artifact archive size overflowed",
                ))?;
            if aggregate_archive_bytes
                > PRIVATE_DIND_MAX_HTTP_BYTES_V12
            {
                return Err(ControllerError::Rejected(
                    "private DinD artifact archive set exceeds its bound",
                ));
            }
            let archive_sha256 = sha256(&archive);
            let archive_relative_path = format!(
                "docker-image-{}.tar",
                digest_hex(&object.manifest_digest_sha256),
            );
            publish_exact_private_file(
                &output_mount,
                &output_mount.join(&archive_relative_path),
                &archive,
            )?;
            archives.push(SealedDockerArchiveEntryV12 {
                reference: object,
                archive_relative_path,
                archive_bytes: archive.len() as u64,
                archive_sha256,
            });
        }
        let closure = SealedDockerArtifactClosureV12 {
            version: PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12.to_owned(),
            source_manifest_sha256:
                expected.0.source_manifest_sha256,
            build_plan_sha256: expected.0.build_plan_sha256,
            files_sha256: expected.0.files_sha256,
            archives: archives.clone(),
        };
        let closure_sha256 =
            sha256(&canonical_plan_bytes(&closure).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?);
        if closure_sha256 != expected.0.object_sha256 {
            return Err(ControllerError::Rejected(
                "private DinD exported Docker archive closure differs from the signed artifact object",
            ));
        }
        let manifest_projection =
            sealed_docker_artifact_manifest_projection_v12(
                expected.0.object_sha256,
                expected.0.source_manifest_sha256,
                expected.0.build_plan_sha256,
                expected.0.files_sha256,
                closure_sha256,
                &archives,
            );
        let manifest_projection_sha256 = sha256(
            &canonical_plan_bytes(&manifest_projection).map_err(
                |error| {
                    ControllerError::InvalidOwned(error.to_string())
                },
            )?,
        );
        if manifest_projection_sha256
            != expected.0.manifest_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD exported Docker archive manifest differs from the signed artifact manifest",
            ));
        }
        let manifest = SealedDockerArtifactManifestV12 {
            version: PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12.to_owned(),
            format: "docker-image-archive".to_owned(),
            artifact_object_sha256: expected.0.object_sha256,
            artifact_manifest_sha256: expected.0.manifest_sha256,
            closure_sha256,
            source_manifest_sha256:
                expected.0.source_manifest_sha256,
            build_plan_sha256: expected.0.build_plan_sha256,
            files_sha256: expected.0.files_sha256,
            archives,
        };
        let metadata =
            canonical_plan_bytes(&manifest).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        if metadata.len() > 16 * 1024 * 1024 {
            return Err(ControllerError::Rejected(
                "private DinD exported Docker archive metadata exceeds its bound",
            ));
        }
        publish_exact_private_file(
            &output_mount,
            &output_mount.join(PRIVATE_DIND_ARTIFACT_METADATA_V12),
            &metadata,
        )?;
        let output_fd = open_directory_fd_v12(&output_mount)?;
        let fd_identity = directory_fd_identity_sha256_v12(
            output_fd.as_raw_fd(),
        )?;
        let result = json!({
            "artifactManifest": manifest,
            "attachedDirectoryFdSha256": fd_identity,
            "exportTranscriptSha256": sha256(&[
                operation.request.request_sha256.as_slice(),
                closure_sha256.as_slice(),
                manifest_projection_sha256.as_slice(),
                fd_identity.as_slice(),
            ].concat()),
            "lane": operation.request.lane,
            "planId": operation.request.plan_id,
            "version": PRIVATE_DIND_RESULT_VERSION_V12,
        });
        let result = canonical_plan_bytes(&result).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let observed = sha256(
            &[
                b"serverware/private-dind-export-observed/v12\0"
                    .as_slice(),
                closure_sha256.as_slice(),
                manifest_projection_sha256.as_slice(),
                fd_identity.as_slice(),
            ]
            .concat(),
        );
        Ok((result, output_fd, observed))
    }

    fn verify_exact_export_image_set_v12(
        &self,
        operation: &DockerLaneOperationV12,
        expected_repositories: &[String],
    ) -> Result<()> {
        let filters = canonical_json_bytes_v12(&json!({
            "label": [
                format!(
                    "{}={}",
                    OWNER_LABEL_V12,
                    operation.owner_namespace,
                ),
                format!(
                    "{}={}",
                    GENERATION_LABEL_V12,
                    operation.daemon_generation,
                )
            ]
        }))?;
        let filters = std::str::from_utf8(&filters).map_err(|_| {
            ControllerError::Invalid(
                "private DinD image filters are not UTF-8",
            )
        })?;
        let response = self.docker_http_v12(
            operation,
            "GET",
            &format!(
                "/v1.45/images/json?all=1&filters={}",
                percent_encode_query_v12(filters),
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        let images = require_docker_success_v12(&response, &[200])?;
        let images = images.as_array().ok_or(
            ControllerError::Invalid(
                "private DinD owner image list is not an array",
            ),
        )?;
        let expected = expected_repositories
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        let lane_id = operation.lane_id();
        for image in images {
            let labels = image
                .get("Labels")
                .and_then(Value::as_object)
                .ok_or(ControllerError::Rejected(
                    "private DinD export image lacks owner labels",
                ))?;
            if labels.get(OWNER_LABEL_V12).and_then(Value::as_str)
                != Some(operation.owner_namespace.as_str())
                || labels
                    .get(GENERATION_LABEL_V12)
                    .and_then(Value::as_str)
                    != Some(operation.daemon_generation.as_str())
                || labels.get(LANE_LABEL_V12).and_then(Value::as_str)
                    != Some(lane_id.as_str())
            {
                return Err(ControllerError::Rejected(
                    "private DinD export image crossed ownership labels",
                ));
            }
            let tags = image
                .get("RepoTags")
                .and_then(Value::as_array)
                .ok_or(ControllerError::Rejected(
                    "private DinD export image lacks exact repository tags",
                ))?;
            for tag in tags {
                let tag = tag.as_str().ok_or(
                    ControllerError::Invalid(
                        "private DinD image tag is not text",
                    ),
                )?;
                if tag != "<none>:<none>" {
                    if !expected.contains(tag) {
                        return Err(ControllerError::Rejected(
                            "private DinD owner image has an unexpected export tag",
                        ));
                    }
                    observed.insert(tag.to_owned());
                }
            }
        }
        if images.is_empty() || observed != expected {
            return Err(ControllerError::Rejected(
                "private DinD owner image closure differs from signed export repositories",
            ));
        }
        Ok(())
    }

    fn verify_imported_image_v12(
        &self,
        operation: &DockerLaneOperationV12,
        object: &OciObjectReference,
    ) -> Result<()> {
        let reference = exact_image_reference_v12(object);
        let response = self.docker_http_v12(
            operation,
            "GET",
            &format!(
                "/v1.45/images/{}/json",
                percent_encode_path_v12(&reference),
            ),
            Vec::new(),
            DockerRequestBodyV12::Empty,
            DockerStreamModeV11::BoundedHttp,
        )?;
        let image = require_docker_success_v12(&response, &[200])?;
        let repo_digests = image
            .get("RepoDigests")
            .and_then(Value::as_array)
            .ok_or(ControllerError::Rejected(
                "private DinD imported image lacks repository digests",
            ))?;
        if !repo_digests
            .iter()
            .filter_map(Value::as_str)
            .any(|value| value == reference)
        {
            return Err(ControllerError::Rejected(
                "private DinD imported image differs from its signed manifest digest",
            ));
        }
        Ok(())
    }

    fn query_authoritative_response_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<AuthoritativeReplayV12> {
        let query = match &operation.decoded_payload {
            DockerLaneDecodedPayloadV12::Query(query) => query,
            _ => {
                return Err(ControllerError::Rejected(
                    "private DinD query payload changed after policy",
                ))
            }
        };
        let original = self
            .ledger
            .operation_by_request_sha256(
                query.original_request_sha256,
            )?
            .ok_or(ControllerError::Rejected(
                "private DinD query references an unknown operation",
            ))?;
        if original.plan_id != operation.request.plan_id
            || original.lane != operation.request.lane
            || original.operation != query.original_operation
        {
            return Err(ControllerError::Rejected(
                "private DinD query crossed plan, lane, or operation authority",
            ));
        }
        if !matches!(
            original.status,
            DockerLaneOperationStatusV12::Applied
                | DockerLaneOperationStatusV12::Destroyed
        ) {
            self.destroy_generation_by_identity_v12(
                &original.owner_namespace,
                &original.daemon_generation,
                original.request_sha256,
                operation.request.deadline_boottime_ns,
            )?;
            let generation = self
                .ledger
                .generation(
                    &original.owner_namespace,
                    &original.daemon_generation,
                )?
                .ok_or(ControllerError::Rejected(
                    "private DinD reconciled query generation disappeared",
                ))?;
            let observed = generation.observed_state_sha256.ok_or(
                ControllerError::Rejected(
                    "private DinD reconciled query lacks terminal observation",
                ),
            )?;
            return Ok(AuthoritativeReplayV12 {
                state: AuthoritativeLaneState::Destroyed,
                result: canonical_plan_bytes(&json!({
                    "originalRequestSha256": original.request_sha256,
                    "status": "OUTCOME_UNKNOWN_DESTROYED",
                    "version": PRIVATE_DIND_RESULT_VERSION_V12,
                }))
                .map_err(|error| {
                    ControllerError::InvalidOwned(error.to_string())
                })?,
                returned_fd_roles: Vec::new(),
                observed_state_sha256: observed,
                terminal_destruction_receipt: Some(
                    self.terminal_receipt_for_operation_v12(
                        operation,
                    )?,
                ),
                returned_fds: Vec::new(),
            });
        }
        let (response, _) = self.ledger.replay_response(&original)?;
        let fds = self.recreate_replay_fds_for_record_v12(
            &original,
            &response,
        )?;
        Ok(AuthoritativeReplayV12 {
            state: response.authoritative_state,
            result: response.result,
            returned_fd_roles: response.returned_fd_roles,
            observed_state_sha256:
                response.observed_state_sha256,
            terminal_destruction_receipt:
                response.terminal_destruction_receipt,
            returned_fds: fds,
        })
    }

    fn reconcile_uncertain_operation_v12(
        &self,
        lifecycle_request: &PrivateDindOperationRequestV12,
        operation: &DockerLaneOperationV12,
        _policy: &DockerLanePolicyDecisionV12,
        record: DockerLaneOperationRecordV12,
    ) -> Result<(PrivateDindOperationResponseV12, Vec<OwnedFd>)> {
        if matches!(
            record.status,
            DockerLaneOperationStatusV12::Applied
                | DockerLaneOperationStatusV12::Destroyed
        ) {
            let (response, _) = self.ledger.replay_response(&record)?;
            let fds =
                self.recreate_replay_fds_v12(operation, &response)?;
            return Ok((response, fds));
        }
        self.destroy_generation_by_identity_v12(
            &record.owner_namespace,
            &record.daemon_generation,
            record.request_sha256,
            operation.request.deadline_boottime_ns,
        )?;
        let generation = self
            .ledger
            .generation(
                &record.owner_namespace,
                &record.daemon_generation,
            )?
            .ok_or(ControllerError::Rejected(
                "private DinD reconciled generation disappeared",
            ))?;
        let observed = generation.observed_state_sha256.ok_or(
            ControllerError::Rejected(
                "private DinD reconciled generation lacks terminal evidence",
            ),
        )?;
        let result = canonical_plan_bytes(&json!({
            "originalRequestSha256": record.request_sha256,
            "status": "OUTCOME_UNKNOWN_DESTROYED",
            "version": PRIVATE_DIND_RESULT_VERSION_V12,
        }))
        .map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let response = PrivateDindOperationResponseV12::seal(
            lifecycle_request,
            PrivateDindOperationDispositionV12::OutcomeUnknown,
            AuthoritativeLaneState::Destroyed,
            result,
            Vec::new(),
            observed,
        )?
        .with_terminal_destruction_receipt(
            self.terminal_receipt_for_operation_v12(operation)?,
        )?
        .sign(lifecycle_request, &self.signing_key)?;
        self.ledger.commit_operation(record, &response)?;
        Ok((response, Vec::new()))
    }

    fn recreate_replay_fds_v12(
        &self,
        operation: &DockerLaneOperationV12,
        response: &PrivateDindOperationResponseV12,
    ) -> Result<Vec<OwnedFd>> {
        if response.returned_fd_roles.is_empty() {
            return Ok(Vec::new());
        }
        if response.returned_fd_roles
            != vec!["artifactCasDirectory".to_owned()]
            || !matches!(
                operation.request.operation,
                ProxyOperation::ExportOwnedOci
            ) && !matches!(
                &operation.decoded_payload,
                DockerLaneDecodedPayloadV12::Query(query)
                    if query.original_operation
                        == ProxyOperation::ExportOwnedOci
            )
        {
            return Err(ControllerError::Rejected(
                "private DinD replay descriptor role is invalid",
            ));
        }
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = require_active_handle_v12(&state, operation)?;
        Ok(vec![open_directory_fd_v12(&handle.output_mount)?])
    }

    fn recreate_replay_fds_for_record_v12(
        &self,
        record: &DockerLaneOperationRecordV12,
        response: &PrivateDindOperationResponseV12,
    ) -> Result<Vec<OwnedFd>> {
        if response.returned_fd_roles.is_empty() {
            return Ok(Vec::new());
        }
        if record.operation != ProxyOperation::ExportOwnedOci
            || response.returned_fd_roles
                != vec!["artifactCasDirectory".to_owned()]
        {
            return Err(ControllerError::Rejected(
                "private DinD query replay descriptor role is invalid",
            ));
        }
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = state.active.get(&record.daemon_generation).ok_or(
            ControllerError::Rejected(
                "private DinD export replay output is no longer retained",
            ),
        )?;
        Ok(vec![open_directory_fd_v12(&handle.output_mount)?])
    }

    fn docker_json_v12(
        &self,
        operation: &DockerLaneOperationV12,
        method: &str,
        target: &str,
        value: &Value,
    ) -> Result<Vec<u8>> {
        let body = canonical_json_bytes_v12(value)?;
        self.docker_http_v12(
            operation,
            method,
            target,
            vec![(
                "content-type".to_owned(),
                "application/json".to_owned(),
            )],
            DockerRequestBodyV12::Bytes(body),
            DockerStreamModeV11::BoundedHttp,
        )
    }

    fn docker_http_v12(
        &self,
        operation: &DockerLaneOperationV12,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: DockerRequestBodyV12,
        stream_mode: DockerStreamModeV11,
    ) -> Result<Vec<u8>> {
        self.docker_http_v12_with_deadline(operation, method, target, headers, body,
            stream_mode, operation.request.deadline_boottime_ns)
    }

    fn docker_http_v12_with_deadline(
        &self,
        operation: &DockerLaneOperationV12,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: DockerRequestBodyV12,
        stream_mode: DockerStreamModeV11,
        deadline_boottime_ns: u64,
    ) -> Result<Vec<u8>> {
        self.docker_http_v12_with_cancellation(operation, method, target, headers,
            body, stream_mode, deadline_boottime_ns, Arc::new(AtomicBool::new(false)))
    }

    fn connect_private_dind_v12(
        &self,
        operation: &DockerLaneOperationV12,
        deadline_boottime_ns: u64,
    ) -> Result<UnixStream> {
        if deadline_boottime_ns > operation.request.deadline_boottime_ns
            || boottime_now_ns_v11()? >= deadline_boottime_ns
        {
            return Err(ControllerError::Rejected("private DinD transport deadline widened or expired"));
        }
        let socket = {
            let state = self.state.lock().map_err(|_| {
                ControllerError::Rejected(
                    "private DinD lifecycle mutex is poisoned",
                )
            })?;
            let handle = require_active_handle_v12(&state, operation)?;
            if process_start_time(handle.pid)?
                != handle.start_time_ticks
            {
                return Err(ControllerError::Rejected(
                    "private DinD daemon process identity changed",
                ));
            }
            handle.socket.clone()
        };
        connect_private_dind_stream_v12(&socket, deadline_boottime_ns)
    }

    fn docker_http_v12_with_cancellation(
        &self,
        operation: &DockerLaneOperationV12,
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
        body: DockerRequestBodyV12,
        stream_mode: DockerStreamModeV11,
        deadline_boottime_ns: u64,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Vec<u8>> {
        if cancelled.load(Ordering::Acquire) {
            return Err(ControllerError::Rejected("private DinD body transport was cancelled"));
        }
        let body_bytes = match &body {
            DockerRequestBodyV12::Empty => 0,
            DockerRequestBodyV12::Bytes(bytes) => bytes.len() as u64,
            DockerRequestBodyV12::File { bytes, .. } => *bytes,
        };
        let head = canonical_docker_request_head_v12(
            method,
            target,
            &headers,
            body_bytes,
        )?;
        let mut daemon = self.connect_private_dind_v12(operation, deadline_boottime_ns)?;
        let contract = DockerHttpExchangeContractV12 {
            stream_mode,
            max_request_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            max_response_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            max_stream_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            deadline_boottime_ns,
        };
        match execute_bounded_docker_http_v12_with_cancellation(
            &mut daemon,
            head,
            body,
            &contract,
            cancelled,
        ) {
            DockerDirectHttpOutcomeV12::Complete(receipt) => {
                Ok(receipt.response)
            }
            DockerDirectHttpOutcomeV12::RejectedBeforeSend(error) => {
                Err(error)
            }
            DockerDirectHttpOutcomeV12::PostSendUncertain {
                request_bytes_sent,
                response_bytes_received,
                error,
            } => Err(ControllerError::InvalidOwned(format!(
                "POST_SEND_UNCERTAIN requestBytes={request_bytes_sent} responseBytes={response_bytes_received}: {error}",
            ))),
        }
    }

    fn drain_generation_resources_v12(
        &self,
        generation: &DockerGenerationRecordV12,
        deadline_boottime_ns: u64,
    ) -> Result<DockerResourceDrainV12> {
        let socket = self.config.private_socket_root.join(format!(
            "{}.sock",
            generation.daemon_generation,
        ));
        if !generation.docker_authority_established {
            return Ok(DockerResourceDrainV12 {
                drained: DockerResourceInventoryV12::default(),
                terminal: DockerResourceInventoryV12::default(),
            });
        }
        if !socket.exists() {
            return Err(ControllerError::InvalidOwned(format!(
                "private DinD generation {} has no live Docker authority for resource inventory; recovery must restore the exact daemon before cleanup",
                generation.daemon_generation,
            )));
        }
        let before = self.list_owned_docker_objects_v12(
            &socket,
            generation,
            deadline_boottime_ns,
        )?;
        for id in &before.containers {
            let response = self.docker_http_on_socket_v12(
                &socket,
                deadline_boottime_ns,
                "DELETE",
                &format!(
                    "/v1.45/containers/{}?force=1&v=1",
                    percent_encode_path_v12(id),
                ),
            )?;
            require_docker_success_v12(&response, &[204, 404])?;
        }
        for id in &before.networks {
            let response = self.docker_http_on_socket_v12(
                &socket,
                deadline_boottime_ns,
                "DELETE",
                &format!(
                    "/v1.45/networks/{}",
                    percent_encode_path_v12(id),
                ),
            )?;
            require_docker_success_v12(&response, &[204, 404])?;
        }
        for name in &before.volumes {
            let response = self.docker_http_on_socket_v12(
                &socket,
                deadline_boottime_ns,
                "DELETE",
                &format!(
                    "/v1.45/volumes/{}?force=1",
                    percent_encode_path_v12(name),
                ),
            )?;
            require_docker_success_v12(&response, &[204, 404])?;
        }
        for id in &before.images {
            let response = self.docker_http_on_socket_v12(
                &socket,
                deadline_boottime_ns,
                "DELETE",
                &format!(
                    "/v1.45/images/{}?force=1&noprune=0",
                    percent_encode_path_v12(id),
                ),
            )?;
            require_docker_success_v12(&response, &[200, 404])?;
        }
        let after = self.list_owned_docker_objects_v12(
            &socket,
            generation,
            deadline_boottime_ns,
        )?;
        let terminal = DockerResourceInventoryV12 {
            containers: after.containers.len() as u64,
            images: after.images.len() as u64,
            networks: after.networks.len() as u64,
            volumes: after.volumes.len() as u64,
        };
        if terminal != DockerResourceInventoryV12::default() {
            return Err(ControllerError::Rejected(
                "private DinD terminal resource inventory is nonzero",
            ));
        }
        Ok(DockerResourceDrainV12 {
            drained: DockerResourceInventoryV12 {
                containers: before.containers.len() as u64,
                images: before.images.len() as u64,
                networks: before.networks.len() as u64,
                volumes: before.volumes.len() as u64,
            },
            terminal,
        })
    }

    fn list_owned_docker_objects_v12(
        &self,
        socket: &Path,
        generation: &DockerGenerationRecordV12,
        deadline_boottime_ns: u64,
    ) -> Result<DockerOwnedObjectsV12> {
        let containers = require_docker_success_v12(
            &self.docker_http_on_socket_v12(
                socket,
                deadline_boottime_ns,
                "GET",
                "/v1.45/containers/json?all=1",
            )?,
            &[200],
        )?;
        let images = require_docker_success_v12(
            &self.docker_http_on_socket_v12(
                socket,
                deadline_boottime_ns,
                "GET",
                "/v1.45/images/json?all=1",
            )?,
            &[200],
        )?;
        let networks = require_docker_success_v12(
            &self.docker_http_on_socket_v12(
                socket,
                deadline_boottime_ns,
                "GET",
                "/v1.45/networks",
            )?,
            &[200],
        )?;
        let volumes = require_docker_success_v12(
            &self.docker_http_on_socket_v12(
                socket,
                deadline_boottime_ns,
                "GET",
                "/v1.45/volumes",
            )?,
            &[200],
        )?;
        let empty_volumes = Value::Array(Vec::new());
        let volume_entries = match volumes.get("Volumes") {
            Some(value) if !value.is_null() => value,
            _ => &empty_volumes,
        };
        let mut objects = DockerOwnedObjectsV12 {
            containers: docker_resource_ids_v12(
                &containers,
                "Id",
            )?,
            images: docker_resource_ids_v12(
                &images,
                "Id",
            )?,
            networks: private_dind_network_ids_v12(
                &networks,
                generation,
            )?,
            volumes: docker_resource_ids_v12(
                volume_entries,
                "Name",
            )?,
        };
        for ids in [
            &mut objects.containers,
            &mut objects.images,
            &mut objects.networks,
            &mut objects.volumes,
        ] {
            ids.sort();
            ids.dedup();
            if ids.len() > 100_000 {
                return Err(ControllerError::Rejected(
                    "private DinD resource inventory exceeds its bound",
                ));
            }
        }
        Ok(objects)
    }

    fn docker_http_on_socket_v12(
        &self,
        socket: &Path,
        deadline_boottime_ns: u64,
        method: &str,
        target: &str,
    ) -> Result<Vec<u8>> {
        if boottime_now_ns_v11()? >= deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "private DinD resource operation exceeded its deadline",
            ));
        }
        let head = canonical_docker_request_head_v12(
            method,
            target,
            &[],
            0,
        )?;
        let mut daemon = UnixStream::connect(socket)?;
        let contract = DockerHttpExchangeContractV12 {
            stream_mode: DockerStreamModeV11::BoundedHttp,
            max_request_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            max_response_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            max_stream_bytes: PRIVATE_DIND_MAX_HTTP_BYTES_V12,
            deadline_boottime_ns,
        };
        match execute_bounded_docker_http_v12(
            &mut daemon,
            head,
            DockerRequestBodyV12::Empty,
            &contract,
        ) {
            DockerDirectHttpOutcomeV12::Complete(receipt) => {
                Ok(receipt.response)
            }
            DockerDirectHttpOutcomeV12::RejectedBeforeSend(error) => {
                Err(error)
            }
            DockerDirectHttpOutcomeV12::PostSendUncertain {
                request_bytes_sent,
                response_bytes_received,
                error,
            } => Err(ControllerError::InvalidOwned(format!(
                "POST_SEND_UNCERTAIN requestBytes={request_bytes_sent} responseBytes={response_bytes_received}: {error}",
            ))),
        }
    }

    fn observe_generation_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<Digest> {
        let state = self.state.lock().map_err(|_| {
            ControllerError::Rejected(
                "private DinD lifecycle mutex is poisoned",
            )
        })?;
        let handle = require_active_handle_v12(&state, operation)?;
        let socket_metadata = std::fs::symlink_metadata(&handle.socket)?;
        let generation_metadata =
            std::fs::symlink_metadata(&handle.generation_root)?;
        let cgroup_events =
            std::fs::read(handle.cgroup.join("cgroup.events"))?;
        let observation = json!({
            "cgroupEventsSha256": sha256(&cgroup_events),
            "daemonGeneration": handle.daemon_generation,
            "generationDevice": generation_metadata.dev(),
            "generationInode": generation_metadata.ino(),
            "netnsName": handle.netns_name,
            "ownerNamespace": handle.owner_namespace,
            "pid": handle.pid,
            "processStartTimeTicks": handle.start_time_ticks,
            "profile": handle.profile,
            "runners": handle.runners.iter().map(|(lane, runner)| {
                Ok(json!({
                    "lane": lane,
                    "containerId": runner.id,
                    "runnerIdentitySha256": plan_sha256_bytes(
                        &canonical_plan_bytes(&runner.identity).map_err(|error| {
                            ControllerError::InvalidOwned(error.to_string())
                        })?,
                    ),
                    "createRequestSha256": sha256(&canonical_json_bytes_v12(
                        &runner.expected_create,
                    )?),
                    "createdInspectSha256": runner.created_inspect_sha256,
                    "prestartInspectSha256": runner.prestart_inspect_sha256,
                    "outputDirectoryIdentitySha256": runner.output_identity_sha256,
                    "outputStorageIdentitySha256": runner.output_storage_identity_sha256,
                }))
            }).collect::<Result<Vec<Value>>>()?,
            "socketDevice": socket_metadata.dev(),
            "socketInode": socket_metadata.ino(),
            "version": "serverware/private-dind-observation/v12",
        });
        Ok(sha256(
            &canonical_plan_bytes(&observation).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        ))
    }

    fn destroy_generation_by_identity_v12(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        request_sha256: Digest,
        deadline: u64,
    ) -> Result<()> {
        let generation = self
            .ledger
            .generation(owner_namespace, daemon_generation)?
            .ok_or(ControllerError::Rejected(
                "private DinD destruction generation is absent from ledger",
            ))?;
        self.destroy_generation_record_v12(
            &generation,
            request_sha256,
            deadline,
        )
    }

    fn destroy_generation_record_v12(
        &self,
        generation: &DockerGenerationRecordV12,
        request_sha256: Digest,
        deadline: u64,
    ) -> Result<()> {
        if generation.status == DockerLaneOperationStatusV12::Destroyed
            && generation.state == AuthoritativeLaneState::Destroyed
            && generation.terminal_receipt_sha256.is_some()
        {
            self.terminal_receipt_for_generation_v12(
                &generation.owner_namespace,
                &generation.daemon_generation,
            )?;
            return Ok(());
        }
        let before = sha256(
            &canonical_plan_bytes(generation).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        self.ledger.begin_destroying_generation(
            &generation.owner_namespace,
            &generation.daemon_generation,
            before,
        )?;
        if let Some(observation) =
            self.ledger.pending_destruction_observation(
                &generation.owner_namespace,
                &generation.daemon_generation,
            )?
        {
            return self.finish_destruction_observation_v12(
                generation,
                &observation,
            );
        }
        let resource_drain = self.drain_generation_resources_v12(
            generation,
            deadline,
        )?;
        let generation_root = self
            .config
            .dind_root
            .join(&generation.owner_namespace)
            .join(&generation.daemon_generation);
        let retained_process =
            retained_process_identity_v12(&generation_root, generation)?;
        let mut failures = Vec::new();
        if let Ok(mut state) = self.state.lock() {
            if let Some(mut handle) =
                state.active.remove(&generation.daemon_generation)
            {
                if let Err(error) =
                    kill_and_reap_private_dind_v12(&mut handle, deadline)
                {
                    failures.push(error.to_string());
                }
            }
        } else {
            failures.push(
                "private DinD lifecycle mutex poisoned during destruction"
                    .to_owned(),
            );
        }
        if let Err(error) = cleanup_private_dind_root_v12(
            &generation_root,
            &self.config,
            generation,
            deadline,
        ) {
            failures.push(error.to_string());
        }
        let lane_slot = generation.lane_slot.to_string();
        let cleanup_ruleset =
            path_text_v12(&self.config.lane_cleanup_ruleset)?;
        let network_ledger =
            path_text_v12(&self.config.network_ownership_ledger)?;
        let network_arguments = [
            "destroy-lane",
            generation.daemon_generation.as_str(),
            lane_slot.as_str(),
            cleanup_ruleset.as_str(),
            network_ledger.as_str(),
        ];
        let network_allocation = network_ownership_record_v12(
            &self.config.network_ownership_ledger,
            &generation.daemon_generation,
            generation.lane_slot,
        )?;
        let network_namespace = match (
            network_allocation.as_ref(),
            generation.network_namespace.as_deref(),
        ) {
            (Some(allocation), Some(retained))
                if allocation.namespace != retained =>
            {
                return Err(ControllerError::Rejected(
                    "private DinD network allocation differs from durable generation authority",
                ))
            }
            (Some(allocation), _) => allocation.namespace.clone(),
            (None, Some(retained)) => retained.to_owned(),
            (None, None) => {
                return Err(ControllerError::Rejected(
                    "private DinD generation lacks an exact network namespace identity",
                ))
            }
        };
        match network_allocation.as_ref() {
            Some(_) => {
                if let Err(error) =
                    self.run_network_hook_v12(&network_arguments, deadline)
                {
                    failures.push(error.to_string());
                }
            }
            None => {}
        }
        if !failures.is_empty() {
            return Err(ControllerError::InvalidOwned(format!(
                "private DinD destruction attempted every owned cleanup path: {}",
                failures.join("; "),
            )));
        }
        let observation = observe_terminal_absence_v12(
            &self.config,
            generation,
            retained_process,
            Some(&network_namespace),
        )?;
        let resource_observation =
            canonical_plan_bytes(&json!({
                "drainedContainers": resource_drain.drained.containers,
                "drainedImages": resource_drain.drained.images,
                "drainedNetworks": resource_drain.drained.networks,
                "drainedVolumes": resource_drain.drained.volumes,
                "dockerAuthorityEstablished":
                    generation.docker_authority_established,
                "dockerInternalStorageAbsenceProof":
                    DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
                "dockerTopLevelObjectCountScope":
                    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
                "terminalContainers": resource_drain.terminal.containers,
                "terminalImages": resource_drain.terminal.images,
                "terminalNetworks": resource_drain.terminal.networks,
                "terminalVolumes": resource_drain.terminal.volumes,
                "version": "serverware/private-dind-resource-drain/v12",
            }))
            .map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        let resource_observation_sha256 =
            sha256(&resource_observation);
        let observed_state_sha256 = sha256(
            &[
                b"serverware/private-dind-terminal-state/v12\0"
                    .as_slice(),
                observation.sha256.as_slice(),
                resource_observation_sha256.as_slice(),
            ]
            .concat(),
        );
        let mut durable_observation =
            DockerGenerationDestructionObservationV12 {
                version:
                    "serverware/private-dind-destruction-observation/v12"
                        .to_owned(),
                boot_id_sha256: generation.boot_id_sha256,
                plan_id: generation.plan_id,
                capability_sha256: generation.capability_sha256,
                profile: generation.profile,
                owner_namespace:
                    generation.owner_namespace.clone(),
                daemon_generation:
                    generation.daemon_generation.clone(),
                network_namespace,
                request_sha256,
                observed_at_boottime_ns: boottime_now_ns_v11()?,
                docker_top_level_object_count_scope:
                    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12.to_owned(),
                docker_internal_storage_absence_proof:
                    DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12.to_owned(),
                drained_containers:
                    resource_drain.drained.containers,
                drained_images: resource_drain.drained.images,
                drained_networks: resource_drain.drained.networks,
                drained_volumes: resource_drain.drained.volumes,
                terminal_containers:
                    resource_drain.terminal.containers,
                terminal_images: resource_drain.terminal.images,
                terminal_networks: resource_drain.terminal.networks,
                terminal_volumes: resource_drain.terminal.volumes,
                docker_authority_established:
                    generation.docker_authority_established,
                mounts: 0,
                cgroup_processes: 0,
                proxy_accepting: false,
                dind_reaped: observation.dind_reaped,
                netns_absent: observation.netns_absent,
                socket_absent: observation.socket_absent,
                state_root_absent:
                    observation.state_root_absent,
                observed_state_sha256,
                observation_sha256: [0; 32],
            };
        durable_observation.observation_sha256 = sha256(
            &canonical_plan_bytes(&durable_observation).map_err(
                |error| {
                    ControllerError::InvalidOwned(error.to_string())
                },
            )?,
        );
        self.ledger.commit_destruction_observation(
            &durable_observation,
        )?;
        self.finish_destruction_observation_v12(
            generation,
            &durable_observation,
        )
    }

    fn finish_destruction_observation_v12(
        &self,
        generation: &DockerGenerationRecordV12,
        durable_observation:
            &DockerGenerationDestructionObservationV12,
    ) -> Result<()> {
        if durable_observation.boot_id_sha256
                != generation.boot_id_sha256
            || durable_observation.plan_id != generation.plan_id
            || durable_observation.capability_sha256
                != generation.capability_sha256
            || durable_observation.profile != generation.profile
            || durable_observation.owner_namespace
                != generation.owner_namespace
            || durable_observation.daemon_generation
                != generation.daemon_generation
            || generation.network_namespace.as_deref()
                != Some(
                    durable_observation.network_namespace.as_str(),
                )
        {
            return Err(ControllerError::Rejected(
                "durable destruction observation crossed generation authority",
            ));
        }
        let current_absence = observe_terminal_absence_v12(
            &self.config,
            generation,
            generation.dind_pid.zip(
                generation.dind_start_time_ticks,
            ),
            Some(
                durable_observation.network_namespace.as_str(),
            ),
        )?;
        let resource_observation =
            canonical_plan_bytes(&json!({
                "drainedContainers":
                    durable_observation.drained_containers,
                "drainedImages": durable_observation.drained_images,
                "drainedNetworks":
                    durable_observation.drained_networks,
                "drainedVolumes": durable_observation.drained_volumes,
                "dockerAuthorityEstablished":
                    durable_observation
                        .docker_authority_established,
                "dockerInternalStorageAbsenceProof":
                    durable_observation
                        .docker_internal_storage_absence_proof
                        .as_str(),
                "dockerTopLevelObjectCountScope":
                    durable_observation
                        .docker_top_level_object_count_scope
                        .as_str(),
                "terminalContainers":
                    durable_observation.terminal_containers,
                "terminalImages":
                    durable_observation.terminal_images,
                "terminalNetworks":
                    durable_observation.terminal_networks,
                "terminalVolumes":
                    durable_observation.terminal_volumes,
                "version":
                    "serverware/private-dind-resource-drain/v12",
            }))
            .map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        let resource_observation_sha256 =
            sha256(&resource_observation);
        let observed_state_sha256 = sha256(
            &[
                b"serverware/private-dind-terminal-state/v12\0"
                    .as_slice(),
                current_absence.sha256.as_slice(),
                resource_observation_sha256.as_slice(),
            ]
            .concat(),
        );
        if observed_state_sha256
                != durable_observation.observed_state_sha256
            || durable_observation.dind_reaped
                != current_absence.dind_reaped
            || durable_observation.netns_absent
                != current_absence.netns_absent
            || durable_observation.socket_absent
                != current_absence.socket_absent
            || durable_observation.state_root_absent
                != current_absence.state_root_absent
        {
            return Err(ControllerError::Rejected(
                "current terminal absence differs from durable destruction observation",
            ));
        }
        let mut receipt = RootTerminalDestructionReceiptV12 {
            version:
                "serverware/private-dind-terminal-destruction/v12"
                    .to_owned(),
            trust_profile:
                "trusted-host-userspace-digest-no-ima".to_owned(),
            plan_id: generation.plan_id,
            capability_sha256: generation.capability_sha256,
            profile: generation.profile,
            owner_namespace: generation.owner_namespace.clone(),
            daemon_generation:
                generation.daemon_generation.clone(),
            network_namespace:
                durable_observation.network_namespace.clone(),
            request_sha256:
                durable_observation.request_sha256,
            observed_at_boottime_ns:
                durable_observation.observed_at_boottime_ns,
            docker_top_level_object_count_scope:
                durable_observation
                    .docker_top_level_object_count_scope
                    .clone(),
            docker_internal_storage_absence_proof:
                durable_observation
                    .docker_internal_storage_absence_proof
                    .clone(),
            drained_containers:
                durable_observation.drained_containers,
            drained_images: durable_observation.drained_images,
            drained_networks:
                durable_observation.drained_networks,
            drained_volumes: durable_observation.drained_volumes,
            containers:
                durable_observation.terminal_containers,
            images: durable_observation.terminal_images,
            networks: durable_observation.terminal_networks,
            volumes: durable_observation.terminal_volumes,
            docker_authority_established:
                durable_observation.docker_authority_established,
            mounts: durable_observation.mounts,
            cgroup_processes:
                durable_observation.cgroup_processes,
            proxy_accepting:
                durable_observation.proxy_accepting,
            ledger_terminal: true,
            dind_reaped: durable_observation.dind_reaped,
            netns_absent: durable_observation.netns_absent,
            socket_absent: durable_observation.socket_absent,
            state_root_absent:
                durable_observation.state_root_absent,
            observed_state_sha256:
                durable_observation.observed_state_sha256,
            signer_spki_sha256:
                self.config.root_signer_spki_sha256,
            signer_public_key_spki_der: self
                .signing_key
                .verifying_key()
                .to_public_key_der()
                .map_err(|_| {
                    ControllerError::Invalid(
                        "private DinD terminal signer public key cannot be encoded",
                    )
                })?
                .as_bytes()
                .to_vec(),
            signature: Vec::new(),
            receipt_sha256: [0; 32],
        };
        let unsigned = canonical_plan_bytes(&receipt).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        receipt.signature = self
            .signing_key
            .sign(
                &[
                    b"serverware/private-dind-terminal-receipt/v12\0"
                        .as_slice(),
                    unsigned.as_slice(),
                ]
                .concat(),
            )
            .to_bytes()
            .to_vec();
        receipt.receipt_sha256 = sha256(
            &canonical_plan_bytes(&receipt).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        let exact_receipt =
            canonical_plan_bytes(&receipt).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?;
        self.ledger.commit_destroyed_generation(
            &generation.owner_namespace,
            &generation.daemon_generation,
            durable_observation,
            &exact_receipt,
        )?;
        let exact_receipt_sha256 = sha256(&exact_receipt);
        let receipt_path = self.config.terminal_receipt_root.join(
            format!("{}.json", digest_hex(&exact_receipt_sha256)),
        );
        publish_exact_private_file(
            &self.config.terminal_receipt_root,
            &receipt_path,
            &exact_receipt,
        )?;
        Ok(())
    }

    fn terminal_receipt_for_operation_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<Vec<u8>> {
        self.terminal_receipt_for_generation_v12(
            &operation.owner_namespace,
            &operation.daemon_generation,
        )
        .map(|(_, exact)| exact)
    }

    fn terminal_receipt_for_generation_v12(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<(RootTerminalDestructionReceiptV12, Vec<u8>)> {
        let generation = self
            .ledger
            .generation(owner_namespace, daemon_generation)?
            .ok_or(ControllerError::Rejected(
                "private DinD terminal receipt generation is absent",
            ))?;
        let digest = generation.terminal_receipt_sha256.ok_or(
            ControllerError::Rejected(
                "private DinD terminal receipt digest is absent",
            ),
        )?;
        let receipt = self.ledger.exact_terminal_receipt(
            owner_namespace,
            daemon_generation,
        )?;
        if sha256(&receipt) != digest {
            return Err(ControllerError::Rejected(
                "private DinD terminal receipt differs from terminal ledger",
            ));
        }
        let mirror = self
            .config
            .terminal_receipt_root
            .join(format!("{}.json", digest_hex(&digest)));
        publish_exact_private_file(
            &self.config.terminal_receipt_root,
            &mirror,
            &receipt,
        )?;
        let decoded: RootTerminalDestructionReceiptV12 =
            serde_json::from_slice(&receipt).map_err(|_| {
                ControllerError::Invalid(
                    "private DinD terminal receipt is invalid",
                )
            })?;
        if canonical_plan_bytes(&decoded).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })? != receipt
            || decoded.owner_namespace != owner_namespace
            || decoded.daemon_generation != daemon_generation
            || generation.network_namespace.as_deref()
                != Some(decoded.network_namespace.as_str())
            || !decoded.ledger_terminal
        {
            return Err(ControllerError::Rejected(
                "private DinD terminal receipt lost its ledger binding",
            ));
        }
        self.verify_terminal_receipt_v12(&decoded, &receipt)?;
        Ok((decoded, receipt))
    }

    fn verify_terminal_receipt_v12(
        &self,
        receipt: &RootTerminalDestructionReceiptV12,
        exact_receipt: &[u8],
    ) -> Result<()> {
        if receipt.version
                != "serverware/private-dind-terminal-destruction/v12"
            || receipt.trust_profile
                != "trusted-host-userspace-digest-no-ima"
            || receipt.plan_id == [0; 32]
            || receipt.capability_sha256 == [0; 32]
            || receipt.request_sha256 == [0; 32]
            || receipt.observed_at_boottime_ns == 0
            || receipt.network_namespace.is_empty()
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
            || receipt.signer_spki_sha256
                != self.config.root_signer_spki_sha256
            || receipt.signer_public_key_spki_der.is_empty()
            || sha256(&receipt.signer_public_key_spki_der)
                != receipt.signer_spki_sha256
            || receipt.signature.len() != 64
            || receipt.receipt_sha256 == [0; 32]
            || canonical_plan_bytes(receipt).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })? != exact_receipt
        {
            return Err(ControllerError::Rejected(
                "private DinD terminal receipt is incomplete or nonterminal",
            ));
        }
        let mut digest_projection = receipt.clone();
        digest_projection.receipt_sha256 = [0; 32];
        if sha256(
            &canonical_plan_bytes(&digest_projection).map_err(
                |error| {
                    ControllerError::InvalidOwned(error.to_string())
                },
            )?,
        ) != receipt.receipt_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD terminal receipt digest is invalid",
            ));
        }
        let signature_bytes: [u8; 64] = receipt
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| {
                ControllerError::Rejected(
                    "private DinD terminal receipt signature length is invalid",
                )
            })?;
        let mut signature_projection = receipt.clone();
        signature_projection.signature.clear();
        signature_projection.receipt_sha256 = [0; 32];
        let unsigned = canonical_plan_bytes(
            &signature_projection,
        )
        .map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        self.signing_key
            .verifying_key()
            .verify(
                &[
                    b"serverware/private-dind-terminal-receipt/v12\0"
                        .as_slice(),
                    unsigned.as_slice(),
                ]
                .concat(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| {
                ControllerError::Rejected(
                    "private DinD terminal receipt signature is invalid",
                )
            })
    }

    fn destruction_result_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<(Vec<u8>, Digest)> {
        let generation = self
            .ledger
            .generation(
                &operation.owner_namespace,
                &operation.daemon_generation,
            )?
            .ok_or(ControllerError::Rejected(
                "destroyed generation disappeared from terminal ledger",
            ))?;
        if generation.status != DockerLaneOperationStatusV12::Destroyed
            || generation.state != AuthoritativeLaneState::Destroyed
            || generation.terminal_receipt_sha256.is_none()
        {
            return Err(ControllerError::Rejected(
                "private DinD terminal result lacks ledger receipt",
            ));
        }
        let observed = generation
            .observed_state_sha256
            .ok_or(ControllerError::Rejected(
                "private DinD terminal generation lacks observed evidence",
            ))?;
        let (receipt, exact_receipt) =
            self.terminal_receipt_for_generation_v12(
                &generation.owner_namespace,
                &generation.daemon_generation,
            )?;
        let mut result = json!({
            "cgroupProcesses": receipt.cgroup_processes,
            "containers": receipt.containers,
            "dindReaped": receipt.dind_reaped,
            "drainedContainers": receipt.drained_containers,
            "drainedImages": receipt.drained_images,
            "drainedNetworks": receipt.drained_networks,
            "drainedVolumes": receipt.drained_volumes,
            "dockerAuthorityEstablished":
                receipt.docker_authority_established,
            "dockerInternalStorageAbsenceProof":
                receipt.docker_internal_storage_absence_proof.as_str(),
            "dockerTopLevelObjectCountScope":
                receipt.docker_top_level_object_count_scope.as_str(),
            "generationKind": operation.profile.generation_kind(),
            "images": receipt.images,
            "ledgerTerminal": receipt.ledger_terminal,
            "mounts": receipt.mounts,
            "networks": receipt.networks,
            "planId": operation.request.plan_id,
            "proxyAccepting": receipt.proxy_accepting,
            "resultSha256": ([0u8; 32]),
            "terminalReceiptSha256": sha256(&exact_receipt),
            "stateRootAbsent": receipt.state_root_absent,
            "version": PRIVATE_DIND_RESULT_VERSION_V12,
            "volumes": receipt.volumes,
        });
        let digest = sha256(
            &canonical_plan_bytes(&result).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
        );
        result
            .as_object_mut()
            .ok_or(ControllerError::Invalid(
                "private DinD destruction result is not an object",
            ))?
            .insert(
                "resultSha256".to_owned(),
                serde_json::to_value(digest).map_err(|_| {
                    ControllerError::Invalid(
                        "destruction result digest is not JSON serializable",
                    )
                })?,
            );
        Ok((
            canonical_plan_bytes(&result).map_err(|error| {
                ControllerError::InvalidOwned(error.to_string())
            })?,
            observed,
        ))
    }

    fn run_network_hook_v12(
        &self,
        arguments: &[&str],
        deadline: u64,
    ) -> Result<Digest> {
        verify_pinned_file(
            &self.config.network_hook,
            self.config.network_hook_sha256,
        )?;
        let mut child = Command::new(&self.config.network_hook)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let status = wait_child_deadline(&mut child, deadline)?;
        if !status.success() {
            return Err(ControllerError::Rejected(
                "private DinD network hook failed",
            ));
        }
        Ok(sha256(
            &[
                self.config.network_hook.as_os_str().as_bytes(),
                arguments.join("\0").as_bytes(),
                b"success",
            ]
            .concat(),
        ))
    }

    fn socket_path_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> PathBuf {
        self.config.private_socket_root.join(format!(
            "{}.sock",
            operation.daemon_generation,
        ))
    }

    fn cgroup_path_v12(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> PathBuf {
        self.config.cgroup_root.join(format!(
            "serverware-coder-v12-{}",
            operation.daemon_generation,
        ))
    }

    fn reject_unledgered_generation_roots_v12(&self) -> Result<()> {
        let mut count = 0usize;
        for owner in std::fs::read_dir(&self.config.dind_root)? {
            let owner = owner?;
            if !owner.file_type()?.is_dir() {
                return Err(ControllerError::Rejected(
                    "private DinD root contains a foreign non-directory",
                ));
            }
            for generation in std::fs::read_dir(owner.path())? {
                count = count.saturating_add(1);
                if count > PRIVATE_DIND_MAX_GENERATIONS_V12 {
                    return Err(ControllerError::Rejected(
                        "private DinD generation root bound exceeded",
                    ));
                }
                let generation = generation?;
                if generation.file_type()?.is_dir() {
                    return Err(ControllerError::Rejected(
                        "private DinD startup retained an unledgered generation root",
                    ));
                }
            }
        }
        if std::fs::read_dir(&self.config.dind_root)?
            .next()
            .is_some()
        {
            return Err(ControllerError::Rejected(
                "private DinD startup retained an unledgered state root",
            ));
        }
        if std::fs::read_dir(&self.config.private_socket_root)?
            .next()
            .is_some()
        {
            return Err(ControllerError::Rejected(
                "private DinD startup retained an unledgered proxy socket",
            ));
        }
        if self.config.cgroup_root.exists() {
            for entry in std::fs::read_dir(&self.config.cgroup_root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    return Err(ControllerError::Rejected(
                        "private DinD startup retained an unledgered cgroup",
                    ));
                }
            }
        }
        for entry in std::fs::read_dir(&self.config.netns_root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| {
                    name.starts_with(&self.config.netns_prefix)
                })
            {
                return Err(ControllerError::Rejected(
                    "private DinD startup retained an unledgered network namespace",
                ));
            }
        }
        if self.config.network_ownership_ledger.exists() {
            let ledger = read_private_file(
                &self.config.network_ownership_ledger,
                4 * 1024 * 1024,
            )?;
            if std::str::from_utf8(&ledger)
                .map_err(|_| {
                    ControllerError::Invalid(
                        "private DinD network ledger is not UTF-8",
                    )
                })?
                .lines()
                .any(|line| line.starts_with("network|"))
            {
                return Err(ControllerError::Rejected(
                    "private DinD startup retained unledgered network ownership",
                ));
            }
        }
        Ok(())
    }
}

fn operation_payload_content_v12(
    operation: &DockerLaneOperationV12,
) -> Result<DockerLanePayloadContentV12> {
    match &operation.decoded_payload {
        DockerLaneDecodedPayloadV12::Operation(payload) => {
            Ok(payload.content.clone())
        }
        _ => Err(ControllerError::Rejected(
            "private DinD operation does not carry an operation payload",
        )),
    }
}

fn require_active_handle_v12<'a>(
    state: &'a PrivateDindStateV12,
    operation: &DockerLaneOperationV12,
) -> Result<&'a PrivateDindHandleV12> {
    let handle = state
        .active
        .get(&operation.daemon_generation)
        .ok_or(ControllerError::Rejected(
            "private DinD generation is not active",
        ))?;
    if handle.owner_namespace != operation.owner_namespace
        || handle.daemon_generation != operation.daemon_generation
        || handle.profile != operation.profile
    {
        return Err(ControllerError::Rejected(
            "private DinD active handle differs from request authority",
        ));
    }
    Ok(handle)
}

fn require_active_handle_mut_v12<'a>(
    state: &'a mut PrivateDindStateV12,
    operation: &DockerLaneOperationV12,
) -> Result<&'a mut PrivateDindHandleV12> {
    let handle = state
        .active
        .get_mut(&operation.daemon_generation)
        .ok_or(ControllerError::Rejected(
            "private DinD generation is not active",
        ))?;
    if handle.owner_namespace != operation.owner_namespace
        || handle.daemon_generation != operation.daemon_generation
        || handle.profile != operation.profile
    {
        return Err(ControllerError::Rejected(
            "private DinD active handle differs from request authority",
        ));
    }
    Ok(handle)
}

fn applied_result_v12(
    operation: &DockerLaneOperationV12,
    authoritative_state: AuthoritativeLaneState,
    observed_state_sha256: Digest,
) -> Result<Vec<u8>> {
    let transition_sha256 = sha256(
        &[
            b"serverware/private-dind-applied-transition/v12\0"
                .as_slice(),
            operation.request.request_sha256.as_slice(),
            observed_state_sha256.as_slice(),
        ]
        .concat(),
    );
    canonical_plan_bytes(&json!({
        "authoritativeState": authoritative_state,
        "lane": operation.request.lane,
        "operation": operation.request.operation,
        "planId": operation.request.plan_id,
        "transitionSha256": transition_sha256,
        "version": PRIVATE_DIND_RESULT_VERSION_V12,
    }))
    .map_err(|error| ControllerError::InvalidOwned(error.to_string()))
}

fn owner_labels_json_v12(operation: &DockerLaneOperationV12) -> Value {
    let mut labels = Map::new();
    labels.insert(
        OWNER_LABEL_V12.to_owned(),
        Value::String(operation.owner_namespace.clone()),
    );
    labels.insert(
        GENERATION_LABEL_V12.to_owned(),
        Value::String(operation.daemon_generation.clone()),
    );
    labels.insert(
        LANE_LABEL_V12.to_owned(),
        Value::String(operation.lane_id()),
    );
    labels.insert(
        RESOURCE_LABEL_V12.to_owned(),
        Value::String(digest_hex(&operation.request.target_sha256)),
    );
    if let DockerLaneDecodedPayloadV12::Operation(payload) =
        &operation.decoded_payload
    {
        labels.insert(
            SOURCE_SEAL_LABEL_V12.to_owned(),
            Value::String(digest_hex(
                &payload.source.manifest_sha256,
            )),
        );
        if let Some(artifact) = payload.artifact_manifest_sha256 {
            labels.insert(
                ARTIFACT_SEAL_LABEL_V12.to_owned(),
                Value::String(digest_hex(&artifact)),
            );
        }
    }
    Value::Object(labels)
}

fn runner_create_body_v12(
    operation: &DockerLaneOperationV12,
    handle: &PrivateDindHandleV12,
    runner: &RunnerIdentity,
    command: &ContainerCommand,
    output_mount: &Path,
) -> Result<Value> {
    let mounts = &runner.mount_policy;
    let mut binds = vec![
        format!(
            "{}:{}:ro",
            handle.source_mount.display(),
            mounts.source_destination,
        ),
        format!(
            "{}:{}:rw",
            output_mount.display(),
            mounts.output_destination,
        ),
    ];
    if let Some(artifact) = &handle.artifact_mount {
        binds.push(format!(
            "{}:{}:ro",
            artifact.display(),
            mounts.artifact_destination,
        ));
    }
    binds.sort();
    let environment = command
        .environment
        .iter()
        .map(|entry| format!("{}={}", entry.name, entry.value))
        .collect::<Vec<_>>();
    let command_tail = if command.argv.first().map(String::as_str)
        == Some(command.executable.as_str())
    {
        command.argv[1..].to_vec()
    } else {
        command.argv.clone()
    };
    let network_mode = if matches!(
        operation.request.lane,
        LogicalLane::Integration | LogicalLane::E2e
    ) {
        network_name_v12(&operation.request.plan_id)
    } else {
        "none".to_owned()
    };
    let host_config = execution_host_config_v12(
        &runner.execution_bounds, binds, &network_mode,
    )?;
    Ok(json!({
        "AttachStderr": false,
        "AttachStdin": false,
        "AttachStdout": false,
        "Cmd": command_tail,
        "Entrypoint": [command.executable.clone()],
        "Env": environment,
        "HostConfig": host_config,
        "Healthcheck": {"Test": ["NONE"]},
        "Image": exact_image_reference_v12(&runner.image),
        "Labels": owner_labels_json_v12(operation),
        "NetworkDisabled": network_mode == "none",
        "OpenStdin": false,
        "StdinOnce": false,
        "StopSignal": "SIGTERM",
        "StopTimeout": 10,
        "Tty": false,
        "User": format!("{}:{}", runner.execution_bounds.user_uid,
            runner.execution_bounds.user_gid),
        "WorkingDir": command.cwd,
    }))
}

fn service_create_body_v12(
    operation: &DockerLaneOperationV12,
    service: &ServiceInstanceV12,
    network_name: &str,
) -> Result<Value> {
    let command = &service.command;
    let command_tail = if command.argv.first().map(String::as_str)
        == Some(command.executable.as_str())
    {
        command.argv[1..].to_vec()
    } else {
        command.argv.clone()
    };
    let environment = command
        .environment
        .iter()
        .map(|entry| format!("{}={}", entry.name, entry.value))
        .collect::<Vec<_>>();
    let mut labels = owner_labels_json_v12(operation);
    labels
        .as_object_mut()
        .ok_or(ControllerError::Invalid(
            "private DinD owner labels are not an object",
        ))?
        .insert(
            SERVICE_ID_LABEL_V12.to_owned(),
            Value::String(digest_hex(&service.service_id)),
        );
    let mut exposed_ports = Map::new();
    exposed_ports.insert(
        format!("{}/tcp", service.health.port),
        Value::Object(Map::new()),
    );
    let mut endpoint = Map::new();
    endpoint.insert(
        network_name.to_owned(),
        json!({
            "Aliases": [service.private_alias.clone()]
        }),
    );
    Ok(json!({
        "Cmd": command_tail,
        "Entrypoint": [command.executable.clone()],
        "Env": environment,
        "ExposedPorts": exposed_ports,
        "Healthcheck": {
            "Interval": service.health.interval_ns,
            "Retries": service.health.failure_threshold,
            "StartPeriod": 0,
            "Test": [
                "CMD",
                "/usr/bin/curl",
                "--fail",
                "--silent",
                format!(
                    "{}://127.0.0.1:{}{}",
                    match service.health.protocol {
                        EndpointProtocol::Http => "http",
                        EndpointProtocol::Https => "https",
                        EndpointProtocol::Tcp => "tcp",
                    },
                    service.health.port,
                    service.health.path,
                )
            ],
            "Timeout": service.health.timeout_ns
        },
        "HostConfig": {
            "CapDrop": ["ALL"],
            "CpuPeriod": service.limits.cpu_period_micros,
            "CpuQuota": service.limits.cpu_quota_micros,
            "Memory": service.limits.memory_bytes,
            "NetworkMode": network_name,
            "PidsLimit": service.limits.pids,
            "ReadonlyRootfs": true,
            "SecurityOpt": ["no-new-privileges=true"],
            "Tmpfs": {
                "/run": "rw,nosuid,nodev,noexec,size=64m",
                "/tmp": format!(
                    "rw,nosuid,nodev,noexec,size={}",
                    service.limits.writable_bytes.max(16 * 1024 * 1024)
                )
            },
            "Ulimits": [{
                "Hard": service.limits.open_files,
                "Name": "nofile",
                "Soft": service.limits.open_files
            }]
        },
        "Image": exact_image_reference_v12(&service.sealed_image),
        "Labels": labels,
        "NetworkingConfig": {
            "EndpointsConfig": endpoint
        },
        "OpenStdin": false,
        "Tty": false,
        "WorkingDir": command.cwd
    }))
}

fn exact_image_reference_v12(object: &OciObjectReference) -> String {
    format!(
        "{}@sha256:{}",
        object.repository,
        digest_hex(&object.manifest_digest_sha256),
    )
}

fn validate_source_cas_mount_v12(
    operation: &DockerLaneOperationV12,
    source_mount: &Path,
) -> Result<()> {
    let payload = match &operation.decoded_payload {
        DockerLaneDecodedPayloadV12::Operation(payload) => payload,
        _ => {
            return Err(ControllerError::Rejected(
                "private DinD source FD lacks operation authority",
            ))
        }
    };
    let bytes = read_sealed_cas_file_v12(
        &source_mount.join(PRIVATE_DIND_SOURCE_METADATA_V12),
        4 * 1024 * 1024,
    )?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        ControllerError::Invalid(
            "private DinD source CAS metadata is not JSON",
        )
    })?;
    if canonical_json_bytes_v12(&value)? != bytes
        || value.get("sourceObjectSha256")
            != Some(
                &serde_json::to_value(payload.source.object_sha256)
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "source object digest is not JSON serializable",
                        )
                    })?,
            )
        || value
            .get("filesystem")
            .and_then(|filesystem| filesystem.get("manifestSha256"))
            != Some(
                &serde_json::to_value(payload.source.manifest_sha256)
                    .map_err(|_| {
                        ControllerError::Invalid(
                            "source manifest digest is not JSON serializable",
                        )
                    })?,
            )
    {
        return Err(ControllerError::Rejected(
            "private DinD source FD differs from signed source CAS",
        ));
    }
    Ok(())
}

fn validate_artifact_cas_mount_v12(
    operation: &DockerLaneOperationV12,
    artifact_mount: &Path,
) -> Result<()> {
    let artifacts = match operation_payload_content_v12(operation)? {
        DockerLanePayloadContentV12::CreateNoBuildDind {
            artifacts,
            ..
        } => artifacts,
        _ => {
            return Err(ControllerError::Rejected(
                "private DinD artifact FD lacks no-build authority",
            ))
        }
    };
    let manifest =
        read_sealed_docker_artifact_manifest_v12(artifact_mount)?;
    validate_sealed_docker_artifact_manifest_v12(
        artifact_mount,
        &manifest,
        &artifacts,
    )
}

fn container_name_v12(
    role: &str,
    lane: LogicalLane,
    identity: &Digest,
) -> String {
    format!(
        "swv12-{}-{}-{}",
        role,
        lane.ordinal(),
        &digest_hex(identity)[..20],
    )
}

fn network_name_v12(plan_id: &Digest) -> String {
    format!("swv12-net-{}", &digest_hex(plan_id)[..20])
}

fn require_docker_success_v12(
    response: &[u8],
    allowed_statuses: &[u16],
) -> Result<Value> {
    let (status, body) = docker_http_response_body_v12(response)?;
    if !allowed_statuses.contains(&status) {
        return Err(ControllerError::InvalidOwned(format!(
            "private Docker API returned unexpected status {status}: {}",
            String::from_utf8_lossy(&body),
        )));
    }
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            ControllerError::Invalid(
                "private Docker API response body is not JSON",
            )
        })
    }
}

fn docker_resource_ids_v12(
    value: &Value,
    id_field: &'static str,
) -> Result<Vec<String>> {
    let entries = value.as_array().ok_or(
        ControllerError::Invalid(
            "private Docker resource inventory is not an array",
        ),
    )?;
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or(
            ControllerError::Invalid(
                "private Docker resource inventory entry is not an object",
            ),
        )?;
        let id = object
            .get(id_field)
            .and_then(Value::as_str)
            .ok_or(ControllerError::Invalid(
                "private Docker resource inventory lacks its identity",
            ))?;
        if id.is_empty()
            || id.len() > 256
            || id.bytes().any(|byte| {
                byte.is_ascii_control()
                    || matches!(byte, b'/' | b'?' | b'#')
            })
        {
            return Err(ControllerError::Rejected(
                "private Docker resource identity is unsafe",
            ));
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}

fn private_dind_network_ids_v12(
    value: &Value,
    generation: &DockerGenerationRecordV12,
) -> Result<Vec<String>> {
    let entries = value.as_array().ok_or(
        ControllerError::Invalid(
            "private Docker network inventory is not an array",
        ),
    )?;
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or(
            ControllerError::Invalid(
                "private Docker network inventory entry is not an object",
            ),
        )?;
        let name = object
            .get("Name")
            .and_then(Value::as_str)
            .ok_or(ControllerError::Invalid(
                "private Docker network inventory lacks its name",
            ))?;
        let labels = object.get("Labels").and_then(Value::as_object);
        let generation_owned = labels.is_some_and(|labels| {
            labels.get(OWNER_LABEL_V12).and_then(Value::as_str)
                    == Some(generation.owner_namespace.as_str())
                && labels
                    .get(GENERATION_LABEL_V12)
                    .and_then(Value::as_str)
                    == Some(generation.daemon_generation.as_str())
        });
        if matches!(name, "bridge" | "host" | "none")
            && !generation_owned
        {
            continue;
        }
        let id = object
            .get("Id")
            .and_then(Value::as_str)
            .ok_or(ControllerError::Invalid(
                "private Docker network inventory lacks its identity",
            ))?;
        if id.is_empty()
            || id.len() > 256
            || id.bytes().any(|byte| {
                byte.is_ascii_control()
                    || matches!(byte, b'/' | b'?' | b'#')
            })
        {
            return Err(ControllerError::Rejected(
                "private Docker network identity is unsafe",
            ));
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}

fn valid_nonroot_container_user_v12(value: &str) -> bool {
    parse_nonroot_container_user_v12(value).is_some()
}

fn parse_nonroot_container_user_v12(
    value: &str,
) -> Option<(u32, u32)> {
    let Some((uid, gid)) = value.split_once(':') else {
        return None;
    };
    let Ok(uid) = uid.parse::<u32>() else {
        return None;
    };
    let Ok(gid) = gid.parse::<u32>() else {
        return None;
    };
    (uid >= 1000 && gid >= 1000).then_some((uid, gid))
}

fn json_text_v12<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ControllerError::Invalid(field))
}

fn read_sealed_docker_artifact_manifest_v12(
    artifact_root: &Path,
) -> Result<SealedDockerArtifactManifestV12> {
    let bytes = read_sealed_cas_file_v12(
        &artifact_root.join(PRIVATE_DIND_ARTIFACT_METADATA_V12),
        16 * 1024 * 1024,
    )?;
    let manifest: SealedDockerArtifactManifestV12 =
        serde_json::from_slice(&bytes).map_err(|_| {
            ControllerError::Invalid(
                "private DinD Docker artifact metadata is invalid",
            )
        })?;
    if canonical_plan_bytes(&manifest).map_err(|error| {
        ControllerError::InvalidOwned(error.to_string())
    })? != bytes
    {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact metadata is noncanonical",
        ));
    }
    Ok(manifest)
}

fn sealed_docker_artifact_manifest_projection_v12(
    artifact_object_sha256: Digest,
    source_manifest_sha256: Digest,
    build_plan_sha256: Digest,
    files_sha256: Digest,
    closure_sha256: Digest,
    archives: &[SealedDockerArchiveEntryV12],
) -> Value {
    json!({
        "archives": archives,
        "artifactObjectSha256": artifact_object_sha256,
        "buildPlanSha256": build_plan_sha256,
        "closureSha256": closure_sha256,
        "filesSha256": files_sha256,
        "format": "docker-image-archive",
        "sourceManifestSha256": source_manifest_sha256,
        "version": PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12,
    })
}

fn validate_sealed_docker_artifact_manifest_self_v12(
    manifest: &SealedDockerArtifactManifestV12,
) -> Result<()> {
    if manifest.version != PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12
        || manifest.format != "docker-image-archive"
        || manifest.archives.is_empty()
        || manifest.archives.len() > 256
    {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact manifest shape is invalid",
        ));
    }
    let mut prior: Option<(&str, &str, Digest)> = None;
    let mut aggregate_bytes = 0u64;
    for archive in &manifest.archives {
        archive.reference.validate().map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
        let identity = (
            archive.reference.repository.as_str(),
            archive.reference.platform.as_str(),
            archive.reference.manifest_digest_sha256,
        );
        if prior.is_some_and(|prior| prior >= identity)
            || archive.archive_bytes == 0
            || archive.archive_sha256 == [0; 32]
            || archive.archive_relative_path
                != format!(
                    "docker-image-{}.tar",
                    digest_hex(
                        &archive.reference.manifest_digest_sha256,
                    ),
                )
        {
            return Err(ControllerError::Rejected(
                "private DinD Docker artifact archive set is noncanonical",
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(archive.archive_bytes)
            .ok_or(ControllerError::Invalid(
                "private DinD Docker artifact size overflowed",
            ))?;
        prior = Some(identity);
    }
    if aggregate_bytes > PRIVATE_DIND_MAX_HTTP_BYTES_V12 {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact archive set exceeds its bound",
        ));
    }
    let closure = SealedDockerArtifactClosureV12 {
        version: PRIVATE_DIND_DOCKER_ARCHIVE_FORMAT_V12.to_owned(),
        source_manifest_sha256:
            manifest.source_manifest_sha256,
        build_plan_sha256: manifest.build_plan_sha256,
        files_sha256: manifest.files_sha256,
        archives: manifest.archives.clone(),
    };
    let closure_sha256 =
        sha256(&canonical_plan_bytes(&closure).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?);
    let projection =
        sealed_docker_artifact_manifest_projection_v12(
            manifest.artifact_object_sha256,
            manifest.source_manifest_sha256,
            manifest.build_plan_sha256,
            manifest.files_sha256,
            closure_sha256,
            &manifest.archives,
        );
    let manifest_sha256 =
        sha256(&canonical_plan_bytes(&projection).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?);
    if closure_sha256 != manifest.closure_sha256
        || closure_sha256 != manifest.artifact_object_sha256
        || manifest_sha256 != manifest.artifact_manifest_sha256
    {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact digest closure is invalid",
        ));
    }
    Ok(())
}

fn validate_sealed_docker_artifact_manifest_v12(
    artifact_root: &Path,
    manifest: &SealedDockerArtifactManifestV12,
    expected: &ArtifactCasReference,
) -> Result<()> {
    validate_sealed_docker_artifact_manifest_self_v12(manifest)?;
    if manifest.artifact_object_sha256 != expected.object_sha256
        || manifest.artifact_manifest_sha256
            != expected.manifest_sha256
        || manifest.source_manifest_sha256
            != expected.source_manifest_sha256
        || manifest.build_plan_sha256 != expected.build_plan_sha256
        || manifest.files_sha256 != expected.files_sha256
        || manifest
            .archives
            .iter()
            .map(|archive| archive.reference.clone())
            .collect::<Vec<_>>()
            != {
                let mut objects = expected.oci_objects.clone();
                objects.sort_by(|left, right| {
                    (
                        left.repository.as_str(),
                        left.platform.as_str(),
                        left.manifest_digest_sha256,
                    )
                        .cmp(&(
                            right.repository.as_str(),
                            right.platform.as_str(),
                            right.manifest_digest_sha256,
                        ))
                });
                objects
            }
    {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact manifest differs from signed authority",
        ));
    }
    for archive in &manifest.archives {
        let bytes = read_sealed_cas_file_v12(
            &artifact_root.join(&archive.archive_relative_path),
            PRIVATE_DIND_MAX_HTTP_BYTES_V12,
        )?;
        if bytes.len() as u64 != archive.archive_bytes
            || sha256(&bytes) != archive.archive_sha256
        {
            return Err(ControllerError::Rejected(
                "private DinD Docker artifact archive differs from its manifest",
            ));
        }
    }
    Ok(())
}

fn sealed_docker_archive_entry_v12<'a>(
    manifest: &'a SealedDockerArtifactManifestV12,
    expected: &OciObjectReference,
) -> Result<&'a SealedDockerArchiveEntryV12> {
    let mut matches = manifest
        .archives
        .iter()
        .filter(|archive| &archive.reference == expected);
    let matched = matches.next().ok_or(ControllerError::Rejected(
        "private DinD Docker artifact lacks the signed image object",
    ))?;
    if matches.next().is_some() {
        return Err(ControllerError::Rejected(
            "private DinD Docker artifact duplicates a signed image object",
        ));
    }
    Ok(matched)
}

fn require_directory_fd_v12(fd: RawFd) -> Result<()> {
    if fd < 3 {
        return Err(ControllerError::Rejected(
            "private DinD retained directory aliases a standard descriptor",
        ));
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o022 != 0
    {
        return Err(ControllerError::Rejected(
            "private DinD retained CAS descriptor is not a sealed directory",
        ));
    }
    Ok(())
}

fn open_directory_fd_v12(path: &Path) -> Result<OwnedFd> {
    let path = c_path(path)?;
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
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    require_directory_fd_v12(fd.as_raw_fd())?;
    Ok(fd)
}

fn directory_fd_identity_sha256_v12(fd: RawFd) -> Result<Digest> {
    require_directory_fd_v12(fd)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(sha256(
        &[
            b"serverware/private-dind-directory-fd/v12\0".as_slice(),
            stat.st_dev.to_be_bytes().as_slice(),
            stat.st_ino.to_be_bytes().as_slice(),
            stat.st_mode.to_be_bytes().as_slice(),
            stat.st_uid.to_be_bytes().as_slice(),
            stat.st_gid.to_be_bytes().as_slice(),
        ]
        .concat(),
    ))
}

fn bind_mount_fd_read_only_v12(
    source_fd: RawFd,
    target: &Path,
) -> Result<()> {
    require_directory_fd_v12(source_fd)?;
    let source = CString::new(format!("/proc/self/fd/{source_fd}"))
        .map_err(|_| {
            ControllerError::Invalid(
                "private DinD retained FD path contains NUL",
            )
        })?;
    let target = c_path(target)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV,
            std::ptr::null(),
        )
    } != 0
    {
        unsafe {
            libc::umount2(target.as_ptr(), libc::MNT_DETACH);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn create_pinned_tool_links_v12(
    root: &Path,
    containerd: &Path,
    shim: &Path,
    runc: &Path,
) -> Result<()> {
    for (name, target) in [
        ("containerd", containerd),
        ("containerd-shim-runc-v2", shim),
        ("runc", runc),
    ] {
        let link = root.join(name);
        if link.exists() {
            return Err(ControllerError::Rejected(
                "private DinD tool projection already exists",
            ));
        }
        std::os::unix::fs::symlink(target, &link)?;
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PrivateDindPidRecordV12 {
    version: String,
    boot_id: String,
    pid: i32,
    start_time_ticks: u64,
    owner_namespace: String,
    daemon_generation: String,
    socket: PathBuf,
    cgroup: PathBuf,
    netns_name: String,
}

fn write_private_dind_pid_record_v12(
    path: &Path,
    pid: libc::pid_t,
    start_time_ticks: u64,
    owner_namespace: &str,
    daemon_generation: &str,
    socket: &Path,
    cgroup: &Path,
    netns_name: &str,
) -> Result<()> {
    let record = PrivateDindPidRecordV12 {
        version: "serverware/private-dind-process/v12".to_owned(),
        boot_id: current_boot_id()?,
        pid,
        start_time_ticks,
        owner_namespace: owner_namespace.to_owned(),
        daemon_generation: daemon_generation.to_owned(),
        socket: socket.to_path_buf(),
        cgroup: cgroup.to_path_buf(),
        netns_name: netns_name.to_owned(),
    };
    let bytes =
        canonical_plan_bytes(&record).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?;
    let parent = path.parent().ok_or(ControllerError::Invalid(
        "private DinD process record has no parent",
    ))?;
    publish_exact_private_file(parent, path, &bytes)
}

fn read_private_dind_pid_record_v12(
    path: &Path,
) -> Result<PrivateDindPidRecordV12> {
    let bytes = read_private_file(path, 64 * 1024)?;
    let record: PrivateDindPidRecordV12 =
        serde_json::from_slice(&bytes).map_err(|_| {
            ControllerError::Invalid(
                "private DinD process record is not JSON",
            )
        })?;
    if canonical_plan_bytes(&record).map_err(|error| {
        ControllerError::InvalidOwned(error.to_string())
    })? != bytes
        || record.version != "serverware/private-dind-process/v12"
    {
        return Err(ControllerError::Rejected(
            "private DinD process record is noncanonical",
        ));
    }
    Ok(record)
}

fn kill_and_reap_private_dind_v12(
    handle: &mut PrivateDindHandleV12,
    deadline: u64,
) -> Result<()> {
    kill_cgroup(&handle.cgroup)?;
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
    wait_pidfd(handle.pidfd.as_raw_fd(), deadline)?;
    let _ = handle.child.try_wait()?;
    Ok(())
}

fn cleanup_private_dind_root_v12(
    generation_root: &Path,
    config: &PrivateDindConfigV12,
    generation: &DockerGenerationRecordV12,
    deadline: u64,
) -> Result<()> {
    let process_path = generation_root.join("process-v12.json");
    if process_path.exists() {
        let record = read_private_dind_pid_record_v12(&process_path)?;
        if record.owner_namespace != generation.owner_namespace
            || record.daemon_generation
                != generation.daemon_generation
            || record.boot_id != current_boot_id()?
            || generation.dind_pid != Some(record.pid)
            || generation.dind_start_time_ticks
                != Some(record.start_time_ticks)
        {
            return Err(ControllerError::Rejected(
                "private DinD stale process record differs from ledger",
            ));
        }
        if process_start_time(record.pid).ok()
            == Some(record.start_time_ticks)
        {
            let _ = kill_cgroup(&record.cgroup);
            let raw = unsafe {
                libc::syscall(libc::SYS_pidfd_open, record.pid, 0)
                    as RawFd
            };
            if raw >= 0 {
                let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
                wait_pidfd(pidfd.as_raw_fd(), deadline)?;
            }
        }
    }
    // Stop and remove the generation's process cgroup before releasing any
    // output filesystem. A busy or substituted output mount is an error, not
    // permission to detach it lazily or recurse through its contents.
    let cgroup = config.cgroup_root.join(format!(
        "serverware-coder-v12-{}",
        generation.daemon_generation,
    ));
    kill_cgroup(&cgroup)?;
    remove_cgroup(&cgroup, deadline)?;
    runner_output_storage_v12::teardown(generation_root, deadline)?;
    for mount in [
        generation_root.join("mounts/artifacts"),
        generation_root.join("mounts/source"),
    ] {
        if mount.exists() {
            let target = c_path(&mount)?;
            let result =
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINVAL) {
                    return Err(error.into());
                }
            }
        }
    }
    let socket = config.private_socket_root.join(format!(
        "{}.sock",
        generation.daemon_generation,
    ));
    remove_socket_if_owned(&socket)?;
    if generation_root.exists() {
        if mountinfo_contains_path_v12(generation_root)? {
            return Err(ControllerError::Rejected(
                "private DinD cleanup refuses to recurse through retained mounts",
            ));
        }
        bounded_remove_tree(
            &config.dind_root,
            generation_root,
            deadline,
        )?;
    }
    if let Some(owner) = generation_root.parent() {
        if owner != config.dind_root {
            match std::fs::read_dir(owner) {
                Ok(mut entries) => {
                    if entries.next().is_none() {
                        std::fs::remove_dir(owner)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn retained_process_identity_v12(
    generation_root: &Path,
    generation: &DockerGenerationRecordV12,
) -> Result<Option<(libc::pid_t, u64)>> {
    let retained = match (
        generation.dind_pid,
        generation.dind_start_time_ticks,
    ) {
        (Some(pid), Some(start_time_ticks)) => {
            Some((pid, start_time_ticks))
        }
        (None, None) => None,
        _ => {
            return Err(ControllerError::Rejected(
                "private DinD durable process identity is incomplete",
            ))
        }
    };
    let path = generation_root.join("process-v12.json");
    if !path.exists() {
        return Ok(retained);
    }
    let record = read_private_dind_pid_record_v12(&path)?;
    if record.owner_namespace != generation.owner_namespace
        || record.daemon_generation != generation.daemon_generation
        || record.boot_id != current_boot_id()?
        || retained.is_some_and(|identity| {
            identity != (record.pid, record.start_time_ticks)
        })
    {
        return Err(ControllerError::Rejected(
            "private DinD process identity differs from durable generation",
        ));
    }
    Ok(Some((record.pid, record.start_time_ticks)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkOwnershipRecordV12 {
    namespace: String,
    host_veth: String,
    peer_veth: String,
    profile: String,
    subnet_index: u32,
    host_address: String,
    lane_address: String,
    lane_gateway: String,
}

fn network_ownership_record_v12(
    ledger: &Path,
    generation: &str,
    lane_slot: u8,
) -> Result<Option<NetworkOwnershipRecordV12>> {
    let bytes = read_private_file(ledger, 4 * 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        ControllerError::Invalid(
            "private DinD network ownership ledger is not UTF-8",
        )
    })?;
    let expected_prefix = format!("network|{generation}|{lane_slot}|");
    let records = text
        .lines()
        .filter(|line| line.starts_with(&expected_prefix))
        .collect::<Vec<_>>();
    if records.len() > 1 {
        return Err(ControllerError::Rejected(
            "private DinD network ownership is duplicated",
        ));
    }
    let Some(record) = records.first() else {
        return Ok(None);
    };
    let fields = record.split('|').collect::<Vec<_>>();
    if fields.len() != 11
        || fields[0] != "network"
        || fields[1] != generation
        || fields[2].parse::<u8>().ok() != Some(lane_slot)
        || fields[3].is_empty()
        || fields[4].is_empty()
        || fields[5].is_empty()
        || !matches!(fields[6], "build" | "no-build")
    {
        return Err(ControllerError::Rejected(
            "private DinD network ownership record is invalid",
        ));
    }
    let subnet_index = fields[7].parse::<u32>().map_err(|_| {
        ControllerError::Invalid(
            "private DinD subnet allocation is invalid",
        )
    })?;
    if subnet_index >= 1_048_576 {
        return Err(ControllerError::Rejected(
            "private DinD subnet allocation exceeds its range",
        ));
    }
    Ok(Some(NetworkOwnershipRecordV12 {
        namespace: fields[3].to_owned(),
        host_veth: fields[4].to_owned(),
        peer_veth: fields[5].to_owned(),
        profile: fields[6].to_owned(),
        subnet_index,
        host_address: fields[8].to_owned(),
        lane_address: fields[9].to_owned(),
        lane_gateway: fields[10].to_owned(),
    }))
}

fn network_ownership_present_v12(
    ledger: &Path,
    generation: &str,
    lane_slot: u8,
) -> Result<bool> {
    Ok(network_ownership_record_v12(
        ledger,
        generation,
        lane_slot,
    )?
    .is_some())
}

#[derive(Clone, Debug)]
struct TerminalAbsenceObservationV12 {
    cgroup_absent: bool,
    mounts_absent: bool,
    netns_absent: bool,
    nft_absent: bool,
    ownership_ledger_absent: bool,
    socket_absent: bool,
    state_root_absent: bool,
    dind_reaped: bool,
    sha256: Digest,
}

fn observe_terminal_absence_v12(
    config: &PrivateDindConfigV12,
    generation: &DockerGenerationRecordV12,
    retained_process: Option<(libc::pid_t, u64)>,
    allocated_netns: Option<&str>,
) -> Result<TerminalAbsenceObservationV12> {
    let generation_root = config
        .dind_root
        .join(&generation.owner_namespace)
        .join(&generation.daemon_generation);
    let socket = config.private_socket_root.join(format!(
        "{}.sock",
        generation.daemon_generation,
    ));
    let cgroup = config.cgroup_root.join(format!(
        "serverware-coder-v12-{}",
        generation.daemon_generation,
    ));
    let netns_absent = allocated_netns
        .map(|name| !config.netns_root.join(name).exists())
        .unwrap_or(true);
    let state_root_absent = !generation_root.exists();
    let socket_absent = !socket.exists();
    let mounts_absent =
        !mountinfo_contains_path_v12(&generation_root)?;
    let cgroup_absent = !cgroup.exists();
    let dind_reaped =
        !retained_process.is_some_and(|(pid, start_time)| {
            process_start_time(pid).ok() == Some(start_time)
        });
    let ownership_ledger_absent = !network_ownership_present_v12(
        &config.network_ownership_ledger,
        &generation.daemon_generation,
        generation.lane_slot,
    )?;
    let nft_absent = netns_absent && ownership_ledger_absent;
    if !state_root_absent
        || !socket_absent
        || !netns_absent
        || !mounts_absent
        || !cgroup_absent
        || !dind_reaped
        || !ownership_ledger_absent
        || !nft_absent
    {
        return Err(ControllerError::Rejected(
            "private DinD terminal observation retained owned resources",
        ));
    }
    let value = json!({
        "cgroupAbsent": true,
        "dindReaped": dind_reaped,
        "daemonGeneration": generation.daemon_generation,
        "mountsAbsent": mounts_absent,
        "networkNamespace": allocated_netns,
        "netnsAbsent": netns_absent,
        "nftAbsent": nft_absent,
        "ownershipLedgerAbsent": ownership_ledger_absent,
        "ownerNamespace": generation.owner_namespace,
        "retainedProcessIdentity": retained_process,
        "socketAbsent": socket_absent,
        "stateRootAbsent": state_root_absent,
        "version": "serverware/private-dind-terminal-observation/v12",
    });
    let digest = sha256(
        &canonical_plan_bytes(&value).map_err(|error| {
            ControllerError::InvalidOwned(error.to_string())
        })?,
    );
    Ok(TerminalAbsenceObservationV12 {
        cgroup_absent,
        mounts_absent,
        netns_absent,
        nft_absent,
        ownership_ledger_absent,
        socket_absent,
        state_root_absent,
        dind_reaped,
        sha256: digest,
    })
}

fn mountinfo_contains_path_v12(path: &Path) -> Result<bool> {
    runner_output_storage_v12::contains_mount_under(path)
}

fn validate_private_dind_config_v12(
    config: &PrivateDindConfigV12,
) -> Result<()> {
    for path in [
        &config.state_root,
        &config.lane_ledger_root,
        &config.network_ownership_ledger,
        &config.terminal_receipt_root,
        &config.dind_root,
        &config.cgroup_root,
        &config.private_socket_root,
        &config.private_mount_root,
        &config.netns_root,
        &config.network_hook,
        &config.host_ruleset,
        &config.host_cleanup_ruleset,
        &config.build_lane_ruleset,
        &config.no_build_lane_ruleset,
        &config.lane_cleanup_ruleset,
        &config.dockerd_binary,
        &config.containerd_binary,
        &config.containerd_shim_binary,
        &config.runc_binary,
        &config.readiness_fixture_root,
        &config.readiness_docker_client_stream,
        &config.readiness_docker_server_stream,
        &config.readiness_service_image_archive,
        &config.readiness_service_probe,
        &config.readiness_browser_image_archive,
        &config.readiness_chromium_page,
        &config.readiness_chromium_script,
        &config.readiness_chromium_probe,
        &config.readiness_chromium_expected_cdp,
        &config.readiness_chromium_expected_dom,
        &config.readiness_chromium_expected_js,
        &config.readiness_chromium_expected_fetch,
        &config.readiness_teardown_fixture,
    ] {
        require_absolute_normalized(path)?;
    }
    if config.netns_prefix != "serverware-coder-v12-"
        || config.root_signer_spki_sha256 == [0; 32]
        || config.network_hook_sha256 == [0; 32]
        || config.readiness_fixture_key_id.is_empty()
        || config.readiness_fixture_public_key == [0; 32]
        || config.readiness_fixture_assets_sha256 == [0; 32]
    {
        return Err(ControllerError::Rejected(
            "private DinD v12 configuration is not exact",
        ));
    }
    for (path, expected) in [
        (&config.network_hook, config.network_hook_sha256),
        (&config.dockerd_binary, config.dockerd_sha256),
        (&config.containerd_binary, config.containerd_sha256),
        (
            &config.containerd_shim_binary,
            config.containerd_shim_sha256,
        ),
        (&config.runc_binary, config.runc_sha256),
        (
            &config.readiness_docker_client_stream,
            config.readiness_docker_client_stream_sha256,
        ),
        (
            &config.readiness_docker_server_stream,
            config.readiness_docker_server_stream_sha256,
        ),
        (
            &config.readiness_service_image_archive,
            config.readiness_service_image_archive_sha256,
        ),
        (
            &config.readiness_service_probe,
            config.readiness_service_probe_sha256,
        ),
        (
            &config.readiness_browser_image_archive,
            config.readiness_browser_image_archive_sha256,
        ),
        (
            &config.readiness_chromium_page,
            config.readiness_chromium_page_sha256,
        ),
        (
            &config.readiness_chromium_script,
            config.readiness_chromium_script_sha256,
        ),
        (
            &config.readiness_chromium_probe,
            config.readiness_chromium_probe_sha256,
        ),
        (
            &config.readiness_chromium_expected_cdp,
            config.readiness_chromium_expected_cdp_sha256,
        ),
        (
            &config.readiness_chromium_expected_dom,
            config.readiness_chromium_expected_dom_sha256,
        ),
        (
            &config.readiness_chromium_expected_js,
            config.readiness_chromium_expected_js_sha256,
        ),
        (
            &config.readiness_chromium_expected_fetch,
            config.readiness_chromium_expected_fetch_sha256,
        ),
        (
            &config.readiness_teardown_fixture,
            config.readiness_teardown_fixture_sha256,
        ),
    ] {
        verify_pinned_file(path, expected)?;
    }
    Ok(())
}

fn path_text_v12(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ControllerError::Invalid(
            "private DinD path is not UTF-8",
        ))
}

fn percent_encode_query_v12(value: &str) -> String {
    percent_encode_v12(value, false)
}

fn percent_encode_path_v12(value: &str) -> String {
    percent_encode_v12(value, true)
}

fn percent_encode_v12(value: &str, preserve_slash: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || preserve_slash && byte == b'/'
        {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalDockerArchiveMemberV12 {
    path: String,
    kind: u8,
    bytes: Vec<u8>,
}

fn canonicalize_docker_image_archive_v12(
    archive: &[u8],
) -> Result<Vec<u8>> {
    if archive.is_empty()
        || archive.len() as u64 > PRIVATE_DIND_MAX_HTTP_BYTES_V12
        || archive.len() % 512 != 0
    {
        return Err(ControllerError::Rejected(
            "Docker image archive size or alignment is invalid",
        ));
    }
    let mut offset = 0usize;
    let mut members = Vec::new();
    let mut terminal_blocks = 0usize;
    while offset < archive.len() {
        let header = &archive[offset..offset + 512];
        offset += 512;
        if header.iter().all(|byte| *byte == 0) {
            if archive[offset..].iter().any(|byte| *byte != 0) {
                return Err(ControllerError::Rejected(
                    "Docker image archive has data after its terminal blocks",
                ));
            }
            terminal_blocks =
                1usize.saturating_add((archive.len() - offset) / 512);
            break;
        }
        terminal_blocks = 0;
        let expected_checksum =
            parse_tar_octal_v12(&header[148..156])?;
        let mut checksum_header = [0u8; 512];
        checksum_header.copy_from_slice(header);
        checksum_header[148..156].fill(b' ');
        let observed_checksum = checksum_header
            .iter()
            .map(|byte| *byte as u64)
            .sum::<u64>();
        if expected_checksum != observed_checksum {
            return Err(ControllerError::Rejected(
                "Docker image archive header checksum is invalid",
            ));
        }
        let name = tar_text_field_v12(&header[..100])?;
        let prefix = if header[345..500]
            .iter()
            .all(|byte| *byte == 0)
        {
            String::new()
        } else {
            tar_text_field_v12(&header[345..500])?
        };
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = match header[156] {
            0 | b'0' => b'0',
            b'5' => b'5',
            _ => {
                return Err(ControllerError::Rejected(
                    "Docker image archive contains an unsupported member type",
                ))
            }
        };
        let path = if kind == b'5' {
            path.trim_end_matches('/').to_owned()
        } else {
            path
        };
        split_ustar_path_v12(&path)?;
        if path.split('/').any(|part| {
            part.is_empty() || matches!(part, "." | "..")
        }) {
            return Err(ControllerError::Rejected(
                "Docker image archive path is not normalized",
            ));
        }
        let size = parse_tar_octal_v12(&header[124..136])?;
        if kind == b'5' && size != 0 {
            return Err(ControllerError::Rejected(
                "Docker image archive directory has a body",
            ));
        }
        let size = usize::try_from(size).map_err(|_| {
            ControllerError::Rejected(
                "Docker image archive member size exceeds usize",
            )
        })?;
        let padded = size
            .checked_add(511)
            .ok_or(ControllerError::Invalid(
                "Docker image archive member size overflowed",
            ))?
            / 512
            * 512;
        let terminal = offset.checked_add(padded).ok_or(
            ControllerError::Invalid(
                "Docker image archive offset overflowed",
            ),
        )?;
        if terminal > archive.len() {
            return Err(ControllerError::Rejected(
                "Docker image archive member exceeds the archive",
            ));
        }
        let mut bytes = archive[offset..offset + size].to_vec();
        if archive[offset + size..terminal]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ControllerError::Rejected(
                "Docker image archive padding is nonzero",
            ));
        }
        offset = terminal;
        if kind == b'0'
            && matches!(path.as_str(), "manifest.json" | "repositories")
        {
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| {
                    ControllerError::Invalid(
                        "Docker image archive metadata is not JSON",
                    )
                })?;
            bytes = canonical_json_bytes_v12(&value)?;
        }
        members.push(CanonicalDockerArchiveMemberV12 {
            path,
            kind,
            bytes,
        });
        if members.len() > PRIVATE_DIND_MAX_TAR_ENTRIES_V12 {
            return Err(ControllerError::Rejected(
                "Docker image archive entry count exceeds its bound",
            ));
        }
    }
    if terminal_blocks < 2
        || members.is_empty()
        || !members.iter().any(|member| {
            member.path == "manifest.json" && member.kind == b'0'
        })
    {
        return Err(ControllerError::Rejected(
            "Docker image archive lacks terminal blocks or manifest.json",
        ));
    }
    members.sort_by(|left, right| left.path.cmp(&right.path));
    if members
        .windows(2)
        .any(|pair| pair[0].path == pair[1].path)
    {
        return Err(ControllerError::Rejected(
            "Docker image archive contains duplicate paths",
        ));
    }
    validate_docker_archive_manifest_members_v12(&members)?;
    let mut canonical = Vec::with_capacity(archive.len());
    for member in members {
        write_tar_header_v12(
            &mut canonical,
            &member.path,
            if member.kind == b'5' { 0o755 } else { 0o644 },
            member.bytes.len() as u64,
            member.kind,
            None,
        )?;
        canonical.extend_from_slice(&member.bytes);
        write_tar_padding_v12(
            &mut canonical,
            member.bytes.len() as u64,
        )?;
    }
    canonical.extend_from_slice(&[0u8; 1024]);
    if canonical.len() as u64 > PRIVATE_DIND_MAX_HTTP_BYTES_V12 {
        return Err(ControllerError::Rejected(
            "canonical Docker image archive exceeds its bound",
        ));
    }
    Ok(canonical)
}

fn validate_docker_archive_manifest_members_v12(
    members: &[CanonicalDockerArchiveMemberV12],
) -> Result<()> {
    let manifest = members
        .iter()
        .find(|member| member.path == "manifest.json")
        .ok_or(ControllerError::Rejected(
            "canonical Docker image archive lacks manifest.json",
        ))?;
    let value: Value =
        serde_json::from_slice(&manifest.bytes).map_err(|_| {
            ControllerError::Invalid(
                "canonical Docker image manifest is not JSON",
            )
        })?;
    let entries = value.as_array().ok_or(
        ControllerError::Invalid(
            "canonical Docker image manifest is not an array",
        ),
    )?;
    let paths = members
        .iter()
        .map(|member| member.path.as_str())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        let object = entry.as_object().ok_or(
            ControllerError::Invalid(
                "canonical Docker image manifest entry is not an object",
            ),
        )?;
        let config = object
            .get("Config")
            .and_then(Value::as_str)
            .ok_or(ControllerError::Invalid(
                "canonical Docker image manifest lacks Config",
            ))?;
        if !paths.contains(config) {
            return Err(ControllerError::Rejected(
                "canonical Docker image manifest references an absent config",
            ));
        }
        let layers = object
            .get("Layers")
            .and_then(Value::as_array)
            .ok_or(ControllerError::Invalid(
                "canonical Docker image manifest lacks Layers",
            ))?;
        for layer in layers {
            let layer = layer.as_str().ok_or(
                ControllerError::Invalid(
                    "canonical Docker image layer path is not text",
                ),
            )?;
            if !paths.contains(layer) {
                return Err(ControllerError::Rejected(
                    "canonical Docker image manifest references an absent layer",
                ));
            }
        }
    }
    Ok(())
}

fn tar_text_field_v12(field: &[u8]) -> Result<String> {
    let terminal =
        field.iter().position(|byte| *byte == 0).unwrap_or(field.len());
    if field[terminal..].iter().any(|byte| *byte != 0) {
        return Err(ControllerError::Rejected(
            "Docker image archive text field has nonzero suffix bytes",
        ));
    }
    let text = std::str::from_utf8(&field[..terminal]).map_err(|_| {
        ControllerError::Rejected(
            "Docker image archive text field is not UTF-8",
        )
    })?;
    if text.is_empty() {
        return Err(ControllerError::Rejected(
            "Docker image archive text field is empty",
        ));
    }
    Ok(text.to_owned())
}

fn parse_tar_octal_v12(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(ControllerError::Rejected(
            "Docker image archive uses unsupported base-256 metadata",
        ));
    }
    let text = std::str::from_utf8(field).map_err(|_| {
        ControllerError::Rejected(
            "Docker image archive numeric field is not ASCII",
        )
    })?;
    let text = text.trim_matches(|character| {
        matches!(character, '\0' | ' ')
    });
    if text.is_empty()
        || text.bytes().any(|byte| !(b'0'..=b'7').contains(&byte))
    {
        return Err(ControllerError::Rejected(
            "Docker image archive numeric field is not octal",
        ));
    }
    u64::from_str_radix(text, 8).map_err(|_| {
        ControllerError::Rejected(
            "Docker image archive numeric field overflowed",
        )
    })
}

fn write_deterministic_tar_v12(
    root: &Path,
    output: &Path,
) -> Result<(u64, Digest)> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ControllerError::Rejected(
            "private DinD tar root is not a directory",
        ));
    }
    let mut entries = Vec::<(String, PathBuf)>::new();
    collect_tar_entries_v12(root, root, &mut entries)?;
    if entries.is_empty()
        || entries.len() > PRIVATE_DIND_MAX_TAR_ENTRIES_V12
    {
        return Err(ControllerError::Rejected(
            "private DinD tar entry count is invalid",
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    for (relative, path) in entries {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.nlink() != 1 {
            return Err(ControllerError::Rejected(
                "private DinD tar entry has multiple hard links",
            ));
        }
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            write_tar_header_v12(
                &mut file,
                &format!("{relative}/"),
                metadata.mode() & 0o777,
                0,
                b'5',
                None,
            )?;
        } else if file_type.is_file() {
            write_tar_header_v12(
                &mut file,
                &relative,
                metadata.mode() & 0o777,
                metadata.len(),
                b'0',
                None,
            )?;
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            std::io::copy(&mut input, &mut file)?;
            write_tar_padding_v12(
                &mut file,
                metadata.len() as u64,
            )?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&path)?;
            let target = target.to_str().ok_or(
                ControllerError::Rejected(
                    "private DinD tar symlink target is not UTF-8",
                ),
            )?;
            if target.starts_with('/')
                || target.split('/').any(|part| part == "..")
            {
                return Err(ControllerError::Rejected(
                    "private DinD tar symlink escapes its root",
                ));
            }
            write_tar_header_v12(
                &mut file,
                &relative,
                metadata.mode() & 0o777,
                0,
                b'2',
                Some(target),
            )?;
        } else {
            return Err(ControllerError::Rejected(
                "private DinD tar contains a special file",
            ));
        }
    }
    file.write_all(&[0u8; 1024])?;
    file.sync_all()?;
    let bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let digest =
        sha256_exact_reader(&mut file, bytes)?;
    Ok((bytes, digest))
}

fn collect_tar_entries_v12(
    root: &Path,
    directory: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|_| {
            ControllerError::Rejected(
                "private DinD tar path escaped its root",
            )
        })?;
        let relative = relative
            .components()
            .map(|component| match component {
                Component::Normal(value) => value
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(ControllerError::Rejected(
                        "private DinD tar path is not UTF-8",
                    )),
                _ => Err(ControllerError::Rejected(
                    "private DinD tar path is not normalized",
                )),
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        if relative.is_empty() || relative.len() > 255 {
            return Err(ControllerError::Rejected(
                "private DinD tar path length is invalid",
            ));
        }
        output.push((relative, path.clone()));
        if entry.file_type()?.is_dir() {
            collect_tar_entries_v12(root, &path, output)?;
        }
        if output.len() > PRIVATE_DIND_MAX_TAR_ENTRIES_V12 {
            return Err(ControllerError::Rejected(
                "private DinD tar entry bound exceeded",
            ));
        }
    }
    Ok(())
}

fn write_tar_header_v12<W: Write>(
    output: &mut W,
    path: &str,
    mode: u32,
    size: u64,
    kind: u8,
    link: Option<&str>,
) -> Result<()> {
    let mut header = [0u8; 512];
    let (name, prefix) = split_ustar_path_v12(path)?;
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_tar_octal_v12(&mut header[100..108], mode as u64)?;
    write_tar_octal_v12(&mut header[108..116], 0)?;
    write_tar_octal_v12(&mut header[116..124], 0)?;
    write_tar_octal_v12(&mut header[124..136], size)?;
    write_tar_octal_v12(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = kind;
    if let Some(link) = link {
        if link.len() > 100 {
            return Err(ControllerError::Rejected(
                "private DinD tar symlink target is too long",
            ));
        }
        header[157..157 + link.len()].copy_from_slice(link.as_bytes());
    }
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    if let Some(prefix) = prefix {
        header[345..345 + prefix.len()]
            .copy_from_slice(prefix.as_bytes());
    }
    let checksum = header.iter().map(|byte| *byte as u64).sum();
    write_tar_checksum_v12(&mut header[148..156], checksum)?;
    output.write_all(&header)?;
    Ok(())
}

fn split_ustar_path_v12(path: &str) -> Result<(&str, Option<&str>)> {
    if path.as_bytes().contains(&0) || path.starts_with('/') {
        return Err(ControllerError::Rejected(
            "private DinD tar path is invalid",
        ));
    }
    if path.len() <= 100 {
        return Ok((path, None));
    }
    for (index, byte) in path.bytes().enumerate().rev() {
        if byte == b'/' {
            let prefix = &path[..index];
            let name = &path[index + 1..];
            if !name.is_empty()
                && name.len() <= 100
                && prefix.len() <= 155
            {
                return Ok((name, Some(prefix)));
            }
        }
    }
    Err(ControllerError::Rejected(
        "private DinD tar path exceeds ustar bounds",
    ))
}

fn write_tar_octal_v12(field: &mut [u8], value: u64) -> Result<()> {
    let text = format!("{:0width$o}\0", value, width = field.len() - 1);
    if text.len() != field.len() {
        return Err(ControllerError::Rejected(
            "private DinD tar numeric field overflowed",
        ));
    }
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

fn write_tar_checksum_v12(
    field: &mut [u8],
    value: u64,
) -> Result<()> {
    let text = format!("{value:06o}\0 ");
    if text.len() != field.len() {
        return Err(ControllerError::Rejected(
            "private DinD tar checksum overflowed",
        ));
    }
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

fn write_tar_padding_v12<W: Write>(
    output: &mut W,
    size: u64,
) -> Result<()> {
    let padding = (512 - size % 512) % 512;
    if padding != 0 {
        output.write_all(&vec![0u8; padding as usize])?;
    }
    Ok(())
}

#[derive(Clone)]
struct PidRecordV11 {
    pid: libc::pid_t,
    start_time_ticks: u64,
    boot_id: String,
    owner_namespace: String,
    generation: String,
    socket: PathBuf,
    cgroup: PathBuf,
}

fn validate_config(config: &DindLifecycleConfigV11) -> Result<()> {
    for path in [
        &config.state_root,
        &config.cgroup_root,
        &config.private_socket_root,
        &config.oci_cas_root,
        &config.dockerd_path,
        &config.docker_path,
        &config.oci_exporter_path,
    ] {
        require_absolute_normalized(path)?;
    }
    if config.state_root.starts_with(&config.oci_cas_root)
        || config.oci_cas_root.starts_with(&config.state_root)
        || config.private_socket_root.starts_with(&config.state_root)
    {
        return Err(ControllerError::Rejected(
            "DinD state, socket, and OCI CAS roots overlap unsafely",
        ));
    }
    verify_pinned_file(&config.dockerd_path, config.dockerd_sha256)?;
    verify_pinned_file(&config.docker_path, config.docker_sha256)
        .and_then(|_| {
            verify_pinned_file(
                &config.oci_exporter_path,
                config.oci_exporter_sha256,
            )
        })
}

fn image_inventory_sha256(
    images: &BTreeMap<String, Digest>,
    capability: &DockerLaneCapabilityV11,
) -> Result<Digest> {
    let tuple = capability.build_tuple.as_ref().ok_or(
        ControllerError::Rejected(
            "OCI image inventory lacks its exact build tuple",
        ),
    )?;
    image_inventory_sha256_parts(
        images,
        capability.source_seal_sha256,
        tuple,
    )
}

fn image_inventory_sha256_parts(
    images: &BTreeMap<String, Digest>,
    source_seal_sha256: Digest,
    tuple: &DockerBuildTupleV11,
) -> Result<Digest> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"serverware/dind-oci-inventory/v11\0");
    bytes.extend_from_slice(&source_seal_sha256);
    bytes.extend_from_slice(&tuple.context_cas_sha256);
    bytes.extend_from_slice(&tuple.dockerfile_cas_sha256);
    bytes.extend_from_slice(&tuple.build_args_sha256);
    for value in [&tuple.target, &tuple.platform, &tuple.output] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    for (reference, digest) in images {
        bytes.extend_from_slice(&(reference.len() as u64).to_be_bytes());
        bytes.extend_from_slice(reference.as_bytes());
        bytes.extend_from_slice(digest);
    }
    Ok(sha256(&bytes))
}

fn publish_exact_private_file(
    root: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    if !final_path.starts_with(root)
        || final_path.parent() != Some(root)
        || bytes.is_empty()
        || bytes.len() as u64 > OCI_MANIFEST_MAX_BYTES_V11
    {
        return Err(ControllerError::Rejected(
            "sealed OCI manifest publication target is invalid",
        ));
    }
    let temporary = root.join(format!(
        ".manifest-{}-{}.tmp",
        unsafe { libc::getpid() },
        OCI_TRANSFER_SEQUENCE_V11.fetch_add(1, Ordering::AcqRel),
    ));
    let mut cleanup = TemporaryCasFileV11 {
        path: temporary.clone(),
        armed: true,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let temporary_c = c_path(&temporary)?;
    let final_c = c_path(final_path)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            temporary_c.as_ptr(),
            libc::AT_FDCWD,
            final_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        if read_private_file(final_path, OCI_MANIFEST_MAX_BYTES_V11)?
            != bytes
        {
            return Err(ControllerError::Rejected(
                "existing sealed OCI manifest differs byte-for-byte",
            ));
        }
        std::fs::remove_file(&temporary)?;
    }
    cleanup.armed = false;
    let final_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(final_path)?;
    final_file.sync_all()?;
    File::open(root)?.sync_all()?;
    if read_private_file(final_path, OCI_MANIFEST_MAX_BYTES_V11)? != bytes {
        return Err(ControllerError::Rejected(
            "sealed OCI manifest changed after publication",
        ));
    }
    Ok(())
}

fn create_runner_output_v12(
    generation_root: &Path, path: &Path, bounds: &RunnerExecutionBoundsV12,
) -> Result<RunnerOutputStorageV12> {
    runner_output_storage_v12::create(generation_root, path, bounds)
}

fn read_runner_result_v12(
    directory: RawFd, name: &str, uid: u32, gid: u32, maximum: u64,
) -> Result<Vec<u8>> {
    require_directory_fd_v12(directory)?;
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err(ControllerError::Rejected("runner result is not one fixed filename"));
    }
    let name = CString::new(name).map_err(|_| {
        ControllerError::Rejected("runner result name contains NUL")
    })?;
    let raw = unsafe {
        libc::openat(directory, name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != uid || before.gid() != gid
        || before.mode() & 0o077 != 0 || before.nlink() != 1
        || before.len() == 0 || before.len() > maximum
    {
        return Err(ControllerError::Rejected(
            "runner result is not its owned bounded private regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(before.len() + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev() || before.ino() != after.ino()
        || before.uid() != after.uid() || before.gid() != after.gid()
        || before.mode() != after.mode() || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ControllerError::Rejected("runner result changed during bounded read"));
    }
    Ok(bytes)
}

fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(ControllerError::Rejected(
            "sealed OCI manifest storage is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(metadata.len() + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ControllerError::Rejected(
            "sealed OCI manifest changed while reading",
        ));
    }
    Ok(bytes)
}

fn read_root_pinned_file_v12(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(ControllerError::Rejected(
            "root-pinned readiness asset is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(metadata.len() + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ControllerError::Rejected(
            "root-pinned readiness asset changed while reading",
        ));
    }
    Ok(bytes)
}

fn read_probe_result_file_v12(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() == 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(ControllerError::Rejected(
            "readiness probe result storage is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(metadata.len() + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ControllerError::Rejected(
            "readiness probe result changed while reading",
        ));
    }
    Ok(bytes)
}

fn read_sealed_cas_file_v12(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.mode() & 0o222 != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum
    {
        return Err(ControllerError::Rejected(
            "sealed CAS metadata storage is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ControllerError::Rejected(
            "sealed CAS metadata changed while reading",
        ));
    }
    Ok(bytes)
}

fn exact_manifest_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(ControllerError::Invalid(
        "sealed OCI manifest value is not an object",
    ))?;
    if object.len() != fields.len()
        || fields.iter().any(|field| !object.contains_key(*field))
    {
        return Err(ControllerError::Rejected(
            "sealed OCI manifest fields differ from v11",
        ));
    }
    Ok(object)
}

fn manifest_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ControllerError::Invalid(
            "sealed OCI manifest text field is invalid",
        ))
}

fn parse_hex_digest(value: &str) -> Result<Digest> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
    {
        return Err(ControllerError::Invalid(
            "sealed OCI manifest digest is invalid",
        ));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| {
                ControllerError::Invalid(
                    "sealed OCI manifest digest is invalid",
                )
            })?;
    }
    Ok(digest)
}

fn local_transfer_tag(
    phase: &str,
    handle: &DindHandleV11,
    image_id: &str,
) -> Result<String> {
    if !matches!(phase, "export" | "sealed")
        || !valid_image_id(image_id)
    {
        return Err(ControllerError::Rejected(
            "OCI transfer tag input is invalid",
        ));
    }
    let digest = image_id.strip_prefix("sha256:").ok_or(
        ControllerError::Invalid("OCI transfer image ID is malformed"),
    )?;
    Ok(format!(
        "serverware-{phase}/{}:{}",
        handle.owner_namespace,
        &digest[..24],
    ))
}

fn verify_owned_image_labels(
    inspect: &[u8],
    image_id: &str,
    capability: &DockerLaneCapabilityV11,
) -> Result<()> {
    let value: Value = serde_json::from_slice(inspect).map_err(|_| {
        ControllerError::Invalid(
            "owned image inspect output is not JSON",
        )
    })?;
    let image = value
        .as_array()
        .and_then(|values| {
            (values.len() == 1).then(|| &values[0])
        })
        .ok_or(ControllerError::Rejected(
            "owned image inspect result is not singular",
        ))?;
    if image.get("Id").and_then(Value::as_str) != Some(image_id) {
        return Err(ControllerError::Rejected(
            "owned image inspect content ID differs",
        ));
    }
    let labels = image
        .pointer("/Config/Labels")
        .and_then(Value::as_object)
        .ok_or(ControllerError::Rejected(
            "owned image lacks exact controller labels",
        ))?;
    let logical_prefix = format!("{}:", capability.owner_namespace);
    let source_seal = digest_hex(&capability.source_seal_sha256);
    let artifact_seal = digest_hex(&capability.artifact_seal_sha256);
    if labels.len() < 6
        || labels.get(OWNER_LABEL_V11).and_then(Value::as_str)
            != Some(capability.owner_namespace.as_str())
        || labels.get(LANE_LABEL_V11).and_then(Value::as_str)
            != Some(capability.lane_id.as_str())
        || labels.get(GENERATION_LABEL_V11).and_then(Value::as_str)
            != Some(capability.daemon_generation.as_str())
        || labels
            .get(SOURCE_SEAL_LABEL_V11)
            .and_then(Value::as_str)
            != Some(source_seal.as_str())
        || labels
            .get(ARTIFACT_SEAL_LABEL_V11)
            .and_then(Value::as_str)
            != Some(artifact_seal.as_str())
        || labels
            .get(LOGICAL_ID_LABEL_V11)
            .and_then(Value::as_str)
            .is_none_or(|logical| !logical.starts_with(&logical_prefix))
    {
        return Err(ControllerError::Rejected(
            "owned image labels differ from the signed lane",
        ));
    }
    Ok(())
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

fn publish_cas_file(
    temporary: &Path,
    final_path: &Path,
    expected_sha256: Digest,
) -> Result<()> {
    if digest_file(temporary)? != expected_sha256 {
        return Err(ControllerError::Rejected(
            "OCI CAS temporary file changed before publication",
        ));
    }
    let temporary_c = c_path(temporary)?;
    let final_c = c_path(final_path)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            temporary_c.as_ptr(),
            libc::AT_FDCWD,
            final_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            verify_pinned_file(final_path, expected_sha256)?;
            std::fs::remove_file(temporary)?;
        } else {
            return Err(error.into());
        }
    }
    File::open(final_path)?.sync_all()?;
    File::open(final_path.parent().ok_or(
        ControllerError::Invalid("OCI CAS path has no parent"),
    )?)?
    .sync_all()?;
    verify_pinned_file(final_path, expected_sha256)
}

fn create_cgroup(path: &Path) -> Result<()> {
    std::fs::create_dir(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ControllerError::Rejected(
            "DinD cgroup path is unsafe",
        ));
    }
    Ok(())
}

fn attach_cgroup(path: &Path, pid: libc::pid_t) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.procs"))?;
    file.write_all(format!("{pid}\n").as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn kill_cgroup(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut file =
        OpenOptions::new().write(true).open(path.join("cgroup.kill"))?;
    file.write_all(b"1\n")?;
    file.sync_all()?;
    Ok(())
}

fn remove_cgroup(path: &Path, deadline: u64) -> Result<()> {
    while path.exists() {
        match std::fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::DirectoryNotEmpty
                        | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
        if boottime_now_ns_v11()? >= deadline {
            return Err(ControllerError::Rejected(
                "DinD cgroup removal exceeded its cleanup deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn bounded_remove_tree(
    ownership_root: &Path,
    target: &Path,
    deadline: u64,
) -> Result<()> {
    if !target.starts_with(ownership_root) || target == ownership_root {
        return Err(ControllerError::Rejected(
            "DinD cleanup target is outside owned state",
        ));
    }
    if !target.exists() {
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("--dind-cleanup-helper-v11")
        .arg(ownership_root)
        .arg(target)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_child_deadline(&mut child, deadline).and_then(|status| {
        if status.success() {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "DinD cleanup helper failed",
            ))
        }
    })
}

pub fn run_cleanup_helper_v11(
    ownership_root: &Path,
    target: &Path,
) -> Result<()> {
    require_absolute_normalized(ownership_root)?;
    require_absolute_normalized(target)?;
    if unsafe { libc::geteuid() } != 0
        || !target.starts_with(ownership_root)
        || target == ownership_root
    {
        return Err(ControllerError::Rejected(
            "DinD cleanup helper target is outside root-owned state",
        ));
    }
    let root = std::fs::symlink_metadata(ownership_root)?;
    let target_metadata = std::fs::symlink_metadata(target)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || root.uid() != 0
        || target_metadata.file_type().is_symlink()
        || target_metadata.uid() != 0
    {
        return Err(ControllerError::Rejected(
            "DinD cleanup helper ownership check failed",
        ));
    }
    std::fs::remove_dir_all(target)?;
    File::open(ownership_root)?.sync_all()?;
    Ok(())
}

fn wait_child_deadline(
    child: &mut Child,
    deadline: u64,
) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if boottime_now_ns_v11()? >= deadline {
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    child.id() as libc::pid_t,
                    0,
                ) as RawFd
            };
            if raw >= 0 {
                let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            return Err(ControllerError::Rejected(
                "private Docker control operation exceeded its deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_pidfd(pidfd: RawFd, deadline: u64) -> Result<()> {
    loop {
        let now = boottime_now_ns_v11()?;
        if now >= deadline {
            return Err(ControllerError::Rejected(
                "DinD pidfd cleanup exceeded its deadline",
            ));
        }
        let timeout = ((deadline - now) / 1_000_000)
            .min(250)
            .max(1) as i32;
        let mut descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result < 0
            && std::io::Error::last_os_error().kind()
                != std::io::ErrorKind::Interrupted
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn connect_private_dind_stream_v12(socket: &Path, deadline: u64) -> Result<UnixStream> {
    require_absolute_normalized(socket)?;
    if boottime_now_ns_v11()? >= deadline {
        return Err(ControllerError::Rejected("private DinD connect deadline expired"));
    }
    let path = socket.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err(ControllerError::Rejected("private DinD socket path is invalid"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, byte) in address.sun_path.iter_mut().zip(path) {
        *destination = *byte as libc::c_char;
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX,
        libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1)
        as libc::socklen_t;
    // The private local socket must connect immediately. Queue pressure,
    // interruption or a pending connect is rejected before any HTTP bytes;
    // neither blocking connect nor a fresh retry can renew the body deadline.
    if unsafe { libc::connect(owned.as_raw_fd(),
        (&address as *const libc::sockaddr_un).cast(), length) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if boottime_now_ns_v11()? >= deadline {
        return Err(ControllerError::Rejected("private DinD connect exceeded its original deadline"));
    }
    Ok(unsafe { UnixStream::from_raw_fd(owned.into_raw_fd()) })
}

fn docker_ping(socket: &Path, deadline: u64) -> Result<()> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_nonblocking(true)?;
    let request =
        b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n";
    write_socket_deadline(&mut stream, request, deadline)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = read_socket_deadline(&mut stream, &mut buffer, deadline)?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > 4096 {
            return Err(ControllerError::Rejected(
                "private Docker ping response exceeded its bound",
            ));
        }
    }
    if !response.starts_with(b"HTTP/1.1 200")
        || !response.windows(2).any(|window| window == b"OK")
    {
        return Err(ControllerError::Rejected(
            "private Docker ping failed",
        ));
    }
    Ok(())
}

fn write_socket_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    mut bytes: &[u8],
    deadline: u64,
) -> Result<()> {
    while !bytes.is_empty() {
        poll_socket(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(ControllerError::Rejected(
                    "DinD socket closed during write",
                ))
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_socket_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &mut [u8],
    deadline: u64,
) -> Result<usize> {
    loop {
        poll_socket(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        match stream.read(bytes) {
            Ok(count) => return Ok(count),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn poll_socket(fd: RawFd, events: i16, deadline: u64) -> Result<()> {
    let now = boottime_now_ns_v11()?;
    if now >= deadline {
        return Err(ControllerError::Rejected(
            "DinD socket deadline expired",
        ));
    }
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let timeout = ((deadline - now) / 1_000_000)
        .min(250)
        .max(1) as i32;
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    if result > 0 {
        Ok(())
    } else if result == 0 {
        Err(ControllerError::Rejected(
            "DinD socket deadline quantum expired",
        ))
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn write_pid_record(
    path: &Path,
    pid: libc::pid_t,
    start_time_ticks: u64,
    owner_namespace: &str,
    generation: &str,
    socket: &Path,
    cgroup: &Path,
) -> Result<()> {
    let boot_id = current_boot_id()?;
    let content = format!(
        "version=12\npid={pid}\nstart_time_ticks={start_time_ticks}\nboot_id={boot_id}\nowner_namespace={owner_namespace}\ngeneration={generation}\nsocket={}\ncgroup={}\n",
        socket.display(),
        cgroup.display(),
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    File::open(path.parent().ok_or(ControllerError::Invalid(
        "DinD ownership record has no parent",
    ))?)?
    .sync_all()?;
    Ok(())
}

fn read_pid_record(path: &Path) -> Result<PidRecordV11> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > DIND_PID_RECORD_MAX_BYTES_V11
    {
        return Err(ControllerError::Rejected(
            "DinD ownership record is unsafe",
        ));
    }
    let text = std::fs::read_to_string(path)?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(
            ControllerError::Invalid(
                "DinD ownership record is malformed",
            ),
        )?;
        if fields.insert(key, value).is_some() {
            return Err(ControllerError::Rejected(
                "DinD ownership record contains duplicate fields",
            ));
        }
    }
    let expected = [
        "version",
        "pid",
        "start_time_ticks",
        "boot_id",
        "owner_namespace",
        "generation",
        "socket",
        "cgroup",
    ];
    if fields.len() != expected.len()
        || expected.iter().any(|key| !fields.contains_key(key))
        || fields.get("version") != Some(&"12")
    {
        return Err(ControllerError::Rejected(
            "DinD ownership record fields differ",
        ));
    }
    Ok(PidRecordV11 {
        pid: fields["pid"].parse().map_err(|_| {
            ControllerError::Invalid("DinD PID is invalid")
        })?,
        start_time_ticks: fields["start_time_ticks"].parse().map_err(
            |_| ControllerError::Invalid("DinD start time is invalid"),
        )?,
        boot_id: fields["boot_id"].to_owned(),
        owner_namespace: fields["owner_namespace"].to_owned(),
        generation: fields["generation"].to_owned(),
        socket: PathBuf::from(fields["socket"]),
        cgroup: PathBuf::from(fields["cgroup"]),
    })
}

fn current_boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(ControllerError::Rejected(
            "kernel boot identity is not canonical",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn digest_file(path: &Path) -> Result<Digest> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(ControllerError::Rejected(
            "OCI CAS input is not private root-owned data",
        ));
    }
    sha256_exact_reader(&mut File::open(path)?, metadata.len())
}

fn verify_pinned_file(path: &Path, expected: Digest) -> Result<()> {
    if !constant_time_eq(&digest_file(path)?, &expected) {
        return Err(ControllerError::Rejected(
            "pinned DinD input digest changed",
        ));
    }
    Ok(())
}

fn process_start_time(pid: libc::pid_t) -> Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = text.rfind(')').ok_or(ControllerError::Invalid(
        "process stat command field is malformed",
    ))?;
    text[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(ControllerError::Invalid(
            "process start-time field is absent",
        ))?
        .parse::<u64>()
        .map_err(|_| {
            ControllerError::Invalid("process start time is invalid")
        })
}

fn cleanup_deadline() -> Result<u64> {
    boottime_now_ns_v11()?
        .checked_add(DIND_CLEANUP_TIMEOUT_NS_V11)
        .ok_or(ControllerError::Invalid(
            "DinD cleanup deadline overflowed",
        ))
}

fn require_private_root(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(ControllerError::Rejected(
            "DinD private root is unsafe",
        ));
    }
    Ok(())
}

fn require_socket_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(ControllerError::Rejected(
            "DinD socket path is already occupied",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_socket_if_owned(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == 0 =>
        {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(ControllerError::Rejected(
            "DinD cleanup socket is foreign",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn require_component(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err(ControllerError::Rejected(
            "DinD generation component is unsafe",
        ));
    }
    Ok(())
}

fn require_absolute_normalized(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(ControllerError::Rejected(
            "DinD path is not absolute and normalized",
        ));
    }
    c_path(path)?;
    Ok(())
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ControllerError::Invalid("DinD path contains NUL"))
}

fn safe_label(label: &str) -> String {
    label
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || byte == b'-' {
                byte as char
            } else {
                '_'
            }
        })
        .collect()
}
