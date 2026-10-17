#![allow(dead_code)]

use crate::coder_controller_v11::{
    canonical_json_bytes_v11, constant_time_eq, digest_hex, sha256,
    ControllerError, Digest, Result,
};
use crate::docker_contract::{
    boottime_now_ns_v11, DockerApiRequestV11, DockerLaneOperationV12,
    DockerMountKindV12, DockerNetworkMembershipV12, DockerObjectStateV11,
    DockerResourceKindV11, AuthoritativeLaneState, LogicalLane,
    PrivateDindOperationResponseV12, PrivateDindProfileV12,
    ProxyOperation, DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
};
use crate::docker_policy::{
    DockerCasIdentityKindV12, DockerOwnershipViewV11,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const LEDGER_RECORD_MAX_BYTES: u64 = 8 * 1024 * 1024;
const LEDGER_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const LEDGER_VERSION: &str = "12";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerMutationStatusV11 {
    Intent,
    Applied,
    Unknown,
    Destroying,
    Destroyed,
}

impl DockerMutationStatusV11 {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::Applied => "APPLIED",
            Self::Unknown => "UNKNOWN",
            Self::Destroying => "DESTROYING",
            Self::Destroyed => "DESTROYED",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "INTENT" => Ok(Self::Intent),
            "APPLIED" => Ok(Self::Applied),
            "UNKNOWN" => Ok(Self::Unknown),
            "DESTROYING" => Ok(Self::Destroying),
            "DESTROYED" => Ok(Self::Destroyed),
            _ => Err(ControllerError::Rejected(
                "Docker ledger mutation status is invalid",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DockerObjectRecordV11 {
    pub boot_id_sha256: Digest,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub source_seal_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub kind: DockerResourceKindV11,
    pub logical_id: String,
    pub engine_id: Option<String>,
    pub state: DockerObjectStateV11,
    pub labels: BTreeMap<String, String>,
    pub last_sequence: u64,
    pub last_request_sha256: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct DockerMutationRecordV11 {
    pub boot_id_sha256: Digest,
    pub request_id: String,
    pub request_sha256: Digest,
    pub capability_sha256: Digest,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub source_seal_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub sequence: u64,
    pub kind: DockerResourceKindV11,
    pub logical_id: String,
    pub engine_id: Option<String>,
    pub from_state: DockerObjectStateV11,
    pub intended_state: DockerObjectStateV11,
    pub terminal_state: Option<DockerObjectStateV11>,
    pub status: DockerMutationStatusV11,
    pub response_sha256: Option<Digest>,
    pub response_bytes: Option<u64>,
    pub reconciliation_sha256: Option<Digest>,
    pub uncertainty: Option<DockerMutationUncertaintyV12>,
    pub network_membership: Option<DockerNetworkMembershipIntentV12>,
    pub deadline_boottime_ns: u64,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerMutationUncertaintyV12 {
    NotSent,
    PostSendUncertain,
}

impl DockerMutationUncertaintyV12 {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotSent => "NOT_SENT",
            Self::PostSendUncertain => "POST_SEND_UNCERTAIN",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "NOT_SENT" => Ok(Self::NotSent),
            "POST_SEND_UNCERTAIN" => Ok(Self::PostSendUncertain),
            _ => Err(ControllerError::Rejected(
                "Docker mutation uncertainty class is invalid",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerNetworkMembershipStatusV12 {
    PendingConnect,
    Connected,
    PendingDisconnect,
    Disconnected,
    Unknown,
}

impl DockerNetworkMembershipStatusV12 {
    fn as_str(self) -> &'static str {
        match self {
            Self::PendingConnect => "PENDING_CONNECT",
            Self::Connected => "CONNECTED",
            Self::PendingDisconnect => "PENDING_DISCONNECT",
            Self::Disconnected => "DISCONNECTED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "PENDING_CONNECT" => Ok(Self::PendingConnect),
            "CONNECTED" => Ok(Self::Connected),
            "PENDING_DISCONNECT" => Ok(Self::PendingDisconnect),
            "DISCONNECTED" => Ok(Self::Disconnected),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(ControllerError::Rejected(
                "Docker network-membership status is invalid",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DockerNetworkMembershipIntentV12 {
    pub authority_sha256: Digest,
    pub membership_id: String,
    pub network_logical_id: String,
    pub network_engine_id: String,
    pub container_logical_id: String,
    pub container_engine_id: String,
    pub endpoint_id: String,
    pub aliases: Vec<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub desired_connected: bool,
}

#[derive(Clone, Debug)]
pub struct DockerNetworkMembershipRecordV12 {
    pub boot_id_sha256: Digest,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub intent: DockerNetworkMembershipIntentV12,
    pub status: DockerNetworkMembershipStatusV12,
    pub last_sequence: u64,
    pub last_request_sha256: Digest,
    pub reconciliation_sha256: Option<Digest>,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct DockerObservedNetworkMembershipV12 {
    pub connected: bool,
    pub network_engine_id: String,
    pub container_engine_id: String,
    pub endpoint_id: Option<String>,
    pub aliases: Vec<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub observation_sha256: Digest,
}

pub enum BeginMutationV11 {
    Prepared(DockerPreparedMutationV11),
    ExactReplay {
        record: DockerMutationRecordV11,
        response_path: PathBuf,
        response_bytes: u64,
        response_sha256: Digest,
    },
    RequiresReconciliation(DockerMutationRecordV11),
}

#[derive(Clone, Debug)]
pub struct DockerPreparedMutationV11 {
    pub request: DockerApiRequestV11,
    pub record: DockerMutationRecordV11,
}

#[derive(Clone, Debug)]
pub struct DockerObservedObjectV11 {
    pub exists: bool,
    pub engine_id: Option<String>,
    pub state: DockerObjectStateV11,
    pub labels: BTreeMap<String, String>,
    pub observation_sha256: Digest,
}

pub fn observe_network_membership_v12(
    exact_inspect_body: &[u8],
    intent: &DockerNetworkMembershipIntentV12,
) -> Result<DockerObservedNetworkMembershipV12> {
    if exact_inspect_body.is_empty()
        || exact_inspect_body.len() as u64 > LEDGER_RECORD_MAX_BYTES
    {
        return Err(ControllerError::Rejected(
            "Docker network inspect response exceeds its reconciliation bound",
        ));
    }
    let value: Value = serde_json::from_slice(exact_inspect_body).map_err(
        |_| ControllerError::Invalid("Docker network inspect is not JSON"),
    )?;
    let object = value.as_object().ok_or(ControllerError::Invalid(
        "Docker network inspect is not an object",
    ))?;
    if object.get("Id").and_then(Value::as_str)
        != Some(intent.network_engine_id.as_str())
    {
        return Err(ControllerError::Rejected(
            "Docker network inspect ID differs from reconciliation authority",
        ));
    }
    let containers = match object.get("Containers") {
        Some(Value::Object(containers)) => containers,
        Some(Value::Null) | None => {
            return Ok(DockerObservedNetworkMembershipV12 {
                connected: false,
                network_engine_id: intent.network_engine_id.clone(),
                container_engine_id: intent.container_engine_id.clone(),
                endpoint_id: None,
                aliases: Vec::new(),
                ipv4_address: None,
                ipv6_address: None,
                observation_sha256: sha256(exact_inspect_body),
            })
        }
        _ => {
            return Err(ControllerError::Invalid(
                "Docker network inspect Containers is invalid",
            ))
        }
    };
    let membership = containers.get(&intent.container_engine_id);
    let (endpoint_id, aliases, ipv4_address, ipv6_address) = match membership {
        None => (None, Vec::new(), None, None),
        Some(Value::Object(membership)) => {
            let endpoint_id = membership
                .get("EndpointID")
                .and_then(Value::as_str)
                .ok_or(ControllerError::Invalid(
                    "Docker network inspect endpoint ID is invalid",
                ))?
                .to_owned();
            let address = |field: &'static str| -> Result<Option<String>> {
                let value = membership
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(ControllerError::Invalid(field))?;
                Ok((!value.is_empty()).then(|| {
                    value.split('/').next().unwrap_or(value).to_owned()
                }))
            };
            let aliases = match membership.get("DNSNames") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(values)) => values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .ok_or(ControllerError::Invalid(
                                "Docker network inspect DNS name is invalid",
                            ))
                    })
                    .collect::<Result<Vec<_>>>()?,
                Some(_) => {
                    return Err(ControllerError::Invalid(
                        "Docker network inspect DNS names are invalid",
                    ))
                }
            };
            (
                Some(endpoint_id),
                aliases,
                address("IPv4Address")?,
                address("IPv6Address")?,
            )
        }
        Some(_) => {
            return Err(ControllerError::Invalid(
                "Docker network inspect membership is invalid",
            ))
        }
    };
    Ok(DockerObservedNetworkMembershipV12 {
        connected: endpoint_id.is_some(),
        network_engine_id: intent.network_engine_id.clone(),
        container_engine_id: intent.container_engine_id.clone(),
        endpoint_id,
        aliases,
        ipv4_address,
        ipv6_address,
        observation_sha256: sha256(exact_inspect_body),
    })
}

pub trait DockerReconcilerV11 {
    fn query_exact(
        &self,
        record: &DockerMutationRecordV11,
        deadline_boottime_ns: u64,
    ) -> Result<DockerObservedObjectV11>;

    fn query_network_membership(
        &self,
        _record: &DockerMutationRecordV11,
        _membership: &DockerNetworkMembershipIntentV12,
        _deadline_boottime_ns: u64,
    ) -> Result<DockerObservedNetworkMembershipV12> {
        Err(ControllerError::Rejected(
            "Docker reconciler does not implement exact network-membership observation",
        ))
    }
}

pub struct DockerOwnershipLedgerV11 {
    root: PathBuf,
    lease: File,
    boot_id_sha256: Digest,
    local: Mutex<()>,
}

pub struct DockerLaneOperationLeaseV11 {
    _file: File,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DockerLaneOperationStatusV12 {
    Intent,
    Applied,
    OutcomeUnknown,
    Destroying,
    Destroyed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DockerLaneAuthorityKindV12 {
    Generation,
    Readiness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerLaneOperationRecordV12 {
    pub version: String,
    pub boot_id_sha256: Digest,
    pub request_id: Digest,
    pub request_sha256: Digest,
    pub lifecycle_request_sha256: Digest,
    pub plan_id: Digest,
    pub capability_sha256: Digest,
    pub authority_kind: DockerLaneAuthorityKindV12,
    pub lane: LogicalLane,
    pub profile: PrivateDindProfileV12,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub sequence: u64,
    pub operation: ProxyOperation,
    pub target_sha256: Digest,
    pub payload_sha256: Digest,
    pub expected_state: AuthoritativeLaneState,
    pub authoritative_state: AuthoritativeLaneState,
    pub status: DockerLaneOperationStatusV12,
    pub result_sha256: Option<Digest>,
    pub response_sha256: Option<Digest>,
    pub observed_state_sha256: Option<Digest>,
    pub deadline_boottime_ns: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerGenerationRecordV12 {
    pub version: String,
    pub boot_id_sha256: Digest,
    pub plan_id: Digest,
    pub capability_sha256: Digest,
    pub profile: PrivateDindProfileV12,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub lane_slot: u8,
    pub network_namespace: Option<String>,
    pub dind_pid: Option<i32>,
    pub dind_start_time_ticks: Option<u64>,
    pub docker_authority_established: bool,
    pub state: AuthoritativeLaneState,
    pub status: DockerLaneOperationStatusV12,
    pub last_sequence: u64,
    pub last_request_sha256: Digest,
    pub observed_state_sha256: Option<Digest>,
    pub terminal_receipt_sha256: Option<Digest>,
    pub expected_oci_imports: Vec<Digest>,
    pub imported_oci_imports: Vec<Digest>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerReadinessAuthorityRecordV12 {
    pub version: String,
    pub boot_id_sha256: Digest,
    pub plan_id: Digest,
    pub capability_sha256: Digest,
    pub state: AuthoritativeLaneState,
    pub status: DockerLaneOperationStatusV12,
    pub last_sequence: u64,
    pub last_request_sha256: Digest,
    pub observed_state_sha256: Option<Digest>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DockerPlanCleanupRecordV12 {
    version: String,
    boot_id_sha256: Digest,
    plan_id: Digest,
    request_sha256_canonical: Digest,
    state: AuthoritativeLaneState,
    observed_terminal_sha256: Option<Digest>,
    revision: u64,
    record_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerGenerationDestructionObservationV12 {
    pub version: String,
    pub boot_id_sha256: Digest,
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
    pub terminal_containers: u64,
    pub terminal_images: u64,
    pub terminal_networks: u64,
    pub terminal_volumes: u64,
    pub docker_authority_established: bool,
    pub mounts: u64,
    pub cgroup_processes: u64,
    pub proxy_accepting: bool,
    pub dind_reaped: bool,
    pub netns_absent: bool,
    pub socket_absent: bool,
    pub state_root_absent: bool,
    pub observed_state_sha256: Digest,
    pub observation_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerLegacyDestructionRecoveryV12 {
    pub version: String,
    pub recovery_boot_id_sha256: Digest,
    pub plan_id: Digest,
    pub capability_sha256: Digest,
    pub profile: PrivateDindProfileV12,
    pub owner_namespace: String,
    pub daemon_generation: String,
    pub recovered_at_boottime_ns: u64,
    pub source_generation_sha256: Digest,
    pub source_terminal_receipt_sha256: Digest,
    pub current_absence_sha256: Digest,
    pub mounts: u64,
    pub cgroup_processes: u64,
    pub proxy_accepting: bool,
    pub dind_reaped: bool,
    pub netns_absent: bool,
    pub socket_absent: bool,
    pub state_root_absent: bool,
    pub signer_spki_sha256: Digest,
    pub signature: Vec<u8>,
    pub recovery_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DockerLaneTerminalTransactionV12 {
    version: String,
    boot_id_sha256: Digest,
    request_id: Digest,
    request_sha256: Digest,
    operation: DockerLaneOperationRecordV12,
    generation: Option<DockerGenerationRecordV12>,
    readiness: Option<DockerReadinessAuthorityRecordV12>,
    response: PrivateDindOperationResponseV12,
    transaction_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DockerGenerationDestructionTransactionV12 {
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation: Option<DockerGenerationDestructionObservationV12>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_recovery: Option<DockerLegacyDestructionRecoveryV12>,
    exact_terminal_receipt: Option<Vec<u8>>,
    terminal_generation: Option<DockerGenerationRecordV12>,
    transaction_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DockerTerminalReceiptBindingV12 {
    version: String,
    trust_profile: String,
    plan_id: Digest,
    capability_sha256: Digest,
    profile: PrivateDindProfileV12,
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

pub enum BeginLaneOperationV12 {
    Prepared(DockerLaneOperationRecordV12),
    ExactReplay {
        record: DockerLaneOperationRecordV12,
        response: PrivateDindOperationResponseV12,
        exact_response: Vec<u8>,
    },
    RequiresReconciliation(DockerLaneOperationRecordV12),
}

pub struct DockerLaneLedgerV12 {
    root: PathBuf,
    boot_id_sha256: Digest,
    local: Mutex<()>,
}

impl DockerLaneLedgerV12 {
    pub fn open_without_legacy_lease(root: &Path) -> Result<Self> {
        Self::open_internal(root, true)
    }

    pub fn open_for_legacy_recovery(root: &Path) -> Result<Self> {
        Self::open_internal(root, false)
    }

    fn open_internal(
        root: &Path,
        require_transaction_coverage: bool,
    ) -> Result<Self> {
        require_absolute_normalized(root)?;
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(
            root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
        {
            return Err(ControllerError::Rejected(
                "v12 lane ledger root is not private root-owned storage",
            ));
        }
        for relative in [
            "lane-requests-v12",
            "lane-responses-v12",
            "generations-v12",
            "readiness-authorities-v12",
            "terminal-transactions-v12",
            "destruction-transactions-v12",
            "terminal-receipts-v12",
            "plan-cleanups-v12",
        ] {
            let directory = root.join(relative);
            std::fs::create_dir_all(&directory)?;
            std::fs::set_permissions(
                &directory,
                std::fs::Permissions::from_mode(0o700),
            )?;
            let metadata = std::fs::symlink_metadata(&directory)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o077 != 0
            {
                return Err(ControllerError::Rejected(
                    "v12 lane ledger subdirectory is unsafe",
                ));
            }
            File::open(&directory)?.sync_all()?;
        }
        File::open(root)?.sync_all()?;
        let ledger = Self {
            root: root.to_path_buf(),
            boot_id_sha256: current_boot_id_sha256_v12()?,
            local: Mutex::new(()),
        };
        ledger.recover_destruction_transactions()?;
        ledger.validate_plan_cleanup_records()?;
        if require_transaction_coverage {
            ledger.require_destruction_transaction_coverage()?;
        }
        Ok(ledger)
    }

    pub fn begin_operation(
        &self,
        lifecycle_request_sha256: Digest,
        operation: &DockerLaneOperationV12,
    ) -> Result<BeginLaneOperationV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if boottime_now_ns_v11()? >= operation.request.deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "v12 lane operation expired before durable intent",
            ));
        }
        let request_path =
            self.request_path(&operation.request.request_id);
        if request_path.exists() {
            let transaction_path =
                self.transaction_path(&operation.request.request_id);
            let record = if transaction_path.exists() {
                let transaction =
                    self.read_terminal_transaction(&transaction_path)?;
                self.validate_terminal_transaction(&transaction)?;
                self.materialize_terminal_transaction(&transaction)?;
                transaction.operation
            } else {
                self.read_operation(&request_path)?
            };
            if record.request_sha256 != operation.request.request_sha256
                || record.lifecycle_request_sha256
                    != lifecycle_request_sha256
                || record.sequence != operation.request.sequence
                || record.plan_id != operation.request.plan_id
                || record.capability_sha256
                    != operation.request.capability_sha256
                || record.owner_namespace != operation.owner_namespace
                || record.daemon_generation
                    != operation.daemon_generation
            {
                return Err(ControllerError::Rejected(
                    "v12 lane request ID was reused with different authority",
                ));
            }
            return match record.status {
                DockerLaneOperationStatusV12::Applied
                | DockerLaneOperationStatusV12::Destroyed => {
                    let transaction = self.read_terminal_transaction(
                        &self.transaction_path(&record.request_id),
                    )?;
                    self.validate_terminal_transaction(&transaction)?;
                    let response = transaction.response;
                    let exact_response =
                        canonical_json_bytes_v11(
                            &serde_json::to_value(&response).map_err(
                                |_| {
                                    ControllerError::Invalid(
                                        "v12 replay response is not serializable",
                                    )
                                },
                            )?,
                        )?;
                    if record.response_sha256
                        != Some(response.response_sha256)
                        || record.result_sha256
                            != Some(response.result_sha256)
                    {
                        return Err(ControllerError::Rejected(
                            "v12 replay response differs from terminal ledger",
                        ));
                    }
                    Ok(BeginLaneOperationV12::ExactReplay {
                        record,
                        response,
                        exact_response,
                    })
                }
                DockerLaneOperationStatusV12::Intent
                | DockerLaneOperationStatusV12::OutcomeUnknown => {
                    Ok(BeginLaneOperationV12::RequiresReconciliation(
                        record,
                    ))
                }
                DockerLaneOperationStatusV12::Destroying => {
                    Err(ControllerError::Rejected(
                        "v12 lane generation is already destroying",
                    ))
                }
            };
        }
        let plan_cleanup_path =
            self.plan_cleanup_path(&operation.request.plan_id);
        if plan_cleanup_path.exists() {
            let cleanup =
                self.read_plan_cleanup(&plan_cleanup_path)?;
            self.validate_plan_cleanup(&cleanup)?;
            let terminal_destroy_replay = cleanup.state
                    == AuthoritativeLaneState::Destroyed
                && matches!(
                    operation.request.operation,
                    ProxyOperation::DestroyBuildDind
                        | ProxyOperation::DestroyNoBuildDind
                );
            if !terminal_destroy_replay {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup tombstone rejects new lane authority",
                ));
            }
        }
        let authority_kind = operation_authority_kind_v12(operation);
        let generation_path = self.generation_path(
            &operation.owner_namespace,
            &operation.daemon_generation,
        );
        let readiness_path = self.readiness_authority_path(
            &operation.request.plan_id,
            &operation.request.capability_sha256,
        );
        let create = matches!(
            operation.request.operation,
            ProxyOperation::CreateBuildDind
                | ProxyOperation::CreateNoBuildDind
        );
        let mut generation =
            if authority_kind == DockerLaneAuthorityKindV12::Generation {
                Some(if generation_path.exists() {
                    self.read_generation(&generation_path)?
                } else if create {
                    let expected_oci_imports =
                        match &operation.decoded_payload {
                            crate::docker_contract::DockerLaneDecodedPayloadV12::Operation(
                                payload,
                            ) => match &payload.content {
                                crate::docker_contract::DockerLanePayloadContentV12::CreateNoBuildDind {
                                    required_oci_import_closure,
                                    ..
                                } => {
                                    required_oci_import_closure
                                        .validate()
                                        .map_err(|error| {
                                            ControllerError::InvalidOwned(
                                                error.to_string(),
                                            )
                                        })?;
                                    required_oci_import_closure
                                        .manifest_sha256
                                        .clone()
                                }
                                _ => Vec::new(),
                            },
                            _ => Vec::new(),
                        };
                    DockerGenerationRecordV12 {
                        version: LEDGER_VERSION.to_owned(),
                        boot_id_sha256: self.boot_id_sha256,
                        plan_id: operation.request.plan_id,
                        capability_sha256:
                            operation.request.capability_sha256,
                        profile: operation.profile,
                        owner_namespace:
                            operation.owner_namespace.clone(),
                        daemon_generation:
                            operation.daemon_generation.clone(),
                        lane_slot: operation.generation_slot(),
                        network_namespace: None,
                        dind_pid: None,
                        dind_start_time_ticks: None,
                        docker_authority_established: false,
                        state: operation.request.expected_state,
                        status: DockerLaneOperationStatusV12::Intent,
                        last_sequence: 0,
                        last_request_sha256: [0; 32],
                        observed_state_sha256: None,
                        terminal_receipt_sha256: None,
                        expected_oci_imports,
                        imported_oci_imports: Vec::new(),
                        revision: 1,
                    }
                } else {
                    return Err(ControllerError::Rejected(
                        "v12 lane operation references an unknown generation",
                    ));
                })
            } else {
                None
            };
        let mut readiness =
            if authority_kind == DockerLaneAuthorityKindV12::Readiness {
                Some(if readiness_path.exists() {
                    self.read_readiness_authority(&readiness_path)?
                } else if operation.request.operation.is_readiness() {
                    DockerReadinessAuthorityRecordV12 {
                        version: LEDGER_VERSION.to_owned(),
                        boot_id_sha256: self.boot_id_sha256,
                        plan_id: operation.request.plan_id,
                        capability_sha256:
                            operation.request.capability_sha256,
                        state: AuthoritativeLaneState::Declared,
                        status: DockerLaneOperationStatusV12::Applied,
                        last_sequence: 0,
                        last_request_sha256: [0; 32],
                        observed_state_sha256: None,
                        revision: 1,
                    }
                } else {
                    return Err(ControllerError::Rejected(
                        "v12 readiness query references unknown authority",
                    ));
                })
            } else {
                None
            };
        let expected_state_is_precondition = !matches!(
            operation.request.operation,
            ProxyOperation::DestroyBuildDind
                | ProxyOperation::DestroyNoBuildDind
                | ProxyOperation::QueryAuthoritativeState
        );
        let mut authority_last_sequence = 0u64;
        for path in read_dir_sorted(
            &self.root.join("lane-requests-v12"),
        )? {
            let retained = self.read_operation(&path)?;
            if retained.plan_id == operation.request.plan_id
                && retained.capability_sha256
                    == operation.request.capability_sha256
            {
                authority_last_sequence = authority_last_sequence
                    .max(retained.sequence);
            }
        }
        let generation_valid = generation.as_ref().map_or(true, |generation| {
            generation.boot_id_sha256 == self.boot_id_sha256
                && generation.plan_id == operation.request.plan_id
                && generation.capability_sha256
                    == operation.request.capability_sha256
                && generation.profile == operation.profile
                && generation.owner_namespace == operation.owner_namespace
                && generation.daemon_generation
                    == operation.daemon_generation
                && generation.lane_slot
                    == operation.generation_slot()
                && (!expected_state_is_precondition
                    || generation.state
                        == operation.request.expected_state)
                && (operation.profile != PrivateDindProfileV12::NoBuild
                    || !generation.expected_oci_imports.is_empty())
                && (generation.status
                    != DockerLaneOperationStatusV12::Destroyed
                    || matches!(
                        operation.request.operation,
                        ProxyOperation::QueryAuthoritativeState
                            | ProxyOperation::DestroyBuildDind
                            | ProxyOperation::DestroyNoBuildDind
                    ))
        });
        let readiness_valid =
            readiness.as_ref().map_or(true, |readiness| {
                readiness.boot_id_sha256 == self.boot_id_sha256
                    && readiness.plan_id == operation.request.plan_id
                    && readiness.capability_sha256
                        == operation.request.capability_sha256
                    && operation.request.expected_state
                        == AuthoritativeLaneState::Declared
                    && (readiness.state
                        == AuthoritativeLaneState::Declared
                        || operation.request.operation
                            == ProxyOperation::QueryAuthoritativeState
                            && readiness.state
                                == AuthoritativeLaneState::OutcomeUnknown)
            });
        if !generation_valid
            || !readiness_valid
            || operation.request.sequence
                != authority_last_sequence.saturating_add(1)
        {
            return Err(ControllerError::Rejected(
                "v12 lane generation or sequence differs from durable authority",
            ));
        }
        let authoritative_state = generation
            .as_ref()
            .map(|generation| generation.state)
            .or_else(|| readiness.as_ref().map(|readiness| readiness.state))
            .ok_or(ControllerError::Rejected(
                "v12 lane operation lacks durable authority state",
            ))?;
        let record = DockerLaneOperationRecordV12 {
            version: LEDGER_VERSION.to_owned(),
            boot_id_sha256: self.boot_id_sha256,
            request_id: operation.request.request_id,
            request_sha256: operation.request.request_sha256,
            lifecycle_request_sha256,
            plan_id: operation.request.plan_id,
            capability_sha256: operation.request.capability_sha256,
            authority_kind,
            lane: operation.request.lane,
            profile: operation.profile,
            owner_namespace: operation.owner_namespace.clone(),
            daemon_generation: operation.daemon_generation.clone(),
            sequence: operation.request.sequence,
            operation: operation.request.operation,
            target_sha256: operation.request.target_sha256,
            payload_sha256: operation.request.payload_sha256,
            expected_state: operation.request.expected_state,
            authoritative_state,
            status: DockerLaneOperationStatusV12::Intent,
            result_sha256: None,
            response_sha256: None,
            observed_state_sha256: None,
            deadline_boottime_ns:
                operation.request.deadline_boottime_ns,
            revision: 1,
        };
        if let Some(generation) = generation.as_mut() {
            let terminal_destroy_replay = generation.status
                    == DockerLaneOperationStatusV12::Destroyed
                && generation.state
                    == AuthoritativeLaneState::Destroyed
                && generation.terminal_receipt_sha256.is_some()
                && matches!(
                    operation.request.operation,
                    ProxyOperation::DestroyBuildDind
                        | ProxyOperation::DestroyNoBuildDind
                );
            if !terminal_destroy_replay {
                generation.status =
                    DockerLaneOperationStatusV12::Intent;
                generation.last_sequence =
                    operation.request.sequence;
                generation.last_request_sha256 =
                    operation.request.request_sha256;
                generation.revision =
                    generation.revision.saturating_add(1);
            }
        }
        if let Some(readiness) = readiness.as_mut() {
            readiness.status = DockerLaneOperationStatusV12::Intent;
            readiness.last_sequence = operation.request.sequence;
            readiness.last_request_sha256 =
                operation.request.request_sha256;
            readiness.revision = readiness.revision.saturating_add(1);
        }
        self.write_struct_create_new(&request_path, &record)?;
        if let Some(generation) = generation {
            if generation_path.exists() {
                self.write_struct_replace(&generation_path, &generation)?;
            } else {
                self.write_struct_create_new(
                    &generation_path,
                    &generation,
                )?;
            }
            self.sync_directory("generations-v12")?;
        }
        if let Some(readiness) = readiness {
            if readiness_path.exists() {
                self.write_struct_replace(&readiness_path, &readiness)?;
            } else {
                self.write_struct_create_new(
                    &readiness_path,
                    &readiness,
                )?;
            }
            self.sync_directory("readiness-authorities-v12")?;
        }
        self.sync_directory("lane-requests-v12")?;
        Ok(BeginLaneOperationV12::Prepared(record))
    }

    pub fn authoritative_state_after(
        &self,
        prepared: &DockerLaneOperationRecordV12,
        policy_state: AuthoritativeLaneState,
    ) -> Result<AuthoritativeLaneState> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if prepared.authority_kind
            == DockerLaneAuthorityKindV12::Readiness
        {
            if policy_state != AuthoritativeLaneState::Declared {
                return Err(ControllerError::Rejected(
                    "v12 readiness operation attempted a generation state transition",
                ));
            }
            return Ok(AuthoritativeLaneState::Declared);
        }
        if prepared.operation != ProxyOperation::ImportSealedOci {
            return Ok(policy_state);
        }
        let generation = self.read_generation(&self.generation_path(
            &prepared.owner_namespace,
            &prepared.daemon_generation,
        ))?;
        if generation
            .expected_oci_imports
            .binary_search(&prepared.target_sha256)
            .is_err()
            || generation
                .imported_oci_imports
                .binary_search(&prepared.target_sha256)
                .is_ok()
        {
            return Err(ControllerError::Rejected(
                "v12 OCI import is outside or duplicates the exact closure",
            ));
        }
        let complete = generation
            .imported_oci_imports
            .len()
            .saturating_add(1)
            == generation.expected_oci_imports.len();
        Ok(if complete {
            AuthoritativeLaneState::Prepared
        } else {
            AuthoritativeLaneState::Preparing
        })
    }

    pub fn ensure_readiness_generation(
        &self,
        operation: &DockerLaneOperationV12,
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if !operation.request.operation.is_readiness() {
            return Err(ControllerError::Rejected(
                "v12 readiness generation requires a readiness operation",
            ));
        }
        let path = self.generation_path(
            &operation.owner_namespace,
            &operation.daemon_generation,
        );
        if path.exists() {
            let retained = self.read_generation(&path)?;
            if retained.plan_id != operation.request.plan_id
                || retained.capability_sha256
                    != operation.request.capability_sha256
                || retained.profile != operation.profile
                || retained.owner_namespace
                    != operation.owner_namespace
                || retained.daemon_generation
                    != operation.daemon_generation
                || retained.lane_slot
                    != operation.generation_slot()
                || retained.state == AuthoritativeLaneState::Destroyed
                || retained.status
                    == DockerLaneOperationStatusV12::Destroyed
            {
                return Err(ControllerError::Rejected(
                    "v12 readiness generation conflicts with retained authority",
                ));
            }
            return Ok(retained);
        }
        let generation = DockerGenerationRecordV12 {
            version: LEDGER_VERSION.to_owned(),
            boot_id_sha256: self.boot_id_sha256,
            plan_id: operation.request.plan_id,
            capability_sha256: operation.request.capability_sha256,
            profile: operation.profile,
            owner_namespace: operation.owner_namespace.clone(),
            daemon_generation: operation.daemon_generation.clone(),
            lane_slot: operation.generation_slot(),
            network_namespace: None,
            dind_pid: None,
            dind_start_time_ticks: None,
            docker_authority_established: false,
            state: AuthoritativeLaneState::Declared,
            status: DockerLaneOperationStatusV12::Applied,
            last_sequence: operation.request.sequence,
            last_request_sha256: operation.request.request_sha256,
            observed_state_sha256: None,
            terminal_receipt_sha256: None,
            expected_oci_imports: Vec::new(),
            imported_oci_imports: Vec::new(),
            revision: 1,
        };
        self.write_struct_create_new(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        Ok(generation)
    }

    pub fn commit_operation(
        &self,
        prepared: DockerLaneOperationRecordV12,
        response: &PrivateDindOperationResponseV12,
    ) -> Result<DockerLaneOperationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let request_path = self.request_path(&prepared.request_id);
        let mut current = self.read_operation(&request_path)?;
        let plan_cleanup_path =
            self.plan_cleanup_path(&current.plan_id);
        if plan_cleanup_path.exists() {
            let cleanup =
                self.read_plan_cleanup(&plan_cleanup_path)?;
            self.validate_plan_cleanup(&cleanup)?;
            if !matches!(
                current.operation,
                ProxyOperation::DestroyBuildDind
                    | ProxyOperation::DestroyNoBuildDind
            ) {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup tombstone rejects lane commit",
                ));
            }
        }
        if current != prepared
            || !matches!(
                current.status,
                DockerLaneOperationStatusV12::Intent
                    | DockerLaneOperationStatusV12::OutcomeUnknown
            )
            || current.status
                == DockerLaneOperationStatusV12::OutcomeUnknown
                && (response.authoritative_state
                    != AuthoritativeLaneState::Destroyed
                    || response
                        .terminal_destruction_receipt
                        .is_none())
            || response.proxy_request_sha256 != current.request_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 lane operation lost its durable intent before commit",
            ));
        }
        current.status = if response.authoritative_state
            == AuthoritativeLaneState::Destroyed
        {
            DockerLaneOperationStatusV12::Destroyed
        } else {
            DockerLaneOperationStatusV12::Applied
        };
        current.authoritative_state = response.authoritative_state;
        current.result_sha256 = Some(response.result_sha256);
        current.response_sha256 = Some(response.response_sha256);
        current.observed_state_sha256 =
            Some(response.observed_state_sha256);
        current.revision = current.revision.saturating_add(1);
        let (generation, readiness) = match current.authority_kind {
            DockerLaneAuthorityKindV12::Generation => {
                let generation_path = self.generation_path(
                    &current.owner_namespace,
                    &current.daemon_generation,
                );
                let mut generation =
                    self.read_generation(&generation_path)?;
                let terminal_destroy_replay = matches!(
                    current.operation,
                    ProxyOperation::DestroyBuildDind
                        | ProxyOperation::DestroyNoBuildDind
                ) && generation.status
                    == DockerLaneOperationStatusV12::Destroyed
                    && generation.state
                        == AuthoritativeLaneState::Destroyed
                    && generation.terminal_receipt_sha256
                        == response
                            .terminal_destruction_receipt
                            .as_ref()
                            .map(|exact| sha256(exact));
                if !terminal_destroy_replay
                    && (generation.last_sequence != current.sequence
                        || generation.last_request_sha256
                            != current.request_sha256)
                {
                    return Err(ControllerError::Rejected(
                        "v12 generation intent differs from terminal commit",
                    ));
                }
                if current.operation == ProxyOperation::ImportSealedOci {
                    if generation
                        .expected_oci_imports
                        .binary_search(&current.target_sha256)
                        .is_err()
                        || generation
                            .imported_oci_imports
                            .binary_search(&current.target_sha256)
                            .is_ok()
                    {
                        return Err(ControllerError::Rejected(
                            "v12 OCI import terminal commit differs from its closure",
                        ));
                    }
                    generation
                        .imported_oci_imports
                        .push(current.target_sha256);
                    generation.imported_oci_imports.sort();
                    if ((response.authoritative_state
                        == AuthoritativeLaneState::Prepared)
                        != (generation.imported_oci_imports
                            == generation.expected_oci_imports))
                    {
                        return Err(ControllerError::Rejected(
                            "v12 no-build generation became prepared before exact closure import",
                        ));
                    }
                }
                if !terminal_destroy_replay {
                    generation.state =
                        response.authoritative_state;
                    generation.status = current.status;
                    generation.observed_state_sha256 =
                        Some(response.observed_state_sha256);
                    generation.revision =
                        generation.revision.saturating_add(1);
                }
                (Some(generation), None)
            }
            DockerLaneAuthorityKindV12::Readiness => {
                if response.authoritative_state
                    != AuthoritativeLaneState::Declared
                    || !current.operation.is_readiness()
                        && current.operation
                            != ProxyOperation::QueryAuthoritativeState
                {
                    return Err(ControllerError::Rejected(
                        "v12 readiness terminal response attempted generation authority",
                    ));
                }
                let readiness_path = self.readiness_authority_path(
                    &current.plan_id,
                    &current.capability_sha256,
                );
                let mut readiness =
                    self.read_readiness_authority(&readiness_path)?;
                if readiness.last_sequence != current.sequence
                    || readiness.last_request_sha256
                        != current.request_sha256
                {
                    return Err(ControllerError::Rejected(
                        "v12 readiness intent differs from terminal commit",
                    ));
                }
                readiness.state = AuthoritativeLaneState::Declared;
                readiness.status =
                    DockerLaneOperationStatusV12::Applied;
                readiness.observed_state_sha256 =
                    Some(response.observed_state_sha256);
                readiness.revision =
                    readiness.revision.saturating_add(1);
                (None, Some(readiness))
            }
        };
        let mut transaction = DockerLaneTerminalTransactionV12 {
            version: LEDGER_VERSION.to_owned(),
            boot_id_sha256: self.boot_id_sha256,
            request_id: current.request_id,
            request_sha256: current.request_sha256,
            operation: current.clone(),
            generation,
            readiness,
            response: response.clone(),
            transaction_sha256: [0; 32],
        };
        transaction.transaction_sha256 =
            terminal_transaction_sha256_v12(&transaction)?;
        let transaction_path =
            self.transaction_path(&current.request_id);
        if transaction_path.exists() {
            let retained =
                self.read_terminal_transaction(&transaction_path)?;
            if retained != transaction {
                return Err(ControllerError::Rejected(
                    "v12 terminal transaction conflicts with durable recovery state",
                ));
            }
        } else {
            self.write_struct_create_new(
                &transaction_path,
                &transaction,
            )?;
            self.sync_directory("terminal-transactions-v12")?;
        }
        self.materialize_terminal_transaction(&transaction)?;
        Ok(current)
    }

    pub fn bind_generation_network_namespace(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        network_namespace: &str,
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if network_namespace.is_empty()
            || network_namespace.len() > 64
            || !network_namespace.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-'
            })
        {
            return Err(ControllerError::Rejected(
                "v12 generation network namespace is noncanonical",
            ));
        }
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        let mut generation = self.read_generation(&path)?;
        if generation.owner_namespace != owner_namespace
            || generation.daemon_generation != daemon_generation
            || generation.status == DockerLaneOperationStatusV12::Destroyed
            || generation.network_namespace.as_deref().is_some_and(
                |retained| retained != network_namespace,
            )
        {
            return Err(ControllerError::Rejected(
                "v12 generation network namespace crossed durable authority",
            ));
        }
        if generation.network_namespace.as_deref()
            == Some(network_namespace)
        {
            return Ok(generation);
        }
        generation.network_namespace =
            Some(network_namespace.to_owned());
        generation.revision = generation.revision.saturating_add(1);
        self.write_struct_replace(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        Ok(generation)
    }

    pub fn bind_generation_process_identity(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        pid: i32,
        start_time_ticks: u64,
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if pid <= 0 || start_time_ticks == 0 {
            return Err(ControllerError::Rejected(
                "v12 generation process identity is incomplete",
            ));
        }
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        let mut generation = self.read_generation(&path)?;
        if generation.owner_namespace != owner_namespace
            || generation.daemon_generation != daemon_generation
            || generation.status == DockerLaneOperationStatusV12::Destroyed
            || generation.dind_pid.is_some_and(
                |retained| retained != pid,
            )
            || generation.dind_start_time_ticks.is_some_and(
                |retained| retained != start_time_ticks,
            )
        {
            return Err(ControllerError::Rejected(
                "v12 generation process identity crossed durable authority",
            ));
        }
        if generation.dind_pid == Some(pid)
            && generation.dind_start_time_ticks
                == Some(start_time_ticks)
        {
            return Ok(generation);
        }
        generation.dind_pid = Some(pid);
        generation.dind_start_time_ticks =
            Some(start_time_ticks);
        generation.revision = generation.revision.saturating_add(1);
        self.write_struct_replace(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        Ok(generation)
    }

    pub fn mark_generation_docker_authority_established(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        let mut generation = self.read_generation(&path)?;
        if generation.owner_namespace != owner_namespace
            || generation.daemon_generation != daemon_generation
            || generation.status == DockerLaneOperationStatusV12::Destroyed
            || generation.dind_pid.is_none()
            || generation.dind_start_time_ticks.is_none()
            || generation.network_namespace.is_none()
        {
            return Err(ControllerError::Rejected(
                "v12 Docker authority became live before exact generation identity",
            ));
        }
        if generation.docker_authority_established {
            return Ok(generation);
        }
        generation.docker_authority_established = true;
        generation.revision = generation.revision.saturating_add(1);
        self.write_struct_replace(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        Ok(generation)
    }

    pub fn mark_outcome_unknown(
        &self,
        prepared: DockerLaneOperationRecordV12,
        observed_state_sha256: Digest,
    ) -> Result<DockerLaneOperationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if observed_state_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "v12 unknown outcome lacks observed uncertainty evidence",
            ));
        }
        let path = self.request_path(&prepared.request_id);
        let mut current = self.read_operation(&path)?;
        if current != prepared
            || current.status != DockerLaneOperationStatusV12::Intent
        {
            return Err(ControllerError::Rejected(
                "v12 unknown outcome lost its durable intent",
            ));
        }
        current.status = DockerLaneOperationStatusV12::OutcomeUnknown;
        current.authoritative_state =
            AuthoritativeLaneState::OutcomeUnknown;
        current.observed_state_sha256 = Some(observed_state_sha256);
        current.revision = current.revision.saturating_add(1);
        self.write_struct_replace(&path, &current)?;
        match current.authority_kind {
            DockerLaneAuthorityKindV12::Generation => {
                let generation_path = self.generation_path(
                    &current.owner_namespace,
                    &current.daemon_generation,
                );
                let mut generation =
                    self.read_generation(&generation_path)?;
                generation.state =
                    AuthoritativeLaneState::OutcomeUnknown;
                generation.status =
                    DockerLaneOperationStatusV12::OutcomeUnknown;
                generation.observed_state_sha256 =
                    Some(observed_state_sha256);
                generation.revision =
                    generation.revision.saturating_add(1);
                self.write_struct_replace(
                    &generation_path,
                    &generation,
                )?;
                self.sync_directory("generations-v12")?;
            }
            DockerLaneAuthorityKindV12::Readiness => {
                let readiness_path = self.readiness_authority_path(
                    &current.plan_id,
                    &current.capability_sha256,
                );
                let mut readiness =
                    self.read_readiness_authority(&readiness_path)?;
                readiness.state =
                    AuthoritativeLaneState::OutcomeUnknown;
                readiness.status =
                    DockerLaneOperationStatusV12::OutcomeUnknown;
                readiness.observed_state_sha256 =
                    Some(observed_state_sha256);
                readiness.revision =
                    readiness.revision.saturating_add(1);
                self.write_struct_replace(
                    &readiness_path,
                    &readiness,
                )?;
                self.sync_directory("readiness-authorities-v12")?;
            }
        }
        self.sync_directory("lane-requests-v12")?;
        Ok(current)
    }

    pub fn operation_by_request_sha256(
        &self,
        request_sha256: Digest,
    ) -> Result<Option<DockerLaneOperationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("lane-requests-v12"),
        )? {
            let record = self.read_operation(&path)?;
            if record.request_sha256 == request_sha256 {
                records.push(record);
            }
        }
        if records.len() > 1 {
            return Err(ControllerError::Rejected(
                "v12 request digest has duplicate durable records",
            ));
        }
        Ok(records.pop())
    }

    pub fn replay_response(
        &self,
        record: &DockerLaneOperationRecordV12,
    ) -> Result<(PrivateDindOperationResponseV12, Vec<u8>)> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if !matches!(
            record.status,
            DockerLaneOperationStatusV12::Applied
                | DockerLaneOperationStatusV12::Destroyed
        ) {
            return Err(ControllerError::Rejected(
                "v12 lane operation is not terminally replayable",
            ));
        }
        let transaction = self.read_terminal_transaction(
            &self.transaction_path(&record.request_id),
        )?;
        self.validate_terminal_transaction(&transaction)?;
        if transaction.operation != *record {
            return Err(ControllerError::Rejected(
                "v12 replay record differs from terminal transaction",
            ));
        }
        let response = transaction.response;
        if record.response_sha256 != Some(response.response_sha256)
            || record.result_sha256 != Some(response.result_sha256)
            || record.request_sha256
                != response.proxy_request_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 lane replay response differs from its terminal record",
            ));
        }
        let exact = canonical_json_bytes_v11(
            &serde_json::to_value(&response).map_err(|_| {
                ControllerError::Invalid(
                    "v12 lane replay response is not serializable",
                )
            })?,
        )?;
        Ok((response, exact))
    }

    pub fn nonterminal_generations(
        &self,
    ) -> Result<Vec<DockerGenerationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let record = self.read_generation(&path)?;
            if record.status != DockerLaneOperationStatusV12::Destroyed
                || record.state != AuthoritativeLaneState::Destroyed
                || record.terminal_receipt_sha256.is_none()
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn begin_plan_cleanup(
        &self,
        plan_id: Digest,
        request_sha256_canonical: Digest,
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if plan_id == [0; 32]
            || request_sha256_canonical == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "v12 plan cleanup authority is incomplete",
            ));
        }
        let path = self.plan_cleanup_path(&plan_id);
        if path.exists() {
            let retained = self.read_plan_cleanup(&path)?;
            self.validate_plan_cleanup(&retained)?;
            if retained.plan_id != plan_id
                || retained.request_sha256_canonical
                    != request_sha256_canonical
            {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup tombstone was reused by different authority",
                ));
            }
            return Ok(());
        }
        let mut cleanup = DockerPlanCleanupRecordV12 {
            version:
                "catchplate/private-dind-plan-cleanup/v12"
                    .to_owned(),
            boot_id_sha256: self.boot_id_sha256,
            plan_id,
            request_sha256_canonical,
            state: AuthoritativeLaneState::Destroying,
            observed_terminal_sha256: None,
            revision: 1,
            record_sha256: [0; 32],
        };
        cleanup.record_sha256 =
            plan_cleanup_record_sha256_v12(&cleanup)?;
        self.validate_plan_cleanup(&cleanup)?;
        self.write_struct_create_new(&path, &cleanup)?;
        self.sync_directory("plan-cleanups-v12")
    }

    pub fn commit_plan_cleanup(
        &self,
        plan_id: Digest,
        request_sha256_canonical: Digest,
        observed_terminal_sha256: Digest,
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if observed_terminal_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "v12 plan cleanup terminal observation is absent",
            ));
        }
        let path = self.plan_cleanup_path(&plan_id);
        let mut cleanup = self.read_plan_cleanup(&path)?;
        self.validate_plan_cleanup(&cleanup)?;
        if cleanup.plan_id != plan_id
            || cleanup.request_sha256_canonical
                != request_sha256_canonical
        {
            return Err(ControllerError::Rejected(
                "v12 plan cleanup terminal commit crossed authority",
            ));
        }
        if cleanup.state == AuthoritativeLaneState::Destroyed {
            if cleanup.observed_terminal_sha256
                != Some(observed_terminal_sha256)
            {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup replay differs from terminal commit",
                ));
            }
            return Ok(());
        }
        let mut terminal_generations = Vec::new();
        for generation_path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let generation =
                self.read_generation(&generation_path)?;
            if generation.plan_id != plan_id {
                continue;
            }
            if generation.status
                    != DockerLaneOperationStatusV12::Destroyed
                || generation.state
                    != AuthoritativeLaneState::Destroyed
                || generation.terminal_receipt_sha256.is_none()
            {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup cannot commit before every generation is terminal",
                ));
            }
            terminal_generations.push(generation);
        }
        terminal_generations.sort_by(|left, right| {
            (
                left.owner_namespace.as_str(),
                left.daemon_generation.as_str(),
            )
                .cmp(&(
                    right.owner_namespace.as_str(),
                    right.daemon_generation.as_str(),
                ))
        });
        let mut aggregate =
            Vec::with_capacity(terminal_generations.len());
        for generation in &terminal_generations {
            let transaction = self.read_destruction_transaction(
                &self.destruction_transaction_path(
                    &generation.owner_namespace,
                    &generation.daemon_generation,
                ),
            )?;
            self.validate_materialized_destruction_transaction(
                &transaction,
            )?;
            let exact_receipt = transaction
                .exact_terminal_receipt
                .as_ref()
                .ok_or(ControllerError::Rejected(
                    "v12 plan cleanup terminal transaction lost its receipt",
                ))?;
            let receipt = self.validate_terminal_receipt_binding(
                exact_receipt,
                generation,
            )?;
            aggregate.push(serde_json::json!({
                "capabilitySha256": receipt.capability_sha256,
                "daemonGeneration": receipt.daemon_generation,
                "exactReceiptBytes": exact_receipt.len(),
                "networkNamespace": receipt.network_namespace,
                "observedStateSha256": receipt.observed_state_sha256,
                "ownerNamespace": receipt.owner_namespace,
                "profile": receipt.profile,
                "receiptSha256": sha256(exact_receipt),
            }));
        }
        let computed_terminal_sha256 = sha256(
            &canonical_json_bytes_v11(&serde_json::json!({
                "planId": plan_id,
                "receipts": aggregate,
                "version": "catchplate/private-dind-scoped-terminal/v12",
            }))?,
        );
        if computed_terminal_sha256 != observed_terminal_sha256 {
            return Err(ControllerError::Rejected(
                "v12 plan cleanup terminal observation differs from durable exact receipts",
            ));
        }
        cleanup.state = AuthoritativeLaneState::Destroyed;
        cleanup.observed_terminal_sha256 =
            Some(observed_terminal_sha256);
        cleanup.revision = cleanup.revision.saturating_add(1);
        cleanup.record_sha256 = [0; 32];
        cleanup.record_sha256 =
            plan_cleanup_record_sha256_v12(&cleanup)?;
        self.validate_plan_cleanup(&cleanup)?;
        self.write_struct_replace(&path, &cleanup)?;
        self.sync_directory("plan-cleanups-v12")
    }

    pub fn generations_for_plan(
        &self,
        plan_id: Digest,
    ) -> Result<Vec<DockerGenerationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let record = self.read_generation(&path)?;
            if record.plan_id == plan_id {
                records.push(record);
            }
        }
        records.sort_by(|left, right| {
            (
                left.owner_namespace.as_str(),
                left.daemon_generation.as_str(),
            )
                .cmp(&(
                    right.owner_namespace.as_str(),
                    right.daemon_generation.as_str(),
                ))
        });
        Ok(records)
    }

    pub fn terminal_observation_sha256(&self) -> Result<Digest> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let record = self.read_generation(&path)?;
            if record.status != DockerLaneOperationStatusV12::Destroyed
                || record.state != AuthoritativeLaneState::Destroyed
                || record.observed_state_sha256.is_none()
                || record.terminal_receipt_sha256.is_none()
            {
                return Err(ControllerError::Rejected(
                    "v12 lane ledger terminal observation found a nonterminal generation",
                ));
            }
            records.push(record);
        }
        let value = serde_json::to_value(&records).map_err(|_| {
            ControllerError::Invalid(
                "v12 terminal generation set is not serializable",
            )
        })?;
        Ok(sha256(&canonical_json_bytes_v11(&value)?))
    }

    pub fn begin_destroying_generation(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        observed_state_sha256: Digest,
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        let mut generation = self.read_generation(&path)?;
        if generation.status == DockerLaneOperationStatusV12::Destroyed
            && generation.state == AuthoritativeLaneState::Destroyed
        {
            return Ok(generation);
        }
        generation.status =
            DockerLaneOperationStatusV12::Destroying;
        generation.state = AuthoritativeLaneState::Destroying;
        generation.observed_state_sha256 =
            Some(observed_state_sha256);
        generation.revision = generation.revision.saturating_add(1);
        self.write_struct_replace(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        Ok(generation)
    }

    pub fn commit_destruction_observation(
        &self,
        observation: &DockerGenerationDestructionObservationV12,
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        self.validate_destruction_observation(observation)?;
        let generation = self.read_generation(&self.generation_path(
            &observation.owner_namespace,
            &observation.daemon_generation,
        ))?;
        if generation.boot_id_sha256 != observation.boot_id_sha256
            || generation.plan_id != observation.plan_id
            || generation.capability_sha256
                != observation.capability_sha256
            || generation.profile != observation.profile
            || generation.network_namespace.as_deref()
                != Some(observation.network_namespace.as_str())
            || generation.docker_authority_established
                != observation.docker_authority_established
            || generation.status
                != DockerLaneOperationStatusV12::Destroying
            || generation.state != AuthoritativeLaneState::Destroying
        {
            return Err(ControllerError::Rejected(
                "v12 destruction observation differs from destroying authority",
            ));
        }
        let path = self.destruction_transaction_path(
            &observation.owner_namespace,
            &observation.daemon_generation,
        );
        if path.exists() {
            let retained =
                self.read_destruction_transaction(&path)?;
            self.validate_destruction_transaction(&retained)?;
            if retained.observation.as_ref() != Some(observation)
                || retained.legacy_recovery.is_some()
            {
                return Err(ControllerError::Rejected(
                    "v12 destruction observation conflicts with durable recovery state",
                ));
            }
            return Ok(());
        }
        let mut transaction =
            DockerGenerationDestructionTransactionV12 {
                version: LEDGER_VERSION.to_owned(),
                observation: Some(observation.clone()),
                legacy_recovery: None,
                exact_terminal_receipt: None,
                terminal_generation: None,
                transaction_sha256: [0; 32],
            };
        transaction.transaction_sha256 =
            destruction_transaction_sha256_v12(&transaction)?;
        self.write_struct_create_new(&path, &transaction)?;
        self.sync_directory("destruction-transactions-v12")
    }

    pub fn pending_destruction_observation(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<Option<DockerGenerationDestructionObservationV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let path = self.destruction_transaction_path(
            owner_namespace,
            daemon_generation,
        );
        if !path.exists() {
            return Ok(None);
        }
        let transaction = self.read_destruction_transaction(&path)?;
        self.validate_destruction_transaction(&transaction)?;
        if transaction.legacy_recovery.is_some()
            || transaction.exact_terminal_receipt.is_some()
            || transaction.terminal_generation.is_some()
        {
            return Ok(None);
        }
        let observation = transaction.observation.ok_or(
            ControllerError::Rejected(
                "v12 pending destruction transaction lacks its observation",
            ),
        )?;
        if observation.owner_namespace != owner_namespace
            || observation.daemon_generation != daemon_generation
        {
            return Err(ControllerError::Rejected(
                "v12 pending destruction observation crossed generation authority",
            ));
        }
        Ok(Some(observation))
    }

    pub fn commit_destroyed_generation(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        observation: &DockerGenerationDestructionObservationV12,
        exact_terminal_receipt: &[u8],
    ) -> Result<DockerGenerationRecordV12> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        self.validate_destruction_observation(observation)?;
        if observation.owner_namespace != owner_namespace
            || observation.daemon_generation != daemon_generation
            || exact_terminal_receipt.is_empty()
            || exact_terminal_receipt.len() as u64
                > LEDGER_RECORD_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "v12 terminal destruction evidence is absent or oversized",
            ));
        }
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        let mut generation = self.read_generation(&path)?;
        if generation.status
            != DockerLaneOperationStatusV12::Destroying
            || generation.state != AuthoritativeLaneState::Destroying
            || generation.plan_id != observation.plan_id
            || generation.capability_sha256
                != observation.capability_sha256
            || generation.profile != observation.profile
            || generation.boot_id_sha256
                != observation.boot_id_sha256
            || generation.network_namespace.as_deref()
                != Some(observation.network_namespace.as_str())
            || generation.docker_authority_established
                != observation.docker_authority_established
        {
            return Err(ControllerError::Rejected(
                "v12 terminal destruction commit lost its destroying authority",
            ));
        }
        let receipt_sha256 = sha256(exact_terminal_receipt);
        let receipt_path = self.root.join("terminal-receipts-v12").join(
            format!("{}.json", digest_hex(&receipt_sha256)),
        );
        if receipt_path.exists() {
            let existing = std::fs::read(&receipt_path)?;
            if !constant_time_eq(
                &sha256(&existing),
                &receipt_sha256,
            ) || existing != exact_terminal_receipt
            {
                return Err(ControllerError::Rejected(
                    "v12 terminal destruction receipt CAS conflicts",
                ));
            }
        } else {
            write_create_new(&receipt_path, exact_terminal_receipt)?;
        }
        generation.status =
            DockerLaneOperationStatusV12::Destroyed;
        generation.state = AuthoritativeLaneState::Destroyed;
        generation.observed_state_sha256 =
            Some(observation.observed_state_sha256);
        generation.terminal_receipt_sha256 = Some(receipt_sha256);
        generation.revision = generation.revision.saturating_add(1);

        let transaction_path = self.destruction_transaction_path(
            owner_namespace,
            daemon_generation,
        );
        let retained =
            self.read_destruction_transaction(&transaction_path)?;
        self.validate_destruction_transaction(&retained)?;
        if retained.observation.as_ref() != Some(observation)
            || retained.legacy_recovery.is_some()
            || retained.exact_terminal_receipt.as_deref().is_some_and(
                |exact| exact != exact_terminal_receipt,
            )
            || retained.terminal_generation.as_ref().is_some_and(
                |terminal| terminal != &generation,
            )
        {
            return Err(ControllerError::Rejected(
                "v12 signed destruction differs from its durable observation",
            ));
        }
        let mut transaction =
            DockerGenerationDestructionTransactionV12 {
                version: LEDGER_VERSION.to_owned(),
                observation: Some(observation.clone()),
                legacy_recovery: None,
                exact_terminal_receipt:
                    Some(exact_terminal_receipt.to_vec()),
                terminal_generation: Some(generation.clone()),
                transaction_sha256: [0; 32],
            };
        transaction.transaction_sha256 =
            destruction_transaction_sha256_v12(&transaction)?;
        self.write_struct_replace(
            &transaction_path,
            &transaction,
        )?;
        self.sync_directory("destruction-transactions-v12")?;
        self.sync_directory("terminal-receipts-v12")?;
        self.write_struct_replace(&path, &generation)?;
        self.sync_directory("generations-v12")?;
        self.validate_materialized_destruction_transaction(
            &transaction,
        )?;
        Ok(generation)
    }

    pub fn legacy_generations_requiring_recovery(
        &self,
    ) -> Result<Vec<DockerGenerationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let generation = self.read_generation(&path)?;
            if generation.status
                    == DockerLaneOperationStatusV12::Destroyed
                && generation.state
                    == AuthoritativeLaneState::Destroyed
                && !self
                    .destruction_transaction_path(
                        &generation.owner_namespace,
                        &generation.daemon_generation,
                    )
                    .exists()
            {
                records.push(generation);
            }
        }
        records.sort_by(|left, right| {
            (
                left.owner_namespace.as_str(),
                left.daemon_generation.as_str(),
            )
                .cmp(&(
                    right.owner_namespace.as_str(),
                    right.daemon_generation.as_str(),
                ))
        });
        Ok(records)
    }

    pub fn legacy_terminal_receipt(
        &self,
        generation: &DockerGenerationRecordV12,
    ) -> Result<Vec<u8>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        if generation.status
                != DockerLaneOperationStatusV12::Destroyed
            || generation.state
                != AuthoritativeLaneState::Destroyed
        {
            return Err(ControllerError::Rejected(
                "v12 legacy recovery selected a nonterminal generation",
            ));
        }
        let receipt_sha256 =
            generation.terminal_receipt_sha256.ok_or(
                ControllerError::Rejected(
                    "v12 legacy terminal generation has no receipt digest",
                ),
            )?;
        let path = self.root.join("terminal-receipts-v12").join(
            format!("{}.json", digest_hex(&receipt_sha256)),
        );
        let exact = std::fs::read(path)?;
        if exact.is_empty()
            || exact.len() as u64 > LEDGER_RECORD_MAX_BYTES
            || sha256(&exact) != receipt_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 legacy terminal receipt CAS is absent or inconsistent",
            ));
        }
        Ok(exact)
    }

    pub fn commit_legacy_destruction_recovery(
        &self,
        generation: &DockerGenerationRecordV12,
        recovery: &DockerLegacyDestructionRecoveryV12,
        exact_terminal_receipt: &[u8],
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let retained = self.read_generation(
            &self.generation_path(
                &generation.owner_namespace,
                &generation.daemon_generation,
            ),
        )?;
        if retained != *generation
            || retained.status
                != DockerLaneOperationStatusV12::Destroyed
            || retained.state
                != AuthoritativeLaneState::Destroyed
            || retained.terminal_receipt_sha256
                != Some(sha256(exact_terminal_receipt))
            || recovery.recovery_boot_id_sha256
                != self.boot_id_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 legacy recovery differs from retained terminal authority",
            ));
        }
        let path = self.destruction_transaction_path(
            &generation.owner_namespace,
            &generation.daemon_generation,
        );
        if path.exists() {
            return Err(ControllerError::Rejected(
                "v12 legacy recovery transaction already exists",
            ));
        }
        let mut transaction =
            DockerGenerationDestructionTransactionV12 {
                version: LEDGER_VERSION.to_owned(),
                observation: None,
                legacy_recovery: Some(recovery.clone()),
                exact_terminal_receipt:
                    Some(exact_terminal_receipt.to_vec()),
                terminal_generation: Some(generation.clone()),
                transaction_sha256: [0; 32],
            };
        transaction.transaction_sha256 =
            destruction_transaction_sha256_v12(&transaction)?;
        self.validate_destruction_transaction(&transaction)?;
        self.write_struct_create_new(&path, &transaction)?;
        self.sync_directory("destruction-transactions-v12")?;
        self.validate_materialized_destruction_transaction(
            &transaction,
        )
    }

    pub fn generation(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<Option<DockerGenerationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let path =
            self.generation_path(owner_namespace, daemon_generation);
        if path.exists() {
            self.read_generation(&path).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn exact_terminal_receipt(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<Vec<u8>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let transaction = self.read_destruction_transaction(
            &self.destruction_transaction_path(
                owner_namespace,
                daemon_generation,
            ),
        )?;
        self.validate_materialized_destruction_transaction(
            &transaction,
        )?;
        transaction.exact_terminal_receipt.ok_or(
            ControllerError::Rejected(
                "v12 terminal receipt is absent from destruction transaction",
            ),
        )
    }

    pub fn recovered_legacy_evidence(
        &self,
    ) -> Result<
        Vec<(
            DockerGenerationRecordV12,
            DockerLegacyDestructionRecoveryV12,
            Vec<u8>,
        )>,
    > {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("destruction-transactions-v12"),
        )? {
            let transaction =
                self.read_destruction_transaction(&path)?;
            let Some(recovery) =
                transaction.legacy_recovery.clone()
            else {
                continue;
            };
            self.validate_materialized_destruction_transaction(
                &transaction,
            )?;
            records.push((
                transaction
                    .terminal_generation
                    .ok_or(ControllerError::Rejected(
                        "v12 recovered legacy evidence lost its generation",
                    ))?,
                recovery,
                transaction
                    .exact_terminal_receipt
                    .ok_or(ControllerError::Rejected(
                        "v12 recovered legacy evidence lost its receipt",
                    ))?,
            ));
        }
        records.sort_by(|left, right| {
            (
                left.0.owner_namespace.as_str(),
                left.0.daemon_generation.as_str(),
            )
                .cmp(&(
                    right.0.owner_namespace.as_str(),
                    right.0.daemon_generation.as_str(),
                ))
        });
        Ok(records)
    }

    pub fn generations_for_authority(
        &self,
        plan_id: Digest,
        capability_sha256: Digest,
        profile: PrivateDindProfileV12,
    ) -> Result<Vec<DockerGenerationRecordV12>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("v12 lane ledger mutex is poisoned")
        })?;
        let mut records = Vec::new();
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let record = self.read_generation(&path)?;
            if record.plan_id == plan_id
                && record.capability_sha256 == capability_sha256
                && record.profile == profile
            {
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.lane_slot);
        Ok(records)
    }

    fn request_path(&self, request_id: &Digest) -> PathBuf {
        self.root.join("lane-requests-v12").join(format!(
            "{}.json",
            digest_hex(request_id),
        ))
    }

    fn response_path(&self, request_id: &Digest) -> PathBuf {
        self.root.join("lane-responses-v12").join(format!(
            "{}.json",
            digest_hex(request_id),
        ))
    }

    fn transaction_path(&self, request_id: &Digest) -> PathBuf {
        self.root
            .join("terminal-transactions-v12")
            .join(format!("{}.json", digest_hex(request_id)))
    }

    fn destruction_transaction_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> PathBuf {
        let identity = sha256(
            &[
                b"catchplate/private-dind-destruction-transaction/v12\0"
                    .as_slice(),
                owner_namespace.as_bytes(),
                b"\0",
                daemon_generation.as_bytes(),
            ]
            .concat(),
        );
        self.root
            .join("destruction-transactions-v12")
            .join(format!("{}.json", digest_hex(&identity)))
    }

    fn readiness_authority_path(
        &self,
        plan_id: &Digest,
        capability_sha256: &Digest,
    ) -> PathBuf {
        let identity = sha256(
            &[
                b"catchplate/private-dind-readiness-authority/v12\0"
                    .as_slice(),
                plan_id.as_slice(),
                capability_sha256.as_slice(),
            ]
            .concat(),
        );
        self.root
            .join("readiness-authorities-v12")
            .join(format!("{}.json", digest_hex(&identity)))
    }

    fn plan_cleanup_path(&self, plan_id: &Digest) -> PathBuf {
        self.root
            .join("plan-cleanups-v12")
            .join(format!("{}.json", digest_hex(plan_id)))
    }

    fn generation_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> PathBuf {
        let identity = sha256(
            &[
                b"catchplate/private-dind-generation-path/v12\0"
                    .as_slice(),
                owner_namespace.as_bytes(),
                b"\0",
                daemon_generation.as_bytes(),
            ]
            .concat(),
        );
        self.root.join("generations-v12").join(format!(
            "{}.json",
            digest_hex(&identity),
        ))
    }

    fn read_operation(
        &self,
        path: &Path,
    ) -> Result<DockerLaneOperationRecordV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 lane operation ledger record is invalid",
            )
        })
    }

    fn read_generation(
        &self,
        path: &Path,
    ) -> Result<DockerGenerationRecordV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 generation ledger record is invalid",
            )
        })
    }

    fn read_readiness_authority(
        &self,
        path: &Path,
    ) -> Result<DockerReadinessAuthorityRecordV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 readiness authority record is invalid",
            )
        })
    }

    fn read_plan_cleanup(
        &self,
        path: &Path,
    ) -> Result<DockerPlanCleanupRecordV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 plan cleanup ledger record is invalid",
            )
        })
    }

    fn validate_plan_cleanup(
        &self,
        cleanup: &DockerPlanCleanupRecordV12,
    ) -> Result<()> {
        if cleanup.version
                != "catchplate/private-dind-plan-cleanup/v12"
            || cleanup.boot_id_sha256 == [0; 32]
            || cleanup.plan_id == [0; 32]
            || cleanup.request_sha256_canonical == [0; 32]
            || !matches!(
                cleanup.state,
                AuthoritativeLaneState::Destroying
                    | AuthoritativeLaneState::Destroyed
            )
            || (cleanup.state == AuthoritativeLaneState::Destroying
                && cleanup.observed_terminal_sha256.is_some())
            || (cleanup.state == AuthoritativeLaneState::Destroyed
                && cleanup.observed_terminal_sha256.is_none())
            || cleanup.revision == 0
            || cleanup.record_sha256 == [0; 32]
            || plan_cleanup_record_sha256_v12(cleanup)?
                != cleanup.record_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 plan cleanup tombstone is invalid",
            ));
        }
        Ok(())
    }

    fn validate_plan_cleanup_records(&self) -> Result<()> {
        for path in read_dir_sorted(
            &self.root.join("plan-cleanups-v12"),
        )? {
            let cleanup = self.read_plan_cleanup(&path)?;
            self.validate_plan_cleanup(&cleanup)?;
            if path != self.plan_cleanup_path(&cleanup.plan_id) {
                return Err(ControllerError::Rejected(
                    "v12 plan cleanup tombstone path differs from its plan",
                ));
            }
        }
        Ok(())
    }

    fn read_terminal_transaction(
        &self,
        path: &Path,
    ) -> Result<DockerLaneTerminalTransactionV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 terminal transaction record is invalid",
            )
        })
    }

    fn read_destruction_transaction(
        &self,
        path: &Path,
    ) -> Result<DockerGenerationDestructionTransactionV12> {
        let value = read_canonical_value(path)?;
        serde_json::from_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 destruction transaction record is invalid",
            )
        })
    }

    fn validate_destruction_observation(
        &self,
        observation: &DockerGenerationDestructionObservationV12,
    ) -> Result<()> {
        if observation.version
            != "catchplate/private-dind-destruction-observation/v12"
            || observation.boot_id_sha256 != self.boot_id_sha256
            || observation.plan_id == [0; 32]
            || observation.capability_sha256 == [0; 32]
            || observation.owner_namespace.is_empty()
            || observation.daemon_generation.is_empty()
            || observation.network_namespace.is_empty()
            || observation.request_sha256 == [0; 32]
            || observation.observed_at_boottime_ns == 0
            || observation.docker_top_level_object_count_scope
                != DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
            || observation.docker_internal_storage_absence_proof
                != DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
            || observation.terminal_containers != 0
            || observation.terminal_images != 0
            || observation.terminal_networks != 0
            || observation.terminal_volumes != 0
            || (!observation.docker_authority_established
                && (observation.drained_containers != 0
                    || observation.drained_images != 0
                    || observation.drained_networks != 0
                    || observation.drained_volumes != 0))
            || observation.mounts != 0
            || observation.cgroup_processes != 0
            || observation.proxy_accepting
            || !observation.dind_reaped
            || !observation.netns_absent
            || !observation.socket_absent
            || !observation.state_root_absent
            || observation.observed_state_sha256 == [0; 32]
            || observation.observation_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "v12 destruction observation is incomplete or nonterminal",
            ));
        }
        let mut projection = observation.clone();
        projection.observation_sha256 = [0; 32];
        let value = serde_json::to_value(&projection).map_err(|_| {
            ControllerError::Invalid(
                "v12 destruction observation is not serializable",
            )
        })?;
        if sha256(&canonical_json_bytes_v11(&value)?)
            != observation.observation_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 destruction observation digest is not canonical",
            ));
        }
        Ok(())
    }

    fn validate_destruction_transaction(
        &self,
        transaction: &DockerGenerationDestructionTransactionV12,
    ) -> Result<()> {
        let ordinary = transaction.observation.is_some()
            && transaction.legacy_recovery.is_none();
        let recovered = transaction.observation.is_none()
            && transaction.legacy_recovery.is_some();
        if transaction.version != LEDGER_VERSION
            || !(ordinary || recovered)
            || transaction.exact_terminal_receipt.is_some()
                != transaction.terminal_generation.is_some()
            || recovered
                && transaction.exact_terminal_receipt.is_none()
            || destruction_transaction_sha256_v12(transaction)?
                != transaction.transaction_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 destruction transaction is not recoverable",
            ));
        }
        if let Some(observation) = transaction.observation.as_ref() {
            self.validate_destruction_observation(observation)?;
        }
        if let (Some(exact_receipt), Some(generation)) = (
            transaction.exact_terminal_receipt.as_ref(),
            transaction.terminal_generation.as_ref(),
        ) {
            if exact_receipt.is_empty()
                || exact_receipt.len() as u64
                    > LEDGER_RECORD_MAX_BYTES
                || generation.status
                    != DockerLaneOperationStatusV12::Destroyed
                || generation.state
                    != AuthoritativeLaneState::Destroyed
                || generation.terminal_receipt_sha256
                    != Some(sha256(exact_receipt))
            {
                return Err(ControllerError::Rejected(
                    "v12 signed destruction transaction differs from terminal authority",
                ));
            }
            let receipt = self.validate_terminal_receipt_binding(
                exact_receipt,
                generation,
            )?;
            if let Some(observation) =
                transaction.observation.as_ref()
            {
                if generation.boot_id_sha256
                        != observation.boot_id_sha256
                    || generation.plan_id != observation.plan_id
                    || generation.capability_sha256
                        != observation.capability_sha256
                    || generation.profile != observation.profile
                    || generation.owner_namespace
                        != observation.owner_namespace
                    || generation.daemon_generation
                        != observation.daemon_generation
                    || generation.network_namespace.as_deref()
                        != Some(
                            observation.network_namespace.as_str(),
                        )
                    || generation.observed_state_sha256
                        != Some(
                            observation.observed_state_sha256,
                        )
                    || receipt.request_sha256
                        != observation.request_sha256
                    || receipt.network_namespace
                        != observation.network_namespace
                    || receipt.observed_at_boottime_ns
                        != observation.observed_at_boottime_ns
                    || receipt.docker_top_level_object_count_scope
                        != observation
                            .docker_top_level_object_count_scope
                    || receipt.docker_internal_storage_absence_proof
                        != observation
                            .docker_internal_storage_absence_proof
                    || receipt.drained_containers
                        != observation.drained_containers
                    || receipt.drained_images
                        != observation.drained_images
                    || receipt.drained_networks
                        != observation.drained_networks
                    || receipt.drained_volumes
                        != observation.drained_volumes
                    || receipt.containers
                        != observation.terminal_containers
                    || receipt.images
                        != observation.terminal_images
                    || receipt.networks
                        != observation.terminal_networks
                    || receipt.volumes
                        != observation.terminal_volumes
                    || receipt.docker_authority_established
                        != observation
                            .docker_authority_established
                    || receipt.mounts != observation.mounts
                    || receipt.cgroup_processes
                        != observation.cgroup_processes
                    || receipt.proxy_accepting
                        != observation.proxy_accepting
                    || receipt.dind_reaped
                        != observation.dind_reaped
                    || receipt.netns_absent
                        != observation.netns_absent
                    || receipt.socket_absent
                        != observation.socket_absent
                    || receipt.state_root_absent
                        != observation.state_root_absent
                    || receipt.observed_state_sha256
                        != observation.observed_state_sha256
                {
                    return Err(ControllerError::Rejected(
                        "v12 ordinary destruction transaction differs from its observation",
                    ));
                }
            }
            if let Some(recovery) =
                transaction.legacy_recovery.as_ref()
            {
                self.validate_legacy_destruction_recovery(
                    recovery,
                    generation,
                    exact_receipt,
                )?;
            }
        }
        Ok(())
    }

    fn validate_terminal_receipt_binding(
        &self,
        exact_receipt: &[u8],
        generation: &DockerGenerationRecordV12,
    ) -> Result<DockerTerminalReceiptBindingV12> {
        let receipt: DockerTerminalReceiptBindingV12 =
            serde_json::from_slice(exact_receipt).map_err(|_| {
                ControllerError::Rejected(
                    "v12 destruction transaction uses a legacy or invalid terminal receipt",
                )
            })?;
        let receipt_value =
            serde_json::to_value(&receipt).map_err(|_| {
                ControllerError::Invalid(
                    "v12 terminal receipt is not serializable",
                )
            })?;
        if canonical_json_bytes_v11(&receipt_value)?
                != exact_receipt
            || receipt.version
                != "catchplate/private-dind-terminal-destruction/v12"
            || receipt.trust_profile
                != "trusted-host-userspace-digest-no-ima"
            || receipt.plan_id != generation.plan_id
            || receipt.capability_sha256
                != generation.capability_sha256
            || receipt.profile != generation.profile
            || receipt.owner_namespace != generation.owner_namespace
            || receipt.daemon_generation
                != generation.daemon_generation
            || receipt.network_namespace.is_empty()
            || generation.network_namespace.as_deref()
                != Some(receipt.network_namespace.as_str())
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
            || receipt.docker_authority_established
                != generation.docker_authority_established
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
            || receipt.signer_spki_sha256 == [0; 32]
            || receipt.signer_public_key_spki_der.is_empty()
            || sha256(&receipt.signer_public_key_spki_der)
                != receipt.signer_spki_sha256
            || receipt.signature.len() != 64
            || receipt.receipt_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "v12 terminal receipt is incomplete or crossed generation authority",
            ));
        }
        let mut projection = receipt.clone();
        projection.receipt_sha256 = [0; 32];
        let projection =
            serde_json::to_value(&projection).map_err(|_| {
                ControllerError::Invalid(
                    "v12 terminal receipt projection is not serializable",
                )
            })?;
        if sha256(&canonical_json_bytes_v11(&projection)?)
            != receipt.receipt_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 terminal receipt digest is not canonical",
            ));
        }
        Ok(receipt)
    }

    fn validate_legacy_destruction_recovery(
        &self,
        recovery: &DockerLegacyDestructionRecoveryV12,
        generation: &DockerGenerationRecordV12,
        exact_receipt: &[u8],
    ) -> Result<()> {
        let generation_value =
            serde_json::to_value(generation).map_err(|_| {
                ControllerError::Invalid(
                    "v12 legacy generation is not serializable",
                )
            })?;
        if recovery.version
                != "catchplate/private-dind-legacy-destruction-recovery/v12"
            || recovery.recovery_boot_id_sha256
                == [0; 32]
            || recovery.plan_id != generation.plan_id
            || recovery.capability_sha256
                != generation.capability_sha256
            || recovery.profile != generation.profile
            || recovery.owner_namespace
                != generation.owner_namespace
            || recovery.daemon_generation
                != generation.daemon_generation
            || recovery.recovered_at_boottime_ns == 0
            || recovery.source_generation_sha256
                != sha256(
                    &canonical_json_bytes_v11(
                        &generation_value,
                    )?,
                )
            || recovery.source_terminal_receipt_sha256
                != sha256(exact_receipt)
            || recovery.current_absence_sha256 == [0; 32]
            || recovery.mounts != 0
            || recovery.cgroup_processes != 0
            || recovery.proxy_accepting
            || !recovery.dind_reaped
            || !recovery.netns_absent
            || !recovery.socket_absent
            || !recovery.state_root_absent
            || recovery.signer_spki_sha256 == [0; 32]
            || recovery.signature.len() != 64
            || recovery.recovery_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "v12 legacy destruction recovery is incomplete",
            ));
        }
        let mut projection = recovery.clone();
        projection.recovery_sha256 = [0; 32];
        let value = serde_json::to_value(&projection).map_err(|_| {
            ControllerError::Invalid(
                "v12 legacy destruction recovery is not serializable",
            )
        })?;
        if sha256(&canonical_json_bytes_v11(&value)?)
            != recovery.recovery_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 legacy destruction recovery digest is not canonical",
            ));
        }
        Ok(())
    }

    fn validate_materialized_destruction_transaction(
        &self,
        transaction: &DockerGenerationDestructionTransactionV12,
    ) -> Result<()> {
        self.validate_destruction_transaction(transaction)?;
        let exact_receipt = transaction
            .exact_terminal_receipt
            .as_ref()
            .ok_or(ControllerError::Rejected(
                "v12 materialized destruction lacks its exact receipt",
            ))?;
        let generation = transaction
            .terminal_generation
            .as_ref()
            .ok_or(ControllerError::Rejected(
                "v12 materialized destruction lacks its generation",
            ))?;
        let retained_generation =
            self.read_generation(&self.generation_path(
                &generation.owner_namespace,
                &generation.daemon_generation,
            ))?;
        let receipt_path = self.root.join("terminal-receipts-v12").join(
            format!("{}.json", digest_hex(&sha256(exact_receipt))),
        );
        if retained_generation != *generation
            || std::fs::read(receipt_path)? != *exact_receipt
        {
            return Err(ControllerError::Rejected(
                "v12 destruction transaction was not exactly materialized",
            ));
        }
        Ok(())
    }

    fn recover_destruction_transactions(&self) -> Result<()> {
        for path in read_dir_sorted(
            &self.root.join("destruction-transactions-v12"),
        )? {
            let transaction =
                self.read_destruction_transaction(&path)?;
            self.validate_destruction_transaction(&transaction)?;
            if let (Some(exact_receipt), Some(generation)) = (
                transaction.exact_terminal_receipt.as_ref(),
                transaction.terminal_generation.as_ref(),
            ) {
                let receipt_path = self
                    .root
                    .join("terminal-receipts-v12")
                    .join(format!(
                        "{}.json",
                        digest_hex(&sha256(exact_receipt)),
                    ));
                if receipt_path.exists() {
                    if std::fs::read(&receipt_path)? != *exact_receipt {
                        return Err(ControllerError::Rejected(
                            "v12 recovered destruction receipt CAS conflicts",
                        ));
                    }
                } else {
                    write_create_new(
                        &receipt_path,
                        exact_receipt,
                    )?;
                    self.sync_directory("terminal-receipts-v12")?;
                }
                self.write_struct_replace(
                    &self.generation_path(
                        &generation.owner_namespace,
                        &generation.daemon_generation,
                    ),
                    generation,
                )?;
                self.sync_directory("generations-v12")?;
                self.validate_materialized_destruction_transaction(
                    &transaction,
                )?;
            }
        }
        Ok(())
    }

    fn require_destruction_transaction_coverage(&self) -> Result<()> {
        for path in read_dir_sorted(
            &self.root.join("generations-v12"),
        )? {
            let generation = self.read_generation(&path)?;
            if generation.status
                    == DockerLaneOperationStatusV12::Destroyed
                && generation.state
                    == AuthoritativeLaneState::Destroyed
            {
                let transaction_path =
                    self.destruction_transaction_path(
                        &generation.owner_namespace,
                        &generation.daemon_generation,
                    );
                if !transaction_path.exists() {
                    return Err(ControllerError::InvalidOwned(format!(
                        "legacy terminal generation {} lacks a v12 destruction transaction; in-service migration is forbidden, so quarantine or explicitly migrate the legacy ledger offline before serving",
                        generation.daemon_generation,
                    )));
                }
                let transaction =
                    self.read_destruction_transaction(
                        &transaction_path,
                    )?;
                self.validate_materialized_destruction_transaction(
                    &transaction,
                )?;
            }
        }
        Ok(())
    }

    fn validate_terminal_transaction(
        &self,
        transaction: &DockerLaneTerminalTransactionV12,
    ) -> Result<()> {
        let operation = &transaction.operation;
        let response = &transaction.response;
        let terminal_status = matches!(
            operation.status,
            DockerLaneOperationStatusV12::Applied
                | DockerLaneOperationStatusV12::Destroyed
        );
        let authority_matches = match operation.authority_kind {
            DockerLaneAuthorityKindV12::Generation => {
                transaction.readiness.is_none()
                    && transaction.generation.as_ref().map_or(
                        false,
                        |generation| {
                            let terminal_destroy_replay = matches!(
                                operation.operation,
                                ProxyOperation::DestroyBuildDind
                                    | ProxyOperation::DestroyNoBuildDind
                            ) && generation.status
                                == DockerLaneOperationStatusV12::Destroyed
                                && generation.state
                                    == AuthoritativeLaneState::Destroyed
                                && generation
                                    .terminal_receipt_sha256
                                    == response
                                        .terminal_destruction_receipt
                                        .as_ref()
                                        .map(|exact| sha256(exact));
                            generation.boot_id_sha256
                                == self.boot_id_sha256
                                && generation.plan_id
                                    == operation.plan_id
                                && generation.capability_sha256
                                    == operation.capability_sha256
                                && generation.owner_namespace
                                    == operation.owner_namespace
                                && generation.daemon_generation
                                    == operation.daemon_generation
                                && (terminal_destroy_replay
                                    || generation.last_sequence
                                        == operation.sequence
                                        && generation
                                            .last_request_sha256
                                            == operation
                                                .request_sha256)
                                && generation.state
                                    == response.authoritative_state
                                && generation
                                    .imported_oci_imports
                                    .windows(2)
                                    .all(|pair| pair[0] < pair[1])
                                && generation
                                    .imported_oci_imports
                                    .iter()
                                    .all(|digest| {
                                        generation
                                            .expected_oci_imports
                                            .binary_search(digest)
                                            .is_ok()
                                    })
                        },
                    )
            }
            DockerLaneAuthorityKindV12::Readiness => {
                transaction.generation.is_none()
                    && transaction.readiness.as_ref().map_or(
                        false,
                        |readiness| {
                            readiness.boot_id_sha256
                                == self.boot_id_sha256
                                && readiness.plan_id == operation.plan_id
                                && readiness.capability_sha256
                                    == operation.capability_sha256
                                && readiness.last_sequence
                                    == operation.sequence
                                && readiness.last_request_sha256
                                    == operation.request_sha256
                                && readiness.state
                                    == AuthoritativeLaneState::Declared
                                && response.authoritative_state
                                    == AuthoritativeLaneState::Declared
                                && readiness.status
                                    == DockerLaneOperationStatusV12::Applied
                        },
                    )
            }
        };
        if transaction.version != LEDGER_VERSION
            || transaction.boot_id_sha256 != self.boot_id_sha256
            || transaction.request_id != operation.request_id
            || transaction.request_sha256 != operation.request_sha256
            || !terminal_status
            || operation.response_sha256
                != Some(response.response_sha256)
            || operation.result_sha256 != Some(response.result_sha256)
            || operation.observed_state_sha256
                != Some(response.observed_state_sha256)
            || response.proxy_request_sha256
                != operation.request_sha256
            || sha256(&response.result) != response.result_sha256
            || !authority_matches
            || terminal_transaction_sha256_v12(transaction)?
                != transaction.transaction_sha256
        {
            return Err(ControllerError::Rejected(
                "v12 terminal transaction is not a complete recoverable commit",
            ));
        }
        Ok(())
    }

    fn materialize_terminal_transaction(
        &self,
        transaction: &DockerLaneTerminalTransactionV12,
    ) -> Result<()> {
        self.validate_terminal_transaction(transaction)?;
        if let Some(generation) = &transaction.generation {
            let path = self.generation_path(
                &generation.owner_namespace,
                &generation.daemon_generation,
            );
            self.write_struct_replace(&path, generation)?;
            self.sync_directory("generations-v12")?;
        }
        if let Some(readiness) = &transaction.readiness {
            let path = self.readiness_authority_path(
                &readiness.plan_id,
                &readiness.capability_sha256,
            );
            self.write_struct_replace(&path, readiness)?;
            self.sync_directory("readiness-authorities-v12")?;
        }
        self.write_struct_replace(
            &self.response_path(&transaction.request_id),
            &transaction.response,
        )?;
        self.sync_directory("lane-responses-v12")?;
        self.write_struct_replace(
            &self.request_path(&transaction.request_id),
            &transaction.operation,
        )?;
        self.sync_directory("lane-requests-v12")
    }

    fn write_struct_create_new<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<()> {
        let value = serde_json::to_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 ledger value is not serializable",
            )
        })?;
        write_create_new(path, &canonical_json_bytes_v11(&value)?)
    }

    fn write_struct_replace<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<()> {
        let value = serde_json::to_value(value).map_err(|_| {
            ControllerError::Invalid(
                "v12 ledger value is not serializable",
            )
        })?;
        write_replace(path, &canonical_json_bytes_v11(&value)?)
    }

    fn sync_directory(&self, relative: &str) -> Result<()> {
        File::open(self.root.join(relative))?.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn operation_authority_kind_v12(
    operation: &DockerLaneOperationV12,
) -> DockerLaneAuthorityKindV12 {
    if operation.request.operation.is_readiness()
        || matches!(
            &operation.decoded_payload,
            crate::docker_contract::DockerLaneDecodedPayloadV12::Query(
                query
            ) if query.original_operation.is_readiness()
        )
    {
        DockerLaneAuthorityKindV12::Readiness
    } else {
        DockerLaneAuthorityKindV12::Generation
    }
}

fn terminal_transaction_sha256_v12(
    transaction: &DockerLaneTerminalTransactionV12,
) -> Result<Digest> {
    let mut projection = transaction.clone();
    projection.transaction_sha256 = [0; 32];
    let value = serde_json::to_value(&projection).map_err(|_| {
        ControllerError::Invalid(
            "v12 terminal transaction is not serializable",
        )
    })?;
    Ok(sha256(&canonical_json_bytes_v11(&value)?))
}

fn plan_cleanup_record_sha256_v12(
    cleanup: &DockerPlanCleanupRecordV12,
) -> Result<Digest> {
    let mut projection = cleanup.clone();
    projection.record_sha256 = [0; 32];
    let value = serde_json::to_value(&projection).map_err(|_| {
        ControllerError::Invalid(
            "v12 plan cleanup tombstone is not serializable",
        )
    })?;
    Ok(sha256(&canonical_json_bytes_v11(&value)?))
}

fn destruction_transaction_sha256_v12(
    transaction: &DockerGenerationDestructionTransactionV12,
) -> Result<Digest> {
    let mut projection = transaction.clone();
    projection.transaction_sha256 = [0; 32];
    let value = serde_json::to_value(&projection).map_err(|_| {
        ControllerError::Invalid(
            "v12 destruction transaction is not serializable",
        )
    })?;
    Ok(sha256(&canonical_json_bytes_v11(&value)?))
}

impl DockerOwnershipLedgerV11 {
    pub fn open(root: &Path) -> Result<Self> {
        require_absolute_normalized(root)?;
        let boot_id_sha256 = current_boot_id_sha256_v12()?;
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(
            root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
        {
            return Err(ControllerError::Rejected(
                "Docker ledger root is not private root-owned storage",
            ));
        }
        for relative in [
            "objects",
            "requests",
            "responses",
            "sequences",
            "lanes",
            "memberships",
            "cas-bindings",
            "oci-closures",
        ] {
            let path = root.join(relative);
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o700),
            )?;
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o077 != 0
            {
                return Err(ControllerError::Rejected(
                    "Docker ledger subdirectory is unsafe",
                ));
            }
            File::open(&path)?.sync_all()?;
        }
        let lease_path = root.join("authority.lock");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lease_path)?;
        let lease_metadata = lease.metadata()?;
        if !lease_metadata.is_file()
            || lease_metadata.uid() != 0
            || lease_metadata.mode() & 0o077 != 0
            || lease_metadata.nlink() != 1
        {
            return Err(ControllerError::Rejected(
                "Docker authority lease is unsafe",
            ));
        }
        if unsafe {
            libc::flock(
                lease.as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(ControllerError::Rejected(
                "another Docker ownership authority holds the durable lease",
            ));
        }
        lease.set_len(0)?;
        (&lease).write_all(b"catchplate/docker-ownership-ledger/v12\n")?;
        lease.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(Self {
            root: root.to_path_buf(),
            lease,
            boot_id_sha256,
            local: Mutex::new(()),
        })
    }

    pub fn boot_id_sha256(&self) -> Digest {
        self.boot_id_sha256
    }

    pub fn bind_retained_cas_mount_v12(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        mount_id: &str,
        kind: DockerMountKindV12,
        cas_sha256: Digest,
        subpath: &str,
    ) -> Result<()> {
        let kind_text = match kind {
            DockerMountKindV12::SourceCas => "SOURCE_CAS",
            DockerMountKindV12::ArtifactCas => "ARTIFACT_CAS",
            DockerMountKindV12::Tmpfs => {
                return Err(ControllerError::Rejected(
                    "tmpfs cannot be registered as retained CAS",
                ))
            }
        };
        if cas_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "retained CAS registration lacks its digest",
            ));
        }
        validate_relative_cas_subpath_v12(subpath)?;
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let path = self.cas_binding_path(
            owner_namespace,
            daemon_generation,
            mount_id,
        )?;
        let value = object_value([
            ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
            (
                "bootIdSha256",
                Value::String(digest_hex(&self.boot_id_sha256)),
            ),
            (
                "ownerNamespace",
                Value::String(owner_namespace.to_owned()),
            ),
            (
                "daemonGeneration",
                Value::String(daemon_generation.to_owned()),
            ),
            ("mountId", Value::String(mount_id.to_owned())),
            ("kind", Value::String(kind_text.to_owned())),
            (
                "casSha256",
                Value::String(digest_hex(&cas_sha256)),
            ),
            ("subpath", Value::String(subpath.to_owned())),
        ]);
        let bytes = canonical_json_bytes_v11(&value)?;
        if path.exists() {
            let existing = read_canonical_value(&path)?;
            if canonical_json_bytes_v11(&existing)? != bytes {
                return Err(ControllerError::Rejected(
                    "retained CAS mount ID conflicts with its durable binding",
                ));
            }
            return Ok(());
        }
        write_create_new(&path, &bytes)?;
        self.sync_root("cas-bindings")
    }

    pub fn bind_oci_image_closure_v12(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        image_id: &str,
        source_seal_sha256: Digest,
        artifact_seal_sha256: Digest,
        oci_manifest_sha256: Digest,
    ) -> Result<()> {
        validate_engine_id(image_id)?;
        if source_seal_sha256 == [0; 32]
            || artifact_seal_sha256 == [0; 32]
            || oci_manifest_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "OCI closure registration lacks a digest identity",
            ));
        }
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let path = self.oci_closure_path(
            owner_namespace,
            daemon_generation,
            image_id,
        )?;
        let value = object_value([
            ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
            (
                "bootIdSha256",
                Value::String(digest_hex(&self.boot_id_sha256)),
            ),
            (
                "ownerNamespace",
                Value::String(owner_namespace.to_owned()),
            ),
            (
                "daemonGeneration",
                Value::String(daemon_generation.to_owned()),
            ),
            ("imageId", Value::String(image_id.to_owned())),
            (
                "sourceSealSha256",
                Value::String(digest_hex(&source_seal_sha256)),
            ),
            (
                "artifactSealSha256",
                Value::String(digest_hex(&artifact_seal_sha256)),
            ),
            (
                "ociManifestSha256",
                Value::String(digest_hex(&oci_manifest_sha256)),
            ),
        ]);
        let bytes = canonical_json_bytes_v11(&value)?;
        if path.exists() {
            let existing = read_canonical_value(&path)?;
            if canonical_json_bytes_v11(&existing)? != bytes {
                return Err(ControllerError::Rejected(
                    "OCI image closure conflicts with its durable binding",
                ));
            }
            return Ok(());
        }
        write_create_new(&path, &bytes)?;
        self.sync_root("oci-closures")
    }

    pub fn acquire_lane_operation(
        &self,
        owner_namespace: &str,
        lane_id: &str,
        deadline_boottime_ns: u64,
    ) -> Result<DockerLaneOperationLeaseV11> {
        self.require_lease()?;
        let path = self.root.join("lanes").join(format!(
            "{}--{}.lock",
            safe_component(owner_namespace)?,
            safe_component(lane_id)?
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(ControllerError::Rejected(
                "Docker lane operation lease is unsafe",
            ));
        }
        loop {
            if unsafe {
                libc::flock(
                    file.as_raw_fd(),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } == 0
            {
                return Ok(DockerLaneOperationLeaseV11 {
                    _file: file,
                });
            }
            let error = std::io::Error::last_os_error();
            if !error.raw_os_error().is_some_and(|code| {
                code == libc::EAGAIN || code == libc::EWOULDBLOCK
            }) {
                return Err(error.into());
            }
            if boottime_now_ns_v11()? >= deadline_boottime_ns {
                return Err(ControllerError::Rejected(
                    "Docker lane operation lease deadline expired",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn begin_mutation(
        &self,
        request: &DockerApiRequestV11,
        labels: &BTreeMap<String, String>,
        max_objects: u32,
        sequence_start: u64,
    ) -> Result<BeginMutationV11> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        if boottime_now_ns_v11()? >= request.deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "Docker mutation deadline expired before durable intent",
            ));
        }
        let request_path = self.request_path(&request.request_id)?;
        if request_path.exists() {
            let existing = self.read_mutation(&request_path)?;
            if !constant_time_eq(
                &existing.request_sha256,
                &request.canonical_sha256,
            ) || existing.sequence != request.sequence
                || existing.owner_namespace != request.owner_namespace
                || existing.daemon_generation
                    != request.daemon_generation
            {
                return Err(ControllerError::Rejected(
                    "Docker request ID was reused with conflicting authority",
                ));
            }
            return match existing.status {
                DockerMutationStatusV11::Applied => {
                    let (response_path, response_bytes, response_sha256) =
                        self.verify_response(&existing)?;
                    Ok(BeginMutationV11::ExactReplay {
                        record: existing,
                        response_path,
                        response_bytes,
                        response_sha256,
                    })
                }
                DockerMutationStatusV11::Intent
                | DockerMutationStatusV11::Unknown => {
                    Ok(BeginMutationV11::RequiresReconciliation(existing))
                }
                DockerMutationStatusV11::Destroying
                | DockerMutationStatusV11::Destroyed => {
                    Err(ControllerError::Rejected(
                        "Docker lane is destroying and cannot replay a mutation",
                    ))
                }
            };
        }
        let object_path = self.object_path(
            &request.owner_namespace,
            &request.daemon_generation,
            request.target.kind,
            &request.target.logical_id,
        )?;
        let existing = if object_path.exists() {
            Some(self.read_object(&object_path)?)
        } else {
            None
        };
        if existing.is_none()
            && self
                .read_generation_objects(
                    &request.owner_namespace,
                    &request.daemon_generation,
                )?
                .len()
                >= max_objects as usize
        {
            return Err(ControllerError::Rejected(
                "Docker lane exceeded its signed durable object bound",
            ));
        }
        let observed_state = existing
            .as_ref()
            .map(|record| record.state)
            .unwrap_or(DockerObjectStateV11::Absent);
        if observed_state != request.expected_transition.from {
            return Err(ControllerError::Rejected(
                "Docker durable object state differs from the signed transition precondition",
            ));
        }
        if existing.as_ref().is_some_and(|record| {
            record.owner_namespace != request.owner_namespace
                || record.daemon_generation != request.daemon_generation
                || record.kind != request.target.kind
                || record.logical_id != request.target.logical_id
                || record.engine_id != request.target.engine_id
        }) {
            return Err(ControllerError::Rejected(
                "Docker target binding differs from durable ownership",
            ));
        }
        self.require_next_sequence(request, sequence_start)?;
        let intent_state =
            intent_state(request.expected_transition.to);
        let revision = existing
            .as_ref()
            .map(|record| record.revision.saturating_add(1))
            .unwrap_or(1);
        let object = DockerObjectRecordV11 {
            boot_id_sha256: self.boot_id_sha256,
            owner_namespace: request.owner_namespace.clone(),
            daemon_generation: request.daemon_generation.clone(),
            source_seal_sha256: request.source_seal_sha256,
            artifact_seal_sha256: request.artifact_seal_sha256,
            kind: request.target.kind,
            logical_id: request.target.logical_id.clone(),
            engine_id: request.target.engine_id.clone(),
            state: intent_state,
            labels: labels.clone(),
            last_sequence: request.sequence,
            last_request_sha256: request.canonical_sha256,
            revision,
        };
        let mutation = DockerMutationRecordV11 {
            boot_id_sha256: self.boot_id_sha256,
            request_id: request.request_id.clone(),
            request_sha256: request.canonical_sha256,
            capability_sha256: request.capability_sha256,
            owner_namespace: request.owner_namespace.clone(),
            daemon_generation: request.daemon_generation.clone(),
            source_seal_sha256: request.source_seal_sha256,
            artifact_seal_sha256: request.artifact_seal_sha256,
            sequence: request.sequence,
            kind: request.target.kind,
            logical_id: request.target.logical_id.clone(),
            engine_id: request.target.engine_id.clone(),
            from_state: request.expected_transition.from,
            intended_state: request.expected_transition.to,
            terminal_state: None,
            status: DockerMutationStatusV11::Intent,
            response_sha256: None,
            response_bytes: None,
            reconciliation_sha256: None,
            uncertainty: None,
            network_membership: request
                .network_membership
                .as_ref()
                .map(|membership| {
                    network_membership_intent_v12(request, membership)
                })
                .transpose()?,
            deadline_boottime_ns: request.deadline_boottime_ns,
            revision: 1,
        };
        self.write_object(&object_path, &object, existing.is_none())?;
        self.write_mutation(&request_path, &mutation, true)?;
        if let Some(membership) = mutation.network_membership.as_ref() {
            self.write_network_membership_intent_locked(
                request,
                membership,
            )?;
        }
        self.commit_sequence(request, sequence_start)?;
        self.sync_root("requests")?;
        self.sync_root("objects")?;
        self.sync_root("memberships")?;
        Ok(BeginMutationV11::Prepared(
            DockerPreparedMutationV11 {
                request: request.clone(),
                record: mutation,
            },
        ))
    }

    pub fn exact_replay(
        &self,
        request: &DockerApiRequestV11,
    ) -> Result<Option<(PathBuf, u64, Digest)>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let request_path = self.request_path(&request.request_id)?;
        if !request_path.exists() {
            return Ok(None);
        }
        let existing = self.read_mutation(&request_path)?;
        if !constant_time_eq(
            &existing.request_sha256,
            &request.canonical_sha256,
        ) || existing.sequence != request.sequence
            || existing.owner_namespace != request.owner_namespace
            || existing.daemon_generation != request.daemon_generation
        {
            return Err(ControllerError::Rejected(
                "Docker replay request ID conflicts with durable authority",
            ));
        }
        if existing.status == DockerMutationStatusV11::Applied {
            self.verify_response(&existing).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn commit_read_sequence(
        &self,
        request: &DockerApiRequestV11,
        sequence_start: u64,
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        if boottime_now_ns_v11()? >= request.deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "Docker read deadline expired before sequence commit",
            ));
        }
        self.commit_sequence(request, sequence_start)
    }

    pub fn commit_applied(
        &self,
        prepared: DockerPreparedMutationV11,
        response: &[u8],
        engine_id: Option<&str>,
    ) -> Result<DockerMutationRecordV11> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        if response.len() as u64 > LEDGER_RESPONSE_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "Docker terminal response exceeds the durable replay bound",
            ));
        }
        let request_path =
            self.request_path(&prepared.record.request_id)?;
        let current = self.read_mutation(&request_path)?;
        if current.status != DockerMutationStatusV11::Intent
            || current.request_sha256
                != prepared.record.request_sha256
            || current.revision != prepared.record.revision
        {
            return Err(ControllerError::Rejected(
                "Docker mutation lost its exact durable intent",
            ));
        }
        let response_sha256 = sha256(response);
        let response_path =
            self.response_path(&current.request_id)?;
        write_create_new(&response_path, response)?;
        self.sync_root("responses")?;
        let object_path = self.object_path(
            &current.owner_namespace,
            &current.daemon_generation,
            current.kind,
            &current.logical_id,
        )?;
        let mut object = self.read_object(&object_path)?;
        if object.last_request_sha256 != current.request_sha256
            || object.last_sequence != current.sequence
            || object.state != intent_state(current.intended_state)
        {
            return Err(ControllerError::Rejected(
                "Docker object intent changed before terminal commit",
            ));
        }
        if let Some(engine_id) = engine_id {
            validate_engine_id(engine_id)?;
            if object.engine_id.as_deref().is_some_and(|existing| {
                existing != engine_id
            }) {
                return Err(ControllerError::Rejected(
                    "Docker response engine ID conflicts with durable ownership",
                ));
            }
            object.engine_id = Some(engine_id.to_owned());
        }
        object.state = current.intended_state;
        object.revision = object.revision.saturating_add(1);
        self.write_object(&object_path, &object, false)?;
        self.commit_network_membership_locked(&current, None)?;
        let mut terminal = current;
        terminal.engine_id = object.engine_id.clone();
        terminal.terminal_state = Some(object.state);
        terminal.status = DockerMutationStatusV11::Applied;
        terminal.response_sha256 = Some(response_sha256);
        terminal.response_bytes = Some(response.len() as u64);
        terminal.revision = terminal.revision.saturating_add(1);
        self.write_mutation(&request_path, &terminal, false)?;
        self.sync_root("objects")?;
        self.sync_root("requests")?;
        self.sync_root("memberships")?;
        Ok(terminal)
    }

    pub fn commit_applied_spool(
        &self,
        prepared: DockerPreparedMutationV11,
        source_path: &Path,
        expected_bytes: u64,
        expected_sha256: Digest,
        engine_id: Option<&str>,
    ) -> Result<DockerMutationRecordV11> {
        let path_metadata = std::fs::symlink_metadata(source_path)?;
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source_path)?;
        let metadata = source.metadata()?;
        if !metadata.is_file()
            || path_metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.len() != expected_bytes
            || expected_bytes > LEDGER_RESPONSE_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "Docker response spool is unsafe or exceeds its bound",
            ));
        }
        let actual = crate::coder_controller_v11::sha256_exact_reader(
            &mut source,
            expected_bytes,
        )?;
        if !constant_time_eq(&actual, &expected_sha256) {
            return Err(ControllerError::Rejected(
                "Docker response spool digest differs",
            ));
        }
        source.seek(SeekFrom::Start(0))?;
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let request_path =
            self.request_path(&prepared.record.request_id)?;
        let current = self.read_mutation(&request_path)?;
        if current.status != DockerMutationStatusV11::Intent
            || current.request_sha256
                != prepared.record.request_sha256
            || current.revision != prepared.record.revision
        {
            return Err(ControllerError::Rejected(
                "Docker mutation lost its exact durable intent",
            ));
        }
        let response_path = self.response_path(&current.request_id)?;
        copy_create_new(&mut source, &response_path, expected_bytes)?;
        self.sync_root("responses")?;
        let object_path = self.object_path(
            &current.owner_namespace,
            &current.daemon_generation,
            current.kind,
            &current.logical_id,
        )?;
        let mut object = self.read_object(&object_path)?;
        if object.last_request_sha256 != current.request_sha256
            || object.last_sequence != current.sequence
            || object.state != intent_state(current.intended_state)
        {
            return Err(ControllerError::Rejected(
                "Docker object intent changed before terminal spool commit",
            ));
        }
        if let Some(engine_id) = engine_id {
            validate_engine_id(engine_id)?;
            if object.engine_id.as_deref().is_some_and(|existing| {
                existing != engine_id
            }) {
                return Err(ControllerError::Rejected(
                    "Docker response engine ID conflicts with durable ownership",
                ));
            }
            object.engine_id = Some(engine_id.to_owned());
        }
        object.state = current.intended_state;
        object.revision = object.revision.saturating_add(1);
        self.write_object(&object_path, &object, false)?;
        self.commit_network_membership_locked(&current, None)?;
        let mut terminal = current;
        terminal.engine_id = object.engine_id.clone();
        terminal.terminal_state = Some(object.state);
        terminal.status = DockerMutationStatusV11::Applied;
        terminal.response_sha256 = Some(expected_sha256);
        terminal.response_bytes = Some(expected_bytes);
        terminal.revision = terminal.revision.saturating_add(1);
        self.write_mutation(&request_path, &terminal, false)?;
        self.sync_root("objects")?;
        self.sync_root("requests")?;
        self.sync_root("memberships")?;
        Ok(terminal)
    }

    pub fn mark_unknown(
        &self,
        prepared: DockerPreparedMutationV11,
        reason_sha256: Digest,
    ) -> Result<DockerMutationRecordV11> {
        if reason_sha256 == [0; 32] {
            return Err(ControllerError::Invalid(
                "Docker UNKNOWN reason digest is absent",
            ));
        }
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let request_path =
            self.request_path(&prepared.record.request_id)?;
        let mut current = self.read_mutation(&request_path)?;
        if current.request_sha256 != prepared.record.request_sha256
            || current.status != DockerMutationStatusV11::Intent
        {
            return Err(ControllerError::Rejected(
                "Docker UNKNOWN transition lost its durable intent",
            ));
        }
        let object_path = self.object_path(
            &current.owner_namespace,
            &current.daemon_generation,
            current.kind,
            &current.logical_id,
        )?;
        let mut object = self.read_object(&object_path)?;
        if current.network_membership.is_none() {
            object.state = DockerObjectStateV11::Unknown;
            object.revision = object.revision.saturating_add(1);
            self.write_object(&object_path, &object, false)?;
        }
        self.mark_network_membership_unknown_locked(
            &current,
            reason_sha256,
        )?;
        current.status = DockerMutationStatusV11::Unknown;
        current.terminal_state = Some(object.state);
        current.reconciliation_sha256 = Some(reason_sha256);
        current.uncertainty =
            Some(DockerMutationUncertaintyV12::PostSendUncertain);
        current.revision = current.revision.saturating_add(1);
        self.write_mutation(&request_path, &current, false)?;
        self.sync_root("objects")?;
        self.sync_root("requests")?;
        self.sync_root("memberships")?;
        Ok(current)
    }

    pub fn reconcile_unknown(
        &self,
        request_id: &str,
        reconciler: &dyn DockerReconcilerV11,
        deadline_boottime_ns: u64,
    ) -> Result<DockerMutationRecordV11> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        if boottime_now_ns_v11()? >= deadline_boottime_ns {
            return Err(ControllerError::Rejected(
                "Docker reconciliation deadline expired",
            ));
        }
        let request_path = self.request_path(request_id)?;
        let mut current = self.read_mutation(&request_path)?;
        if !matches!(
            current.status,
            DockerMutationStatusV11::Intent
                | DockerMutationStatusV11::Unknown
        ) {
            return Ok(current);
        }
        if current.uncertainty.is_none() {
            current.status = DockerMutationStatusV11::Unknown;
            current.uncertainty =
                Some(DockerMutationUncertaintyV12::PostSendUncertain);
            current.reconciliation_sha256 = Some(sha256(
                b"catchplate/docker-reconciliation-required/v12",
            ));
            current.revision = current.revision.saturating_add(1);
            self.write_mutation(&request_path, &current, false)?;
            self.sync_root("requests")?;
        }
        let observed =
            reconciler.query_exact(&current, deadline_boottime_ns)?;
        if observed.observation_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "Docker reconciliation observation is unauthenticated",
            ));
        }
        let object_path = self.object_path(
            &current.owner_namespace,
            &current.daemon_generation,
            current.kind,
            &current.logical_id,
        )?;
        let mut object = self.read_object(&object_path)?;
        let observed_membership =
            if let Some(membership) = current.network_membership.as_ref() {
                let observed = reconciler.query_network_membership(
                    &current,
                    membership,
                    deadline_boottime_ns,
                )?;
                if observed.observation_sha256 == [0; 32]
                    || observed.network_engine_id
                        != membership.network_engine_id
                    || observed.container_engine_id
                        != membership.container_engine_id
                    || observed.connected != membership.desired_connected
                    || observed.connected
                        && observed.endpoint_id.as_deref()
                            != Some(membership.endpoint_id.as_str())
                    || observed.connected
                        && (observed.ipv4_address
                            != membership.ipv4_address
                            || observed.ipv6_address
                                != membership.ipv6_address)
                    || observed.connected
                        && membership.aliases.iter().any(|alias| {
                            !observed.aliases.contains(alias)
                        })
                {
                    self.mark_network_membership_unknown_locked(
                        &current,
                        if observed.observation_sha256 == [0; 32] {
                            sha256(
                                b"catchplate/docker-network-observation-absent/v12",
                            )
                        } else {
                            observed.observation_sha256
                        },
                    )?;
                    return Err(ControllerError::Rejected(
                        "Docker network-membership reconciliation is conflicting or unauthenticated",
                    ));
                }
                Some(observed)
            } else {
                None
            };
        if observed.exists {
            if observed.labels != object.labels
                || observed.engine_id.is_none()
                || !matches!(
                    observed.state,
                    DockerObjectStateV11::Created
                        | DockerObjectStateV11::Running
                        | DockerObjectStateV11::Exited
                        | DockerObjectStateV11::Removed
                        | DockerObjectStateV11::Destroyed
                )
            {
                object.state = DockerObjectStateV11::Unknown;
                object.revision = object.revision.saturating_add(1);
                self.write_object(&object_path, &object, false)?;
                current.status = DockerMutationStatusV11::Unknown;
                current.terminal_state =
                    Some(DockerObjectStateV11::Unknown);
                current.reconciliation_sha256 =
                    Some(observed.observation_sha256);
                current.revision = current.revision.saturating_add(1);
                self.write_mutation(&request_path, &current, false)?;
                return Err(ControllerError::Rejected(
                    "Docker reconciliation found a conflicting or foreign object",
                ));
            }
            object.engine_id = observed.engine_id.clone();
            object.state = observed.state;
        } else if matches!(
            current.intended_state,
            DockerObjectStateV11::Removed
                | DockerObjectStateV11::Destroyed
        ) {
            object.engine_id = None;
            object.state = current.intended_state;
        } else {
            object.state = DockerObjectStateV11::Destroyed;
            current.status = DockerMutationStatusV11::Destroyed;
        }
        object.revision = object.revision.saturating_add(1);
        self.write_object(&object_path, &object, false)?;
        self.commit_network_membership_locked(
            &current,
            observed_membership
                .as_ref()
                .map(|observed| observed.observation_sha256),
        )?;
        current.engine_id = object.engine_id.clone();
        current.terminal_state = Some(object.state);
        current.reconciliation_sha256 =
            Some(observed.observation_sha256);
        if current.status != DockerMutationStatusV11::Destroyed {
            current.status = DockerMutationStatusV11::Unknown;
        }
        current.revision = current.revision.saturating_add(1);
        self.write_mutation(&request_path, &current, false)?;
        self.sync_root("objects")?;
        self.sync_root("requests")?;
        self.sync_root("memberships")?;
        Ok(current)
    }

    pub fn begin_destroying_generation(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        reason_sha256: Digest,
    ) -> Result<Vec<DockerObjectRecordV11>> {
        if reason_sha256 == [0; 32] {
            return Err(ControllerError::Invalid(
                "Docker destruction reason digest is absent",
            ));
        }
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let mut records =
            self.read_generation_objects(owner_namespace, daemon_generation)?;
        for record in &mut records {
            if !matches!(
                record.state,
                DockerObjectStateV11::Destroyed
                    | DockerObjectStateV11::Removed
            ) {
                record.state = DockerObjectStateV11::Destroying;
                record.revision = record.revision.saturating_add(1);
                let path = self.object_path(
                    owner_namespace,
                    daemon_generation,
                    record.kind,
                    &record.logical_id,
                )?;
                self.write_object(&path, record, false)?;
            }
        }
        let marker =
            self.destroy_marker_path(owner_namespace, daemon_generation)?;
        let record = object_value([
            ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
            (
                "bootIdSha256",
                Value::String(digest_hex(&self.boot_id_sha256)),
            ),
            ("status", Value::String("DESTROYING".to_owned())),
            (
                "ownerNamespace",
                Value::String(owner_namespace.to_owned()),
            ),
            (
                "daemonGeneration",
                Value::String(daemon_generation.to_owned()),
            ),
            (
                "reasonSha256",
                Value::String(digest_hex(&reason_sha256)),
            ),
            (
                "boottimeNs",
                Value::Number(Number::from(boottime_now_ns_v11()?)),
            ),
        ]);
        write_replace(&marker, &canonical_json_bytes_v11(&record)?)?;
        self.sync_root("objects")?;
        self.sync_root("requests")?;
        Ok(records)
    }

    pub fn generation_is_terminal(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let marker =
            self.destroy_marker_path(owner_namespace, daemon_generation)?;
        match std::fs::symlink_metadata(&marker) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o077 != 0
                    || metadata.nlink() != 1
                    || metadata.len() == 0
                    || metadata.len() > LEDGER_RECORD_MAX_BYTES
                {
                    return Err(ControllerError::Rejected(
                        "Docker generation terminal marker is unsafe",
                    ));
                }
                let value = read_canonical_value(&marker)?;
                let object = exact_object(
                    &value,
                    &[
                        "contractVersion",
                        "bootIdSha256",
                        "status",
                        "ownerNamespace",
                        "daemonGeneration",
                        "reasonSha256",
                        "boottimeNs",
                    ],
                )?;
                require_version(object)?;
                if parse_digest(text(object, "bootIdSha256")?)?
                    != self.boot_id_sha256
                    || text(object, "ownerNamespace")?
                        != owner_namespace
                    || text(object, "daemonGeneration")?
                        != daemon_generation
                    || !matches!(
                        text(object, "status")?,
                        "DESTROYING" | "DESTROYED"
                    )
                {
                    return Err(ControllerError::Rejected(
                        "Docker generation terminal marker binding is invalid",
                    ));
                }
                Ok(true)
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn startup_reconciliation(
        &self,
    ) -> Result<Vec<(String, String)>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let objects = self.root.join("objects");
        let mut generations = BTreeMap::<(String, String), bool>::new();
        for owner in read_dir_sorted(&objects)? {
            let owner_name = file_name(&owner)?;
            for generation in read_dir_sorted(&owner)? {
                let generation_name = file_name(&generation)?;
                for kind in read_dir_sorted(&generation)? {
                    for object_path in read_dir_sorted(&kind)? {
                        let record = self.read_object(&object_path)?;
                        if !matches!(
                            record.state,
                            DockerObjectStateV11::Destroyed
                                | DockerObjectStateV11::Removed
                        ) {
                            generations.insert(
                                (
                                    owner_name.clone(),
                                    generation_name.clone(),
                                ),
                                true,
                            );
                        }
                    }
                }
            }
        }
        for marker in read_dir_sorted(&self.root.join("requests"))? {
            let Some(name) = marker.file_name().and_then(|name| name.to_str())
            else {
                return Err(ControllerError::Rejected(
                    "Docker request ledger contains a non-UTF-8 filename",
                ));
            };
            if !name.starts_with("destroy-") || !name.ends_with(".json") {
                continue;
            }
            let value = read_canonical_value(&marker)?;
            let object = exact_object(
                &value,
                &[
                    "contractVersion",
                    "bootIdSha256",
                    "status",
                    "ownerNamespace",
                    "daemonGeneration",
                    "reasonSha256",
                    "boottimeNs",
                ],
            )?;
            require_version(object)?;
            let owner_namespace = text(object, "ownerNamespace")?;
            let daemon_generation = text(object, "daemonGeneration")?;
            let expected =
                self.destroy_marker_path(owner_namespace, daemon_generation)?;
            if marker != expected
                || parse_digest(text(object, "bootIdSha256")?)?
                    != self.boot_id_sha256
                || parse_digest(text(object, "reasonSha256")?)? == [0; 32]
                || number(object, "boottimeNs")? == 0
            {
                return Err(ControllerError::Rejected(
                    "Docker destruction marker binding is invalid",
                ));
            }
            match text(object, "status")? {
                "DESTROYING" => {
                    generations.insert(
                        (
                            owner_namespace.to_owned(),
                            daemon_generation.to_owned(),
                        ),
                        true,
                    );
                }
                "DESTROYED" => {}
                _ => {
                    return Err(ControllerError::Rejected(
                        "Docker destruction marker status is invalid",
                    ));
                }
            }
        }
        Ok(generations.into_keys().collect())
    }

    pub fn startup_uncertain_mutations(
        &self,
    ) -> Result<Vec<DockerMutationRecordV11>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let mut records = Vec::new();
        for path in read_dir_sorted(&self.root.join("requests"))? {
            let name = file_name(&path)?;
            if name.starts_with("destroy-") || !name.ends_with(".json") {
                continue;
            }
            let record = self.read_mutation(&path)?;
            if matches!(
                record.status,
                DockerMutationStatusV11::Intent
                    | DockerMutationStatusV11::Unknown
            ) {
                records.push(record);
            }
        }
        records.sort_by(|left, right| {
            (
                &left.owner_namespace,
                &left.daemon_generation,
                left.sequence,
                &left.request_id,
            )
                .cmp(&(
                    &right.owner_namespace,
                    &right.daemon_generation,
                    right.sequence,
                    &right.request_id,
                ))
        });
        Ok(records)
    }

    pub fn mark_generation_destroyed(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<()> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        self.require_lease()?;
        let marker =
            self.destroy_marker_path(owner_namespace, daemon_generation)?;
        let existing = read_canonical_value(&marker)?;
        let object = exact_object(
            &existing,
            &[
                "contractVersion",
                "bootIdSha256",
                "status",
                "ownerNamespace",
                "daemonGeneration",
                "reasonSha256",
                "boottimeNs",
            ],
        )?;
        require_version(object)?;
        if parse_digest(text(object, "bootIdSha256")?)?
            != self.boot_id_sha256
            || text(object, "ownerNamespace")? != owner_namespace
            || text(object, "daemonGeneration")? != daemon_generation
            || !matches!(text(object, "status")?, "DESTROYING" | "DESTROYED")
        {
            return Err(ControllerError::Rejected(
                "Docker destruction marker differs from its generation",
            ));
        }
        let reason_sha256 = parse_digest(text(object, "reasonSha256")?)?;
        if reason_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "Docker destruction marker lacks its reason",
            ));
        }
        let mut records =
            self.read_generation_objects(owner_namespace, daemon_generation)?;
        for record in &mut records {
            record.state = DockerObjectStateV11::Destroyed;
            record.engine_id = None;
            record.revision = record.revision.saturating_add(1);
            let path = self.object_path(
                owner_namespace,
                daemon_generation,
                record.kind,
                &record.logical_id,
            )?;
            self.write_object(&path, record, false)?;
        }
        let destroyed = object_value([
            ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
            (
                "bootIdSha256",
                Value::String(digest_hex(&self.boot_id_sha256)),
            ),
            ("status", Value::String("DESTROYED".to_owned())),
            (
                "ownerNamespace",
                Value::String(owner_namespace.to_owned()),
            ),
            (
                "daemonGeneration",
                Value::String(daemon_generation.to_owned()),
            ),
            (
                "reasonSha256",
                Value::String(digest_hex(&reason_sha256)),
            ),
            (
                "boottimeNs",
                Value::Number(Number::from(boottime_now_ns_v11()?)),
            ),
        ]);
        write_replace(&marker, &canonical_json_bytes_v11(&destroyed)?)?;
        self.sync_root("objects")?;
        self.sync_root("requests")
    }

    fn write_network_membership_intent_locked(
        &self,
        request: &DockerApiRequestV11,
        intent: &DockerNetworkMembershipIntentV12,
    ) -> Result<()> {
        let path = self.network_membership_path(
            &request.owner_namespace,
            &request.daemon_generation,
            &intent.network_logical_id,
            &intent.container_logical_id,
        )?;
        let existing = if path.exists() {
            Some(self.read_network_membership(&path)?)
        } else {
            None
        };
        if let Some(existing) = existing.as_ref() {
            require_same_network_membership_identity_v12(
                &existing.intent,
                intent,
            )?;
            let valid_precondition = if intent.desired_connected {
                existing.status
                    == DockerNetworkMembershipStatusV12::Disconnected
            } else {
                existing.status
                    == DockerNetworkMembershipStatusV12::Connected
            };
            if !valid_precondition {
                return Err(ControllerError::Rejected(
                    "Docker network-membership durable precondition is not terminal",
                ));
            }
        } else if !intent.desired_connected {
            return Err(ControllerError::Rejected(
                "Docker network disconnect has no durable connected membership",
            ));
        }
        let record = DockerNetworkMembershipRecordV12 {
            boot_id_sha256: self.boot_id_sha256,
            owner_namespace: request.owner_namespace.clone(),
            daemon_generation: request.daemon_generation.clone(),
            intent: intent.clone(),
            status: if intent.desired_connected {
                DockerNetworkMembershipStatusV12::PendingConnect
            } else {
                DockerNetworkMembershipStatusV12::PendingDisconnect
            },
            last_sequence: request.sequence,
            last_request_sha256: request.canonical_sha256,
            reconciliation_sha256: None,
            revision: existing
                .as_ref()
                .map(|record| record.revision.saturating_add(1))
                .unwrap_or(1),
        };
        self.write_network_membership(
            &path,
            &record,
            existing.is_none(),
        )
    }

    fn commit_network_membership_locked(
        &self,
        mutation: &DockerMutationRecordV11,
        reconciliation_sha256: Option<Digest>,
    ) -> Result<()> {
        let Some(intent) = mutation.network_membership.as_ref() else {
            return Ok(());
        };
        let path = self.network_membership_path(
            &mutation.owner_namespace,
            &mutation.daemon_generation,
            &intent.network_logical_id,
            &intent.container_logical_id,
        )?;
        let mut record = self.read_network_membership(&path)?;
        require_same_network_membership_identity_v12(
            &record.intent,
            intent,
        )?;
        let expected = if intent.desired_connected {
            DockerNetworkMembershipStatusV12::PendingConnect
        } else {
            DockerNetworkMembershipStatusV12::PendingDisconnect
        };
        let status_matches = record.status == expected
            || reconciliation_sha256.is_some()
                && record.status
                    == DockerNetworkMembershipStatusV12::Unknown;
        if !status_matches
            || record.last_request_sha256 != mutation.request_sha256
            || record.last_sequence != mutation.sequence
        {
            return Err(ControllerError::Rejected(
                "Docker network-membership intent changed before terminal commit",
            ));
        }
        if reconciliation_sha256 == Some([0; 32]) {
            return Err(ControllerError::Rejected(
                "Docker network-membership reconciliation digest is absent",
            ));
        }
        record.status = if intent.desired_connected {
            DockerNetworkMembershipStatusV12::Connected
        } else {
            DockerNetworkMembershipStatusV12::Disconnected
        };
        record.reconciliation_sha256 = reconciliation_sha256;
        record.revision = record.revision.saturating_add(1);
        self.write_network_membership(&path, &record, false)
    }

    fn mark_network_membership_unknown_locked(
        &self,
        mutation: &DockerMutationRecordV11,
        reason_sha256: Digest,
    ) -> Result<()> {
        let Some(intent) = mutation.network_membership.as_ref() else {
            return Ok(());
        };
        if reason_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "Docker network-membership uncertainty lacks evidence",
            ));
        }
        let path = self.network_membership_path(
            &mutation.owner_namespace,
            &mutation.daemon_generation,
            &intent.network_logical_id,
            &intent.container_logical_id,
        )?;
        let mut record = self.read_network_membership(&path)?;
        require_same_network_membership_identity_v12(
            &record.intent,
            intent,
        )?;
        record.status = DockerNetworkMembershipStatusV12::Unknown;
        record.reconciliation_sha256 = Some(reason_sha256);
        record.revision = record.revision.saturating_add(1);
        self.write_network_membership(&path, &record, false)
    }

    fn require_next_sequence(
        &self,
        request: &DockerApiRequestV11,
        sequence_start: u64,
    ) -> Result<()> {
        if sequence_start == 0 || request.sequence < sequence_start {
            return Err(ControllerError::Rejected(
                "Docker sequence precedes its capability range",
            ));
        }
        let path = self
            .root
            .join("sequences")
            .join(format!(
                "{}--{}.seq",
                safe_component(&request.owner_namespace)?,
                safe_component(&request.lane_id)?
            ));
        let previous = match read_canonical_value(&path) {
            Ok(value) => {
                let object = exact_object(
                    &value,
                    &[
                        "contractVersion",
                        "bootIdSha256",
                        "sequence",
                    ],
                )?;
                require_version(object)?;
                if parse_digest(text(object, "bootIdSha256")?)?
                    != self.boot_id_sha256
                {
                    return Err(ControllerError::Rejected(
                        "Docker sequence high-water belongs to a different boot identity",
                    ));
                }
                number(object, "sequence")?
            }
            Err(error)
                if matches!(
                    &error,
                    ControllerError::Io(io)
                        if io.kind() == std::io::ErrorKind::NotFound
                ) =>
            {
                sequence_start.saturating_sub(1)
            }
            Err(error) => return Err(error),
        };
        if request.sequence != previous.saturating_add(1) {
            return Err(ControllerError::Rejected(
                "Docker request sequence is not the next durable value",
            ));
        }
        Ok(())
    }

    fn commit_sequence(
        &self,
        request: &DockerApiRequestV11,
        sequence_start: u64,
    ) -> Result<()> {
        self.require_next_sequence(request, sequence_start)?;
        let path = self
            .root
            .join("sequences")
            .join(format!(
                "{}--{}.seq",
                safe_component(&request.owner_namespace)?,
                safe_component(&request.lane_id)?
            ));
        let value = object_value([
            ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
            (
                "bootIdSha256",
                Value::String(digest_hex(&self.boot_id_sha256)),
            ),
            (
                "sequence",
                Value::Number(Number::from(request.sequence)),
            ),
        ]);
        write_replace(&path, &canonical_json_bytes_v11(&value)?)?;
        self.sync_root("sequences")
    }

    fn read_generation_objects(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<Vec<DockerObjectRecordV11>> {
        let root = self
            .root
            .join("objects")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(daemon_generation)?);
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for kind in read_dir_sorted(&root)? {
            for path in read_dir_sorted(&kind)? {
                records.push(self.read_object(&path)?);
            }
        }
        Ok(records)
    }

    fn request_path(&self, request_id: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("requests")
            .join(format!("{}.json", safe_component(request_id)?)))
    }

    fn response_path(&self, request_id: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join("responses")
            .join(format!("{}.response", safe_component(request_id)?)))
    }

    fn network_membership_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        network_logical_id: &str,
        container_logical_id: &str,
    ) -> Result<PathBuf> {
        let root = self
            .root
            .join("memberships")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(daemon_generation)?);
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(
            &root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let identity = sha256(
            &[
                b"catchplate/docker-network-membership-path/v12\0"
                    .as_slice(),
                network_logical_id.as_bytes(),
                b"\0",
                container_logical_id.as_bytes(),
            ]
            .concat(),
        );
        Ok(root.join(format!("{}.json", digest_hex(&identity))))
    }

    fn cas_binding_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        mount_id: &str,
    ) -> Result<PathBuf> {
        let root = self
            .root
            .join("cas-bindings")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(daemon_generation)?);
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(
            &root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        Ok(root.join(format!("{}.json", safe_component(mount_id)?)))
    }

    fn oci_closure_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        image_id: &str,
    ) -> Result<PathBuf> {
        let root = self
            .root
            .join("oci-closures")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(daemon_generation)?);
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(
            &root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let identity = sha256(
            &[
                b"catchplate/docker-oci-closure-path/v12\0".as_slice(),
                image_id.as_bytes(),
            ]
            .concat(),
        );
        Ok(root.join(format!("{}.json", digest_hex(&identity))))
    }

    fn destroy_marker_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
    ) -> Result<PathBuf> {
        Ok(self
            .root
            .join("requests")
            .join(format!(
                "destroy-{}-{}.json",
                safe_component(owner_namespace)?,
                safe_component(daemon_generation)?
            )))
    }

    fn object_path(
        &self,
        owner_namespace: &str,
        daemon_generation: &str,
        kind: DockerResourceKindV11,
        logical_id: &str,
    ) -> Result<PathBuf> {
        let root = self
            .root
            .join("objects")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(daemon_generation)?)
            .join(kind.as_str().to_ascii_lowercase());
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(
            &root,
            std::fs::Permissions::from_mode(0o700),
        )?;
        Ok(root.join(format!(
            "{}.json",
            safe_component(logical_id)?
        )))
    }

    fn verify_response(
        &self,
        record: &DockerMutationRecordV11,
    ) -> Result<(PathBuf, u64, Digest)> {
        let expected_length = record.response_bytes.ok_or(
            ControllerError::Rejected(
                "applied Docker record lacks response length",
            ),
        )?;
        let expected_sha256 = record.response_sha256.ok_or(
            ControllerError::Rejected(
                "applied Docker record lacks response digest",
            ),
        )?;
        if expected_length > LEDGER_RESPONSE_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "Docker replay response exceeds its durable bound",
            ));
        }
        let path = self.response_path(&record.request_id)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.len() != expected_length
        {
            return Err(ControllerError::Rejected(
                "Docker replay response storage is unsafe",
            ));
        }
        let actual = crate::coder_controller_v11::sha256_exact_reader(
            &mut File::open(&path)?,
            expected_length,
        )?;
        if actual != expected_sha256 {
            return Err(ControllerError::Rejected(
                "Docker replay response differs from its terminal record",
            ));
        }
        Ok((path, expected_length, expected_sha256))
    }

    fn read_object(&self, path: &Path) -> Result<DockerObjectRecordV11> {
        let value = read_canonical_value(path)?;
        let record = parse_object_record(&value)?;
        if record.boot_id_sha256 != self.boot_id_sha256 {
            return Err(ControllerError::Rejected(
                "Docker object ledger belongs to a different boot identity",
            ));
        }
        Ok(record)
    }

    fn write_object(
        &self,
        path: &Path,
        record: &DockerObjectRecordV11,
        create: bool,
    ) -> Result<()> {
        let bytes =
            canonical_json_bytes_v11(&object_record_value(record))?;
        if create {
            write_create_new(path, &bytes)
        } else {
            write_replace(path, &bytes)
        }
    }

    fn read_mutation(
        &self,
        path: &Path,
    ) -> Result<DockerMutationRecordV11> {
        let value = read_canonical_value(path)?;
        let record = parse_mutation_record(&value)?;
        if record.boot_id_sha256 != self.boot_id_sha256 {
            return Err(ControllerError::Rejected(
                "Docker mutation deadline belongs to a different boot identity",
            ));
        }
        Ok(record)
    }

    fn read_network_membership(
        &self,
        path: &Path,
    ) -> Result<DockerNetworkMembershipRecordV12> {
        let value = read_canonical_value(path)?;
        let record = parse_network_membership_record_v12(&value)?;
        if record.boot_id_sha256 != self.boot_id_sha256 {
            return Err(ControllerError::Rejected(
                "Docker network-membership ledger belongs to a different boot identity",
            ));
        }
        Ok(record)
    }

    fn write_network_membership(
        &self,
        path: &Path,
        record: &DockerNetworkMembershipRecordV12,
        create: bool,
    ) -> Result<()> {
        let bytes = canonical_json_bytes_v11(
            &network_membership_record_value_v12(record),
        )?;
        if create {
            write_create_new(path, &bytes)
        } else {
            write_replace(path, &bytes)
        }
    }

    fn write_mutation(
        &self,
        path: &Path,
        record: &DockerMutationRecordV11,
        create: bool,
    ) -> Result<()> {
        let bytes =
            canonical_json_bytes_v11(&mutation_record_value(record))?;
        if create {
            write_create_new(path, &bytes)
        } else {
            write_replace(path, &bytes)
        }
    }

    fn require_lease(&self) -> Result<()> {
        if unsafe { libc::flock(self.lease.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn sync_root(&self, relative: &str) -> Result<()> {
        File::open(self.root.join(relative))?.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

impl DockerOwnershipViewV11 for DockerOwnershipLedgerV11 {
    fn engine_id_is_owned(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        logical_id: &str,
        engine_id: &str,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let path = self.object_path(
            owner_namespace,
            generation,
            kind,
            logical_id,
        )?;
        if !path.exists() {
            return Ok(false);
        }
        let record = self.read_object(&path)?;
        Ok(record.owner_namespace == owner_namespace
            && record.daemon_generation == generation
            && record.kind == kind
            && record.logical_id == logical_id
            && record.engine_id.as_deref() == Some(engine_id)
            && !matches!(
                record.state,
                DockerObjectStateV11::Removed
                    | DockerObjectStateV11::Destroyed
                    | DockerObjectStateV11::Unknown
            ))
    }

    fn logical_id_is_available(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        logical_id: &str,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let path = self.object_path(
            owner_namespace,
            generation,
            kind,
            logical_id,
        )?;
        if !path.exists() {
            return Ok(true);
        }
        let record = self.read_object(&path)?;
        Ok(matches!(
            record.state,
            DockerObjectStateV11::Absent
                | DockerObjectStateV11::Removed
                | DockerObjectStateV11::Destroyed
        ))
    }

    fn engine_id_is_owned_any(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerResourceKindV11,
        engine_id: &str,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let root = self
            .root
            .join("objects")
            .join(safe_component(owner_namespace)?)
            .join(safe_component(generation)?)
            .join(kind.as_str().to_ascii_lowercase());
        if !root.exists() {
            return Ok(false);
        }
        let mut matched = false;
        for path in read_dir_sorted(&root)? {
            let record = self.read_object(&path)?;
            if record.engine_id.as_deref() == Some(engine_id)
                && !matches!(
                    record.state,
                    DockerObjectStateV11::Removed
                        | DockerObjectStateV11::Destroyed
                        | DockerObjectStateV11::Unknown
                )
            {
                if matched {
                    return Err(ControllerError::Rejected(
                        "Docker engine ID has duplicate ownership records",
                    ));
                }
                matched = true;
            }
        }
        Ok(matched)
    }

    fn retained_cas_mount_is_bound(
        &self,
        owner_namespace: &str,
        generation: &str,
        kind: DockerCasIdentityKindV12,
        mount_id: &str,
        cas_sha256: Digest,
        subpath: &str,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let path =
            self.cas_binding_path(owner_namespace, generation, mount_id)?;
        if !path.exists() {
            return Ok(false);
        }
        let value = read_canonical_value(&path)?;
        let object = exact_object(
            &value,
            &[
                "contractVersion",
                "bootIdSha256",
                "ownerNamespace",
                "daemonGeneration",
                "mountId",
                "kind",
                "casSha256",
                "subpath",
            ],
        )?;
        require_version(object)?;
        let expected_kind = match kind {
            DockerCasIdentityKindV12::Source => "SOURCE_CAS",
            DockerCasIdentityKindV12::Artifact => "ARTIFACT_CAS",
        };
        Ok(parse_digest(text(object, "bootIdSha256")?)?
            == self.boot_id_sha256
            && text(object, "ownerNamespace")? == owner_namespace
            && text(object, "daemonGeneration")? == generation
            && text(object, "mountId")? == mount_id
            && text(object, "kind")? == expected_kind
            && parse_digest(text(object, "casSha256")?)? == cas_sha256
            && text(object, "subpath")? == subpath)
    }

    fn image_is_oci_closed(
        &self,
        owner_namespace: &str,
        generation: &str,
        image_id: &str,
        source_seal_sha256: Digest,
        artifact_seal_sha256: Digest,
    ) -> Result<bool> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let path =
            self.oci_closure_path(owner_namespace, generation, image_id)?;
        if !path.exists() {
            return Ok(false);
        }
        let value = read_canonical_value(&path)?;
        let object = exact_object(
            &value,
            &[
                "contractVersion",
                "bootIdSha256",
                "ownerNamespace",
                "daemonGeneration",
                "imageId",
                "sourceSealSha256",
                "artifactSealSha256",
                "ociManifestSha256",
            ],
        )?;
        require_version(object)?;
        let manifest_sha256 =
            parse_digest(text(object, "ociManifestSha256")?)?;
        Ok(manifest_sha256 != [0; 32]
            && parse_digest(text(object, "bootIdSha256")?)?
                == self.boot_id_sha256
            && text(object, "ownerNamespace")? == owner_namespace
            && text(object, "daemonGeneration")? == generation
            && text(object, "imageId")? == image_id
            && parse_digest(text(object, "sourceSealSha256")?)?
                == source_seal_sha256
            && parse_digest(text(object, "artifactSealSha256")?)?
                == artifact_seal_sha256)
    }

    fn network_membership_is_connected(
        &self,
        owner_namespace: &str,
        generation: &str,
        network_logical_id: &str,
        container_logical_id: &str,
        network_engine_id: &str,
        container_engine_id: &str,
    ) -> Result<Option<bool>> {
        let _guard = self.local.lock().map_err(|_| {
            ControllerError::Rejected("Docker ledger mutex is poisoned")
        })?;
        let path = self.network_membership_path(
            owner_namespace,
            generation,
            network_logical_id,
            container_logical_id,
        )?;
        if !path.exists() {
            return Ok(None);
        }
        let record = self.read_network_membership(&path)?;
        if record.owner_namespace != owner_namespace
            || record.daemon_generation != generation
            || record.intent.network_logical_id != network_logical_id
            || record.intent.container_logical_id != container_logical_id
            || record.intent.network_engine_id != network_engine_id
            || record.intent.container_engine_id != container_engine_id
        {
            return Err(ControllerError::Rejected(
                "Docker network-membership identity conflicts with the ledger",
            ));
        }
        match record.status {
            DockerNetworkMembershipStatusV12::Connected => Ok(Some(true)),
            DockerNetworkMembershipStatusV12::Disconnected => Ok(Some(false)),
            DockerNetworkMembershipStatusV12::PendingConnect
            | DockerNetworkMembershipStatusV12::PendingDisconnect
            | DockerNetworkMembershipStatusV12::Unknown => {
                Err(ControllerError::Rejected(
                    "Docker network-membership state requires reconciliation",
                ))
            }
        }
    }
}

fn intent_state(final_state: DockerObjectStateV11) -> DockerObjectStateV11 {
    match final_state {
        DockerObjectStateV11::Created => DockerObjectStateV11::Creating,
        DockerObjectStateV11::Running => DockerObjectStateV11::Starting,
        DockerObjectStateV11::Removed => DockerObjectStateV11::Removing,
        DockerObjectStateV11::Destroyed => {
            DockerObjectStateV11::Destroying
        }
        state => state,
    }
}

fn network_membership_intent_v12(
    request: &DockerApiRequestV11,
    membership: &DockerNetworkMembershipV12,
) -> Result<DockerNetworkMembershipIntentV12> {
    let network_engine_id = request.target.engine_id.clone().ok_or(
        ControllerError::Rejected(
            "Docker network-membership request lacks its network engine ID",
        ),
    )?;
    let desired_connected =
        if request.normalized_route.ends_with("/connect") {
            true
        } else if request.normalized_route.ends_with("/disconnect") {
            false
        } else {
            return Err(ControllerError::Rejected(
                "Docker network-membership intent is on the wrong route",
            ));
        };
    Ok(DockerNetworkMembershipIntentV12 {
        authority_sha256: membership.canonical_sha256,
        membership_id: membership.membership_id.clone(),
        network_logical_id: membership.network_logical_id.clone(),
        network_engine_id,
        container_logical_id: membership.container_logical_id.clone(),
        container_engine_id: membership.container_engine_id.clone(),
        endpoint_id: membership.endpoint_id.clone(),
        aliases: membership.aliases.clone(),
        ipv4_address: membership.ipv4_address.clone(),
        ipv6_address: membership.ipv6_address.clone(),
        desired_connected,
    })
}

fn require_same_network_membership_identity_v12(
    existing: &DockerNetworkMembershipIntentV12,
    requested: &DockerNetworkMembershipIntentV12,
) -> Result<()> {
    if existing.network_logical_id != requested.network_logical_id
        || existing.network_engine_id != requested.network_engine_id
        || existing.container_logical_id != requested.container_logical_id
        || existing.container_engine_id != requested.container_engine_id
        || existing.endpoint_id != requested.endpoint_id
        || existing.aliases != requested.aliases
        || existing.ipv4_address != requested.ipv4_address
        || existing.ipv6_address != requested.ipv6_address
    {
        return Err(ControllerError::Rejected(
            "Docker network-membership identity changed across transitions",
        ));
    }
    Ok(())
}

fn network_membership_intent_value_v12(
    intent: &DockerNetworkMembershipIntentV12,
) -> Value {
    object_value([
        (
            "authoritySha256",
            Value::String(digest_hex(&intent.authority_sha256)),
        ),
        (
            "membershipId",
            Value::String(intent.membership_id.clone()),
        ),
        (
            "networkLogicalId",
            Value::String(intent.network_logical_id.clone()),
        ),
        (
            "networkEngineId",
            Value::String(intent.network_engine_id.clone()),
        ),
        (
            "containerLogicalId",
            Value::String(intent.container_logical_id.clone()),
        ),
        (
            "containerEngineId",
            Value::String(intent.container_engine_id.clone()),
        ),
        (
            "endpointId",
            Value::String(intent.endpoint_id.clone()),
        ),
        (
            "aliases",
            Value::Array(
                intent
                    .aliases
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        (
            "ipv4Address",
            intent
                .ipv4_address
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "ipv6Address",
            intent
                .ipv6_address
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "desiredConnected",
            Value::Bool(intent.desired_connected),
        ),
    ])
}

fn parse_optional_network_membership_intent_v12(
    value: &Value,
) -> Result<Option<DockerNetworkMembershipIntentV12>> {
    if value.is_null() {
        return Ok(None);
    }
    let object = exact_object(
        value,
        &[
            "authoritySha256",
            "membershipId",
            "networkLogicalId",
            "networkEngineId",
            "containerLogicalId",
            "containerEngineId",
            "endpointId",
            "aliases",
            "ipv4Address",
            "ipv6Address",
            "desiredConnected",
        ],
    )?;
    let aliases = object
        .get("aliases")
        .and_then(Value::as_array)
        .ok_or(ControllerError::Invalid(
            "Docker network-membership aliases are invalid",
        ))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ControllerError::Invalid(
                    "Docker network-membership alias is invalid",
                ))
        })
        .collect::<Result<Vec<_>>>()?;
    let desired_connected = object
        .get("desiredConnected")
        .and_then(Value::as_bool)
        .ok_or(ControllerError::Invalid(
            "Docker network-membership desired state is invalid",
        ))?;
    Ok(Some(DockerNetworkMembershipIntentV12 {
        authority_sha256: parse_digest(text(object, "authoritySha256")?)?,
        membership_id: text(object, "membershipId")?.to_owned(),
        network_logical_id: text(object, "networkLogicalId")?.to_owned(),
        network_engine_id: text(object, "networkEngineId")?.to_owned(),
        container_logical_id: text(object, "containerLogicalId")?
            .to_owned(),
        container_engine_id: text(object, "containerEngineId")?.to_owned(),
        endpoint_id: text(object, "endpointId")?.to_owned(),
        aliases,
        ipv4_address: optional_text(object, "ipv4Address")?,
        ipv6_address: optional_text(object, "ipv6Address")?,
        desired_connected,
    }))
}

fn network_membership_record_value_v12(
    record: &DockerNetworkMembershipRecordV12,
) -> Value {
    object_value([
        ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
        (
            "bootIdSha256",
            Value::String(digest_hex(&record.boot_id_sha256)),
        ),
        (
            "ownerNamespace",
            Value::String(record.owner_namespace.clone()),
        ),
        (
            "daemonGeneration",
            Value::String(record.daemon_generation.clone()),
        ),
        (
            "intent",
            network_membership_intent_value_v12(&record.intent),
        ),
        (
            "status",
            Value::String(record.status.as_str().to_owned()),
        ),
        (
            "lastSequence",
            Value::Number(Number::from(record.last_sequence)),
        ),
        (
            "lastRequestSha256",
            Value::String(digest_hex(&record.last_request_sha256)),
        ),
        (
            "reconciliationSha256",
            record
                .reconciliation_sha256
                .map(|digest| Value::String(digest_hex(&digest)))
                .unwrap_or(Value::Null),
        ),
        ("revision", Value::Number(Number::from(record.revision))),
    ])
}

fn parse_network_membership_record_v12(
    value: &Value,
) -> Result<DockerNetworkMembershipRecordV12> {
    let object = exact_object(
        value,
        &[
            "contractVersion",
            "bootIdSha256",
            "ownerNamespace",
            "daemonGeneration",
            "intent",
            "status",
            "lastSequence",
            "lastRequestSha256",
            "reconciliationSha256",
            "revision",
        ],
    )?;
    require_version(object)?;
    Ok(DockerNetworkMembershipRecordV12 {
        boot_id_sha256: parse_digest(text(object, "bootIdSha256")?)?,
        owner_namespace: text(object, "ownerNamespace")?.to_owned(),
        daemon_generation: text(object, "daemonGeneration")?.to_owned(),
        intent: parse_optional_network_membership_intent_v12(
            object.get("intent").ok_or(ControllerError::Invalid(
                "Docker network-membership intent is absent",
            ))?,
        )?
        .ok_or(ControllerError::Invalid(
            "Docker network-membership intent is null",
        ))?,
        status: DockerNetworkMembershipStatusV12::parse(text(
            object,
            "status",
        )?)?,
        last_sequence: number(object, "lastSequence")?,
        last_request_sha256: parse_digest(text(
            object,
            "lastRequestSha256",
        )?)?,
        reconciliation_sha256: optional_text(
            object,
            "reconciliationSha256",
        )?
        .map(|digest| parse_digest(&digest))
        .transpose()?,
        revision: number(object, "revision")?,
    })
}

fn object_record_value(record: &DockerObjectRecordV11) -> Value {
    object_value([
        ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
        (
            "bootIdSha256",
            Value::String(digest_hex(&record.boot_id_sha256)),
        ),
        (
            "ownerNamespace",
            Value::String(record.owner_namespace.clone()),
        ),
        (
            "daemonGeneration",
            Value::String(record.daemon_generation.clone()),
        ),
        (
            "sourceSealSha256",
            Value::String(digest_hex(&record.source_seal_sha256)),
        ),
        (
            "artifactSealSha256",
            Value::String(digest_hex(&record.artifact_seal_sha256)),
        ),
        ("kind", Value::String(record.kind.as_str().to_owned())),
        ("logicalId", Value::String(record.logical_id.clone())),
        (
            "engineId",
            record
                .engine_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        ("state", Value::String(record.state.as_str().to_owned())),
        (
            "labels",
            Value::Object(
                record
                    .labels
                    .iter()
                    .map(|(key, value)| {
                        (key.clone(), Value::String(value.clone()))
                    })
                    .collect(),
            ),
        ),
        (
            "lastSequence",
            Value::Number(Number::from(record.last_sequence)),
        ),
        (
            "lastRequestSha256",
            Value::String(digest_hex(&record.last_request_sha256)),
        ),
        ("revision", Value::Number(Number::from(record.revision))),
    ])
}

fn mutation_record_value(record: &DockerMutationRecordV11) -> Value {
    object_value([
        ("contractVersion", Value::String(LEDGER_VERSION.to_owned())),
        (
            "bootIdSha256",
            Value::String(digest_hex(&record.boot_id_sha256)),
        ),
        ("requestId", Value::String(record.request_id.clone())),
        (
            "requestSha256",
            Value::String(digest_hex(&record.request_sha256)),
        ),
        (
            "capabilitySha256",
            Value::String(digest_hex(&record.capability_sha256)),
        ),
        (
            "ownerNamespace",
            Value::String(record.owner_namespace.clone()),
        ),
        (
            "daemonGeneration",
            Value::String(record.daemon_generation.clone()),
        ),
        (
            "sourceSealSha256",
            Value::String(digest_hex(&record.source_seal_sha256)),
        ),
        (
            "artifactSealSha256",
            Value::String(digest_hex(&record.artifact_seal_sha256)),
        ),
        ("sequence", Value::Number(Number::from(record.sequence))),
        ("kind", Value::String(record.kind.as_str().to_owned())),
        ("logicalId", Value::String(record.logical_id.clone())),
        (
            "engineId",
            record
                .engine_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "fromState",
            Value::String(record.from_state.as_str().to_owned()),
        ),
        (
            "intendedState",
            Value::String(record.intended_state.as_str().to_owned()),
        ),
        (
            "terminalState",
            record
                .terminal_state
                .map(|state| Value::String(state.as_str().to_owned()))
                .unwrap_or(Value::Null),
        ),
        ("status", Value::String(record.status.as_str().to_owned())),
        (
            "responseSha256",
            record
                .response_sha256
                .map(|digest| Value::String(digest_hex(&digest)))
                .unwrap_or(Value::Null),
        ),
        (
            "responseBytes",
            record
                .response_bytes
                .map(|length| Value::Number(Number::from(length)))
                .unwrap_or(Value::Null),
        ),
        (
            "reconciliationSha256",
            record
                .reconciliation_sha256
                .map(|digest| Value::String(digest_hex(&digest)))
                .unwrap_or(Value::Null),
        ),
        (
            "uncertainty",
            record
                .uncertainty
                .map(|value| Value::String(value.as_str().to_owned()))
                .unwrap_or(Value::Null),
        ),
        (
            "networkMembership",
            record
                .network_membership
                .as_ref()
                .map(network_membership_intent_value_v12)
                .unwrap_or(Value::Null),
        ),
        (
            "deadlineBoottimeNs",
            Value::Number(Number::from(record.deadline_boottime_ns)),
        ),
        ("revision", Value::Number(Number::from(record.revision))),
    ])
}

fn parse_object_record(value: &Value) -> Result<DockerObjectRecordV11> {
    let object = exact_object(
        value,
        &[
            "contractVersion",
            "bootIdSha256",
            "ownerNamespace",
            "daemonGeneration",
            "sourceSealSha256",
            "artifactSealSha256",
            "kind",
            "logicalId",
            "engineId",
            "state",
            "labels",
            "lastSequence",
            "lastRequestSha256",
            "revision",
        ],
    )?;
    require_version(object)?;
    let labels = object
        .get("labels")
        .and_then(Value::as_object)
        .ok_or(ControllerError::Invalid(
            "Docker object labels are invalid",
        ))?
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or(ControllerError::Invalid(
                    "Docker object label value is invalid",
                ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(DockerObjectRecordV11 {
        boot_id_sha256: parse_digest(text(object, "bootIdSha256")?)?,
        owner_namespace: text(object, "ownerNamespace")?.to_owned(),
        daemon_generation: text(object, "daemonGeneration")?.to_owned(),
        source_seal_sha256: parse_digest(text(
            object,
            "sourceSealSha256",
        )?)?,
        artifact_seal_sha256: parse_digest(text(
            object,
            "artifactSealSha256",
        )?)?,
        kind: DockerResourceKindV11::parse(text(object, "kind")?)?,
        logical_id: text(object, "logicalId")?.to_owned(),
        engine_id: optional_text(object, "engineId")?,
        state: DockerObjectStateV11::parse(text(object, "state")?)?,
        labels,
        last_sequence: number(object, "lastSequence")?,
        last_request_sha256: parse_digest(text(
            object,
            "lastRequestSha256",
        )?)?,
        revision: number(object, "revision")?,
    })
}

fn parse_mutation_record(
    value: &Value,
) -> Result<DockerMutationRecordV11> {
    let object = exact_object(
        value,
        &[
            "contractVersion",
            "bootIdSha256",
            "requestId",
            "requestSha256",
            "capabilitySha256",
            "ownerNamespace",
            "daemonGeneration",
            "sourceSealSha256",
            "artifactSealSha256",
            "sequence",
            "kind",
            "logicalId",
            "engineId",
            "fromState",
            "intendedState",
            "terminalState",
            "status",
            "responseSha256",
            "responseBytes",
            "reconciliationSha256",
            "uncertainty",
            "networkMembership",
            "deadlineBoottimeNs",
            "revision",
        ],
    )?;
    require_version(object)?;
    Ok(DockerMutationRecordV11 {
        boot_id_sha256: parse_digest(text(object, "bootIdSha256")?)?,
        request_id: text(object, "requestId")?.to_owned(),
        request_sha256: parse_digest(text(object, "requestSha256")?)?,
        capability_sha256: parse_digest(text(
            object,
            "capabilitySha256",
        )?)?,
        owner_namespace: text(object, "ownerNamespace")?.to_owned(),
        daemon_generation: text(object, "daemonGeneration")?.to_owned(),
        source_seal_sha256: parse_digest(text(
            object,
            "sourceSealSha256",
        )?)?,
        artifact_seal_sha256: parse_digest(text(
            object,
            "artifactSealSha256",
        )?)?,
        sequence: number(object, "sequence")?,
        kind: DockerResourceKindV11::parse(text(object, "kind")?)?,
        logical_id: text(object, "logicalId")?.to_owned(),
        engine_id: optional_text(object, "engineId")?,
        from_state: DockerObjectStateV11::parse(text(
            object,
            "fromState",
        )?)?,
        intended_state: DockerObjectStateV11::parse(text(
            object,
            "intendedState",
        )?)?,
        terminal_state: optional_text(object, "terminalState")?
            .map(|state| DockerObjectStateV11::parse(&state))
            .transpose()?,
        status: DockerMutationStatusV11::parse(text(object, "status")?)?,
        response_sha256: optional_text(object, "responseSha256")?
            .map(|digest| parse_digest(&digest))
            .transpose()?,
        response_bytes: optional_number(object, "responseBytes")?,
        reconciliation_sha256: optional_text(
            object,
            "reconciliationSha256",
        )?
        .map(|digest| parse_digest(&digest))
        .transpose()?,
        uncertainty: optional_text(object, "uncertainty")?
            .map(|value| DockerMutationUncertaintyV12::parse(&value))
            .transpose()?,
        network_membership: object
            .get("networkMembership")
            .ok_or(ControllerError::Invalid(
                "Docker network-membership intent field is absent",
            ))
            .and_then(parse_optional_network_membership_intent_v12)?,
        deadline_boottime_ns: number(object, "deadlineBoottimeNs")?,
        revision: number(object, "revision")?,
    })
}

fn read_canonical_value(path: &Path) -> Result<Value> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > LEDGER_RECORD_MAX_BYTES
    {
        return Err(ControllerError::Rejected(
            "Docker ledger record storage is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(metadata.len() + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ControllerError::Rejected(
            "Docker ledger record changed while reading",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        ControllerError::Invalid("Docker ledger record is not JSON")
    })?;
    if canonical_json_bytes_v11(&value)? != bytes {
        return Err(ControllerError::Rejected(
            "Docker ledger record is not canonical JSON",
        ));
    }
    Ok(value)
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or(ControllerError::Invalid(
        "Docker ledger path has no parent",
    ))?)?
    .sync_all()?;
    Ok(())
}

fn copy_create_new(
    source: &mut File,
    destination: &Path,
    expected_bytes: u64,
) -> Result<()> {
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let copied = std::io::copy(
        &mut source.take(expected_bytes + 1),
        &mut destination_file,
    )?;
    if copied != expected_bytes {
        return Err(ControllerError::Rejected(
            "Docker response spool changed during durable copy",
        ));
    }
    destination_file.sync_all()?;
    File::open(destination.parent().ok_or(
        ControllerError::Invalid(
            "Docker response path has no parent",
        ),
    )?)?
    .sync_all()?;
    Ok(())
}

fn write_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(ControllerError::Invalid(
        "Docker ledger path has no parent",
    ))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(ControllerError::Invalid(
                "Docker ledger filename is not UTF-8",
            ))?,
        unsafe { libc::getpid() },
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_dir_sorted(root: &Path) -> Result<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
    {
        return Err(ControllerError::Rejected(
            "Docker ledger directory is unsafe",
        ));
    }
    let mut entries = std::fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

fn exact_object<'a>(
    value: &'a Value,
    expected: &[&str],
) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(ControllerError::Invalid(
        "Docker ledger record is not an object",
    ))?;
    if object.len() != expected.len()
        || expected.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ControllerError::Rejected(
            "Docker ledger record contains missing or unknown fields",
        ));
    }
    Ok(object)
}

fn require_version(object: &Map<String, Value>) -> Result<()> {
    if text(object, "contractVersion")? != LEDGER_VERSION {
        return Err(ControllerError::Rejected(
            "Docker ledger record version differs",
        ));
    }
    Ok(())
}

fn text<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ControllerError::Invalid(key))
}

fn optional_text(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(ControllerError::Invalid(key)),
    }
}

fn number(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(ControllerError::Invalid(key))
}

fn optional_number(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<u64>> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or(ControllerError::Invalid(key)),
        _ => Err(ControllerError::Invalid(key)),
    }
}

fn object_value<const N: usize>(
    entries: [(&str, Value); N],
) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn parse_digest(value: &str) -> Result<Digest> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
    {
        return Err(ControllerError::Invalid(
            "Docker ledger digest is invalid",
        ));
    }
    let decoded = hex::decode(value).map_err(|_| {
        ControllerError::Invalid("Docker ledger digest is invalid")
    })?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    if digest == [0; 32] {
        return Err(ControllerError::Rejected(
            "Docker ledger digest is zero",
        ));
    }
    Ok(digest)
}

fn validate_engine_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'_' | b':' | b'@' | b'/' | b'-'
                ))
        })
    {
        return Err(ControllerError::Rejected(
            "Docker engine ID is noncanonical",
        ));
    }
    Ok(())
}

fn safe_component(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err(ControllerError::Rejected(
            "Docker ledger component is unsafe",
        ));
    }
    Ok(value.to_owned())
}

fn current_boot_id_sha256_v12() -> Result<Digest> {
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
            "kernel boot identity is unavailable or noncanonical",
        ));
    }
    let digest = sha256(value.as_bytes());
    if digest == [0; 32] {
        return Err(ControllerError::Rejected(
            "kernel boot identity digest is absent",
        ));
    }
    Ok(digest)
}

pub(crate) fn validate_relative_cas_subpath_v12(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.len() > 4096
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
                    | Component::RootDir
            )
        })
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(ControllerError::Rejected(
            "retained CAS subpath is not relative and canonical",
        ));
    }
    Ok(())
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or(ControllerError::Invalid(
            "Docker ledger filename is not UTF-8",
        ))
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
            "Docker ledger path is not absolute and normalized",
        ));
    }
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        ControllerError::Invalid("Docker ledger path contains NUL")
    })?;
    Ok(())
}
