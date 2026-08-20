#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use crate::coder_controller_v11::{
    build_signed_request_from_template_v11, ed25519_spki_der_sha256_v11,
    format_rfc3339_seconds_v11, now_unix_ms, CanonicalControllerRequestV11,
    CanonicalFrameKindV11, CanonicalPreallocationFrameV11, Lane, Plan,
    FIXED_FRAME_BYTES, MAX_DEADLINE_FUTURE_MS, REQUEST_MAX_BYTES,
};
use crate::controller_v12::{
    sha256, AcceptanceRecordV12, AcceptanceStateV12,
    ControllerWorkflowInvocationV12, DestructionEvidence,
    ExecutorFdLayoutV12, ExecutorLaneProxyBindingV12,
    ExecutorManifestTrustKeyV12, ExecutorTerminalEvidenceV12,
    LifecycleCleanupRequestV12, LifecycleCleanupResponseV12, RequestBindingV11,
    SourceSeal, TerminalVerdict, WorkflowSelectionV12,
    CONTROLLER_EXECUTOR_PROTOCOL_V12, CONTROLLER_LIFECYCLE_PROTOCOL_V12,
    CONTROLLER_RUNTIME_PROTOCOL_V12,
};
use crate::plan_protocol::{
    canonical_bytes as canonical_plan_bytes,
    canonical_sha256_without_digest, current_boot_id_sha256,
    LogicalPlanV12,
};
use crate::readiness::{
    ReadinessFixtureTrust, SignedReadinessFixtureV12,
};
use crate::receipt_contract_v12::{
    authority_rpc_v12, boot_id_sha256_v12, boottime_now_ns, canonical_json,
    envelope_digest, extract_request_v11_summary, final_trust_observation_digest,
    finalization_binding_digest, h11, h12, logged_receipt_bundle_digest,
    now_utc_rfc3339, parse_canonical_json,
    receipt_authority_submission_digest, request_admission_digest, sha256_bytes,
    sign_envelope, trust_generation_bundle_digest, AuthorityDeadlineV12,
    AuthorityFrameHeaderV12, AuthorityRoleV12, CanonicalRequestAdmissionV12,
    CanonicalU64, DigestHex, FinalSettlementArtifactV12,
    FinalVerdictAuthorityRequestV12,
    FinalVerdictAuthorityResponseV12, FinalizedLookupRequestV12,
    FinalizedLookupResponseV12, KeyAuthorizationV12, LedgerHighWaterRequestV12,
    LedgerHighWaterResponseV12, ReceiptAuthorityRequestV12,
    ReceiptAuthorityResponseV12, ReceiptBodyV12, ReceiptV12, ReplayIdentityV12,
    TrustGenerationResolveRequestV12, TrustGenerationResolveResponseV12,
    VerificationHighWaterV12, VerdictV12, WitnessFinalizationRequestV12,
    WitnessFinalizationResponseV12, AUTHORITY_FRAME_BYTES,
    CONTROLLER_RECEIVE_DOMAIN, MAX_AUTHORITY_REQUEST_BYTES,
    MAX_AUTHORITY_RESPONSE_BYTES, MAX_RECEIPT_BYTES,
};
use crate::receipt_verifier_v12::{
    build_final_trust_observation, verify_canonical_request_v11_admission,
    verify_final_settlement_artifact_v12, verify_historical_receipt_v12,
    verify_logged_bundle_v12, verify_receipt_v12,
    verify_trust_generation_bundle, AuthorityPinV12,
    StrictVerifierPinsV12, VerifiedReceiptV12,
};
use crate::source_cas::{
    AuthorizedManifestKey, ManifestTrustPolicy, PublicationControlV12,
    SourceManifestV12,
};

const DEFAULT_CONTROLLER_SOCKET: &str =
    "/run/serverware/coder/v12/controller/control.sock";
const DEFAULT_RELEASE_ROOT: &str =
    "/opt/serverware/coder-controller-v12/current";
const STRICT_PINS_BASENAME: &str = "strict-verifier-pins-v12.json";
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const MAX_TICKET_BYTES: usize = 256 * 1024;
const MAX_INTERNAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_LIFECYCLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_LIFECYCLE_FDS: usize = 2;
const PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12: &str =
    "serverware/private-dind-lifecycle/v12";
const PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12: &[u8] =
    b"serverware/private-dind-root-response-signature/v12\0";
const PRIVATE_DIND_TERMINAL_RECEIPT_SIGNATURE_DOMAIN_V12: &[u8] =
    b"serverware/private-dind-terminal-receipt/v12\0";
const PRIVILEGED_LIFECYCLE_CLEANUP_SIGNATURE_DOMAIN_V12: &[u8] =
    b"serverware/privileged-lifecycle-cleanup-signature/v12\0";
const PLAN_TERMINAL_AGGREGATE_SIGNATURE_DOMAIN_V12: &[u8] =
    b"serverware/private-dind-plan-aggregate-terminal/v12\0";
const MAX_SOURCE_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const REQUIRED_MEMFD_SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const MFD_ALLOW_SEALING_VALUE: libc::c_uint = 0x0002;
const MAX_RETRIES: usize = 3;

#[derive(Debug)]
pub enum RuntimeError {
    Invalid(String),
    Rejected(String),
    Unavailable(String),
    Io(std::io::Error),
}

impl RuntimeError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected(message.into())
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid: {message}"),
            Self::Rejected(message) => write!(formatter, "rejected: {message}"),
            Self::Unavailable(message) => write!(formatter, "unavailable: {message}"),
            Self::Io(error) => write!(formatter, "I/O failed: {error}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<std::io::Error> for RuntimeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<crate::controller_v12::ControllerV12Error> for RuntimeError {
    fn from(value: crate::controller_v12::ControllerV12Error) -> Self {
        Self::Rejected(value.to_string())
    }
}

impl From<crate::receipt_contract_v12::ContractError> for RuntimeError {
    fn from(value: crate::receipt_contract_v12::ContractError) -> Self {
        Self::Rejected(value.to_string())
    }
}

impl From<crate::coder_controller_v11::ControllerError> for RuntimeError {
    fn from(value: crate::coder_controller_v11::ControllerError) -> Self {
        Self::Rejected(value.to_string())
    }
}

impl From<crate::plan_protocol::PlanProtocolError> for RuntimeError {
    fn from(value: crate::plan_protocol::PlanProtocolError) -> Self {
        Self::Rejected(value.to_string())
    }
}

type Result<T> = std::result::Result<T, RuntimeError>;

#[derive(Clone)]
struct ControllerConfigV12 {
    exact_sha256: [u8; 32],
    socket_path: PathBuf,
    socket_mode: u32,
    state_root: PathBuf,
    receipt_authority_socket: PathBuf,
    final_verdict_socket: PathBuf,
    executor_socket: PathBuf,
    lane_proxy_socket: PathBuf,
    lifecycle_socket: PathBuf,
    source_cas_root: PathBuf,
    artifact_cas_root: PathBuf,
    oci_cas_root: PathBuf,
    source_ingress_descriptor: PathBuf,
    source_ingress_signature: PathBuf,
    canonical_source_bundle: PathBuf,
    native_point_snapshot: PathBuf,
    executor_invocation_inputs: PathBuf,
    source_input_root: PathBuf,
    workflow_manifest: PathBuf,
    deadline_profile: PathBuf,
    deadline_profile_signature: PathBuf,
    configuration_authority_public_key: PathBuf,
    source_ingress_authority_public_key: PathBuf,
    release_manifest: PathBuf,
    release_manifest_signature: PathBuf,
    release_manifest_public_key: PathBuf,
    configuration_generation: PathBuf,
    configuration_generation_signature: PathBuf,
    key_authorization: PathBuf,
    key_authorization_signature: PathBuf,
    revocation_checkpoint: PathBuf,
    revocation_checkpoint_signature: PathBuf,
    private_key_credential: String,
    workflow_id: String,
    deadline_profile_id: String,
    cleanup_reserve_ns: u64,
    receipt_reserve_ns: u64,
    max_connections: usize,
}

#[derive(Clone)]
struct IdentityMapV12 {
    controller_uid: u32,
    controller_gid: u32,
    executor_uid: u32,
    docker_proxy_uid: u32,
    receipt_authority_uid: u32,
    final_verdict_uid: u32,
    trust_generation_uid: u32,
    external_witness_uid: u32,
    lifecycle_uid: u32,
    client_gid: u32,
    controller_supplementary_gids: Vec<u32>,
    generation: u64,
    generation_sha256: [u8; 32],
    trust_generation_socket: PathBuf,
    external_witness_socket: PathBuf,
}

#[derive(Clone)]
struct StaticTrustV12 {
    pins: StrictVerifierPinsV12,
    controller_authorization: KeyAuthorizationV12,
    controller_signing_key: SigningKey,
    identities: IdentityMapV12,
    workflow_manifest_sha256: [u8; 32],
    deadline_profile_sha256: [u8; 32],
    source_ingress_descriptor_sha256: [u8; 32],
    source_publication_sha256: [u8; 32],
    privileged_root_signer_spki_sha256: [u8; 32],
}

#[derive(Clone)]
struct ControllerContextV12 {
    config: ControllerConfigV12,
    trust: StaticTrustV12,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutorInvocationInputsV12 {
    version: String,
    logical_plan_template: LogicalPlanV12,
    source_manifest: SourceManifestV12,
    source_publication_control_template: PublicationControlV12,
    artifact_publication_control_template: PublicationControlV12,
    manifest_trust_keys: Vec<ExecutorManifestTrustKeyV12>,
    readiness_fixture: SignedReadinessFixtureV12,
    readiness_trust_key: ExecutorManifestTrustKeyV12,
    readiness_timeout_ns: u64,
}

struct ResolvedControllerExecutorInvocationV12 {
    envelope: ControllerWorkflowInvocationV12,
    source_input: OwnedFd,
    lane_proxy: OwnedFd,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TicketRequestV12 {
    operation: String,
    workflow_id: String,
    deadline_profile_id: String,
    selection: WorkflowSelectionV12,
    raw_nonce_base64url: String,
    requested_timeout_ms: CanonicalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionTicketV12 {
    operation: String,
    workflow_id: String,
    deadline_profile_id: String,
    selection: WorkflowSelectionV12,
    raw_nonce_sha256: DigestHex,
    boot_id_sha256: DigestHex,
    peer_uid: u32,
    peer_pid: u32,
    accepted_at: String,
    accepted_at_unix_ms: CanonicalU64,
    frame_deadline: String,
    frame_deadline_unix_ms: CanonicalU64,
    request_deadline: String,
    request_deadline_unix_ms: CanonicalU64,
    execution_deadline_boottime_ns: CanonicalU64,
    cleanup_deadline_boottime_ns: CanonicalU64,
    receipt_deadline_boottime_ns: CanonicalU64,
    controller_configuration_sha256: DigestHex,
    verifier_high_water: VerificationHighWaterV12,
    ticket_sha256: DigestHex,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControllerReceiptReplyV12 {
    protocol: String,
    exact_receipt_sha256: DigestHex,
    exact_receipt_bytes: CanonicalU64,
    request_v11_sha256: DigestHex,
    receipt_envelope_sha256: DigestHex,
    next_high_water: VerificationHighWaterV12,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivilegedLifecycleResponseV12 {
    protocol: String,
    operation: String,
    disposition: String,
    request_sha256_canonical: [u8; 32],
    lane_generation_sha256: [u8; 32],
    acceptance_revoked_sha256: [u8; 32],
    cgroup_kill_sha256: [u8; 32],
    cgroup_empty_sha256: [u8; 32],
    dind_destroyed_sha256: [u8; 32],
    network_destroyed_sha256: [u8; 32],
    mounts_destroyed_sha256: [u8; 32],
    sockets_destroyed_sha256: [u8; 32],
    cleanup_terminal_sha256: [u8; 32],
    exact_plan_terminal_aggregate: Vec<u8>,
    plan_terminal_aggregate_sha256: [u8; 32],
    root_signer_spki_sha256: [u8; 32],
    root_signer_public_key_spki_der: Vec<u8>,
    root_signature: Vec<u8>,
    privileged_response_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedPlanTerminalAggregateV12 {
    protocol: String,
    plan_id: [u8; 32],
    request_sha256_canonical: [u8; 32],
    idempotency_key_sha256: [u8; 32],
    observed_terminal_sha256: [u8; 32],
    exact_receipt_sha256s: Vec<[u8; 32]>,
    exact_terminal_receipts: Vec<Vec<u8>>,
    root_signer_spki_sha256: [u8; 32],
    root_signer_public_key_spki_der: Vec<u8>,
    root_signature: Vec<u8>,
    aggregate_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedPrivateDindRequestV12 {
    protocol: String,
    operation: String,
    proxy_request: DelegatedProxyRequestBindingV12,
    attached_fd_roles: Vec<Value>,
    request_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegatedProxyRequestBindingV12 {
    request_sha256: [u8; 32],
    plan_id: [u8; 32],
    capability_sha256: [u8; 32],
    lane: Value,
    operation: Value,
    deadline_boottime_ns: u64,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedPrivateDindQueryPayloadV12 {
    version: String,
    plan_id: [u8; 32],
    lane: Value,
    original_request_sha256: [u8; 32],
    original_operation: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedPrivateDindResponseV12 {
    protocol: String,
    request_sha256: [u8; 32],
    proxy_request_sha256: [u8; 32],
    disposition: Value,
    authoritative_state: Value,
    result_sha256: [u8; 32],
    result: Vec<u8>,
    returned_fd_roles: Vec<String>,
    observed_state_sha256: [u8; 32],
    terminal_destruction_receipt: Option<Vec<u8>>,
    root_signer_spki_sha256: [u8; 32],
    root_signer_public_key_spki_der: Vec<u8>,
    root_signature: Vec<u8>,
    response_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegatedRootTerminalReceiptV12 {
    version: String,
    trust_profile: String,
    plan_id: [u8; 32],
    capability_sha256: [u8; 32],
    profile: Value,
    owner_namespace: String,
    daemon_generation: String,
    network_namespace: String,
    request_sha256: [u8; 32],
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
    observed_state_sha256: [u8; 32],
    signer_spki_sha256: [u8; 32],
    signer_public_key_spki_der: Vec<u8>,
    signature: Vec<u8>,
    receipt_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustGenerationHighWaterFileV12 {
    generation: CanonicalU64,
    generation_sha256: DigestHex,
}

fn parse_kv(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RuntimeError::invalid("configuration is not UTF-8"))?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| RuntimeError::invalid("configuration line lacks '='"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || value.is_empty()
            || values.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err(RuntimeError::invalid(
                "configuration contains an invalid or duplicate key",
            ));
        }
    }
    Ok(values)
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| RuntimeError::invalid(format!("missing configuration key {name}")))
}

fn required_path(
    values: &BTreeMap<String, String>,
    name: &str,
) -> Result<PathBuf> {
    let path = PathBuf::from(required(values, name)?);
    require_absolute_path(&path, name)?;
    Ok(path)
}

fn required_u64(
    values: &BTreeMap<String, String>,
    name: &str,
) -> Result<u64> {
    required(values, name)?
        .parse::<u64>()
        .map_err(|_| RuntimeError::invalid(format!("{name} is not u64")))
}

fn require_absolute_path(path: &Path, name: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(RuntimeError::invalid(format!(
            "{name} is not a normalized absolute path"
        )));
    }
    Ok(())
}

fn load_controller_config(path: &Path) -> Result<ControllerConfigV12> {
    let bytes = read_secure_file(path, MAX_CONFIG_BYTES, Some(0), false)?;
    let values = parse_kv(&bytes)?;
    if required_u64(&values, "contract_version")? != 12
        || required_u64(&values, "request_contract_version")? != 11
        || required_u64(&values, "receipt_contract_version")? != 12
        || required(&values, "trust_profile")?
            != "trusted-host-userspace-digest-no-ima"
        || required(&values, "receipt_replay")? != "exact_canonical_bytes"
        || required(&values, "external_witness_checkpoint_required")? != "true"
        || required(&values, "allow_ima_claim")? != "false"
        || required(&values, "allow_tee_claim")? != "false"
        || required(&values, "hardware_proof")? != "false"
    {
        return Err(RuntimeError::rejected(
            "controller config does not select the bounded trusted-host v12 profile",
        ));
    }
    let cleanup_ms = required_u64(&values, "cleanup_reserve_ms")?;
    let receipt_ms = values
        .get("receipt_reserve_ms")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| RuntimeError::invalid("receipt_reserve_ms is not u64"))?
        .unwrap_or(required_u64(&values, "ledger_operation_timeout_ms")?);
    let socket_mode = u32::from_str_radix(required(&values, "socket_mode")?, 8)
        .map_err(|_| RuntimeError::invalid("socket_mode is not octal"))?;
    let config = ControllerConfigV12 {
        exact_sha256: sha256(&bytes),
        socket_path: required_path(&values, "socket_path")?,
        socket_mode,
        state_root: required_path(&values, "state_root")?,
        receipt_authority_socket: required_path(&values, "ledger_socket")?,
        final_verdict_socket: required_path(&values, "final_verdict_socket")?,
        executor_socket: required_path(&values, "executor_socket")?,
        lane_proxy_socket: required_path(&values, "lane_proxy_socket")?,
        lifecycle_socket: required_path(&values, "lifecycle_socket")?,
        source_cas_root: required_path(&values, "source_cas_root")?,
        artifact_cas_root: required_path(&values, "artifact_cas_root")?,
        oci_cas_root: required_path(&values, "oci_cas_root")?,
        source_ingress_descriptor: required_path(
            &values,
            "source_ingress_descriptor",
        )?,
        source_ingress_signature: required_path(
            &values,
            "source_ingress_signature",
        )?,
        canonical_source_bundle: required_path(
            &values,
            "canonical_source_bundle",
        )?,
        native_point_snapshot: required_path(&values, "native_point_snapshot")?,
        executor_invocation_inputs: required_path(
            &values,
            "executor_invocation_inputs",
        )?,
        source_input_root: required_path(
            &values,
            "source_input_root",
        )?,
        workflow_manifest: required_path(&values, "workflow_manifest")?,
        deadline_profile: required_path(&values, "deadline_profile")?,
        deadline_profile_signature: required_path(
            &values,
            "deadline_profile_signature",
        )?,
        configuration_authority_public_key: required_path(
            &values,
            "configuration_authority_public_key",
        )?,
        source_ingress_authority_public_key: required_path(
            &values,
            "source_ingress_authority_public_key",
        )?,
        release_manifest: required_path(&values, "release_manifest")?,
        release_manifest_signature: required_path(
            &values,
            "release_manifest_signature",
        )?,
        release_manifest_public_key: required_path(
            &values,
            "release_manifest_public_key",
        )?,
        configuration_generation: required_path(
            &values,
            "configuration_generation",
        )?,
        configuration_generation_signature: required_path(
            &values,
            "configuration_generation_signature",
        )?,
        key_authorization: required_path(&values, "key_authorization")?,
        key_authorization_signature: required_path(
            &values,
            "key_authorization_signature",
        )?,
        revocation_checkpoint: required_path(&values, "revocation_checkpoint")?,
        revocation_checkpoint_signature: required_path(
            &values,
            "revocation_checkpoint_signature",
        )?,
        private_key_credential: required(&values, "private_key_credential")?
            .to_owned(),
        workflow_id: required(&values, "workflow_id")?.to_owned(),
        deadline_profile_id: required(&values, "deadline_profile_id")?.to_owned(),
        cleanup_reserve_ns: cleanup_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| RuntimeError::invalid("cleanup reserve overflow"))?,
        receipt_reserve_ns: receipt_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| RuntimeError::invalid("receipt reserve overflow"))?,
        max_connections: required_u64(&values, "max_connections")?
            .try_into()
            .map_err(|_| RuntimeError::invalid("max_connections exceeds usize"))?,
    };
    if config.socket_path != Path::new(DEFAULT_CONTROLLER_SOCKET)
        || config.socket_mode != 0o660
        || config.cleanup_reserve_ns == 0
        || config.receipt_reserve_ns == 0
        || config.max_connections == 0
        || config.max_connections > 256
    {
        return Err(RuntimeError::rejected(
            "controller socket or reserve configuration differs from v12 ops",
        ));
    }
    Ok(config)
}

fn load_static_trust(config: &ControllerConfigV12) -> Result<StaticTrustV12> {
    let configuration_key =
        load_verifying_key(&config.configuration_authority_public_key)?;
    let source_key =
        load_verifying_key(&config.source_ingress_authority_public_key)?;
    let release_key = load_verifying_key(&config.release_manifest_public_key)?;

    let release_manifest_bytes = verify_signed_file(
        &config.release_manifest,
        &config.release_manifest_signature,
        &release_key,
        MAX_MANIFEST_BYTES,
    )?;
    let generation_bytes = verify_signed_file(
        &config.configuration_generation,
        &config.configuration_generation_signature,
        &configuration_key,
        MAX_MANIFEST_BYTES,
    )?;
    let key_authorization_bytes = verify_signed_file(
        &config.key_authorization,
        &config.key_authorization_signature,
        &configuration_key,
        MAX_MANIFEST_BYTES,
    )?;
    let revocation_bytes = verify_signed_file(
        &config.revocation_checkpoint,
        &config.revocation_checkpoint_signature,
        &configuration_key,
        MAX_MANIFEST_BYTES,
    )?;
    let deadline_bytes = verify_signed_file(
        &config.deadline_profile,
        &config.deadline_profile_signature,
        &configuration_key,
        MAX_MANIFEST_BYTES,
    )?;
    let source_descriptor_bytes = verify_signed_file(
        &config.source_ingress_descriptor,
        &config.source_ingress_signature,
        &source_key,
        MAX_SOURCE_DESCRIPTOR_BYTES,
    )?;
    let workflow_bytes =
        read_secure_file(&config.workflow_manifest, MAX_MANIFEST_BYTES, Some(0), false)?;
    let executor_inputs_bytes = read_secure_file(
        &config.executor_invocation_inputs,
        MAX_INTERNAL_BYTES,
        Some(0),
        false,
    )?;

    let release_values = parse_kv(&release_manifest_bytes)?;
    let generation_values = parse_kv(&generation_bytes)?;
    let generation = required_u64(&generation_values, "config_generation")?;
    let now_epoch = time::OffsetDateTime::now_utc().unix_timestamp();
    let valid_from = required(&generation_values, "valid_from_epoch")?
        .parse::<i64>()
        .map_err(|_| RuntimeError::invalid("valid_from_epoch is not i64"))?;
    let valid_until = required(&generation_values, "valid_until_epoch")?
        .parse::<i64>()
        .map_err(|_| RuntimeError::invalid("valid_until_epoch is not i64"))?;
    let rollback_floor =
        required_u64(&generation_values, "rollback_floor_generation")?;
    if generation == 0
        || rollback_floor > generation
        || now_epoch < valid_from
        || now_epoch > valid_until
    {
        return Err(RuntimeError::rejected(
            "configuration generation is expired or below its rollback floor",
        ));
    }
    if required_u64(&release_values, "manifest_version")? != 12
        || required_u64(&release_values, "config_generation")? != generation
        || required(&release_values, "trust_profile")?
            != "trusted-host-userspace-digest-no-ima"
        || required(&release_values, "valid_from_epoch")?
            .parse::<i64>()
            .map_err(|_| RuntimeError::invalid("release valid_from_epoch is not i64"))?
            > now_epoch
        || required(&release_values, "valid_until_epoch")?
            .parse::<i64>()
            .map_err(|_| RuntimeError::invalid("release valid_until_epoch is not i64"))?
            < now_epoch
        || required_u64(&release_values, "rollback_floor_generation")?
            > generation
    {
        return Err(RuntimeError::rejected(
            "signed release manifest is expired or generation-mismatched",
        ));
    }
    require_committed_digest(
        &release_values,
        "config_generation_document_sha256",
        &generation_bytes,
    )?;
    require_committed_digest(
        &release_values,
        "workflow_manifest_sha256",
        &workflow_bytes,
    )?;
    require_committed_digest(
        &release_values,
        "deadline_profile_sha256",
        &deadline_bytes,
    )?;
    require_committed_digest(
        &release_values,
        "source_ingress_descriptor_sha256",
        &source_descriptor_bytes,
    )?;
    require_committed_digest(
        &release_values,
        "executor_invocation_inputs_sha256",
        &executor_inputs_bytes,
    )?;
    let committed_controller_config = DigestHex::parse(
        required(&release_values, "controller_config_sha256")?.to_owned(),
    )?;
    if committed_controller_config != digest_hex(config.exact_sha256)? {
        return Err(RuntimeError::rejected(
            "controller config differs from the signed release manifest",
        ));
    }
    require_committed_digest(
        &generation_values,
        "key_authorization_sha256",
        &key_authorization_bytes,
    )?;
    require_committed_digest(
        &generation_values,
        "revocation_checkpoint_sha256",
        &revocation_bytes,
    )?;
    require_committed_digest(
        &generation_values,
        "deadline_profile_sha256",
        &deadline_bytes,
    )?;
    require_committed_digest(
        &generation_values,
        "source_ingress_descriptor_sha256",
        &source_descriptor_bytes,
    )?;

    let key_authorization_values = parse_kv(&key_authorization_bytes)?;
    let revocation_values = parse_kv(&revocation_bytes)?;
    if required_u64(&key_authorization_values, "config_generation")?
            != generation
        || required_u64(&revocation_values, "config_generation")?
            != generation
        || required_u64(&revocation_values, "rollback_floor_generation")?
            > generation
        || required_u64(&revocation_values, "valid_until_epoch")?
            < u64::try_from(now_epoch)
                .map_err(|_| RuntimeError::rejected("wall clock is before epoch"))?
    {
        return Err(RuntimeError::rejected(
            "key authorization or revocation checkpoint is not current",
        ));
    }

    let source_values = parse_kv(&source_descriptor_bytes)?;
    if required_u64(&source_values, "document_version")? != 12
        || required(&source_values, "live_source_mounts")? != "false"
        || required(&source_values, "publication")?
            != "retained-dirfd-copy-fsync-auth-manifest-renameat2-noreplace"
    {
        return Err(RuntimeError::rejected(
            "source ingress does not select immutable atomic CAS publication",
        ));
    }
    let source_publication_sha256 = select_source_publication(
        config,
        &source_values,
    )?;

    let deadline_values = parse_kv(&deadline_bytes)?;
    if required_u64(&deadline_values, "document_version")? != 12
        || required(&deadline_values, "profile_id")?
            != config.deadline_profile_id
    {
        return Err(RuntimeError::rejected(
            "deadline profile identity differs from controller config",
        ));
    }
    let workflow_values = parse_kv(&workflow_bytes)?;
    if required_u64(&workflow_values, "manifest_version")? != 12
        || required(&workflow_values, "workflow_id")? != config.workflow_id
        || required_u64(&workflow_values, "lane_count")? != 5
        || required(&workflow_values, "host_docker_socket_exposed")? != "false"
        || required(&workflow_values, "failure_transition")? != "Destroying"
        || required(&workflow_values, "post_build.destroy")? != "build-dind"
        || required(&workflow_values, "post_build.no_build_dind")?
            != "fresh-private-import-only"
        || required(&workflow_values, "docker_proxy_contract")?
            != crate::plan_protocol::PLAN_PROXY_PROTOCOL_VERSION
    {
        return Err(RuntimeError::rejected(
            "five-lane workflow manifest violates the v12 controller boundary",
        ));
    }
    for lane in 0..5 {
        let body_authority = required(
            &workflow_values,
            &format!("lane.{lane}.body_docker_authority"),
        )?;
        let projection = required(
            &workflow_values,
            &format!("lane.{lane}.body_docker_socket_projection"),
        )?;
        if projection != "none"
            || (lane != 0 && body_authority != "none")
            || (lane == 0 && body_authority != "sealed-capability-only")
        {
            return Err(RuntimeError::rejected(
                "repository body Docker authority is broader than the v12 manifest",
            ));
        }
    }
    if required(&workflow_values, "lane.2.body_access")?
            != "service-endpoints-only"
        || required(&workflow_values, "lane.3.body_access")?
            != "service-endpoints-only"
    {
        return Err(RuntimeError::rejected(
            "integration or E2E body is not endpoint-only",
        ));
    }

    let pins_path = config
        .configuration_generation
        .parent()
        .ok_or_else(|| RuntimeError::invalid("generation path has no parent"))?
        .join(STRICT_PINS_BASENAME);
    let pins_bytes =
        read_secure_file(&pins_path, MAX_CONFIG_BYTES, Some(0), false)?;
    let pins: StrictVerifierPinsV12 =
        parse_canonical_json(&pins_bytes, MAX_CONFIG_BYTES)?;
    pins.validate()?;
    let controller_authorization =
        authorization_from_pin(&pins.controller_ingress);
    let controller_signing_key =
        load_controller_signing_key(&config.private_key_credential)?;
    if crate::receipt_contract_v12::ed25519_spki_sha256(
        &controller_signing_key.verifying_key(),
    ) != pins.controller_ingress.spki_der_sha256
    {
        return Err(RuntimeError::rejected(
            "controller systemd credential does not match ingress trust pin",
        ));
    }

    let identities = IdentityMapV12 {
        controller_uid: generation_u32(
            &generation_values,
            "identity.controller.uid",
        )?,
        controller_gid: generation_u32(
            &generation_values,
            "identity.controller.gid",
        )?,
        executor_uid: generation_u32(
            &generation_values,
            "identity.executor.uid",
        )?,
        docker_proxy_uid: generation_u32(
            &generation_values,
            "identity.docker_proxy.uid",
        )?,
        receipt_authority_uid: generation_u32(
            &generation_values,
            "identity.receipt_authority.uid",
        )?,
        final_verdict_uid: generation_u32(
            &generation_values,
            "identity.final_verdict_authority.uid",
        )?,
        trust_generation_uid: generation_u32(
            &generation_values,
            "identity.trust_generation_authority.uid",
        )?,
        external_witness_uid: generation_u32(
            &generation_values,
            "identity.external_witness_authority.uid",
        )?,
        lifecycle_uid: generation_u32(
            &generation_values,
            "identity.lifecycle.uid",
        )?,
        client_gid: generation_u32(&generation_values, "client_gid")?,
        controller_supplementary_gids: [
            "group.executor_api.gid",
            "group.docker_api.gid",
            "group.receipt_api.gid",
            "group.verdict_api.gid",
            "group.trust_api.gid",
            "group.witness_api.gid",
            "group.lifecycle_api.gid",
            "group.cas.gid",
        ]
        .iter()
        .map(|name| generation_u32(&generation_values, name))
        .collect::<Result<Vec<_>>>()?,
        generation,
        generation_sha256: sha256(&generation_bytes),
        trust_generation_socket: {
            let path = PathBuf::from(required(
                &generation_values,
                "trust_generation_socket",
            )?);
            require_absolute_path(&path, "trust_generation_socket")?;
            path
        },
        external_witness_socket: {
            let path = PathBuf::from(required(
                &generation_values,
                "external_witness_socket",
            )?);
            require_absolute_path(&path, "external_witness_socket")?;
            path
        },
    };
    let identities_set = [
        identities.controller_uid,
        identities.executor_uid,
        identities.docker_proxy_uid,
        identities.receipt_authority_uid,
        identities.final_verdict_uid,
        identities.trust_generation_uid,
        identities.external_witness_uid,
        identities.lifecycle_uid,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if identities_set.len() != 8 {
        return Err(RuntimeError::rejected(
            "controller and authority UIDs are not distinct",
        ));
    }

    Ok(StaticTrustV12 {
        pins,
        controller_authorization,
        controller_signing_key,
        identities,
        workflow_manifest_sha256: sha256(&workflow_bytes),
        deadline_profile_sha256: sha256(&deadline_bytes),
        source_ingress_descriptor_sha256: sha256(&source_descriptor_bytes),
        source_publication_sha256,
        privileged_root_signer_spki_sha256: DigestHex::parse(
            required(
                &release_values,
                "lifecycle_privileged_authority_spki_sha256",
            )?
            .to_owned(),
        )?
        .decode()?,
    })
}

fn authorization_from_pin(pin: &AuthorityPinV12) -> KeyAuthorizationV12 {
    KeyAuthorizationV12 {
        role: pin.role,
        principal_id: pin.principal_id.clone(),
        key_id: pin.key_id.clone(),
        algorithm: "Ed25519".to_owned(),
        spki_der_sha256: pin.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: pin
            .physical_private_key_identity_sha256
            .clone(),
        key_authorization_sha256: pin.key_authorization_sha256.clone(),
        authorization_root_sha256: pin.authorization_root_sha256.clone(),
        authorization_revision: pin.authorization_revision.clone(),
        revocation_root_sha256: pin.revocation_root_sha256.clone(),
        revocation_revision: pin.revocation_revision.clone(),
        high_water: pin.high_water.clone(),
        valid_from: pin.valid_from.clone(),
        valid_until: pin.valid_until.clone(),
        status: pin.status.clone(),
    }
}

fn require_committed_digest(
    values: &BTreeMap<String, String>,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    let expected = DigestHex::parse(required(values, name)?.to_owned())?;
    if expected != sha256_bytes(bytes) {
        return Err(RuntimeError::rejected(format!(
            "{name} differs from the signed configuration generation"
        )));
    }
    Ok(())
}

fn generation_u32(
    values: &BTreeMap<String, String>,
    name: &str,
) -> Result<u32> {
    required_u64(values, name)?
        .try_into()
        .map_err(|_| RuntimeError::invalid(format!("{name} exceeds u32")))
}

fn select_source_publication(
    config: &ControllerConfigV12,
    values: &BTreeMap<String, String>,
) -> Result<[u8; 32]> {
    let canonical_expected =
        DigestHex::parse(required(values, "canonical_bundle_sha256")?.to_owned())?;
    let native_expected = DigestHex::parse(
        required(values, "native_point_snapshot_sha256")?.to_owned(),
    )?;
    let maximum_publication_bytes = 64u64 * 1024 * 1024 * 1024;
    if config.canonical_source_bundle.exists() {
        let digest = hash_secure_file(
            &config.canonical_source_bundle,
            maximum_publication_bytes,
            0,
        )?;
        if digest_hex(digest)? != canonical_expected {
            return Err(RuntimeError::rejected(
                "canonical source bundle differs from signed source ingress",
            ));
        }
        return Ok(digest);
    }
    let native = hash_secure_file(
        &config.native_point_snapshot,
        maximum_publication_bytes,
        0,
    )?;
    if digest_hex(native)? != native_expected {
        return Err(RuntimeError::rejected(
            "native point snapshot differs from signed source ingress",
        ));
    }
    Ok(native)
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = read_secure_file(path, 64 * 1024, Some(0), false)?;
    if bytes.len() == 32 {
        return VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| RuntimeError::invalid("public key length changed"))?,
        )
        .map_err(|error| RuntimeError::rejected(error.to_string()));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::invalid("public key is not raw Ed25519 or PEM"))?;
    VerifyingKey::from_public_key_pem(text)
        .map_err(|error| RuntimeError::rejected(error.to_string()))
}

fn verify_signed_file(
    path: &Path,
    signature_path: &Path,
    key: &VerifyingKey,
    maximum: usize,
) -> Result<Vec<u8>> {
    let bytes = read_secure_file(path, maximum, Some(0), false)?;
    let signature =
        read_secure_file(signature_path, 4096, Some(0), false)?;
    let signature = if signature.len() == 64 {
        signature
    } else {
        URL_SAFE_NO_PAD
            .decode(
                std::str::from_utf8(&signature)
                    .map_err(|_| RuntimeError::invalid("signature is not binary or base64url"))?
                    .trim(),
            )
            .map_err(|_| RuntimeError::invalid("signature is not binary or base64url"))?
    };
    let signature = Signature::from_slice(&signature)
        .map_err(|error| RuntimeError::rejected(error.to_string()))?;
    key.verify(&bytes, &signature)
        .map_err(|_| RuntimeError::rejected("detached manifest signature is invalid"))?;
    Ok(bytes)
}

fn load_controller_signing_key(credential_name: &str) -> Result<SigningKey> {
    if credential_name.is_empty()
        || !credential_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(RuntimeError::invalid(
            "controller credential name is invalid",
        ));
    }
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or_else(|| RuntimeError::unavailable("CREDENTIALS_DIRECTORY is absent"))?;
    let path = PathBuf::from(directory).join(credential_name);
    let bytes = read_secure_file(
        &path,
        64 * 1024,
        Some(unsafe { libc::geteuid() }),
        true,
    )?;
    if bytes.len() == 32 {
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| RuntimeError::invalid("controller key length changed"))?;
        return Ok(SigningKey::from_bytes(&key_bytes));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::invalid("controller key is not raw or PKCS8 PEM"))?;
    SigningKey::from_pkcs8_pem(text)
        .map_err(|error| RuntimeError::rejected(error.to_string()))
}

fn read_secure_file(
    path: &Path,
    maximum: usize,
    expected_owner: Option<u32>,
    allow_root_owner: bool,
) -> Result<Vec<u8>> {
    require_absolute_path(path, "secure file")?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || expected_owner.is_some_and(|owner| {
            metadata.uid() != owner && !(allow_root_owner && metadata.uid() == 0)
        })
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(RuntimeError::rejected(format!(
            "secure file metadata rejected: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(RuntimeError::rejected(
            "secure file changed while it was read",
        ));
    }
    Ok(bytes)
}

fn hash_secure_file(
    path: &Path,
    maximum_bytes: u64,
    expected_owner: u32,
) -> Result<[u8; 32]> {
    require_absolute_path(path, "secure source publication")?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(RuntimeError::rejected(
            "source publication metadata or size is outside its bound",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| RuntimeError::invalid("source hash length overflow"))?;
        if total > metadata.len() {
            return Err(RuntimeError::rejected(
                "source publication grew while hashing",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total != metadata.len() {
        return Err(RuntimeError::rejected(
            "source publication changed while hashing",
        ));
    }
    Ok(hasher.finalize().into())
}

fn ensure_private_directory(path: &Path, owner: u32) -> Result<()> {
    require_absolute_path(path, "state directory")?;
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(RuntimeError::rejected(format!(
            "state directory is not private and owner-bound: {}",
            path.display()
        )));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8], owner: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::invalid("atomic state path has no parent"))?;
    ensure_private_directory(parent, owner)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RuntimeError::invalid("atomic state filename is invalid"))?;
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        unsafe { libc::getpid() },
        hex::encode(sha256(bytes)),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    let write_result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn persist_generation_high_water(
    context: &ControllerContextV12,
) -> Result<()> {
    ensure_private_directory(
        &context.config.state_root,
        context.trust.identities.controller_uid,
    )?;
    let path = context
        .config
        .state_root
        .join("trust-generation-high-water-v12.json");
    let next = TrustGenerationHighWaterFileV12 {
        generation: CanonicalU64::new(context.trust.identities.generation),
        generation_sha256: digest_hex(context.trust.identities.generation_sha256)?,
    };
    if path.exists() {
        let bytes = read_secure_file(
            &path,
            MAX_CONFIG_BYTES,
            Some(context.trust.identities.controller_uid),
            false,
        )?;
        let current: TrustGenerationHighWaterFileV12 =
            parse_canonical_json(&bytes, MAX_CONFIG_BYTES)?;
        if current.generation.get()? > next.generation.get()?
            || (current.generation == next.generation
                && current.generation_sha256 != next.generation_sha256)
        {
            return Err(RuntimeError::rejected(
                "controller configuration generation rolled back or forked",
            ));
        }
        if current == next {
            return Ok(());
        }
    }
    let bytes = canonical_json(&next, MAX_CONFIG_BYTES)?;
    atomic_write(
        &path,
        &bytes,
        context.trust.identities.controller_uid,
    )
}

fn digest_hex(value: [u8; 32]) -> Result<DigestHex> {
    DigestHex::parse(hex::encode(value)).map_err(Into::into)
}

fn parse_digest(value: &DigestHex) -> Result<[u8; 32]> {
    value.decode().map_err(Into::into)
}

#[derive(Clone, Copy, Debug)]
struct PeerCred {
    pid: u32,
    uid: u32,
    gid: u32,
}

struct SeqpacketListener {
    fd: OwnedFd,
}

impl SeqpacketListener {
    fn activate_or_bind(
        path: &Path,
        mode: u32,
        client_gid: u32,
    ) -> Result<Self> {
        if let Some(fd) = activated_fd()? {
            require_socket_type(fd.as_raw_fd(), libc::SOCK_SEQPACKET)?;
            require_socket_file(path, 0, mode)?;
            return Ok(Self { fd });
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(RuntimeError::rejected(
                "controller ingress must be systemd socket-activated or bound by root",
            ));
        }
        if path.exists() {
            return Err(RuntimeError::rejected(
                "controller socket path is already occupied",
            ));
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (address, length) = unix_address(path)?;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| RuntimeError::invalid("controller socket path contains NUL"))?;
        if unsafe { libc::chown(path_c.as_ptr(), 0, client_gid) } != 0
            || unsafe { libc::chmod(path_c.as_ptr(), mode as libc::mode_t) } != 0
            || unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        require_socket_file(path, 0, mode)?;
        Ok(Self { fd })
    }

    fn accept(&self) -> Result<OwnedFd> {
        let raw = unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

fn activated_fd() -> Result<Option<OwnedFd>> {
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let listen_pid = std::env::var("LISTEN_PID").ok();
    match (listen_fds, listen_pid) {
        (None, None) => Ok(None),
        (Some(fds), Some(pid))
            if fds == "1"
                && pid
                    .parse::<u32>()
                    .ok()
                    .is_some_and(|value| value == unsafe { libc::getpid() } as u32) =>
        {
            let duplicate = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Some(unsafe { OwnedFd::from_raw_fd(duplicate) }))
        }
        _ => Err(RuntimeError::rejected(
            "systemd socket activation state is incomplete or ambiguous",
        )),
    }
}

fn require_socket_type(fd: RawFd, expected: libc::c_int) -> Result<()> {
    let mut value = 0i32;
    let mut length = mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut value as *mut i32 as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || value != expected
    {
        return Err(RuntimeError::rejected(
            "activated socket has the wrong transport type",
        ));
    }
    Ok(())
}

fn require_socket_file(
    path: &Path,
    owner: u32,
    mode: u32,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner
        || metadata.mode() & 0o777 != mode
    {
        return Err(RuntimeError::rejected(
            "controller ingress socket is not root-owned with exact mode",
        ));
    }
    Ok(())
}

fn unix_address(path: &Path) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
        return Err(RuntimeError::invalid("Unix socket path is outside sockaddr_un"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter()) {
        *target = *source as libc::c_char;
    }
    let length = (mem::size_of::<libc::sa_family_t>() + bytes.len() + 1)
        as libc::socklen_t;
    Ok((address, length))
}

fn peer_cred(fd: RawFd) -> Result<PeerCred> {
    let mut credential: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credential as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || credential.pid <= 0
    {
        return Err(RuntimeError::rejected("SO_PEERCRED is unavailable"));
    }
    Ok(PeerCred {
        pid: credential.pid as u32,
        uid: credential.uid,
        gid: credential.gid,
    })
}

fn connect_seqpacket(path: &Path, deadline: u64) -> Result<OwnedFd> {
    require_live(deadline)?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let (address, length) = unix_address(path)?;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    require_live(deadline)?;
    Ok(fd)
}

fn send_packet(fd: RawFd, bytes: &[u8], deadline: u64) -> Result<()> {
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
        return Err(RuntimeError::unavailable(
            "seqpacket send was truncated",
        ));
    }
    Ok(())
}

fn receive_packet(
    fd: RawFd,
    maximum: usize,
    deadline: u64,
) -> Result<Vec<u8>> {
    poll_fd(fd, libc::POLLIN, deadline)?;
    let mut bytes = vec![0u8; maximum];
    let count = unsafe {
        libc::recv(
            fd,
            bytes.as_mut_ptr() as *mut libc::c_void,
            bytes.len(),
            libc::MSG_TRUNC,
        )
    };
    if count <= 0 || count as usize > maximum {
        return Err(RuntimeError::rejected(
            "seqpacket is empty, truncated, or oversized",
        ));
    }
    bytes.truncate(count as usize);
    Ok(bytes)
}

#[repr(C, align(16))]
struct ControlBuffer([u8; 128]);

fn send_fd_packet(
    socket: RawFd,
    bytes: &[u8],
    attached_fd: RawFd,
    deadline: u64,
) -> Result<()> {
    poll_fd(socket, libc::POLLOUT, deadline)?;
    let mut control = ControlBuffer([0; 128]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(RuntimeError::invalid("SCM_RIGHTS header is unavailable"));
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len =
            libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &attached_fd as *const RawFd as *const u8,
            libc::CMSG_DATA(header),
            mem::size_of::<RawFd>(),
        );
    }
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent != bytes.len() as isize {
        return Err(RuntimeError::unavailable(
            "SCM_RIGHTS seqpacket send was truncated",
        ));
    }
    Ok(())
}

fn send_fds_packet(
    socket: RawFd,
    bytes: &[u8],
    attached_fds: &[RawFd],
    deadline: u64,
) -> Result<()> {
    if attached_fds.is_empty()
        || attached_fds.len() > 8
        || attached_fds.iter().any(|fd| *fd < 3)
    {
        return Err(RuntimeError::invalid(
            "SCM_RIGHTS descriptor set is empty or invalid",
        ));
    }
    poll_fd(socket, libc::POLLOUT, deadline)?;
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let control_bytes = unsafe {
        libc::CMSG_SPACE(
            (attached_fds.len() * mem::size_of::<RawFd>())
                as libc::c_uint,
        ) as usize
    };
    let mut control =
        vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control_bytes;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(RuntimeError::invalid(
            "SCM_RIGHTS descriptor header is unavailable",
        ));
    }
    unsafe {
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
    let sent = unsafe {
        libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL)
    };
    if sent != bytes.len() as isize {
        return Err(RuntimeError::unavailable(
            "multi-descriptor SCM_RIGHTS seqpacket send was truncated",
        ));
    }
    Ok(())
}

fn receive_fd_packet(
    socket: RawFd,
    expected_bytes: usize,
    deadline: u64,
) -> Result<(Vec<u8>, OwnedFd)> {
    poll_fd(socket, libc::POLLIN, deadline)?;
    let mut payload = vec![0u8; expected_bytes];
    let mut control = ControlBuffer([0; 128]);
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control.0.len();
    let count = unsafe {
        libc::recvmsg(
            socket,
            &mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
        )
    };
    if count != expected_bytes as isize
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    {
        return Err(RuntimeError::rejected(
            "SCM_RIGHTS packet length or ancillary data is invalid",
        ));
    }
    let mut received = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        unsafe {
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
            {
                let data_bytes = (*header)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize);
                for offset in (0..data_bytes).step_by(mem::size_of::<RawFd>()) {
                    if offset + mem::size_of::<RawFd>() <= data_bytes {
                        let mut raw = -1;
                        std::ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(header).add(offset),
                            &mut raw as *mut RawFd as *mut u8,
                            mem::size_of::<RawFd>(),
                        );
                        if raw >= 0 {
                            received.push(OwnedFd::from_raw_fd(raw));
                        }
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received.len() != 1 {
        drop(received);
        return Err(RuntimeError::rejected(
            "SCM_RIGHTS packet must carry exactly one descriptor",
        ));
    }
    let fd = received
        .pop()
        .ok_or_else(|| RuntimeError::invalid("received descriptor disappeared"))?;
    Ok((payload, fd))
}

fn create_sealed_memfd(name: &str, bytes: &[u8]) -> Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| RuntimeError::invalid("memfd name contains NUL"))?;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | MFD_ALLOW_SEALING_VALUE,
        ) as RawFd
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes)?;
    file.sync_all()?;
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_ADD_SEALS,
            REQUIRED_MEMFD_SEALS,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) })
}

fn read_sealed_memfd(
    fd: OwnedFd,
    expected: u64,
    maximum: u64,
) -> Result<Vec<u8>> {
    let mut file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || expected == 0
        || expected > maximum
        || metadata.size() != expected
    {
        return Err(RuntimeError::rejected(
            "sealed memfd size or type differs from preallocation",
        ));
    }
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & REQUIRED_MEMFD_SEALS != REQUIRED_MEMFD_SEALS {
        return Err(RuntimeError::rejected(
            "request memfd lacks immutable seals",
        ));
    }
    let expected_usize: usize = expected
        .try_into()
        .map_err(|_| RuntimeError::invalid("memfd length exceeds usize"))?;
    let mut bytes = vec![0u8; expected_usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(RuntimeError::rejected(
            "sealed memfd contains bytes beyond preallocation",
        ));
    }
    Ok(bytes)
}

fn poll_fd(fd: RawFd, events: i16, deadline: u64) -> Result<()> {
    loop {
        let now = boottime_now_ns()?;
        if now >= deadline {
            return Err(RuntimeError::unavailable(
                "CLOCK_BOOTTIME transport deadline expired",
            ));
        }
        let remaining_ms = ((deadline - now) / 1_000_000).clamp(1, i32::MAX as u64);
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let status = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining_ms as libc::c_int,
            )
        };
        if status > 0 {
            if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                != 0
            {
                return Err(RuntimeError::unavailable(
                    "transport entered an error state",
                ));
            }
            if descriptor.revents & events != 0 {
                return Ok(());
            }
        } else if status == 0 {
            return Err(RuntimeError::unavailable(
                "CLOCK_BOOTTIME transport deadline expired",
            ));
        } else if std::io::Error::last_os_error().kind()
            != std::io::ErrorKind::Interrupted
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
}

fn require_live(deadline: u64) -> Result<()> {
    if boottime_now_ns()? >= deadline {
        return Err(RuntimeError::unavailable(
            "CLOCK_BOOTTIME deadline expired",
        ));
    }
    Ok(())
}

fn write_all_deadline(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: u64,
) -> Result<()> {
    while !bytes.is_empty() {
        poll_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(RuntimeError::unavailable(
                    "framed service closed during write",
                ))
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: u64,
) -> Result<()> {
    while !bytes.is_empty() {
        poll_fd(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(RuntimeError::unavailable(
                    "framed service closed during read",
                ))
            }
            Ok(count) => {
                let remainder = bytes;
                bytes = &mut remainder[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn connect_stream(
    path: &Path,
    expected_uid: u32,
    deadline: u64,
) -> Result<UnixStream> {
    require_live(deadline)?;
    let stream = UnixStream::connect(path)?;
    stream.set_nonblocking(true)?;
    let peer = peer_cred(stream.as_raw_fd())?;
    if peer.uid != expected_uid {
        return Err(RuntimeError::rejected(format!(
            "service peer UID {} differs from configured UID {expected_uid}",
            peer.uid
        )));
    }
    require_live(deadline)?;
    Ok(stream)
}

fn framed_rpc_exact(
    path: &Path,
    expected_uid: u32,
    exact_request: &[u8],
    deadline: u64,
    maximum_request: usize,
    maximum_response: usize,
) -> Result<Vec<u8>> {
    if exact_request.is_empty() || exact_request.len() > maximum_request {
        return Err(RuntimeError::invalid(
            "framed request is outside its exact byte bound",
        ));
    }
    let mut stream = connect_stream(path, expected_uid, deadline)?;
    let header =
        AuthorityFrameHeaderV12::for_payload(exact_request, deadline, maximum_request)?
            .encode(maximum_request)?;
    write_all_deadline(&mut stream, &header, deadline)?;
    write_all_deadline(&mut stream, exact_request, deadline)?;
    let mut response_header = [0u8; AUTHORITY_FRAME_BYTES];
    read_exact_deadline(&mut stream, &mut response_header, deadline)?;
    let response =
        AuthorityFrameHeaderV12::decode(&response_header, maximum_response)?;
    if response.boottime_deadline_ns > deadline {
        return Err(RuntimeError::rejected(
            "service response widened the caller deadline",
        ));
    }
    let response_len: usize = response
        .payload_bytes
        .try_into()
        .map_err(|_| RuntimeError::invalid("response length exceeds usize"))?;
    let mut bytes = vec![0u8; response_len];
    read_exact_deadline(&mut stream, &mut bytes, deadline)?;
    if sha256_bytes(&bytes) != response.payload_sha256.decode()? {
        return Err(RuntimeError::rejected(
            "service response payload digest mismatch",
        ));
    }
    Ok(bytes)
}

fn framed_rpc_retry<T, R>(
    path: &Path,
    expected_uid: u32,
    request: &T,
    deadline: u64,
    maximum_request: usize,
    maximum_response: usize,
) -> Result<(R, Vec<u8>)>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let request_deadline = AuthorityDeadlineV12::current(deadline, now_unix_ms()?)?;
    authority_rpc_v12(
        path,
        expected_uid,
        request,
        &request_deadline,
        maximum_request,
        maximum_response,
    )
    .map_err(Into::into)
}

fn sealed_seqpacket_rpc<T, R>(
    path: &Path,
    expected_uid: u32,
    request: &T,
    deadline: u64,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let exact = canonical_json(request, MAX_INTERNAL_BYTES)?;
    let payload = create_sealed_memfd("serverware-controller-v12-invocation", &exact)?;
    let socket = connect_seqpacket(path, deadline)?;
    let peer = peer_cred(socket.as_raw_fd())?;
    if peer.uid != expected_uid {
        return Err(RuntimeError::rejected(
            "plan executor peer UID differs from signed generation",
        ));
    }
    let header =
        AuthorityFrameHeaderV12::for_payload(&exact, deadline, MAX_INTERNAL_BYTES)?
            .encode(MAX_INTERNAL_BYTES)?;
    send_fd_packet(
        socket.as_raw_fd(),
        &header,
        payload.as_raw_fd(),
        deadline,
    )?;
    let (response_header, response_fd) =
        receive_fd_packet(socket.as_raw_fd(), AUTHORITY_FRAME_BYTES, deadline)?;
    let response_header: [u8; AUTHORITY_FRAME_BYTES] = response_header
        .try_into()
        .map_err(|_| RuntimeError::invalid("executor frame length changed"))?;
    let response =
        AuthorityFrameHeaderV12::decode(&response_header, MAX_INTERNAL_BYTES)?;
    if response.boottime_deadline_ns > deadline {
        return Err(RuntimeError::rejected(
            "executor response widened the controller deadline",
        ));
    }
    let bytes = read_sealed_memfd(
        response_fd,
        response.payload_bytes,
        MAX_INTERNAL_BYTES as u64,
    )?;
    if sha256_bytes(&bytes) != response.payload_sha256.decode()? {
        return Err(RuntimeError::rejected(
            "executor response payload digest mismatch",
        ));
    }
    parse_canonical_json(&bytes, MAX_INTERNAL_BYTES).map_err(Into::into)
}

fn sealed_executor_seqpacket_rpc<R>(
    path: &Path,
    expected_uid: u32,
    request: &ControllerWorkflowInvocationV12,
    source_input_fd: RawFd,
    lane_proxy_fd: RawFd,
    deadline: u64,
) -> Result<R>
where
    R: DeserializeOwned,
{
    request.validate()?;
    let exact = canonical_json(request, MAX_INTERNAL_BYTES)?;
    let payload = create_sealed_memfd(
        "serverware-controller-v12-executor-invocation",
        &exact,
    )?;
    let socket = connect_seqpacket(path, deadline)?;
    let peer = peer_cred(socket.as_raw_fd())?;
    if peer.uid != expected_uid {
        return Err(RuntimeError::rejected(
            "plan executor peer UID differs from signed generation",
        ));
    }
    let header =
        AuthorityFrameHeaderV12::for_payload(
            &exact,
            deadline,
            MAX_INTERNAL_BYTES,
        )?
        .encode(MAX_INTERNAL_BYTES)?;
    send_fds_packet(
        socket.as_raw_fd(),
        &header,
        &[
            payload.as_raw_fd(),
            source_input_fd,
            lane_proxy_fd,
        ],
        deadline,
    )?;
    let (response_header, response_fd) =
        receive_fd_packet(
            socket.as_raw_fd(),
            AUTHORITY_FRAME_BYTES,
            deadline,
        )?;
    let response_header: [u8; AUTHORITY_FRAME_BYTES] =
        response_header.try_into().map_err(|_| {
            RuntimeError::invalid("executor response frame length changed")
        })?;
    let response = AuthorityFrameHeaderV12::decode(
        &response_header,
        MAX_INTERNAL_BYTES,
    )?;
    if response.boottime_deadline_ns > deadline {
        return Err(RuntimeError::rejected(
            "executor response widened the controller deadline",
        ));
    }
    let bytes = read_sealed_memfd(
        response_fd,
        response.payload_bytes,
        MAX_INTERNAL_BYTES as u64,
    )?;
    if sha256_bytes(&bytes) != response.payload_sha256.decode()? {
        return Err(RuntimeError::rejected(
            "executor response payload digest mismatch",
        ));
    }
    parse_canonical_json(&bytes, MAX_INTERNAL_BYTES).map_err(Into::into)
}

fn lifecycle_rpc(
    context: &ControllerContextV12,
    request: &LifecycleCleanupRequestV12,
) -> Result<LifecycleCleanupResponseV12> {
    loop {
        require_live(request.cleanup_deadline_boottime_ns)?;
        match framed_rpc_retry(
            &context.config.lifecycle_socket,
            context.trust.identities.lifecycle_uid,
            request,
            request.cleanup_deadline_boottime_ns,
            MAX_LIFECYCLE_BYTES,
            MAX_LIFECYCLE_BYTES,
        ) {
            Ok((response, _)) => {
                response.validate_for(request)?;
                verify_lifecycle_cleanup_response_v12(
                    request,
                    &response,
                    context
                        .trust
                        .privileged_root_signer_spki_sha256,
                )?;
                return Ok(response);
            }
            Err(_) => {
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

pub fn run_controller_cli() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(RuntimeError::invalid(
            "usage: serverware-coder-controller-v12 --config ABSOLUTE_PATH",
        ));
    }
    let config_path = PathBuf::from(&arguments[1]);
    require_absolute_path(&config_path, "controller config")?;
    let config = load_controller_config(&config_path)?;
    let trust = load_static_trust(&config)?;
    let listener = SeqpacketListener::activate_or_bind(
        &config.socket_path,
        config.socket_mode,
        trust.identities.client_gid,
    )?;
    drop_to_controller_identity(&trust.identities)?;
    let context = Arc::new(ControllerContextV12 { config, trust });
    persist_generation_high_water(&context)?;
    notify_systemd("READY=1\nSTATUS=controller-v12 accepting canonical request-v11")?;

    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let connection = listener.accept()?;
        let peer = peer_cred(connection.as_raw_fd())?;
        if peer.uid == context.trust.identities.executor_uid
            || peer.uid == context.trust.identities.receipt_authority_uid
            || peer.uid == context.trust.identities.final_verdict_uid
            || peer.uid == context.trust.identities.lifecycle_uid
        {
            continue;
        }
        if active.fetch_add(1, Ordering::AcqRel)
            >= context.config.max_connections
        {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let child_context = Arc::clone(&context);
        let child_active = Arc::clone(&active);
        thread::spawn(move || {
            if let Err(error) =
                handle_controller_connection(&child_context, connection, peer)
            {
                eprintln!("controller-v12 request rejected: {error}");
            }
            child_active.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn drop_to_controller_identity(identities: &IdentityMapV12) -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        let groups = identities
            .controller_supplementary_gids
            .iter()
            .copied()
            .map(libc::gid_t::from)
            .collect::<Vec<_>>();
        if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } != 0
            || unsafe { libc::setgid(identities.controller_gid) } != 0
            || unsafe { libc::setuid(identities.controller_uid) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if unsafe { libc::geteuid() } != identities.controller_uid
        || unsafe { libc::getegid() } != identities.controller_gid
    {
        return Err(RuntimeError::rejected(
            "controller process identity differs from signed generation",
        ));
    }
    Ok(())
}

fn handle_controller_connection(
    context: &ControllerContextV12,
    connection: OwnedFd,
    peer: PeerCred,
) -> Result<()> {
    let first_deadline = boottime_now_ns()?
        .checked_add(5_000_000_000)
        .ok_or_else(|| RuntimeError::invalid("first-frame deadline overflow"))?;
    let ticket_request: TicketRequestV12 =
        receive_seqpacket_json(connection.as_raw_fd(), MAX_TICKET_BYTES, first_deadline)?;
    let ticket = issue_ticket(context, &ticket_request, peer)?;
    send_seqpacket_json(connection.as_raw_fd(), &ticket, first_deadline)?;

    let request_deadline = ticket.execution_deadline_boottime_ns.get()?;
    let (frame_bytes, request_fd) = receive_fd_packet(
        connection.as_raw_fd(),
        FIXED_FRAME_BYTES,
        request_deadline,
    )?;
    if peer_cred(connection.as_raw_fd())?.uid != peer.uid
        || peer_cred(connection.as_raw_fd())?.pid != peer.pid
    {
        return Err(RuntimeError::rejected(
            "controller connection peer changed after ticket issuance",
        ));
    }
    let frame_array: [u8; FIXED_FRAME_BYTES] = frame_bytes
        .clone()
        .try_into()
        .map_err(|_| RuntimeError::invalid("request frame is not 256 bytes"))?;
    let frame = CanonicalPreallocationFrameV11::decode(&frame_array)?;
    if frame.kind != CanonicalFrameKindV11::Request {
        return Err(RuntimeError::rejected(
            "controller ingress accepts only request-v11 frames",
        ));
    }
    let received_wall = now_unix_ms()?;
    let received_boottime = boottime_now_ns()?;
    frame.verify_receive_deadline(received_wall)?;
    let exact_request = read_sealed_memfd(
        request_fd,
        frame.declared_canonical_bytes,
        REQUEST_MAX_BYTES,
    )?;
    let request_key = requester_verifying_key(&context.trust.pins)?;
    let canonical = CanonicalControllerRequestV11::parse_and_verify(
        exact_request.clone(),
        &frame,
        &request_key,
        context
            .trust
            .pins
            .request_v11
            .spki_der_sha256
            .decode()?,
        Some(&ticket.accepted_at),
    )?;
    enforce_ticket_request_join(&ticket_request, &ticket, &canonical)?;
    let admission = build_request_admission(
        context,
        &canonical,
        &frame,
        &frame_bytes,
        &exact_request,
        received_wall,
        received_boottime,
    )?;
    let verified = verify_canonical_request_v11_admission(
        canonical.root(),
        &admission,
        &context.trust.pins,
        true,
    )?;
    if verified.request_deadline_unix_ms
            != ticket.request_deadline_unix_ms.get()?
        || verified.summary.request_v11_sha256
            != canonical_request_v11_digest(&exact_request)
    {
        return Err(RuntimeError::rejected(
            "canonical request does not join its admission ticket",
        ));
    }

    let request_binding = RequestBindingV11 {
        request_id: canonical.request_id_text.clone(),
        replay_identity: context.trust.pins.request_v11.principal_id.clone(),
        boot_id_sha256: boot_id_sha256_v12()?.decode()?,
        request_id_replay_sha256: canonical.request_id,
        nonce_replay_sha256: parse_digest(&h11(
            "replay/nonce",
            &[
                &canonical.requester_key_leaf_sha256,
                &canonical.raw_nonce,
            ],
        ))?,
        exact_request_sha256: canonical_request_sha256(&exact_request),
        request_envelope_sha256: canonical.request_envelope_sha256,
        requester_key_authorization_sha256: parse_digest(
            &verified.trust_observation_sha256,
        )?,
        requester_key_revocation_highwater: context
            .trust
            .pins
            .request_v11
            .revocation_high_water
            .get()?,
        accepted_at_unix_ms: ticket.accepted_at_unix_ms.get()?,
        deadline_boottime_ns: ticket.execution_deadline_boottime_ns.get()?,
    };
    request_binding.validate()?;
    let admission_sha256 = parse_digest(&request_admission_digest(&admission)?)?;
    let mut acceptance = AcceptanceRecordV12 {
        protocol: CONTROLLER_RUNTIME_PROTOCOL_V12.to_owned(),
        state: AcceptanceStateV12::Accepted,
        request: request_binding.clone(),
        workflow_id: context.config.workflow_id.clone(),
        selection: ticket.selection,
        exact_request_base64url: URL_SAFE_NO_PAD.encode(&exact_request),
        exact_preallocation_frame_base64url: URL_SAFE_NO_PAD.encode(&frame_bytes),
        request_admission_sha256: admission_sha256,
        controller_configuration_sha256: context.config.exact_sha256,
        configuration_generation_sha256: context
            .trust
            .identities
            .generation_sha256,
        executor_invocation_sha256: None,
        terminal_evidence_sha256: None,
        exact_receipt_sha256: None,
        record_sha256: [0; 32],
    }
    .seal()?;

    let _replay = ReplayLocks::acquire(
        &context.config.state_root,
        [
            request_binding.request_id_replay_sha256,
            request_binding.nonce_replay_sha256,
        ],
        context.trust.identities.controller_uid,
    )?;
    persist_replay_claims(context, &request_binding)?;
    if let Some(receipt) =
        exact_finalized_retry(context, &acceptance)?
    {
        return send_receipt_reply(
            connection.as_raw_fd(),
            &receipt,
            &context.trust.pins,
            &ticket.verifier_high_water,
            request_deadline,
        );
    }
    persist_acceptance(context, &acceptance, true)?;

    let result = execute_accepted_request(
        context,
        &canonical,
        admission,
        &ticket,
        &mut acceptance,
    );
    match result {
        Ok(receipt) => send_receipt_reply(
            connection.as_raw_fd(),
            &receipt,
            &context.trust.pins,
            &ticket.verifier_high_water,
            ticket.receipt_deadline_boottime_ns.get()?,
        ),
        Err(primary) => {
            let invocation_sha256 = acceptance
                .executor_invocation_sha256
                .unwrap_or_else(|| sha256(primary.to_string().as_bytes()));
            let cleanup = cleanup_request(
                &acceptance.request,
                invocation_sha256,
                acceptance.terminal_evidence_sha256,
                "CONTROLLER_FAILURE",
                ticket.cleanup_deadline_boottime_ns.get()?,
                context.trust.identities.generation_sha256,
                &context.trust.controller_signing_key,
            )
            .and_then(|request| lifecycle_rpc(context, &request));
            match cleanup {
                Ok(_) => Err(primary),
                Err(cleanup_error) => Err(RuntimeError::unavailable(format!(
                    "{primary}; lifecycle reconciliation also failed: {cleanup_error}"
                ))),
            }
        }
    }
}

fn issue_ticket(
    context: &ControllerContextV12,
    request: &TicketRequestV12,
    peer: PeerCred,
) -> Result<AdmissionTicketV12> {
    if request.operation != "REQUEST_ADMISSION_TICKET"
        || request.workflow_id != context.config.workflow_id
        || request.deadline_profile_id != context.config.deadline_profile_id
    {
        return Err(RuntimeError::rejected(
            "ticket request differs from configured workflow",
        ));
    }
    let raw_nonce = URL_SAFE_NO_PAD
        .decode(&request.raw_nonce_base64url)
        .map_err(|_| RuntimeError::invalid("ticket nonce is not base64url"))?;
    if raw_nonce.len() != 32 || raw_nonce.iter().all(|byte| *byte == 0) {
        return Err(RuntimeError::invalid("ticket nonce is not 32 random bytes"));
    }
    let timeout_ms = request.requested_timeout_ms.get()?;
    if timeout_ms == 0 || timeout_ms > MAX_DEADLINE_FUTURE_MS {
        return Err(RuntimeError::rejected(
            "requested workflow timeout is outside the v11 bound",
        ));
    }
    let accepted_ms = now_unix_ms()? / 1000 * 1000;
    let frame_deadline_ms = accepted_ms
        .checked_add(timeout_ms.min(30_000))
        .ok_or_else(|| RuntimeError::invalid("frame deadline overflow"))?;
    let request_deadline_ms = accepted_ms
        .checked_add(timeout_ms)
        .ok_or_else(|| RuntimeError::invalid("request deadline overflow"))?;
    let now_boot = boottime_now_ns()?;
    let execution_deadline = now_boot
        .checked_add(
            timeout_ms
                .checked_mul(1_000_000)
                .ok_or_else(|| RuntimeError::invalid("timeout nanoseconds overflow"))?,
        )
        .ok_or_else(|| RuntimeError::invalid("execution deadline overflow"))?;
    let cleanup_deadline = execution_deadline
        .checked_add(context.config.cleanup_reserve_ns)
        .ok_or_else(|| RuntimeError::invalid("cleanup deadline overflow"))?;
    let receipt_deadline = cleanup_deadline
        .checked_add(context.config.receipt_reserve_ns)
        .ok_or_else(|| RuntimeError::invalid("receipt deadline overflow"))?;
    let high_water = query_high_water(context, receipt_deadline)?;
    let mut ticket = AdmissionTicketV12 {
        operation: "ADMISSION_TICKET".to_owned(),
        workflow_id: request.workflow_id.clone(),
        deadline_profile_id: request.deadline_profile_id.clone(),
        selection: request.selection,
        raw_nonce_sha256: sha256_bytes(&raw_nonce),
        boot_id_sha256: boot_id_sha256_v12()?,
        peer_uid: peer.uid,
        peer_pid: peer.pid,
        accepted_at: format_rfc3339_seconds_v11(accepted_ms)?,
        accepted_at_unix_ms: CanonicalU64::new(accepted_ms),
        frame_deadline: format_rfc3339_seconds_v11(frame_deadline_ms)?,
        frame_deadline_unix_ms: CanonicalU64::new(frame_deadline_ms),
        request_deadline: format_rfc3339_seconds_v11(request_deadline_ms)?,
        request_deadline_unix_ms: CanonicalU64::new(request_deadline_ms),
        execution_deadline_boottime_ns: CanonicalU64::new(execution_deadline),
        cleanup_deadline_boottime_ns: CanonicalU64::new(cleanup_deadline),
        receipt_deadline_boottime_ns: CanonicalU64::new(receipt_deadline),
        controller_configuration_sha256: digest_hex(config_projection_sha256(
            context,
        ))?,
        verifier_high_water: high_water,
        ticket_sha256: DigestHex::zero(),
    };
    ticket.ticket_sha256 = ticket_digest(&ticket)?;
    Ok(ticket)
}

fn ticket_digest(ticket: &AdmissionTicketV12) -> Result<DigestHex> {
    let mut projection = ticket.clone();
    projection.ticket_sha256 = DigestHex::zero();
    let bytes = canonical_json(&projection, MAX_TICKET_BYTES)?;
    Ok(h12("controller-admission-ticket-v12", &[&bytes]))
}

fn config_projection_sha256(context: &ControllerContextV12) -> [u8; 32] {
    sha256(
        &[
            context.config.exact_sha256.as_slice(),
            context.trust.identities.generation_sha256.as_slice(),
            context.trust.workflow_manifest_sha256.as_slice(),
            context.trust.deadline_profile_sha256.as_slice(),
            context.trust.source_ingress_descriptor_sha256.as_slice(),
        ]
        .concat(),
    )
}

fn query_high_water(
    context: &ControllerContextV12,
    deadline: u64,
) -> Result<VerificationHighWaterV12> {
    let nonce = h12(
        "controller-high-water-query",
        &[
            &context.config.exact_sha256,
            &boottime_now_ns()?.to_be_bytes(),
        ],
    );
    let request = LedgerHighWaterRequestV12 {
        operation: "GET_HIGH_WATER".to_owned(),
        request_nonce_sha256: nonce.clone(),
    };
    let (response, _): (LedgerHighWaterResponseV12, Vec<u8>) =
        framed_rpc_retry(
            &context.config.receipt_authority_socket,
            context.trust.identities.receipt_authority_uid,
            &request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        )?;
    if response.operation != "GET_HIGH_WATER"
        || response.request_nonce_sha256 != nonce
    {
        return Err(RuntimeError::rejected(
            "receipt authority high-water response is not query-bound",
        ));
    }
    Ok(response.high_water)
}

fn receive_seqpacket_json<T: DeserializeOwned>(
    fd: RawFd,
    maximum: usize,
    deadline: u64,
) -> Result<T> {
    let header = receive_packet(fd, AUTHORITY_FRAME_BYTES, deadline)?;
    let header: [u8; AUTHORITY_FRAME_BYTES] = header
        .try_into()
        .map_err(|_| RuntimeError::invalid("seqpacket JSON frame is not 32 bytes"))?;
    let header = AuthorityFrameHeaderV12::decode(&header, maximum)?;
    let body = receive_packet(
        fd,
        header
            .payload_bytes
            .try_into()
            .map_err(|_| RuntimeError::invalid("seqpacket JSON length exceeds usize"))?,
        deadline,
    )?;
    if body.len() as u64 != header.payload_bytes {
        return Err(RuntimeError::rejected(
            "seqpacket JSON body differs from preallocation",
        ));
    }
    if sha256_bytes(&body) != header.payload_sha256.decode()? {
        return Err(RuntimeError::rejected(
            "seqpacket JSON payload digest mismatch",
        ));
    }
    parse_canonical_json(&body, maximum).map_err(Into::into)
}

fn send_seqpacket_json<T: Serialize>(
    fd: RawFd,
    value: &T,
    deadline: u64,
) -> Result<()> {
    let bytes = canonical_json(value, MAX_TICKET_BYTES)?;
    let header =
        AuthorityFrameHeaderV12::for_payload(&bytes, deadline, MAX_TICKET_BYTES)?
            .encode(MAX_TICKET_BYTES)?;
    send_packet(fd, &header, deadline)?;
    send_packet(fd, &bytes, deadline)
}

fn requester_verifying_key(pins: &StrictVerifierPinsV12) -> Result<VerifyingKey> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&pins.request_v11.verifying_key_base64url)
        .map_err(|_| RuntimeError::invalid("requester pin key is not base64url"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RuntimeError::invalid("requester pin key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|error| RuntimeError::rejected(error.to_string()))?;
    if crate::receipt_contract_v12::ed25519_spki_sha256(&key)
        != pins.request_v11.spki_der_sha256
    {
        return Err(RuntimeError::rejected(
            "requester pin public key differs from its SPKI digest",
        ));
    }
    Ok(key)
}

fn enforce_ticket_request_join(
    request: &TicketRequestV12,
    ticket: &AdmissionTicketV12,
    canonical: &CanonicalControllerRequestV11,
) -> Result<()> {
    if ticket_digest(ticket)? != ticket.ticket_sha256
        || ticket.boot_id_sha256 != boot_id_sha256_v12()?
        || request.workflow_id != ticket.workflow_id
        || request.deadline_profile_id != ticket.deadline_profile_id
        || request.selection != ticket.selection
        || ticket.raw_nonce_sha256 != sha256_bytes(&canonical.raw_nonce)
        || canonical.deadline_unix_ms != ticket.request_deadline_unix_ms.get()?
    {
        return Err(RuntimeError::rejected(
            "canonical request differs from the issued admission ticket",
        ));
    }
    let selected = match canonical.lane.plan {
        Plan::Build => WorkflowSelectionV12::Build,
        Plan::UnitNoBuild => WorkflowSelectionV12::UnitNoBuild,
        Plan::IntegrationNoBuild => WorkflowSelectionV12::IntegrationNoBuild,
        Plan::E2eNoBuild => WorkflowSelectionV12::E2eNoBuild,
        Plan::AttestationNoBuild => WorkflowSelectionV12::AttestationNoBuild,
    };
    if ticket.selection != WorkflowSelectionV12::FullWorkflow
        && ticket.selection != selected
    {
        return Err(RuntimeError::rejected(
            "request-v11 selected stage differs from fixed v12 selection",
        ));
    }
    if ticket.selection == WorkflowSelectionV12::FullWorkflow
        && canonical.lane.plan != Plan::Build
    {
        return Err(RuntimeError::rejected(
            "full workflow admission must be rooted in the build request",
        ));
    }
    Ok(())
}

fn build_request_admission(
    context: &ControllerContextV12,
    canonical: &CanonicalControllerRequestV11,
    frame: &CanonicalPreallocationFrameV11,
    frame_bytes: &[u8],
    exact_request: &[u8],
    received_wall: u64,
    received_boottime: u64,
) -> Result<CanonicalRequestAdmissionV12> {
    let summary = extract_request_v11_summary(canonical.root())?;
    let requester_authorization =
        requester_authorization_digest(&context.trust.pins)?;
    let verifier_profile = h12(
        "canonical-v11-verifier-profile",
        &[
            &context.trust.pins.request_v11.schema_sha256.decode()?,
            b"fixed-preallocation-frame;exact-canonical-request;request-envelope;replay-identity;trusted-receive;absolute-deadline;current-requester-authorization;current-requester-non-revocation;authority-snapshot;plan-root;final-checkpoint;immutable-evidence;state-quorum;state-epoch-floor;witness-admin;bounded-retrieval;atomic-replay-cas;pipeline-continuity",
        ],
    );
    let configuration = digest_hex(config_projection_sha256(context))?;
    let relationships = h12(
        "canonical-v11-verified-relationships",
        &[
            &summary.request_v11_sha256.decode()?,
            &summary.request_envelope_sha256.decode()?,
            &requester_authorization.decode()?,
            &verifier_profile.decode()?,
            &configuration.decode()?,
        ],
    );
    let accepted_at = canonical.accepted_at.clone();
    let payload = crate::receipt_contract_v12::TrustedReceivePayloadV12 {
        request_v11_sha256: summary.request_v11_sha256,
        request_envelope_sha256: summary.request_envelope_sha256,
        request_canonical_bytes: summary.request_canonical_bytes,
        preallocation_frame_sha256: digest_hex(frame.frame_sha256)?,
        frame_received_at_unix_ms: CanonicalU64::new(received_wall),
        frame_received_boottime_ns: CanonicalU64::new(received_boottime),
        boot_id_sha256: boot_id_sha256_v12()?,
        request_deadline_unix_ms: CanonicalU64::new(canonical.deadline_unix_ms),
        requester_key_leaf_sha256: context
            .trust
            .pins
            .request_v11
            .key_leaf_sha256
            .clone(),
        requester_authorization_sha256: requester_authorization,
        requester_authorization_high_water: context
            .trust
            .pins
            .request_v11
            .authorization_high_water
            .clone(),
        requester_revocation_high_water: context
            .trust
            .pins
            .request_v11
            .revocation_high_water
            .clone(),
        canonical_verifier_profile_sha256: verifier_profile,
        verified_relationships_sha256: relationships,
        controller_configuration_sha256: configuration,
        accepted_at,
    };
    let observed_at = now_utc_rfc3339()?;
    let envelope = sign_envelope(
        CONTROLLER_RECEIVE_DOMAIN,
        AuthorityRoleV12::ControllerIngress,
        payload,
        context.trust.controller_authorization.clone(),
        &context.trust.controller_signing_key,
        &observed_at,
        &observed_at,
    )?;
    let envelope_sha256 = envelope_digest(&envelope)?;
    let admission = CanonicalRequestAdmissionV12 {
        preallocation_frame_base64url: URL_SAFE_NO_PAD.encode(frame_bytes),
        exact_request_base64url: URL_SAFE_NO_PAD.encode(exact_request),
        trusted_receive_envelope: envelope,
        trusted_receive_envelope_sha256: envelope_sha256,
    };
    request_admission_digest(&admission)?;
    Ok(admission)
}

fn requester_authorization_digest(
    pins: &StrictVerifierPinsV12,
) -> Result<DigestHex> {
    let pin = &pins.request_v11;
    Ok(h12(
        "current-requester-authorization-v11",
        &[
            pin.principal_id.as_bytes(),
            pin.key_id.as_bytes(),
            &pin.key_leaf_sha256.decode()?,
            &pin.trust_root_sha256.decode()?,
            pin.trust_revision.as_str().as_bytes(),
            &pin.non_revocation_root_sha256.decode()?,
            pin.non_revocation_revision.as_str().as_bytes(),
            pin.authorization_high_water.as_str().as_bytes(),
            pin.revocation_high_water.as_str().as_bytes(),
        ],
    ))
}

fn canonical_request_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

fn canonical_request_v11_digest(bytes: &[u8]) -> DigestHex {
    h12("canonical-request-v11", &[bytes])
}

struct ReplayLocks {
    files: Vec<File>,
}

impl ReplayLocks {
    fn acquire(
        root: &Path,
        mut replay_keys: [[u8; 32]; 2],
        owner: u32,
    ) -> Result<Self> {
        ensure_private_directory(root, owner)?;
        let directory = root.join("replay");
        ensure_private_directory(&directory, owner)?;
        replay_keys.sort();
        let mut files = Vec::with_capacity(replay_keys.len());
        for replay_key in replay_keys {
            if replay_key == [0; 32] {
                return Err(RuntimeError::invalid("replay lock key is zero"));
            }
            if files.len() == 1 && replay_keys[0] == replay_keys[1] {
                break;
            }
            let path =
                directory.join(format!("{}.lock", hex::encode(replay_key)));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            files.push(file);
        }
        Ok(Self { files })
    }
}

impl Drop for ReplayLocks {
    fn drop(&mut self) {
        for file in self.files.iter().rev() {
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn persist_replay_claims(
    context: &ControllerContextV12,
    request: &RequestBindingV11,
) -> Result<()> {
    let directory = context.config.state_root.join("replay");
    ensure_private_directory(
        &directory,
        context.trust.identities.controller_uid,
    )?;
    let replay_keys = [
        request.request_id_replay_sha256,
        request.nonce_replay_sha256,
    ];
    for replay_key in replay_keys {
        let path =
            directory.join(format!("{}.claim-v12", hex::encode(replay_key)));
        if path.exists() {
            let retained = read_secure_file(
                &path,
                32,
                Some(context.trust.identities.controller_uid),
                false,
            )?;
            if retained.as_slice()
                != request.exact_request_sha256.as_slice()
            {
                return Err(RuntimeError::rejected(
                    "signed v11 replay key was reused for different exact bytes",
                ));
            }
        }
    }
    for replay_key in replay_keys {
        let path =
            directory.join(format!("{}.claim-v12", hex::encode(replay_key)));
        if !path.exists() {
            atomic_write(
                &path,
                &request.exact_request_sha256,
                context.trust.identities.controller_uid,
            )?;
        }
    }
    Ok(())
}

fn acceptance_path(
    context: &ControllerContextV12,
    request_sha256: &[u8; 32],
) -> PathBuf {
    context
        .config
        .state_root
        .join("acceptance")
        .join(format!("{}.json", hex::encode(request_sha256)))
}

fn receipt_path(
    context: &ControllerContextV12,
    request_sha256: &[u8; 32],
) -> PathBuf {
    context
        .config
        .state_root
        .join("receipts")
        .join(format!("{}.receipt-v12.json", hex::encode(request_sha256)))
}

fn persist_acceptance(
    context: &ControllerContextV12,
    record: &AcceptanceRecordV12,
    allow_absent: bool,
) -> Result<()> {
    record.validate()?;
    let path = acceptance_path(context, &record.request.exact_request_sha256);
    if path.exists() {
        let current_bytes = read_secure_file(
            &path,
            MAX_INTERNAL_BYTES,
            Some(context.trust.identities.controller_uid),
            false,
        )?;
        let current: AcceptanceRecordV12 =
            parse_canonical_json(&current_bytes, MAX_INTERNAL_BYTES)?;
        current.validate()?;
        if current.request.exact_request_sha256
                != record.request.exact_request_sha256
            || current.exact_request_base64url
                != record.exact_request_base64url
            || acceptance_rank(current.state) > acceptance_rank(record.state)
        {
            return Err(RuntimeError::rejected(
                "acceptance replay record conflicts or rolls back",
            ));
        }
    } else if !allow_absent {
        return Err(RuntimeError::rejected(
            "acceptance transition lacks durable ACCEPTED predecessor",
        ));
    }
    let bytes = canonical_json(record, MAX_INTERNAL_BYTES)?;
    atomic_write(
        &path,
        &bytes,
        context.trust.identities.controller_uid,
    )
}

fn acceptance_rank(state: AcceptanceStateV12) -> u8 {
    match state {
        AcceptanceStateV12::Accepted => 0,
        AcceptanceStateV12::Executing => 1,
        AcceptanceStateV12::Terminal => 2,
        AcceptanceStateV12::Finalized => 3,
    }
}

fn exact_finalized_retry(
    context: &ControllerContextV12,
    expected: &AcceptanceRecordV12,
) -> Result<Option<Vec<u8>>> {
    let path = acceptance_path(context, &expected.request.exact_request_sha256);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_secure_file(
        &path,
        MAX_INTERNAL_BYTES,
        Some(context.trust.identities.controller_uid),
        false,
    )?;
    let record: AcceptanceRecordV12 =
        parse_canonical_json(&bytes, MAX_INTERNAL_BYTES)?;
    record.validate()?;
    if record.exact_request_base64url != expected.exact_request_base64url
        || record.request.exact_request_sha256
            != expected.request.exact_request_sha256
    {
        return Err(RuntimeError::rejected(
            "replay identity was reused for different exact request bytes",
        ));
    }
    if record.state != AcceptanceStateV12::Finalized {
        return Err(RuntimeError::unavailable(
            "accepted request is pending durable reconciliation",
        ));
    }
    let receipt = read_secure_file(
        &receipt_path(context, &expected.request.exact_request_sha256),
        MAX_RECEIPT_BYTES,
        Some(context.trust.identities.controller_uid),
        false,
    )?;
    if sha256(&receipt)
        != record
            .exact_receipt_sha256
            .ok_or_else(|| RuntimeError::rejected("FINALIZED record lacks receipt digest"))?
    {
        return Err(RuntimeError::rejected(
            "durable exact receipt differs from finalized acceptance",
        ));
    }
    Ok(Some(receipt))
}

fn resolve_executor_invocation(
    context: &ControllerContextV12,
    canonical: &CanonicalControllerRequestV11,
    ticket: &AdmissionTicketV12,
    acceptance: &AcceptanceRecordV12,
    invocation_id: String,
) -> Result<ResolvedControllerExecutorInvocationV12> {
    let inputs_bytes = read_secure_file(
        &context.config.executor_invocation_inputs,
        MAX_INTERNAL_BYTES,
        Some(0),
        false,
    )?;
    let inputs: ExecutorInvocationInputsV12 =
        parse_canonical_json(&inputs_bytes, MAX_INTERNAL_BYTES)?;
    if inputs.version
        != "serverware/controller-executor-inputs/v12"
        || inputs.logical_plan_template.plan_id != [0; 32]
        || inputs.logical_plan_template.boot_id_sha256 != [0; 32]
        || inputs.logical_plan_template.deadline_boottime_ns != 0
        || inputs.logical_plan_template.plan_sha256 != [0; 32]
        || inputs
            .source_publication_control_template
            .operation_id
            != [0; 32]
        || inputs
            .source_publication_control_template
            .deadline_boottime_ns
            != 0
        || inputs
            .source_publication_control_template
            .cleanup_deadline_boottime_ns
            != 0
        || inputs
            .source_publication_control_template
            .control_sha256
            != [0; 32]
        || inputs
            .artifact_publication_control_template
            .operation_id
            != [0; 32]
        || inputs
            .artifact_publication_control_template
            .deadline_boottime_ns
            != 0
        || inputs
            .artifact_publication_control_template
            .cleanup_deadline_boottime_ns
            != 0
        || inputs
            .artifact_publication_control_template
            .control_sha256
            != [0; 32]
        || inputs.readiness_timeout_ns == 0
    {
        return Err(RuntimeError::rejected(
            "signed executor input template contains runtime authority or non-v12 data",
        ));
    }
    let execution_deadline =
        ticket.execution_deadline_boottime_ns.get()?;
    let cleanup_deadline = ticket.cleanup_deadline_boottime_ns.get()?;
    let readiness_deadline = boottime_now_ns()?
        .checked_add(inputs.readiness_timeout_ns)
        .ok_or_else(|| {
            RuntimeError::invalid("readiness deadline overflow")
        })?;
    if readiness_deadline >= execution_deadline {
        return Err(RuntimeError::rejected(
            "signed readiness timeout consumes the execution deadline",
        ));
    }
    let mut plan = inputs.logical_plan_template.clone();
    plan.plan_id = sha256(
        &[
            b"serverware/controller-plan-id/v12\0".as_slice(),
            acceptance.request.exact_request_sha256.as_slice(),
            context.trust.identities.generation_sha256.as_slice(),
        ]
        .concat(),
    );
    plan.generation_sha256 =
        context.trust.identities.generation_sha256;
    plan.boot_id_sha256 = current_boot_id_sha256()?;
    plan.deadline_boottime_ns = execution_deadline;
    plan.plan_sha256 = canonical_sha256_without_digest(
        &plan,
        |value| value.plan_sha256 = [0; 32],
    )?;
    plan.validate()?;

    let owner_identity_sha256 = sha256(
        &[
            b"serverware/controller-executor-owner/v12\0".as_slice(),
            context.config.exact_sha256.as_slice(),
            &context
                .trust
                .identities
                .controller_uid
                .to_be_bytes(),
        ]
        .concat(),
    );
    let mut source_publication_control =
        inputs.source_publication_control_template.clone();
    source_publication_control.operation_id = sha256(
        &[
            plan.plan_id.as_slice(),
            b"source-publication-v12".as_slice(),
        ]
        .concat(),
    );
    source_publication_control.owner_identity_sha256 =
        owner_identity_sha256;
    source_publication_control.deadline_boottime_ns =
        execution_deadline;
    source_publication_control.cleanup_deadline_boottime_ns =
        cleanup_deadline;
    source_publication_control.control_sha256 = sha256(
        &canonical_plan_bytes(&source_publication_control)?,
    );
    source_publication_control.validate()?;

    let mut artifact_publication_control =
        inputs.artifact_publication_control_template.clone();
    artifact_publication_control.operation_id = sha256(
        &[
            plan.plan_id.as_slice(),
            b"artifact-publication-v12".as_slice(),
        ]
        .concat(),
    );
    artifact_publication_control.owner_identity_sha256 =
        owner_identity_sha256;
    artifact_publication_control.deadline_boottime_ns =
        execution_deadline;
    artifact_publication_control.cleanup_deadline_boottime_ns =
        cleanup_deadline;
    artifact_publication_control.control_sha256 = sha256(
        &canonical_plan_bytes(&artifact_publication_control)?,
    );
    artifact_publication_control.validate()?;

    let trust = ManifestTrustPolicy::new(
        inputs
            .manifest_trust_keys
            .iter()
            .map(|key| AuthorizedManifestKey {
                key_id: key.key_id.clone(),
                public_key: key.public_key,
            })
            .collect(),
    )?;
    inputs
        .source_manifest
        .validate(&source_publication_control, &trust)?;
    if inputs.source_manifest.reference(
        plan.source.sealing_evidence.clone(),
    )? != plan.source
    {
        return Err(RuntimeError::rejected(
            "signed source manifest differs from the pinned logical plan",
        ));
    }
    inputs.readiness_trust_key.validate()?;
    let readiness_key = VerifyingKey::from_bytes(
        &inputs.readiness_trust_key.public_key,
    )
    .map_err(|_| {
        RuntimeError::rejected(
            "readiness trust key is not valid Ed25519",
        )
    })?;
    inputs
        .readiness_fixture
        .validate(
            &ReadinessFixtureTrust {
                key_id: inputs.readiness_trust_key.key_id.clone(),
                key: readiness_key,
            },
            boottime_now_ns()?,
        )
        .map_err(|error| RuntimeError::rejected(error.to_string()))?;

    let source_input =
        open_retained_source_input(&context.config.source_input_root)?;
    let lane_proxy =
        connect_seqpacket(&context.config.lane_proxy_socket, execution_deadline)?;
    let peer = peer_cred(lane_proxy.as_raw_fd())?;
    if peer.uid != context.trust.identities.docker_proxy_uid
        || peer.uid == 0
    {
        return Err(RuntimeError::rejected(
            "lane proxy peer is not the pinned unprivileged proxy identity",
        ));
    }
    let peer_identity_sha256 =
        peer_executable_sha256(peer.pid)?;
    let lane_capability_sha256 = sha256(
        &[
            b"serverware/controller-lane-capability/v12\0".as_slice(),
            plan.plan_sha256.as_slice(),
            acceptance.request.exact_request_sha256.as_slice(),
            peer_identity_sha256.as_slice(),
        ]
        .concat(),
    );
    let envelope = ControllerWorkflowInvocationV12 {
        protocol: CONTROLLER_EXECUTOR_PROTOCOL_V12.to_owned(),
        invocation_id,
        workflow_id: context.config.workflow_id.clone(),
        selection: ticket.selection,
        request: acceptance.request.clone(),
        request_v11: canonical.root().clone(),
        exact_request_base64url:
            acceptance.exact_request_base64url.clone(),
        exact_preallocation_frame_base64url: acceptance
            .exact_preallocation_frame_base64url
            .clone(),
        request_admission_sha256:
            acceptance.request_admission_sha256,
        acceptance_record_sha256: acceptance.record_sha256,
        controller_configuration_sha256:
            config_projection_sha256(context),
        configuration_generation_sha256:
            context.trust.identities.generation_sha256,
        workflow_manifest_sha256:
            context.trust.workflow_manifest_sha256,
        deadline_profile_sha256:
            context.trust.deadline_profile_sha256,
        source_ingress_descriptor_sha256:
            context.trust.source_ingress_descriptor_sha256,
        source_publication_sha256:
            context.trust.source_publication_sha256,
        source_cas_root: path_text(&context.config.source_cas_root)?,
        artifact_cas_root:
            path_text(&context.config.artifact_cas_root)?,
        oci_cas_root: path_text(&context.config.oci_cas_root)?,
        logical_plan: serde_json::to_value(&plan)
            .map_err(|error| RuntimeError::invalid(error.to_string()))?,
        source_manifest: serde_json::to_value(&inputs.source_manifest)
            .map_err(|error| RuntimeError::invalid(error.to_string()))?,
        source_publication_control: serde_json::to_value(
            &source_publication_control,
        )
        .map_err(|error| RuntimeError::invalid(error.to_string()))?,
        artifact_publication_control: serde_json::to_value(
            &artifact_publication_control,
        )
        .map_err(|error| RuntimeError::invalid(error.to_string()))?,
        fd_layout: ExecutorFdLayoutV12::canonical(),
        lane_proxy: ExecutorLaneProxyBindingV12 {
            peer_uid: peer.uid,
            peer_pid: peer.pid,
            peer_identity_sha256,
            capability_sha256: lane_capability_sha256,
        },
        manifest_trust_keys: inputs.manifest_trust_keys,
        readiness_fixture: serde_json::to_value(
            &inputs.readiness_fixture,
        )
        .map_err(|error| RuntimeError::invalid(error.to_string()))?,
        readiness_trust_key: inputs.readiness_trust_key,
        readiness_deadline_boottime_ns: readiness_deadline,
        execution_deadline_boottime_ns: execution_deadline,
        cleanup_deadline_boottime_ns: cleanup_deadline,
        receipt_deadline_boottime_ns:
            ticket.receipt_deadline_boottime_ns.get()?,
        logical_lane_count: 5,
        host_docker_socket_exposed: false,
        repository_body_docker_authority: false,
        integration_endpoints_only: true,
        e2e_endpoints_only: true,
        invocation_sha256: [0; 32],
    }
    .seal()?;
    Ok(ResolvedControllerExecutorInvocationV12 {
        envelope,
        source_input,
        lane_proxy,
    })
}

fn open_retained_source_input(path: &Path) -> Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        RuntimeError::invalid("source input path contains NUL")
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
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let metadata = fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(RuntimeError::rejected(
            "source input descriptor is not a root-owned immutable directory",
        ));
    }
    Ok(fd)
}

fn peer_executable_sha256(pid: u32) -> Result<[u8; 32]> {
    let path = CString::new(format!("/proc/{pid}/exe"))
        .map_err(|_| RuntimeError::invalid("peer executable path contains NUL"))?;
    let raw = unsafe {
        libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024 * 1024
    {
        return Err(RuntimeError::rejected(
            "lane proxy executable metadata is outside the trusted bound",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&hasher.finalize());
    Ok(digest)
}

fn execute_accepted_request(
    context: &ControllerContextV12,
    canonical: &CanonicalControllerRequestV11,
    admission: CanonicalRequestAdmissionV12,
    ticket: &AdmissionTicketV12,
    acceptance: &mut AcceptanceRecordV12,
) -> Result<Vec<u8>> {
    let invocation_id = format!(
        "invocation-{}",
        hex::encode(acceptance.request.exact_request_sha256),
    );
    let resolved = resolve_executor_invocation(
        context,
        canonical,
        ticket,
        acceptance,
        invocation_id,
    )?;
    let invocation = &resolved.envelope;
    acceptance.state = AcceptanceStateV12::Executing;
    acceptance.executor_invocation_sha256 = Some(invocation.invocation_sha256);
    acceptance.record_sha256 = [0; 32];
    *acceptance = acceptance.clone().seal()?;
    persist_acceptance(context, acceptance, false)?;

    let executor_result: Result<ExecutorTerminalEvidenceV12> =
        sealed_executor_seqpacket_rpc(
            &context.config.executor_socket,
            context.trust.identities.executor_uid,
            invocation,
            resolved.source_input.as_raw_fd(),
            resolved.lane_proxy.as_raw_fd(),
            invocation.cleanup_deadline_boottime_ns,
        );
    let executor = match executor_result {
        Ok(evidence) => {
            evidence.validate_for(invocation)?;
            evidence
        }
        Err(error) => synthetic_executor_failure(invocation, &error)?,
    };
    let reason = executor
        .failure_code
        .clone()
        .unwrap_or_else(|| "WORKFLOW_TERMINAL".to_owned());
    let cleanup_request = cleanup_request(
        &acceptance.request,
        invocation.invocation_sha256,
        Some(executor.evidence_sha256),
        &reason,
        invocation.cleanup_deadline_boottime_ns,
        context.trust.identities.generation_sha256,
        &context.trust.controller_signing_key,
    )?;
    let cleanup = lifecycle_rpc(context, &cleanup_request)?;
    cleanup.validate_for(&cleanup_request)?;

    let terminal_evidence = h12(
        "controller-terminal-evidence-v12",
        &[
            &executor.terminal_evidence_root_sha256,
            &cleanup.destruction.cleanup_terminal_sha256,
            &cleanup.response_sha256,
        ],
    );
    let terminal_state = h12(
        "controller-terminal-state-v12",
        &[
            &executor.terminal_state_root_sha256,
            &cleanup.destruction.lane_generation_sha256,
            &cleanup.destruction.acceptance_revoked_sha256,
        ],
    );
    let combined_terminal_sha256 = parse_digest(&h12(
        "controller-terminal-complete-v12",
        &[
            &terminal_evidence.decode()?,
            &terminal_state.decode()?,
            &executor.execution_result_sha256,
        ],
    ))?;
    acceptance.state = AcceptanceStateV12::Terminal;
    acceptance.terminal_evidence_sha256 = Some(combined_terminal_sha256);
    acceptance.record_sha256 = [0; 32];
    *acceptance = acceptance.clone().seal()?;
    persist_acceptance(context, acceptance, false)?;

    let receipt = finalize_receipt(
        context,
        canonical.root(),
        admission,
        ticket,
        &executor,
        terminal_evidence,
        terminal_state,
    )?;
    let receipt_digest = sha256(&receipt);
    let receipt_file =
        receipt_path(context, &acceptance.request.exact_request_sha256);
    let receipt_parent = receipt_file
        .parent()
        .ok_or_else(|| RuntimeError::invalid("receipt path has no parent"))?;
    ensure_private_directory(
        receipt_parent,
        context.trust.identities.controller_uid,
    )?;
    atomic_write(
        &receipt_file,
        &receipt,
        context.trust.identities.controller_uid,
    )?;
    acceptance.state = AcceptanceStateV12::Finalized;
    acceptance.exact_receipt_sha256 = Some(receipt_digest);
    acceptance.record_sha256 = [0; 32];
    *acceptance = acceptance.clone().seal()?;
    persist_acceptance(context, acceptance, false)?;
    Ok(receipt)
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| RuntimeError::invalid("configured path is not UTF-8"))
}

fn synthetic_executor_failure(
    invocation: &ControllerWorkflowInvocationV12,
    error: &RuntimeError,
) -> Result<ExecutorTerminalEvidenceV12> {
    let exact = error.to_string().into_bytes();
    let error_sha = sha256(&exact);
    let source = SourceSeal {
        snapshot_id: format!(
            "source-{}",
            hex::encode(invocation.source_publication_sha256),
        ),
        manifest_sha256: invocation.source_ingress_descriptor_sha256,
        canonical_bundle_sha256: invocation.source_publication_sha256,
        source_root_sha256: invocation.source_publication_sha256,
        immutable_object_sha256: invocation.source_publication_sha256,
    };
    let mut evidence = ExecutorTerminalEvidenceV12 {
        protocol: CONTROLLER_EXECUTOR_PROTOCOL_V12.to_owned(),
        invocation_sha256: invocation.invocation_sha256,
        request_sha256: invocation.request.exact_request_sha256,
        terminal_evidence_root_sha256: sha256(
            &[b"executor-unavailable".as_slice(), &error_sha].concat(),
        ),
        terminal_state_root_sha256: sha256(
            &[b"executor-state-unknown".as_slice(), &error_sha].concat(),
        ),
        execution_result_sha256: error_sha,
        source,
        artifacts: None,
        lanes: Vec::new(),
        verdict: TerminalVerdict::Unknown,
        failure_code: Some("EXECUTOR_UNAVAILABLE".to_owned()),
        executor_exact_evidence_base64url: URL_SAFE_NO_PAD.encode(&exact),
        executor_exact_evidence_sha256: error_sha,
        completed_at_boottime_ns: boottime_now_ns()?,
        evidence_sha256: [0; 32],
    };
    let mut projection = evidence.clone();
    projection.evidence_sha256 = [0; 32];
    evidence.evidence_sha256 = sha256(
        &serde_json::to_vec(&projection)
            .map_err(|_| RuntimeError::invalid("synthetic evidence is not serializable"))?,
    );
    evidence.validate_for(invocation)?;
    Ok(evidence)
}

fn cleanup_request(
    request: &RequestBindingV11,
    invocation_sha256: [u8; 32],
    executor_evidence_sha256: Option<[u8; 32]>,
    reason: &str,
    cleanup_deadline: u64,
    configuration_generation_sha256: [u8; 32],
    controller_signing_key: &SigningKey,
) -> Result<LifecycleCleanupRequestV12> {
    let plan_id = sha256(
        &[
            b"serverware/controller-plan-id/v12\0".as_slice(),
            request.exact_request_sha256.as_slice(),
            configuration_generation_sha256.as_slice(),
        ]
        .concat(),
    );
    LifecycleCleanupRequestV12 {
        protocol: CONTROLLER_LIFECYCLE_PROTOCOL_V12.to_owned(),
        operation: "DESTROY_AND_RECONCILE".to_owned(),
        invocation_sha256,
        request_sha256: request.exact_request_sha256,
        plan_id,
        configuration_generation_sha256,
        executor_evidence_sha256,
        reason_code: reason.to_owned(),
        boot_id_sha256: request.boot_id_sha256,
        cleanup_deadline_boottime_ns: cleanup_deadline,
        idempotency_key_sha256: sha256(
            &[
                request.exact_request_sha256.as_slice(),
                invocation_sha256.as_slice(),
                b"destroy-and-reconcile-v12",
            ]
            .concat(),
        ),
        controller_signer_spki_sha256: [0; 32],
        controller_signer_public_key_spki_der: Vec::new(),
        controller_signature: Vec::new(),
        request_sha256_canonical: [0; 32],
    }
    .seal(controller_signing_key)
    .map_err(Into::into)
}

fn finalize_receipt(
    context: &ControllerContextV12,
    request_v11: &Value,
    admission: CanonicalRequestAdmissionV12,
    ticket: &AdmissionTicketV12,
    executor: &ExecutorTerminalEvidenceV12,
    terminal_evidence: DigestHex,
    terminal_state: DigestHex,
) -> Result<Vec<u8>> {
    let deadline = ticket.receipt_deadline_boottime_ns.get()?;
    require_live(deadline)?;
    let summary = extract_request_v11_summary(request_v11)?;
    let replay_identity = ReplayIdentityV12 {
        replay_namespace: "serverware/controller-receipt/v12".to_owned(),
        replay_key: format!(
            "{}:{}",
            context.trust.pins.request_v11.principal_id,
            summary.request_v11_sha256,
        ),
        replay_key_sha256: DigestHex::zero(),
    };
    let replay_identity = ReplayIdentityV12 {
        replay_key_sha256: h12(
            "replay-identity",
            &[
                replay_identity.replay_namespace.as_bytes(),
                replay_identity.replay_key.as_bytes(),
            ],
        ),
        ..replay_identity
    };
    crate::receipt_contract_v12::replay_identity_digest(&replay_identity)?;
    let receipt_id = format!("receipt-{}", summary.request_v11_sha256);
    let verdict = match executor.verdict {
        TerminalVerdict::Pass => VerdictV12::Pass,
        TerminalVerdict::Fail => VerdictV12::Fail,
        TerminalVerdict::Unknown => VerdictV12::Unknown,
        TerminalVerdict::Rejected => VerdictV12::Rejected,
    };
    let body_trust = h12(
        "controller-body-trust-v12",
        &[
            &executor.evidence_sha256,
            &context.config.exact_sha256,
            &context.trust.identities.generation_sha256,
        ],
    );
    let body = ReceiptBodyV12 {
        receipt_id: receipt_id.clone(),
        receipt_sequence: CanonicalU64::new(0),
        requester_principal_id: context
            .trust
            .pins
            .request_v11
            .principal_id
            .clone(),
        replay_key_sha256: replay_identity.replay_key_sha256.clone(),
        request_v11_sha256: summary.request_v11_sha256.clone(),
        request_envelope_sha256: summary.request_envelope_sha256.clone(),
        request_canonical_bytes: summary.request_canonical_bytes.clone(),
        terminal_evidence_root_sha256: terminal_evidence,
        terminal_state_root_sha256: terminal_state,
        execution_result_sha256: digest_hex(executor.execution_result_sha256)?,
        verdict,
        body_trust_observation_sha256: body_trust.clone(),
        completed_at: now_utc_rfc3339()?,
    };
    let admission_sha256 = request_admission_digest(&admission)?;
    let submission = receipt_authority_submission_digest(
        &receipt_id,
        &context.trust.pins.request_v11.principal_id,
        &replay_identity,
        &summary,
        &admission_sha256,
        &body,
    )?;
    let authority_deadline = AuthorityDeadlineV12::current(
        deadline,
        ticket.request_deadline_unix_ms.get()?,
    )?;
    let receipt_request = ReceiptAuthorityRequestV12 {
        operation: "AUTHENTICATE_AND_LOG".to_owned(),
        receipt_id: receipt_id.clone(),
        replay_identity: replay_identity.clone(),
        requester_principal_id: context
            .trust
            .pins
            .request_v11
            .principal_id
            .clone(),
        request_admission: admission,
        receipt_body_template: body,
        submission_binding_sha256: submission,
        deadline: authority_deadline.clone(),
    };
    let (receipt_response, _): (ReceiptAuthorityResponseV12, Vec<u8>) =
        framed_rpc_retry(
            &context.config.receipt_authority_socket,
            context.trust.identities.receipt_authority_uid,
            &receipt_request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        )?;
    if receipt_response.operation != "AUTHENTICATE_AND_LOG"
        || !matches!(
            receipt_response.disposition.as_str(),
            "SETTLED" | "EXACT_RETRY"
        )
        || logged_receipt_bundle_digest(&receipt_response.logged_bundle)?
            != receipt_response.logged_bundle_sha256
    {
        return Err(RuntimeError::rejected(
            "receipt authority response is not an exact logged bundle",
        ));
    }
    let logged_bytes =
        canonical_json(&receipt_response.logged_bundle, MAX_RECEIPT_BYTES)?;
    let logged = verify_logged_bundle_v12(
        &logged_bytes,
        &context.trust.pins,
        &ticket.verifier_high_water,
    )?;

    let minimum_generation = ticket
        .verifier_high_water
        .trust_generation_sequence
        .get()?
        .max(
            context
                .trust
                .pins
                .minimum_trust_generation_sequence
                .get()?,
        )
        .checked_add(1)
        .ok_or_else(|| RuntimeError::invalid("trust generation sequence exhausted"))?;
    let trust_request = TrustGenerationResolveRequestV12 {
        operation: "RESOLVE_FRESH_TRUST_GENERATION".to_owned(),
        receipt_id: receipt_id.clone(),
        receipt_sequence: receipt_response.logged_bundle.receipt_sequence.clone(),
        replay_key_sha256: replay_identity.replay_key_sha256.clone(),
        logged_bundle_sha256: receipt_response.logged_bundle_sha256.clone(),
        minimum_generation_sequence: CanonicalU64::new(minimum_generation),
        deadline: authority_deadline.clone(),
    };
    let trust_binding = h12(
        "trust-generation-resolve-request",
        &[
            receipt_id.as_bytes(),
            receipt_response
                .logged_bundle
                .receipt_sequence
                .as_str()
                .as_bytes(),
            &replay_identity.replay_key_sha256.decode()?,
            &receipt_response.logged_bundle_sha256.decode()?,
            CanonicalU64::new(minimum_generation)
                .as_str()
                .as_bytes(),
        ],
    );
    let (trust_response, _): (TrustGenerationResolveResponseV12, Vec<u8>) =
        framed_rpc_retry(
            &context.trust.identities.trust_generation_socket,
            context.trust.identities.trust_generation_uid,
            &trust_request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        )?;
    if trust_response.operation != "RESOLVE_FRESH_TRUST_GENERATION"
        || trust_response.request_binding_sha256 != trust_binding
    {
        return Err(RuntimeError::rejected(
            "trust-generation response is not exact-request-bound",
        ));
    }
    verify_trust_generation_bundle(
        &trust_response.trust_generation,
        &context.trust.pins,
        &ticket.verifier_high_water,
        true,
    )?;
    let trust_generation_sha256 =
        trust_generation_bundle_digest(&trust_response.trust_generation)?;

    let witness_request = WitnessFinalizationRequestV12 {
        operation: "WITNESS_FINALIZATION".to_owned(),
        logged_bundle_sha256: receipt_response.logged_bundle_sha256.clone(),
        signed_tree_head: receipt_response.logged_bundle.signed_tree_head.clone(),
        trust_generation_envelope_sha256: trust_response
            .trust_generation
            .generation_envelope_sha256
            .clone(),
        deadline: authority_deadline.clone(),
    };
    let witness_binding = h12(
        "witness-finalization-request",
        &[
            &receipt_response.logged_bundle_sha256.decode()?,
            &receipt_response
                .logged_bundle
                .signed_tree_head_envelope_sha256
                .decode()?,
            &trust_response
                .trust_generation
                .generation_envelope_sha256
                .decode()?,
        ],
    );
    let (witness_response, _): (WitnessFinalizationResponseV12, Vec<u8>) =
        framed_rpc_retry(
            &context.trust.identities.external_witness_socket,
            context.trust.identities.external_witness_uid,
            &witness_request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        )?;
    if witness_response.operation != "WITNESS_FINALIZATION"
        || witness_response.request_binding_sha256 != witness_binding
    {
        return Err(RuntimeError::rejected(
            "external witness response is not exact-request-bound",
        ));
    }
    let witness_sha256 =
        envelope_digest(&witness_response.external_witness_checkpoint)?;
    let observed_at = now_utc_rfc3339()?;
    let trust_observation = build_final_trust_observation(
        trust_response.trust_generation.clone(),
        &context.trust.pins,
        &ticket.verifier_high_water,
        logged.request.trust_observation_sha256.clone(),
        body_trust,
        receipt_response
            .logged_bundle
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sha256.clone(),
        observed_at,
    )?;
    if trust_observation.trust_generation_envelope_sha256
        != trust_response
            .trust_generation
            .generation_envelope_sha256
        || trust_generation_sha256 == DigestHex::zero()
    {
        return Err(RuntimeError::rejected(
            "final trust observation differs from resolved generation",
        ));
    }
    let trust_observation_sha256 =
        final_trust_observation_digest(&trust_observation)?;
    let finalization_binding = finalization_binding_digest(
        &receipt_response.logged_bundle_sha256,
        &witness_sha256,
        &trust_observation_sha256,
        verdict,
    )?;
    let final_request = FinalVerdictAuthorityRequestV12 {
        operation: "FINALIZE".to_owned(),
        logged_bundle: receipt_response.logged_bundle,
        logged_bundle_sha256: receipt_response.logged_bundle_sha256,
        external_witness_checkpoint: witness_response
            .external_witness_checkpoint,
        final_trust_observation: trust_observation,
        requested_verdict: verdict,
        expected_finalization_binding_sha256: finalization_binding.clone(),
        deadline: authority_deadline,
    };
    let final_response: Result<(FinalVerdictAuthorityResponseV12, Vec<u8>)> =
        framed_rpc_retry(
            &context.config.final_verdict_socket,
            context.trust.identities.final_verdict_uid,
            &final_request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        );
    let signed_receipt = match final_response {
        Ok((response, _))
            if response.operation == "FINALIZE"
                && matches!(response.disposition.as_str(), "SIGNED" | "EXACT_RETRY") =>
        {
            Some(response.receipt)
        }
        Ok(_) => {
            return Err(RuntimeError::rejected(
                "final-verdict authority returned an invalid disposition",
            ))
        }
        Err(_) => None,
    };
    let artifact = recover_finalized_artifact(
        context,
        &replay_identity.replay_key_sha256,
        &finalization_binding,
        deadline,
    )?;
    let settled_high_water = verify_final_settlement_artifact_v12(
        &artifact,
        &context.trust.pins,
        &ticket.verifier_high_water,
    )?;
    let receipt = artifact.receipt.ok_or_else(|| {
        RuntimeError::unavailable(
            "finalized settlement does not contain an exact receipt",
        )
    })?;
    if signed_receipt
        .as_ref()
        .is_some_and(|signed| signed != &receipt)
    {
        return Err(RuntimeError::rejected(
            "final-verdict response differs from durable settlement",
        ));
    }
    let exact_receipt = canonical_json(&receipt, MAX_RECEIPT_BYTES)?;
    let verified = verify_receipt_v12(
        &exact_receipt,
        &context.trust.pins,
        &ticket.verifier_high_water,
    )?;
    if verified.receipt.request_v11_sha256 != summary.request_v11_sha256
        || verified.receipt.request_admission_sha256 != admission_sha256
        || verified.receipt.receipt_body.verdict != verdict
    {
        return Err(RuntimeError::rejected(
            "final receipt is not exact-request and terminal-verdict bound",
        ));
    }
    let current = query_high_water(context, deadline)?;
    require_current_high_water(&current, &settled_high_water)?;
    Ok(exact_receipt)
}

fn authority_request_binding<T: Serialize>(request: &T) -> Result<DigestHex> {
    let bytes = canonical_json(request, MAX_AUTHORITY_REQUEST_BYTES)?;
    Ok(h12("authority-exact-request-binding-v12", &[&bytes]))
}

fn recover_finalized_artifact(
    context: &ControllerContextV12,
    replay_key_sha256: &DigestHex,
    finalization_binding_sha256: &DigestHex,
    deadline: u64,
) -> Result<FinalSettlementArtifactV12> {
    loop {
        require_live(deadline)?;
        let request = FinalizedLookupRequestV12 {
            operation: "GET_FINALIZED".to_owned(),
            replay_key_sha256: replay_key_sha256.clone(),
            finalization_binding_sha256: finalization_binding_sha256.clone(),
        };
        let response = framed_rpc_retry::<_, FinalizedLookupResponseV12>(
            &context.config.receipt_authority_socket,
            context.trust.identities.receipt_authority_uid,
            &request,
            deadline,
            MAX_AUTHORITY_REQUEST_BYTES,
            MAX_AUTHORITY_RESPONSE_BYTES,
        );
        if let Ok((response, _)) = response {
            if response.operation != "GET_FINALIZED"
                || response.replay_key_sha256 != *replay_key_sha256
                || response.finalization_binding_sha256
                    != *finalization_binding_sha256
            {
                return Err(RuntimeError::rejected(
                    "finalized lookup response is not request-bound",
                ));
            }
            match (response.disposition.as_str(), response.artifact) {
                ("FOUND", Some(artifact)) => return Ok(artifact),
                ("PENDING", None) => {}
                _ => {
                    return Err(RuntimeError::rejected(
                        "finalized lookup response has an invalid disposition",
                    ))
                }
            }
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn require_current_high_water(
    current: &VerificationHighWaterV12,
    expected: &VerificationHighWaterV12,
) -> Result<()> {
    if !high_water_dominates(current, expected)? {
        return Err(RuntimeError::rejected(
            "current receipt/trust high-water does not dominate the verified final receipt",
        ));
    }
    Ok(())
}

fn high_water_dominates(
    candidate: &VerificationHighWaterV12,
    baseline: &VerificationHighWaterV12,
) -> Result<bool> {
    let candidate_receipt = candidate.receipt_sequence.get()?;
    let baseline_receipt = baseline.receipt_sequence.get()?;
    let candidate_tree = candidate.tree_size.get()?;
    let baseline_tree = baseline.tree_size.get()?;
    let candidate_witness = candidate.witness_sequence.get()?;
    let baseline_witness = baseline.witness_sequence.get()?;
    let candidate_settlement = candidate.settlement_sequence.get()?;
    let baseline_settlement = baseline.settlement_sequence.get()?;
    let candidate_generation = candidate.trust_generation_sequence.get()?;
    let baseline_generation = baseline.trust_generation_sequence.get()?;
    Ok(candidate_receipt >= baseline_receipt
        && candidate_tree >= baseline_tree
        && candidate_witness >= baseline_witness
        && candidate_settlement >= baseline_settlement
        && candidate_generation >= baseline_generation
        && candidate.trust_rollback_floor.get()?
            >= baseline.trust_rollback_floor.get()?
        && candidate.authorization_high_water.get()?
            >= baseline.authorization_high_water.get()?
        && candidate.revocation_high_water.get()?
            >= baseline.revocation_high_water.get()?
        && (candidate_receipt != baseline_receipt
            || candidate.receipt_envelope_sha256
                == baseline.receipt_envelope_sha256)
        && (candidate_tree != baseline_tree
            || (candidate.tree_root_sha256 == baseline.tree_root_sha256
                && candidate.signed_tree_head_envelope_sha256
                    == baseline.signed_tree_head_envelope_sha256))
        && (candidate_witness != baseline_witness
            || candidate.witness_checkpoint_envelope_sha256
                == baseline.witness_checkpoint_envelope_sha256)
        && (candidate_settlement != baseline_settlement
            || candidate.settlement_checkpoint_envelope_sha256
                == baseline.settlement_checkpoint_envelope_sha256)
        && (candidate_generation != baseline_generation
            || candidate.trust_generation_envelope_sha256
                == baseline.trust_generation_envelope_sha256))
}

fn send_receipt_reply(
    socket: RawFd,
    exact_receipt: &[u8],
    pins: &StrictVerifierPinsV12,
    prior_high_water: &VerificationHighWaterV12,
    deadline: u64,
) -> Result<()> {
    let verified =
        verify_current_or_historical(exact_receipt, pins, prior_high_water)?;
    let reply = ControllerReceiptReplyV12 {
        protocol: CONTROLLER_RUNTIME_PROTOCOL_V12.to_owned(),
        exact_receipt_sha256: sha256_bytes(exact_receipt),
        exact_receipt_bytes: CanonicalU64::new(exact_receipt.len() as u64),
        request_v11_sha256: verified.receipt.request_v11_sha256.clone(),
        receipt_envelope_sha256: verified.receipt.receipt_envelope_sha256.clone(),
        next_high_water: verified.next_high_water,
    };
    send_seqpacket_json(socket, &reply, deadline)?;
    let payload = create_sealed_memfd("serverware-receipt-v12", exact_receipt)?;
    let header =
        AuthorityFrameHeaderV12::for_payload(exact_receipt, deadline, MAX_RECEIPT_BYTES)?
            .encode(MAX_RECEIPT_BYTES)?;
    send_fd_packet(socket, &header, payload.as_raw_fd(), deadline)
}

fn verify_current_or_historical(
    exact_receipt: &[u8],
    pins: &StrictVerifierPinsV12,
    current: &VerificationHighWaterV12,
) -> Result<VerifiedReceiptV12> {
    match verify_receipt_v12(exact_receipt, pins, current) {
        Ok(receipt) => Ok(receipt),
        Err(current_error) => {
            let historical = verify_historical_receipt_v12(exact_receipt, pins)
                .map_err(|historical_error| {
                    RuntimeError::rejected(format!(
                        "receipt failed current high-water verification ({current_error}) and historical verification ({historical_error})"
                    ))
                })?;
            if !high_water_dominates(current, &historical.next_high_water)? {
                return Err(RuntimeError::rejected(
                    "historical receipt is ahead of current verifier high-water",
                ));
            }
            Ok(historical)
        }
    }
}

pub fn run_client_cli() -> Result<i32> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (selection, workflow_id, deadline_profile_id) =
        parse_client_arguments(&arguments)?;
    let timeout_ms = client_timeout_ms(selection)?;
    let transport_deadline = boottime_now_ns()?
        .checked_add(
            timeout_ms
                .checked_add(120_000)
                .and_then(|value| value.checked_mul(1_000_000))
                .ok_or_else(|| RuntimeError::invalid("client deadline overflow"))?,
        )
        .ok_or_else(|| RuntimeError::invalid("client deadline overflow"))?;
    require_socket_file(Path::new(DEFAULT_CONTROLLER_SOCKET), 0, 0o660)?;
    let socket = connect_seqpacket(Path::new(DEFAULT_CONTROLLER_SOCKET), transport_deadline)?;
    let controller_peer = peer_cred(socket.as_raw_fd())?;
    if controller_peer.uid == unsafe { libc::geteuid() } {
        return Err(RuntimeError::rejected(
            "controller peer cannot be the untrusted requesting process",
        ));
    }

    let raw_nonce = random_nonce()?;
    let ticket_request = TicketRequestV12 {
        operation: "REQUEST_ADMISSION_TICKET".to_owned(),
        workflow_id,
        deadline_profile_id,
        selection,
        raw_nonce_base64url: URL_SAFE_NO_PAD.encode(raw_nonce),
        requested_timeout_ms: CanonicalU64::new(timeout_ms),
    };
    send_seqpacket_json(socket.as_raw_fd(), &ticket_request, transport_deadline)?;
    let ticket: AdmissionTicketV12 =
        receive_seqpacket_json(socket.as_raw_fd(), MAX_TICKET_BYTES, transport_deadline)?;
    if ticket.operation != "ADMISSION_TICKET"
        || ticket.selection != selection
        || ticket.raw_nonce_sha256 != sha256_bytes(&raw_nonce)
        || ticket.boot_id_sha256 != boot_id_sha256_v12()?
        || ticket.peer_uid != unsafe { libc::geteuid() }
        || ticket.peer_pid != unsafe { libc::getpid() } as u32
        || ticket.ticket_sha256 != ticket_digest(&ticket)?
        || ticket.execution_deadline_boottime_ns.get()? <= boottime_now_ns()?
    {
        return Err(RuntimeError::rejected(
            "controller admission ticket is invalid or request-mismatched",
        ));
    }
    let pins = load_client_pins()?;
    require_ticket_not_rolled_back(&ticket.verifier_high_water)?;
    let signing_key = load_requester_signing_key()?;
    let requester_key = requester_verifying_key(&pins)?;
    if signing_key.verifying_key() != requester_key {
        return Err(RuntimeError::rejected(
            "protected requester signing key differs from current trust pin",
        ));
    }
    let lane = lane_for_selection(selection)?;
    let template = load_request_template(selection)?;
    let built = build_signed_request_from_template_v11(
        &template,
        lane,
        raw_nonce,
        &ticket.accepted_at,
        &ticket.frame_deadline,
        &ticket.request_deadline,
        &signing_key,
        ed25519_spki_der_sha256_v11(&requester_key),
    )?;
    if built.request.deadline_unix_ms != ticket.request_deadline_unix_ms.get()?
        || built.request.raw_nonce != raw_nonce
    {
        return Err(RuntimeError::rejected(
            "locally signed request differs from admission ticket",
        ));
    }
    let exact_request = built.request.exact_bytes();
    let request_payload =
        create_sealed_memfd("serverware-controller-request-v11", exact_request)?;
    let frame = built.frame.encode()?;
    send_fd_packet(
        socket.as_raw_fd(),
        &frame,
        request_payload.as_raw_fd(),
        ticket.execution_deadline_boottime_ns.get()?,
    )?;

    let reply: ControllerReceiptReplyV12 = receive_seqpacket_json(
        socket.as_raw_fd(),
        MAX_TICKET_BYTES,
        ticket.receipt_deadline_boottime_ns.get()?,
    )?;
    let (receipt_header, receipt_fd) = receive_fd_packet(
        socket.as_raw_fd(),
        AUTHORITY_FRAME_BYTES,
        ticket.receipt_deadline_boottime_ns.get()?,
    )?;
    let receipt_header: [u8; AUTHORITY_FRAME_BYTES] = receipt_header
        .try_into()
        .map_err(|_| RuntimeError::invalid("receipt reply header length changed"))?;
    let receipt_header =
        AuthorityFrameHeaderV12::decode(&receipt_header, MAX_RECEIPT_BYTES)?;
    let exact_receipt = read_sealed_memfd(
        receipt_fd,
        receipt_header.payload_bytes,
        MAX_RECEIPT_BYTES as u64,
    )?;
    if reply.protocol != CONTROLLER_RUNTIME_PROTOCOL_V12
        || reply.exact_receipt_bytes.get()? != exact_receipt.len() as u64
        || reply.exact_receipt_sha256 != sha256_bytes(&exact_receipt)
    {
        return Err(RuntimeError::rejected(
            "controller receipt reply metadata differs from exact bytes",
        ));
    }
    let verified = verify_current_or_historical(
        &exact_receipt,
        &pins,
        &ticket.verifier_high_water,
    )?;
    let embedded_request = URL_SAFE_NO_PAD
        .decode(
            &verified
                .receipt
                .request_admission
                .exact_request_base64url,
        )
        .map_err(|_| RuntimeError::rejected("receipt request bytes are not base64url"))?;
    let embedded_frame = URL_SAFE_NO_PAD
        .decode(
            &verified
                .receipt
                .request_admission
                .preallocation_frame_base64url,
        )
        .map_err(|_| RuntimeError::rejected("receipt frame bytes are not base64url"))?;
    if embedded_request != exact_request
        || embedded_frame != frame
        || verified.receipt.request_v11_sha256
            != canonical_request_v11_digest(exact_request)
        || reply.request_v11_sha256 != verified.receipt.request_v11_sha256
        || reply.receipt_envelope_sha256
            != verified.receipt.receipt_envelope_sha256
        || reply.next_high_water != verified.next_high_water
    {
        return Err(RuntimeError::rejected(
            "strict receipt verification did not join the submitted exact request",
        ));
    }
    let retained_high_water = if high_water_dominates(
        &ticket.verifier_high_water,
        &verified.next_high_water,
    )? {
        &ticket.verifier_high_water
    } else if high_water_dominates(
        &verified.next_high_water,
        &ticket.verifier_high_water,
    )? {
        &verified.next_high_water
    } else {
        return Err(RuntimeError::rejected(
            "ticket and receipt verifier high-water snapshots are incomparable",
        ));
    };
    persist_client_high_water(retained_high_water)?;
    Ok(match verified.receipt.receipt_body.verdict {
        VerdictV12::Pass => 0,
        VerdictV12::Fail | VerdictV12::Rejected => 2,
        VerdictV12::Unknown => 3,
    })
}

fn parse_client_arguments(
    arguments: &[String],
) -> Result<(WorkflowSelectionV12, String, String)> {
    let (command, flags) = arguments
        .split_first()
        .ok_or_else(|| RuntimeError::invalid("client command is absent"))?;
    let mut values = BTreeMap::new();
    for flag in flags {
        let (name, value) = flag
            .strip_prefix("--")
            .and_then(|value| value.split_once('='))
            .ok_or_else(|| RuntimeError::invalid("client flag is not --name=value"))?;
        if values.insert(name, value).is_some() {
            return Err(RuntimeError::invalid("duplicate client flag"));
        }
    }
    let workflow = values
        .remove("workflow")
        .ok_or_else(|| RuntimeError::invalid("--workflow is required"))?
        .to_owned();
    let deadline = values
        .remove("deadline-profile")
        .ok_or_else(|| RuntimeError::invalid("--deadline-profile is required"))?
        .to_owned();
    let selection = match command.as_str() {
        "submit-workflow-v12" if !values.contains_key("lane") => {
            WorkflowSelectionV12::FullWorkflow
        }
        "submit-fixed-v12" => match values
            .remove("lane")
            .ok_or_else(|| RuntimeError::invalid("--lane is required"))?
        {
            "build" => WorkflowSelectionV12::Build,
            "unit" => WorkflowSelectionV12::UnitNoBuild,
            "integration" => WorkflowSelectionV12::IntegrationNoBuild,
            "e2e" => WorkflowSelectionV12::E2eNoBuild,
            "attestation" => WorkflowSelectionV12::AttestationNoBuild,
            _ => return Err(RuntimeError::invalid("client lane is not fixed v12")),
        },
        _ => {
            return Err(RuntimeError::invalid(
                "usage: serverware-coder-controller-client-v12 submit-workflow-v12 --workflow=ID --deadline-profile=ID | submit-fixed-v12 --workflow=ID --lane=build|unit|integration|e2e|attestation --deadline-profile=ID",
            ))
        }
    };
    if !values.is_empty()
        || workflow != "serverware-coder-five-lane-v12"
        || deadline != "serverware-coder-five-lane-v12"
    {
        return Err(RuntimeError::rejected(
            "client workflow flags differ from installed v12 conventions",
        ));
    }
    Ok((selection, workflow, deadline))
}

fn client_timeout_ms(selection: WorkflowSelectionV12) -> Result<u64> {
    let default = match selection {
        WorkflowSelectionV12::FullWorkflow => MAX_DEADLINE_FUTURE_MS,
        WorkflowSelectionV12::Build => 7_200_000,
        WorkflowSelectionV12::UnitNoBuild => 900_000,
        WorkflowSelectionV12::IntegrationNoBuild => 1_800_000,
        WorkflowSelectionV12::E2eNoBuild => 2_700_000,
        WorkflowSelectionV12::AttestationNoBuild => 900_000,
    };
    let value = std::env::var("SERVERWARE_CONTROLLER_DEADLINE_MS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| RuntimeError::invalid("SERVERWARE_CONTROLLER_DEADLINE_MS is invalid"))?
        .unwrap_or(default);
    if value == 0 || value > MAX_DEADLINE_FUTURE_MS {
        return Err(RuntimeError::rejected(
            "client deadline exceeds canonical request-v11 maximum",
        ));
    }
    Ok(value)
}

fn lane_for_selection(selection: WorkflowSelectionV12) -> Result<Lane> {
    let (operation, plan) = match selection {
        WorkflowSelectionV12::FullWorkflow | WorkflowSelectionV12::Build => {
            ("--operation=build", "--plan=serverware-build-v1")
        }
        WorkflowSelectionV12::UnitNoBuild => (
            "--operation=runNoBuild",
            "--plan=serverware-unit-no-build-v1",
        ),
        WorkflowSelectionV12::IntegrationNoBuild => (
            "--operation=runNoBuild",
            "--plan=serverware-integration-no-build-v1",
        ),
        WorkflowSelectionV12::E2eNoBuild => (
            "--operation=runNoBuild",
            "--plan=serverware-e2e-no-build-v1",
        ),
        WorkflowSelectionV12::AttestationNoBuild => (
            "--operation=runNoBuild",
            "--plan=serverware-attestation-no-build-v1",
        ),
    };
    Lane::parse_frozen_flags(operation, plan).map_err(Into::into)
}

fn selection_name(selection: WorkflowSelectionV12) -> &'static str {
    match selection {
        WorkflowSelectionV12::FullWorkflow | WorkflowSelectionV12::Build => "build",
        WorkflowSelectionV12::UnitNoBuild => "unit",
        WorkflowSelectionV12::IntegrationNoBuild => "integration",
        WorkflowSelectionV12::E2eNoBuild => "e2e",
        WorkflowSelectionV12::AttestationNoBuild => "attestation",
    }
}

fn load_request_template(selection: WorkflowSelectionV12) -> Result<Vec<u8>> {
    let path = std::env::var_os("SERVERWARE_CODER_REQUEST_TEMPLATE_V11")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(DEFAULT_RELEASE_ROOT)
                .join("requests")
                .join(format!("{}.request-v11.json", selection_name(selection)))
        });
    read_secure_file(&path, REQUEST_MAX_BYTES as usize, Some(0), false)
}

fn load_client_pins() -> Result<StrictVerifierPinsV12> {
    let path = std::env::var_os("SERVERWARE_CODER_STRICT_PINS_V12")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(DEFAULT_RELEASE_ROOT)
                .join("authorization")
                .join(STRICT_PINS_BASENAME)
        });
    let bytes = read_secure_file(&path, MAX_CONFIG_BYTES, Some(0), false)?;
    let pins = parse_canonical_json(&bytes, MAX_CONFIG_BYTES)?;
    StrictVerifierPinsV12::validate(&pins)?;
    Ok(pins)
}

fn load_requester_signing_key() -> Result<SigningKey> {
    let path = std::env::var_os("SERVERWARE_CODER_REQUESTER_SIGNING_KEY")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .map(|root| root.join("serverware/coder-v12/requester-signing-key.ed25519"))
        })
        .ok_or_else(|| {
            RuntimeError::unavailable(
                "protected requester key path is not configured",
            )
        })?;
    let owner = unsafe { libc::geteuid() };
    let bytes = read_secure_file(&path, 64 * 1024, Some(owner), false)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.mode() & 0o077 != 0 {
        return Err(RuntimeError::rejected(
            "requester signing key is accessible outside its owner",
        ));
    }
    if bytes.len() == 32 {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| RuntimeError::invalid("requester key length changed"))?;
        return Ok(SigningKey::from_bytes(&key));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| RuntimeError::invalid("requester key is not raw or PKCS8 PEM"))?;
    SigningKey::from_pkcs8_pem(text)
        .map_err(|error| RuntimeError::rejected(error.to_string()))
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")?;
    let mut nonce = [0u8; 32];
    file.read_exact(&mut nonce)?;
    if nonce == [0; 32] {
        return Err(RuntimeError::unavailable(
            "kernel random source returned an empty nonce",
        ));
    }
    Ok(nonce)
}

fn client_state_root() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local/state"))
        })
        .ok_or_else(|| RuntimeError::unavailable("client state directory is absent"))?;
    require_absolute_path(&root, "client state root")?;
    Ok(root)
}

fn client_high_water_path() -> Result<PathBuf> {
    Ok(client_state_root()?
        .join("serverware")
        .join("coder-v12")
        .join("verification-high-water.json"))
}

fn require_ticket_not_rolled_back(
    ticket: &VerificationHighWaterV12,
) -> Result<()> {
    let path = client_high_water_path()?;
    if !path.exists() {
        return Ok(());
    }
    let bytes = read_secure_file(
        &path,
        MAX_CONFIG_BYTES,
        Some(unsafe { libc::geteuid() }),
        false,
    )?;
    let local: VerificationHighWaterV12 =
        parse_canonical_json(&bytes, MAX_CONFIG_BYTES)?;
    if !high_water_dominates(ticket, &local)? {
        return Err(RuntimeError::rejected(
            "controller ticket rolls back the client verification high-water",
        ));
    }
    Ok(())
}

fn persist_client_high_water(high_water: &VerificationHighWaterV12) -> Result<()> {
    let owner = unsafe { libc::geteuid() };
    let state_root = client_state_root()?;
    let metadata = fs::symlink_metadata(&state_root)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
    {
        return Err(RuntimeError::rejected(
            "client state root must already exist as an owner-only directory",
        ));
    }
    let serverware = state_root.join("serverware");
    ensure_private_directory(&serverware, owner)?;
    let parent = serverware.join("coder-v12");
    ensure_private_directory(&parent, owner)?;
    let path = parent.join("verification-high-water.json");
    let bytes = canonical_json(high_water, MAX_CONFIG_BYTES)?;
    atomic_write(&path, &bytes, owner)
}

#[derive(Clone)]
struct LifecycleConfigV12 {
    socket_path: PathBuf,
    socket_mode: u32,
    state_root: PathBuf,
    ownership_ledger: PathBuf,
    privileged_socket: PathBuf,
    lifecycle_uid: u32,
    lifecycle_api_gid: u32,
    allowed_peer_uids: BTreeSet<u32>,
    controller_uid: u32,
    docker_proxy_uid: u32,
    configuration_generation_sha256: [u8; 32],
    controller_signer_spki_sha256: [u8; 32],
    privileged_root_signer_spki_sha256: [u8; 32],
    cleanup_reserve_ns: u64,
}

pub fn run_lifecycle_cli() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(RuntimeError::invalid(
            "usage: serverware-coder-lifecycle-v12 --config ABSOLUTE_PATH",
        ));
    }
    if unsafe { libc::geteuid() } == 0 {
        return Err(RuntimeError::rejected(
            "lifecycle-v12 is an unprivileged coordinator, not the root helper",
        ));
    }
    let path = PathBuf::from(&arguments[1]);
    let config = Arc::new(load_lifecycle_config(&path)?);
    if unsafe { libc::geteuid() } != config.lifecycle_uid {
        return Err(RuntimeError::rejected(
            "lifecycle coordinator UID differs from signed generation",
        ));
    }
    ensure_private_directory(&config.state_root, config.lifecycle_uid)?;
    let ledger_parent = config
        .ownership_ledger
        .parent()
        .ok_or_else(|| RuntimeError::invalid("lifecycle ledger has no parent"))?;
    ensure_private_directory(ledger_parent, config.lifecycle_uid)?;
    reconcile_lifecycle_intents(&config)?;
    let listener = bind_lifecycle_listener(&config)?;
    notify_systemd("READY=1\nSTATUS=lifecycle-v12 reconciliation active")?;
    for stream in listener.incoming() {
        let config = Arc::clone(&config);
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || {
                    if let Err(error) =
                        handle_lifecycle_connection(&config, &mut stream)
                    {
                        eprintln!("lifecycle-v12 request rejected: {error}");
                    }
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(RuntimeError::unavailable(
        "lifecycle listener terminated unexpectedly",
    ))
}

fn load_lifecycle_config(path: &Path) -> Result<LifecycleConfigV12> {
    let bytes = read_secure_file(path, MAX_CONFIG_BYTES, Some(0), false)?;
    let values = parse_kv(&bytes)?;
    if required_u64(&values, "contract_version")? != 12
        || required(&values, "mode")? != "unprivileged-coordinator-v12"
        || required(&values, "socket_activation")? != "systemd-listen-fds"
        || required(&values, "startup_reconcile")? != "true"
        || required(&values, "destroy_nonterminal_lanes")? != "true"
        || required(&values, "failure_transition")? != "Destroying"
        || required(&values, "cgroup_kill_required")? != "true"
        || required(&values, "pidfd_reap_required")? != "true"
    {
        return Err(RuntimeError::rejected(
            "lifecycle config permits direct or incomplete cleanup",
        ));
    }
    let configuration_key =
        load_verifying_key(&required_path(&values, "configuration_authority_public_key")?)?;
    let release_key =
        load_verifying_key(&required_path(&values, "release_manifest_public_key")?)?;
    let release_bytes = verify_signed_file(
        &required_path(&values, "release_manifest")?,
        &required_path(&values, "release_manifest_signature")?,
        &release_key,
        MAX_MANIFEST_BYTES,
    )?;
    let generation_path = required_path(&values, "configuration_generation")?;
    let generation_bytes = verify_signed_file(
        &generation_path,
        &required_path(&values, "configuration_generation_signature")?,
        &configuration_key,
        MAX_MANIFEST_BYTES,
    )?;
    let generation = parse_kv(&generation_bytes)?;
    let release = parse_kv(&release_bytes)?;
    let generation_number = required_u64(&generation, "config_generation")?;
    if required_u64(&release, "manifest_version")? != 12
        || required_u64(&release, "config_generation")?
            != generation_number
        || required(&release, "trust_profile")?
            != "trusted-host-userspace-digest-no-ima"
    {
        return Err(RuntimeError::rejected(
            "lifecycle release manifest differs from its signed generation",
        ));
    }
    require_committed_digest(
        &release,
        "config_generation_document_sha256",
        &generation_bytes,
    )?;
    let committed_lifecycle_config = DigestHex::parse(
        required(&release, "lifecycle_config_sha256")?.to_owned(),
    )?;
    if committed_lifecycle_config != sha256_bytes(&bytes) {
        return Err(RuntimeError::rejected(
            "lifecycle config differs from the signed release manifest",
        ));
    }
    let lifecycle_uid = generation_u32(&generation, "identity.lifecycle.uid")?;
    let socket_mode = u32::from_str_radix(required(&values, "socket_mode")?, 8)
        .map_err(|_| RuntimeError::invalid("lifecycle socket_mode is not octal"))?;
    let cleanup_ms = required_u64(&values, "cleanup_deadline_ms")?;
    let allowed_peer_uids = [
        "identity.controller.uid",
        "identity.executor.uid",
        "identity.docker_proxy.uid",
    ]
    .iter()
    .map(|name| generation_u32(&generation, name))
    .collect::<Result<BTreeSet<_>>>()?;
    let docker_proxy_uid =
        generation_u32(&generation, "identity.docker_proxy.uid")?;
    let controller_uid =
        generation_u32(&generation, "identity.controller.uid")?;
    let privileged_root_signer_spki_sha256 = DigestHex::parse(
        required(
            &release,
            "lifecycle_privileged_authority_spki_sha256",
        )?
        .to_owned(),
    )?
    .decode()?;
    if DigestHex::parse(
        required(
            &release,
            "executor_lifecycle_root_signer_spki_sha256",
        )?
        .to_owned(),
    )?
    .decode()?
        != privileged_root_signer_spki_sha256
    {
        return Err(RuntimeError::rejected(
            "signed release executor pin differs from the privileged lifecycle signer",
        ));
    }
    let controller_signer_spki_sha256 = DigestHex::parse(
        required(&release, "controller_identity_spki_sha256")?
            .to_owned(),
    )?
    .decode()?;
    Ok(LifecycleConfigV12 {
        socket_path: required_path(&values, "socket_path")?,
        socket_mode,
        state_root: required_path(&values, "state_root")?,
        ownership_ledger: required_path(&values, "ownership_ledger")?,
        privileged_socket: required_path(&values, "privileged_lifecycle_socket")?,
        lifecycle_uid,
        lifecycle_api_gid: generation_u32(&generation, "group.lifecycle_api.gid")?,
        allowed_peer_uids,
        controller_uid,
        docker_proxy_uid,
        configuration_generation_sha256: sha256_bytes(
            &generation_bytes,
        ),
        controller_signer_spki_sha256,
        privileged_root_signer_spki_sha256,
        cleanup_reserve_ns: cleanup_ms
            .checked_mul(1_000_000)
            .ok_or_else(|| RuntimeError::invalid("lifecycle cleanup reserve overflow"))?,
    })
}

fn bind_lifecycle_listener(config: &LifecycleConfigV12) -> Result<UnixListener> {
    let fd = activated_fd()?.ok_or_else(|| {
        RuntimeError::rejected(
            "lifecycle coordinator requires systemd socket activation",
        )
    })?;
    require_socket_type(fd.as_raw_fd(), libc::SOCK_STREAM)?;
    let metadata = fs::symlink_metadata(&config.socket_path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != config.lifecycle_api_gid
        || metadata.mode() & 0o777 != config.socket_mode
    {
        return Err(RuntimeError::rejected(
            "lifecycle activated socket ownership or mode differs from config",
        ));
    }
    Ok(unsafe { UnixListener::from_raw_fd(fd.into_raw_fd()) })
}

fn handle_lifecycle_connection(
    config: &LifecycleConfigV12,
    stream: &mut UnixStream,
) -> Result<()> {
    let peer = peer_cred(stream.as_raw_fd())?;
    if !config.allowed_peer_uids.contains(&peer.uid) {
        return Err(RuntimeError::rejected(
            "lifecycle peer UID is not authorized",
        ));
    }
    let (request_bytes, deadline, attached_fds) =
        read_framed_request_with_fds(
            stream,
            MAX_LIFECYCLE_BYTES,
            MAX_LIFECYCLE_FDS,
        )?;
    let envelope: Value =
        parse_canonical_json(&request_bytes, MAX_LIFECYCLE_BYTES)?;
    if envelope.get("protocol").and_then(Value::as_str)
        == Some(PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12)
    {
        if peer.uid != config.docker_proxy_uid {
            return Err(RuntimeError::rejected(
                "private DinD lifecycle request did not originate at the Docker proxy UID",
            ));
        }
        let request: DelegatedPrivateDindRequestV12 =
            serde_json::from_value(envelope).map_err(|_| {
                RuntimeError::invalid(
                    "private DinD lifecycle envelope is invalid",
                )
            })?;
        if request.operation != "EXECUTE_LANE_PROXY_REQUEST"
            || request.request_sha256 == [0; 32]
            || request.proxy_request.request_sha256 == [0; 32]
            || request.proxy_request.deadline_boottime_ns != deadline
            || request.attached_fd_roles.len() != attached_fds.len()
        {
            return Err(RuntimeError::rejected(
                "private DinD lifecycle request lost exact FD or deadline binding",
            ));
        }
        let (response, returned_fds) =
            framed_rpc_exact_with_fds(
                &config.privileged_socket,
                0,
                &request_bytes,
                attached_fds,
                deadline,
                MAX_LIFECYCLE_BYTES,
                MAX_LIFECYCLE_BYTES,
                1,
            )?;
        verify_delegated_private_dind_response(
            config,
            &request,
            &response,
            returned_fds.len(),
        )?;
        return write_framed_response_with_fds(
            stream,
            &response,
            returned_fds,
            deadline,
            MAX_LIFECYCLE_BYTES,
        );
    }
    if !attached_fds.is_empty() {
        return Err(RuntimeError::rejected(
            "lifecycle cleanup request carried descriptors",
        ));
    }
    if peer.uid != config.controller_uid {
        return Err(RuntimeError::rejected(
            "plan-scoped lifecycle cleanup did not originate at the controller UID",
        ));
    }
    let request: LifecycleCleanupRequestV12 =
        serde_json::from_value(envelope).map_err(|_| {
            RuntimeError::invalid(
                "lifecycle cleanup envelope is invalid",
            )
        })?;
    request.validate()?;
    if request.cleanup_deadline_boottime_ns != deadline {
        return Err(RuntimeError::rejected(
            "lifecycle frame and cleanup request deadlines differ",
        ));
    }
    let response = settle_lifecycle_intent(config, &request, &request_bytes)?;
    write_framed_response(stream, &response, deadline, MAX_LIFECYCLE_BYTES)
}

fn lifecycle_intent_path(
    config: &LifecycleConfigV12,
    request_sha256: &[u8; 32],
) -> PathBuf {
    config
        .ownership_ledger
        .parent()
        .unwrap_or(&config.state_root)
        .join(format!("{}.intent-v12.json", hex::encode(request_sha256)))
}

fn lifecycle_response_path(
    config: &LifecycleConfigV12,
    request_sha256: &[u8; 32],
) -> PathBuf {
    config
        .ownership_ledger
        .parent()
        .unwrap_or(&config.state_root)
        .join(format!("{}.response-v12.json", hex::encode(request_sha256)))
}

fn settle_lifecycle_intent(
    config: &LifecycleConfigV12,
    request: &LifecycleCleanupRequestV12,
    exact_request: &[u8],
) -> Result<Vec<u8>> {
    if request.boot_id_sha256 != boot_id_sha256_v12()?.decode()? {
        return Err(RuntimeError::rejected(
            "lifecycle intent belongs to a different host boot",
        ));
    }
    let expected_plan_id = sha256_bytes(
        &[
            b"serverware/controller-plan-id/v12\0".as_slice(),
            request.request_sha256.as_slice(),
            request
                .configuration_generation_sha256
                .as_slice(),
        ]
        .concat(),
    );
    if request.configuration_generation_sha256
            != config.configuration_generation_sha256
        || request.controller_signer_spki_sha256
            != config.controller_signer_spki_sha256
        || request.plan_id != expected_plan_id
    {
        return Err(RuntimeError::rejected(
            "lifecycle cleanup lacks exact signed-generation plan authority",
        ));
    }
    let intent_path =
        lifecycle_intent_path(config, &request.request_sha256_canonical);
    let response_path =
        lifecycle_response_path(config, &request.request_sha256_canonical);
    let owner = config.lifecycle_uid;
    if intent_path.exists() {
        let retained = read_secure_file(
            &intent_path,
            MAX_LIFECYCLE_BYTES,
            Some(owner),
            false,
        )?;
        if retained != exact_request {
            return Err(RuntimeError::rejected(
                "lifecycle idempotency key was reused for different exact bytes",
            ));
        }
    } else {
        atomic_write(&intent_path, exact_request, owner)?;
    }
    if response_path.exists() {
        let retained = read_secure_file(
            &response_path,
            MAX_LIFECYCLE_BYTES,
            Some(owner),
            false,
        )?;
        let response: LifecycleCleanupResponseV12 =
            parse_canonical_json(&retained, MAX_LIFECYCLE_BYTES).map_err(
                |_| {
                    RuntimeError::rejected(
                        "cached lifecycle response is structurally incompatible; in-service migration is forbidden, use offline-state-quarantine-v12.sh while v12 is stopped",
                    )
                },
            )?;
        response.validate_for(request)?;
        verify_lifecycle_cleanup_response_v12(
            request,
            &response,
            config.privileged_root_signer_spki_sha256,
        )?;
        return Ok(retained);
    }
    let privileged_bytes = loop {
        require_live(request.cleanup_deadline_boottime_ns)?;
        match framed_rpc_exact(
            &config.privileged_socket,
            0,
            exact_request,
            request.cleanup_deadline_boottime_ns,
            MAX_LIFECYCLE_BYTES,
            MAX_LIFECYCLE_BYTES,
        ) {
            Ok(bytes) => break bytes,
            Err(_) => {
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    };
    let privileged = verify_privileged_lifecycle_response_v12(
        request,
        &privileged_bytes,
        config.privileged_root_signer_spki_sha256,
    )?;
    let destruction = DestructionEvidence {
        request_binding_sha256: request.request_sha256,
        lane_generation_sha256: privileged.lane_generation_sha256,
        acceptance_revoked_sha256: privileged.acceptance_revoked_sha256,
        cgroup_kill_sha256: privileged.cgroup_kill_sha256,
        cgroup_empty_sha256: privileged.cgroup_empty_sha256,
        dind_destroyed_sha256: privileged.dind_destroyed_sha256,
        network_destroyed_sha256: privileged.network_destroyed_sha256,
        mounts_destroyed_sha256: privileged.mounts_destroyed_sha256,
        sockets_destroyed_sha256: privileged.sockets_destroyed_sha256,
        cleanup_terminal_sha256: privileged.cleanup_terminal_sha256,
    };
    destruction.validate(request.request_sha256, true)?;
    let mut response = LifecycleCleanupResponseV12 {
        protocol: CONTROLLER_LIFECYCLE_PROTOCOL_V12.to_owned(),
        operation: "DESTROY_AND_RECONCILE".to_owned(),
        disposition: "DESTROYED".to_owned(),
        request_sha256_canonical: request.request_sha256_canonical,
        destruction,
        exact_plan_terminal_aggregate:
            privileged.exact_plan_terminal_aggregate,
        plan_terminal_aggregate_sha256:
            privileged.plan_terminal_aggregate_sha256,
        exact_privileged_response: privileged_bytes.clone(),
        privileged_response_sha256: sha256(&privileged_bytes),
        response_sha256: [0; 32],
    };
    let mut projection = response.clone();
    projection.response_sha256 = [0; 32];
    response.response_sha256 = sha256(
        &serde_json::to_vec(&projection)
            .map_err(|_| RuntimeError::invalid("cleanup response is not serializable"))?,
    );
    response.validate_for(request)?;
    verify_lifecycle_cleanup_response_v12(
        request,
        &response,
        config.privileged_root_signer_spki_sha256,
    )?;
    let exact_response = canonical_json(&response, MAX_LIFECYCLE_BYTES)?;
    atomic_write(&response_path, &exact_response, owner)?;
    Ok(exact_response)
}

fn verify_lifecycle_cleanup_response_v12(
    request: &LifecycleCleanupRequestV12,
    response: &LifecycleCleanupResponseV12,
    pinned_root_signer_spki_sha256: [u8; 32],
) -> Result<()> {
    let privileged = verify_privileged_lifecycle_response_v12(
        request,
        &response.exact_privileged_response,
        pinned_root_signer_spki_sha256,
    )?;
    let destruction = DestructionEvidence {
        request_binding_sha256: request.request_sha256,
        lane_generation_sha256: privileged.lane_generation_sha256,
        acceptance_revoked_sha256:
            privileged.acceptance_revoked_sha256,
        cgroup_kill_sha256: privileged.cgroup_kill_sha256,
        cgroup_empty_sha256: privileged.cgroup_empty_sha256,
        dind_destroyed_sha256: privileged.dind_destroyed_sha256,
        network_destroyed_sha256:
            privileged.network_destroyed_sha256,
        mounts_destroyed_sha256:
            privileged.mounts_destroyed_sha256,
        sockets_destroyed_sha256:
            privileged.sockets_destroyed_sha256,
        cleanup_terminal_sha256:
            privileged.cleanup_terminal_sha256,
    };
    if response.exact_plan_terminal_aggregate
            != privileged.exact_plan_terminal_aggregate
        || response.plan_terminal_aggregate_sha256
            != privileged.plan_terminal_aggregate_sha256
        || response.destruction != destruction
    {
        return Err(RuntimeError::rejected(
            "lifecycle cleanup response differs from exact root-signed evidence",
        ));
    }
    Ok(())
}

fn verify_privileged_lifecycle_response_v12(
    request: &LifecycleCleanupRequestV12,
    privileged_bytes: &[u8],
    pinned_root_signer_spki_sha256: [u8; 32],
) -> Result<PrivilegedLifecycleResponseV12> {
    let privileged: PrivilegedLifecycleResponseV12 =
        parse_canonical_json(
            privileged_bytes,
            MAX_LIFECYCLE_BYTES,
        )?;
    if privileged.protocol != CONTROLLER_LIFECYCLE_PROTOCOL_V12
        || privileged.operation != "DESTROY_AND_RECONCILE"
        || privileged.disposition != "DESTROYED"
        || privileged.request_sha256_canonical
            != request.request_sha256_canonical
        || privileged.root_signer_spki_sha256
            != pinned_root_signer_spki_sha256
        || privileged.exact_plan_terminal_aggregate.is_empty()
        || privileged.exact_plan_terminal_aggregate.len()
            > MAX_LIFECYCLE_BYTES
        || sha256_bytes(
            &privileged.exact_plan_terminal_aggregate,
        ) != privileged.plan_terminal_aggregate_sha256
        || privileged.plan_terminal_aggregate_sha256 == [0; 32]
        || privileged.root_signature.len() != 64
        || privileged.privileged_response_sha256 == [0; 32]
    {
        return Err(RuntimeError::rejected(
            "privileged lifecycle helper response is incomplete or mismatched",
        ));
    }
    let mut privileged_projection = privileged.clone();
    privileged_projection.privileged_response_sha256 = [0; 32];
    if sha256_bytes(&canonical_json(
        &privileged_projection,
        MAX_LIFECYCLE_BYTES,
    )?) != privileged.privileged_response_sha256
    {
        return Err(RuntimeError::rejected(
            "privileged lifecycle response digest is not canonical",
        ));
    }
    let cleanup_key = VerifyingKey::from_public_key_der(
        &privileged.root_signer_public_key_spki_der,
    )
    .map_err(|_| {
        RuntimeError::rejected(
            "privileged lifecycle cleanup public key is invalid",
        )
    })?;
    if sha256_bytes(
        &privileged.root_signer_public_key_spki_der,
    ) != privileged.root_signer_spki_sha256
    {
        return Err(RuntimeError::rejected(
            "privileged lifecycle cleanup SPKI differs from its release pin",
        ));
    }
    let signature: [u8; 64] = privileged
        .root_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            RuntimeError::rejected(
                "privileged lifecycle cleanup signature length is invalid",
            )
        })?;
    let mut signature_projection = privileged.clone();
    signature_projection.root_signature.clear();
    signature_projection.privileged_response_sha256 = [0; 32];
    let projection = canonical_json(
        &signature_projection,
        MAX_LIFECYCLE_BYTES,
    )?;
    let mut signed = Vec::with_capacity(
        PRIVILEGED_LIFECYCLE_CLEANUP_SIGNATURE_DOMAIN_V12.len()
            + projection.len(),
    );
    signed.extend_from_slice(
        PRIVILEGED_LIFECYCLE_CLEANUP_SIGNATURE_DOMAIN_V12,
    );
    signed.extend_from_slice(&projection);
    cleanup_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| {
            RuntimeError::rejected(
                "privileged lifecycle cleanup signature is invalid",
            )
        })?;
    verify_plan_terminal_aggregate_v12(
        request,
        &privileged,
        &cleanup_key,
    )?;
    Ok(privileged)
}

fn verify_plan_terminal_aggregate_v12(
    request: &LifecycleCleanupRequestV12,
    privileged: &PrivilegedLifecycleResponseV12,
    cleanup_key: &VerifyingKey,
) -> Result<()> {
    let aggregate: DelegatedPlanTerminalAggregateV12 =
        parse_canonical_json(
            &privileged.exact_plan_terminal_aggregate,
            MAX_LIFECYCLE_BYTES,
        )?;
    if aggregate.protocol
            != "serverware/private-dind-plan-aggregate-terminal/v12"
        || aggregate.plan_id != request.plan_id
        || aggregate.request_sha256_canonical
            != request.request_sha256_canonical
        || aggregate.idempotency_key_sha256
            != request.idempotency_key_sha256
        || aggregate.observed_terminal_sha256 == [0; 32]
        || aggregate.exact_receipt_sha256s.len()
            != aggregate.exact_terminal_receipts.len()
        || aggregate
            .exact_receipt_sha256s
            .iter()
            .zip(&aggregate.exact_terminal_receipts)
            .any(|(digest, exact)| {
                exact.is_empty() || sha256_bytes(exact) != *digest
            })
        || aggregate.root_signer_spki_sha256
            != privileged.root_signer_spki_sha256
        || aggregate.root_signer_public_key_spki_der
            != privileged.root_signer_public_key_spki_der
        || aggregate.root_signature.len() != 64
        || aggregate.aggregate_sha256
            != privileged.cleanup_terminal_sha256
    {
        return Err(RuntimeError::rejected(
            "plan terminal aggregate lost exact cleanup authority",
        ));
    }
    let mut digest_projection = aggregate.clone();
    digest_projection.aggregate_sha256 = [0; 32];
    if sha256_bytes(&canonical_json(
        &digest_projection,
        MAX_LIFECYCLE_BYTES,
    )?) != aggregate.aggregate_sha256
    {
        return Err(RuntimeError::rejected(
            "plan terminal aggregate digest is not canonical",
        ));
    }
    let signature: [u8; 64] = aggregate
        .root_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            RuntimeError::rejected(
                "plan terminal aggregate signature length is invalid",
            )
        })?;
    let mut signature_projection = aggregate;
    signature_projection.root_signature.clear();
    signature_projection.aggregate_sha256 = [0; 32];
    let projection = canonical_json(
        &signature_projection,
        MAX_LIFECYCLE_BYTES,
    )?;
    let mut signed = Vec::with_capacity(
        PLAN_TERMINAL_AGGREGATE_SIGNATURE_DOMAIN_V12.len()
            + projection.len(),
    );
    signed.extend_from_slice(
        PLAN_TERMINAL_AGGREGATE_SIGNATURE_DOMAIN_V12,
    );
    signed.extend_from_slice(&projection);
    cleanup_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| {
            RuntimeError::rejected(
                "plan terminal aggregate signature is invalid",
            )
        })
}

fn reconcile_lifecycle_intents(config: &LifecycleConfigV12) -> Result<()> {
    let ledger = config
        .ownership_ledger
        .parent()
        .ok_or_else(|| RuntimeError::invalid("lifecycle ledger has no parent"))?;
    let mut intents = fs::read_dir(ledger)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".intent-v12.json"))
        })
        .collect::<Vec<_>>();
    intents.sort();
    for path in intents {
        let bytes = read_secure_file(
            &path,
            MAX_LIFECYCLE_BYTES,
            Some(config.lifecycle_uid),
            false,
        )?;
        let request: LifecycleCleanupRequestV12 =
            parse_canonical_json(&bytes, MAX_LIFECYCLE_BYTES).map_err(
                |_| {
                    RuntimeError::rejected(
                        "lifecycle journal is structurally incompatible; in-service migration is forbidden, use offline-state-quarantine-v12.sh while v12 is stopped",
                    )
                },
            )?;
        request.validate()?;
        let response_path =
            lifecycle_response_path(config, &request.request_sha256_canonical);
        if !response_path.exists() {
            if request.cleanup_deadline_boottime_ns <= boottime_now_ns()? {
                return Err(RuntimeError::unavailable(
                    "unsettled lifecycle intent expired before startup reconciliation",
                ));
            }
            settle_lifecycle_intent(config, &request, &bytes)?;
        }
    }
    Ok(())
}

fn verify_delegated_private_dind_response(
    config: &LifecycleConfigV12,
    request: &DelegatedPrivateDindRequestV12,
    exact_response: &[u8],
    returned_fd_count: usize,
) -> Result<()> {
    let response: DelegatedPrivateDindResponseV12 =
        parse_canonical_json(exact_response, MAX_LIFECYCLE_BYTES)?;
    if response.protocol != PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12
        || response.request_sha256 != request.request_sha256
        || response.proxy_request_sha256
            != request.proxy_request.request_sha256
        || response.result_sha256 != sha256_bytes(&response.result)
        || response.observed_state_sha256 == [0; 32]
        || response.root_signer_spki_sha256
            != config.privileged_root_signer_spki_sha256
        || response.returned_fd_roles.len() != returned_fd_count
        || response.returned_fd_roles.len() > 1
    {
        return Err(RuntimeError::rejected(
            "private DinD root response lost request, result, signer, or FD binding",
        ));
    }
    if returned_fd_count == 1
        && response.returned_fd_roles
            != vec!["artifactCasDirectory".to_owned()]
    {
        return Err(RuntimeError::rejected(
            "private DinD root returned an unknown descriptor role",
        ));
    }
    let verifying_key = VerifyingKey::from_public_key_der(
        &response.root_signer_public_key_spki_der,
    )
    .map_err(|_| {
        RuntimeError::rejected(
            "private DinD root response public key is invalid",
        )
    })?;
    if sha256_bytes(&response.root_signer_public_key_spki_der)
        != response.root_signer_spki_sha256
    {
        return Err(RuntimeError::rejected(
            "private DinD root response SPKI differs from its pin",
        ));
    }
    let mut digest_projection = response.clone();
    digest_projection.response_sha256 = [0; 32];
    if sha256_bytes(&canonical_json(
        &digest_projection,
        MAX_LIFECYCLE_BYTES,
    )?) != response.response_sha256
    {
        return Err(RuntimeError::rejected(
            "private DinD root response digest is invalid",
        ));
    }
    let signature: [u8; 64] = response
        .root_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            RuntimeError::rejected(
                "private DinD root response signature length is invalid",
            )
        })?;
    let mut signature_projection = response.clone();
    signature_projection.root_signature.clear();
    signature_projection.response_sha256 = [0; 32];
    let projection = canonical_json(
        &signature_projection,
        MAX_LIFECYCLE_BYTES,
    )?;
    let mut signed = Vec::with_capacity(
        PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12.len()
            + projection.len(),
    );
    signed.extend_from_slice(
        PRIVATE_DIND_ROOT_RESPONSE_SIGNATURE_DOMAIN_V12,
    );
    signed.extend_from_slice(&projection);
    verifying_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| {
            RuntimeError::rejected(
                "private DinD root response signature is invalid",
            )
        })?;
    let destroyed =
        response.authoritative_state == Value::String("destroyed".to_owned());
    if destroyed != response.terminal_destruction_receipt.is_some() {
        return Err(RuntimeError::rejected(
            "private DinD terminal response lost its destruction receipt",
        ));
    }
    if let Some(exact_receipt) =
        &response.terminal_destruction_receipt
    {
        verify_delegated_terminal_receipt(
            config,
            request,
            &response,
            exact_receipt,
            &verifying_key,
        )?;
    }
    Ok(())
}

fn verify_delegated_terminal_receipt(
    config: &LifecycleConfigV12,
    request: &DelegatedPrivateDindRequestV12,
    response: &DelegatedPrivateDindResponseV12,
    exact_receipt: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let receipt: DelegatedRootTerminalReceiptV12 =
        parse_canonical_json(exact_receipt, MAX_LIFECYCLE_BYTES)?;
    let expected_receipt_request_sha256 =
        if request.proxy_request.operation
            == Value::String("queryAuthoritativeState".to_owned())
        {
            let query: DelegatedPrivateDindQueryPayloadV12 =
                parse_canonical_json(
                    &request.proxy_request.payload,
                    MAX_LIFECYCLE_BYTES,
                )?;
            if query.version
                != "serverware/controller-plan-proxy-payload/v12"
                || query.plan_id != request.proxy_request.plan_id
                || query.lane != request.proxy_request.lane
                || query.original_request_sha256 == [0; 32]
                || query.original_operation
                    == Value::String(
                        "queryAuthoritativeState".to_owned(),
                    )
            {
                return Err(RuntimeError::rejected(
                    "private DinD terminal query receipt lost its original request binding",
                ));
            }
            query.original_request_sha256
        } else {
            request.proxy_request.request_sha256
        };
    if receipt.version
        != "serverware/private-dind-terminal-destruction/v12"
        || receipt.trust_profile
            != "trusted-host-userspace-digest-no-ima"
        || receipt.plan_id != request.proxy_request.plan_id
        || receipt.capability_sha256
            != request.proxy_request.capability_sha256
        || receipt.request_sha256
            != expected_receipt_request_sha256
        || receipt.network_namespace.is_empty()
        || receipt.docker_top_level_object_count_scope
            != crate::docker_contract::DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
        || receipt.docker_internal_storage_absence_proof
            != crate::docker_contract::DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
        || receipt.containers != 0
        || receipt.images != 0
        || receipt.networks != 0
        || receipt.volumes != 0
        || receipt.mounts != 0
        || receipt.cgroup_processes != 0
        || receipt.proxy_accepting
        || !receipt.ledger_terminal
        || !receipt.dind_reaped
        || !receipt.netns_absent
        || !receipt.socket_absent
        || !receipt.state_root_absent
        || receipt.observed_state_sha256
            != response.observed_state_sha256
        || receipt.signer_spki_sha256
            != config.privileged_root_signer_spki_sha256
        || receipt.signer_public_key_spki_der.is_empty()
        || sha256_bytes(&receipt.signer_public_key_spki_der)
            != receipt.signer_spki_sha256
        || receipt.observed_at_boottime_ns == 0
        || receipt.observed_at_boottime_ns
            >= request.proxy_request.deadline_boottime_ns
    {
        return Err(RuntimeError::rejected(
            "private DinD terminal receipt is not complete observed destruction evidence",
        ));
    }
    let mut digest_projection = receipt.clone();
    digest_projection.receipt_sha256 = [0; 32];
    if sha256_bytes(&canonical_json(
        &digest_projection,
        MAX_LIFECYCLE_BYTES,
    )?) != receipt.receipt_sha256
    {
        return Err(RuntimeError::rejected(
            "private DinD terminal receipt digest is invalid",
        ));
    }
    let signature: [u8; 64] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            RuntimeError::rejected(
                "private DinD terminal receipt signature length is invalid",
            )
        })?;
    let mut signature_projection = receipt;
    signature_projection.signature.clear();
    signature_projection.receipt_sha256 = [0; 32];
    let projection = canonical_json(
        &signature_projection,
        MAX_LIFECYCLE_BYTES,
    )?;
    let mut signed = Vec::with_capacity(
        PRIVATE_DIND_TERMINAL_RECEIPT_SIGNATURE_DOMAIN_V12.len()
            + projection.len(),
    );
    signed.extend_from_slice(
        PRIVATE_DIND_TERMINAL_RECEIPT_SIGNATURE_DOMAIN_V12,
    );
    signed.extend_from_slice(&projection);
    verifying_key
        .verify(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| {
            RuntimeError::rejected(
                "private DinD terminal receipt signature is invalid",
            )
        })
}

fn read_framed_request(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<(Vec<u8>, u64)> {
    let (bytes, deadline, fds) =
        read_framed_request_with_fds(stream, maximum, 0)?;
    if !fds.is_empty() {
        return Err(RuntimeError::rejected(
            "framed request carried unexpected descriptors",
        ));
    }
    Ok((bytes, deadline))
}

fn read_framed_request_with_fds(
    stream: &mut UnixStream,
    maximum: usize,
    maximum_fds: usize,
) -> Result<(Vec<u8>, u64, Vec<OwnedFd>)> {
    stream.set_nonblocking(true)?;
    let bootstrap = boottime_now_ns()?
        .checked_add(5_000_000_000)
        .ok_or_else(|| RuntimeError::invalid("lifecycle frame deadline overflow"))?;
    let mut header = [0u8; AUTHORITY_FRAME_BYTES];
    poll_fd(stream.as_raw_fd(), libc::POLLIN, bootstrap)?;
    let control_bytes = unsafe {
        libc::CMSG_SPACE(
            (maximum_fds.max(1) * mem::size_of::<RawFd>())
                as libc::c_uint,
        ) as usize
    };
    let mut control =
        vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr() as *mut libc::c_void,
        iov_len: header.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control_bytes;
    let count = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut message,
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count <= 0
        || count as usize > header.len()
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC)
            != 0
    {
        return Err(RuntimeError::rejected(
            "lifecycle frame header or descriptor control is truncated",
        ));
    }
    let mut fds = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return Err(RuntimeError::rejected(
                    "lifecycle frame carried an unknown control message",
                ));
            }
            let descriptor_bytes = (*cmsg)
                .cmsg_len
                .saturating_sub(libc::CMSG_LEN(0) as usize);
            if descriptor_bytes % mem::size_of::<RawFd>() != 0 {
                return Err(RuntimeError::rejected(
                    "lifecycle SCM_RIGHTS payload is malformed",
                ));
            }
            let descriptor_count =
                descriptor_bytes / mem::size_of::<RawFd>();
            if fds.len().saturating_add(descriptor_count)
                > maximum_fds
            {
                return Err(RuntimeError::rejected(
                    "lifecycle frame exceeded its descriptor bound",
                ));
            }
            let values = libc::CMSG_DATA(cmsg) as *const RawFd;
            for index in 0..descriptor_count {
                let raw = *values.add(index);
                if raw < 0 {
                    return Err(RuntimeError::rejected(
                        "lifecycle frame carried an invalid descriptor",
                    ));
                }
                fds.push(OwnedFd::from_raw_fd(raw));
            }
            cmsg = libc::CMSG_NXTHDR(&message, cmsg);
        }
    }
    if (count as usize) < header.len() {
        read_exact_deadline(
            stream,
            &mut header[count as usize..],
            bootstrap,
        )?;
    }
    let header = AuthorityFrameHeaderV12::decode(&header, maximum)?;
    let mut bytes = vec![
        0u8;
        header
            .payload_bytes
            .try_into()
            .map_err(|_| RuntimeError::invalid("framed request length exceeds usize"))?
    ];
    read_exact_deadline(stream, &mut bytes, header.boottime_deadline_ns)?;
    if sha256_bytes(&bytes) != header.payload_sha256.decode()? {
        return Err(RuntimeError::rejected(
            "lifecycle request payload digest mismatch",
        ));
    }
    Ok((bytes, header.boottime_deadline_ns, fds))
}

fn write_framed_response(
    stream: &mut UnixStream,
    exact_response: &[u8],
    deadline: u64,
    maximum: usize,
) -> Result<()> {
    let header =
        AuthorityFrameHeaderV12::for_payload(exact_response, deadline, maximum)?
            .encode(maximum)?;
    write_all_deadline(stream, &header, deadline)?;
    write_all_deadline(stream, exact_response, deadline)
}

fn write_framed_response_with_fds(
    stream: &mut UnixStream,
    exact_response: &[u8],
    fds: Vec<OwnedFd>,
    deadline: u64,
    maximum: usize,
) -> Result<()> {
    let header =
        AuthorityFrameHeaderV12::for_payload(exact_response, deadline, maximum)?
            .encode(maximum)?;
    write_header_with_fds(stream, &header, &fds, deadline)?;
    write_all_deadline(stream, exact_response, deadline)
}

fn write_header_with_fds(
    stream: &mut UnixStream,
    header: &[u8],
    fds: &[OwnedFd],
    deadline: u64,
) -> Result<()> {
    if fds.is_empty() {
        return write_all_deadline(stream, header, deadline);
    }
    if fds.len() > MAX_LIFECYCLE_FDS {
        return Err(RuntimeError::rejected(
            "lifecycle response exceeded its descriptor bound",
        ));
    }
    poll_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
    let raw_fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    let control_bytes = unsafe {
        libc::CMSG_SPACE(
            (raw_fds.len() * mem::size_of::<RawFd>())
                as libc::c_uint,
        ) as usize
    };
    let mut control =
        vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: header.as_ptr() as *mut libc::c_void,
        iov_len: header.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = control_bytes;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        if cmsg.is_null() {
            return Err(RuntimeError::rejected(
                "lifecycle response could not allocate descriptor control",
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(
            (raw_fds.len() * mem::size_of::<RawFd>())
                as libc::c_uint,
        ) as usize;
        std::ptr::copy_nonoverlapping(
            raw_fds.as_ptr(),
            libc::CMSG_DATA(cmsg) as *mut RawFd,
            raw_fds.len(),
        );
        message.msg_controllen = (*cmsg).cmsg_len;
    }
    let sent = unsafe {
        libc::sendmsg(
            stream.as_raw_fd(),
            &message,
            libc::MSG_NOSIGNAL,
        )
    };
    if sent <= 0 || sent as usize > header.len() {
        return Err(std::io::Error::last_os_error().into());
    }
    write_all_deadline(stream, &header[sent as usize..], deadline)
}

fn framed_rpc_exact_with_fds(
    path: &Path,
    expected_uid: u32,
    exact_request: &[u8],
    attached_fds: Vec<OwnedFd>,
    deadline: u64,
    maximum_request: usize,
    maximum_response: usize,
    maximum_response_fds: usize,
) -> Result<(Vec<u8>, Vec<OwnedFd>)> {
    if exact_request.is_empty() || exact_request.len() > maximum_request {
        return Err(RuntimeError::invalid(
            "framed delegated request is outside its byte bound",
        ));
    }
    let mut stream = connect_stream(path, expected_uid, deadline)?;
    let header =
        AuthorityFrameHeaderV12::for_payload(
            exact_request,
            deadline,
            maximum_request,
        )?
        .encode(maximum_request)?;
    write_header_with_fds(
        &mut stream,
        &header,
        &attached_fds,
        deadline,
    )?;
    write_all_deadline(&mut stream, exact_request, deadline)?;
    let (response, response_deadline, response_fds) =
        read_framed_request_with_fds(
            &mut stream,
            maximum_response,
            maximum_response_fds,
        )?;
    if response_deadline > deadline {
        return Err(RuntimeError::rejected(
            "delegated lifecycle response widened its deadline",
        ));
    }
    Ok((response, response_fds))
}

#[derive(Clone)]
struct PrivilegedLifecycleConfigV12 {
    authorized_peer_uid: u32,
    state_root: PathBuf,
    ownership_ledger: PathBuf,
    cgroup_root: PathBuf,
    socket_root: PathBuf,
    network_hook: PathBuf,
    host_cleanup_ruleset: PathBuf,
    lane_cleanup_ruleset: PathBuf,
}

pub fn run_privileged_lifecycle_cli() -> Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(RuntimeError::invalid(
            "usage: serverware-coder-lifecycle-privileged-v12 --config ABSOLUTE_PATH",
        ));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(RuntimeError::rejected(
            "privileged lifecycle helper requires UID 0",
        ));
    }
    let config = load_privileged_lifecycle_config(Path::new(&arguments[1]))?;
    ensure_private_directory(&config.state_root, 0)?;
    reconcile_privileged_responses(&config)?;
    let listen_pid = std::env::var("LISTEN_PID")
        .map_err(|_| RuntimeError::invalid("privileged helper requires LISTEN_PID"))?
        .parse::<u32>()
        .map_err(|_| RuntimeError::invalid("privileged helper LISTEN_PID is invalid"))?;
    let listen_fds = std::env::var("LISTEN_FDS")
        .map_err(|_| RuntimeError::invalid("privileged helper requires LISTEN_FDS"))?
        .parse::<u32>()
        .map_err(|_| RuntimeError::invalid("privileged helper LISTEN_FDS is invalid"))?;
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err(RuntimeError::rejected(
            "privileged helper requires exactly one socket-activated listener",
        ));
    }
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    notify_systemd("READY=1\nSTATUS=privileged lifecycle cleanup authority ready")?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_privileged_lifecycle(&config, &mut stream) {
            eprintln!("privileged lifecycle request rejected: {error}");
        }
    }
    Err(RuntimeError::unavailable(
        "privileged lifecycle listener terminated unexpectedly",
    ))
}

fn load_privileged_lifecycle_config(path: &Path) -> Result<PrivilegedLifecycleConfigV12> {
    let bytes = read_secure_file(path, MAX_CONFIG_BYTES, Some(0), false)?;
    let values = parse_kv(&bytes)?;
    if required_u64(&values, "contract_version")? != 12
        || required(&values, "mode")? != "privileged-helper-v12"
        || required(&values, "socket_activation")? != "systemd-listen-fds"
        || required(&values, "startup_reconcile_owned_resources")? != "true"
        || required(&values, "shutdown_destroy_all_owned_resources")? != "true"
        || required(&values, "destroy_on_any_failure")? != "true"
    {
        return Err(RuntimeError::rejected(
            "privileged lifecycle configuration is not fail-closed",
        ));
    }
    let config = PrivilegedLifecycleConfigV12 {
        authorized_peer_uid: required_u64(&values, "authorized_peer_uid")?
            .try_into()
            .map_err(|_| RuntimeError::invalid("authorized lifecycle UID exceeds u32"))?,
        state_root: required_path(&values, "state_root")?,
        ownership_ledger: required_path(&values, "ownership_ledger")?,
        cgroup_root: required_path(&values, "cgroup_root")?,
        socket_root: required_path(&values, "private_socket_root")?,
        network_hook: required_path(&values, "network_hook")?,
        host_cleanup_ruleset: required_path(&values, "host_cleanup_ruleset")?,
        lane_cleanup_ruleset: required_path(&values, "lane_cleanup_ruleset")?,
    };
    for path in [
        &config.state_root,
        &config.ownership_ledger,
        &config.cgroup_root,
        &config.socket_root,
        &config.network_hook,
        &config.host_cleanup_ruleset,
        &config.lane_cleanup_ruleset,
    ] {
        if !path.is_absolute() {
            return Err(RuntimeError::rejected(
                "privileged lifecycle path is not absolute",
            ));
        }
    }
    Ok(config)
}

fn handle_privileged_lifecycle(
    config: &PrivilegedLifecycleConfigV12,
    stream: &mut UnixStream,
) -> Result<()> {
    if peer_cred(stream.as_raw_fd())?.uid != config.authorized_peer_uid {
        return Err(RuntimeError::rejected(
            "privileged lifecycle peer UID is not authorized",
        ));
    }
    let (bytes, deadline) = read_framed_request(stream, MAX_LIFECYCLE_BYTES)?;
    let request: LifecycleCleanupRequestV12 =
        parse_canonical_json(&bytes, MAX_LIFECYCLE_BYTES)?;
    request.validate()?;
    if request.boot_id_sha256 != boot_id_sha256_v12()?.decode()?
        || request.cleanup_deadline_boottime_ns != deadline
    {
        return Err(RuntimeError::rejected(
            "privileged cleanup request changed boot or deadline",
        ));
    }
    let response_path = config.state_root.join(format!(
        "{}.response-v12.json",
        hex::encode(request.request_sha256_canonical),
    ));
    let response = if response_path.exists() {
        read_secure_file(&response_path, MAX_LIFECYCLE_BYTES, Some(0), false)?
    } else {
        let response = perform_privileged_cleanup(config, &request)?;
        let bytes = canonical_json(&response, MAX_LIFECYCLE_BYTES)?;
        atomic_write(&response_path, &bytes, 0)?;
        bytes
    };
    write_framed_response(stream, &response, deadline, MAX_LIFECYCLE_BYTES)
}

fn perform_privileged_cleanup(
    _config: &PrivilegedLifecycleConfigV12,
    _request: &LifecycleCleanupRequestV12,
) -> Result<PrivilegedLifecycleResponseV12> {
    Err(RuntimeError::rejected(
        "legacy privileged cleanup entrypoint is disabled; use the private DinD v12 root adapter",
    ))
}

fn run_bounded_command(executable: &Path, arguments: &[&str], deadline: u64) -> Result<[u8; 32]> {
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(RuntimeError::Io)?;
    loop {
        if let Some(status) = child.try_wait().map_err(RuntimeError::Io)? {
            if !status.success() {
                return Err(RuntimeError::unavailable(
                    "privileged cleanup command failed",
                ));
            }
            return Ok(sha256(
                &[
                    executable.as_os_str().as_bytes(),
                    arguments.join("\0").as_bytes(),
                    b"success",
                ]
                .concat(),
            ));
        }
        if boottime_now_ns()? >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RuntimeError::unavailable(
                "privileged cleanup command exceeded deadline",
            ));
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn destroy_owned_cgroups(root: &Path, deadline: u64) -> Result<[u8; 32]> {
    if !root.exists() {
        return Ok(sha256(b"trusted-host-local:no-owned-cgroups"));
    }
    let mut entries = fs::read_dir(root)?
        .take(129)
        .collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() > 128 {
        return Err(RuntimeError::rejected(
            "owned cgroup count exceeds fixed cleanup bound",
        ));
    }
    entries.sort_by_key(|entry| entry.file_name());
    let mut evidence = Vec::new();
    for entry in entries {
        require_live(deadline)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| RuntimeError::rejected("owned cgroup name is not UTF-8"))?;
        if !name.starts_with("serverware-coder-v12-") || !entry.file_type()?.is_dir() {
            return Err(RuntimeError::rejected(
                "foreign entry exists under owned cgroup root",
            ));
        }
        let path = entry.path();
        OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.kill"))?
            .write_all(b"1\n")?;
        loop {
            let events = fs::read_to_string(path.join("cgroup.events"))?;
            if events.lines().any(|line| line == "populated 0") {
                break;
            }
            require_live(deadline)?;
            thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::remove_dir(&path)?;
        evidence.extend_from_slice(name.as_bytes());
    }
    Ok(sha256(&evidence))
}

fn remove_owned_sockets(root: &Path) -> Result<[u8; 32]> {
    if !root.exists() {
        return Ok(sha256(b"trusted-host-local:no-owned-sockets"));
    }
    let mut evidence = Vec::new();
    let entries = fs::read_dir(root)?
        .take(257)
        .collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() > 256 {
        return Err(RuntimeError::rejected(
            "owned socket count exceeds fixed cleanup bound",
        ));
    }
    for entry in entries {
        let metadata = entry.metadata()?;
        if !metadata.file_type().is_socket() {
            return Err(RuntimeError::rejected(
                "foreign non-socket exists under private socket root",
            ));
        }
        evidence.extend_from_slice(entry.file_name().as_os_str().as_bytes());
        fs::remove_file(entry.path())?;
    }
    Ok(sha256(&evidence))
}

fn reconcile_privileged_responses(config: &PrivilegedLifecycleConfigV12) -> Result<()> {
    for entry in fs::read_dir(&config.state_root)?.take(257) {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".response-v12.json"))
        {
            return Err(RuntimeError::rejected(
                "privileged lifecycle state root contains a foreign entry",
            ));
        }
        let bytes = read_secure_file(&entry.path(), MAX_LIFECYCLE_BYTES, Some(0), false)?;
        let response: PrivilegedLifecycleResponseV12 =
            parse_canonical_json(&bytes, MAX_LIFECYCLE_BYTES)?;
        if response.protocol != CONTROLLER_LIFECYCLE_PROTOCOL_V12
            || response.disposition != "DESTROYED"
            || response.privileged_response_sha256 == [0; 32]
        {
            return Err(RuntimeError::rejected(
                "privileged lifecycle retained response is invalid",
            ));
        }
    }
    Ok(())
}

fn notify_systemd(message: &str) -> Result<()> {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = socket
        .to_str()
        .ok_or_else(|| RuntimeError::invalid("NOTIFY_SOCKET is not UTF-8"))?;
    if socket.starts_with('@') {
        let name = &socket.as_bytes()[1..];
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        if name.is_empty() || name.len() + 1 > address.sun_path.len() {
            return Err(RuntimeError::invalid(
                "abstract NOTIFY_SOCKET is outside sockaddr_un",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, source) in address.sun_path[1..].iter_mut().zip(name.iter()) {
            *target = *source as libc::c_char;
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let length = (mem::size_of::<libc::sa_family_t>() + 1 + name.len())
            as libc::socklen_t;
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
                libc::MSG_NOSIGNAL,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                length,
            )
        };
        if sent != message.len() as isize {
            return Err(std::io::Error::last_os_error().into());
        }
        return Ok(());
    }
    let datagram = std::os::unix::net::UnixDatagram::unbound()?;
    datagram.send_to(message.as_bytes(), socket)?;
    Ok(())
}
