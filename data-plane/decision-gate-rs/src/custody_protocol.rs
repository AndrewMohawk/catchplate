use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{Date, Duration as TimeDuration, Month, OffsetDateTime};
use zeroize::Zeroize;

pub const PROTOCOL_API_VERSION: &str = "serverware.custodyProtocol/v1";
pub const RESPONSE_STATEMENT_API_VERSION: &str = "serverware.proxyResponseStatement/v2";
pub const HELLO_OPERATION: &str = "hello/v1";
pub const RESPONSE_PROOF_SIGN_OPERATION: &str = "responseProof.sign/v2";
pub const STREAMING_RESPONSE_PROOF_SIGN_OPERATION: &str = "streamingResponseProof.sign/v1";
pub const STREAMING_RESPONSE_STATEMENT_API_VERSION: &str =
    "serverware.streamingResponseStatement/v1";
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const IO_DEADLINE: Duration = Duration::from_secs(2);
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;
pub const MAX_REQUESTS_PER_BOOT: usize = 65_536;
pub const MAX_STATEMENT_AGE_SECONDS: u64 = 300;

const MIN_REQUEST_ID_BYTES: usize = 16;
const MAX_REQUEST_ID_BYTES: usize = 64;
const BOOT_ID_BYTES: usize = 32;
const ED25519_SEED_BYTES: usize = 32;
const TLS_EXPORTER_BYTES: usize = 32;
const MIN_CLIENT_NONCE_BYTES: usize = 32;
const MAX_CLIENT_NONCE_BYTES: usize = 64;
const MAX_OPERATION_BYTES: usize = 64;
const MAX_SERVER_INSTANCE_ID_BYTES: usize = 1024;
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_RAW_HEADER_VALUES: usize = 128;
const MAX_AUTHORIZATION_RECEIPT_BODY_BYTES: usize = 32 * 1024;
const MAX_SIGNED_RESPONSE_STATEMENT_BYTES: usize = 8 * 1024;
const MAX_RELEASE_AUTHORIZATION_BINDING_BYTES: usize = 64 * 1024;
const MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES: usize = 1024;
const MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_BYTES: usize = 72;
const MAX_ATTEMPT_STATEMENT_BINDINGS: usize = MAX_REQUESTS_PER_BOOT;
const MAX_ATTEMPT_LEDGER_RECORD_BYTES: usize = 1024;
const MAX_ATTEMPT_LEDGER_MANIFEST_BYTES: usize = 1024;
const ATTEMPT_LEDGER_DIRECTORY_MODE: u32 = 0o700;
const ATTEMPT_LEDGER_FILE_MODE: u32 = 0o600;
const ATTEMPT_LEDGER_API_VERSION: &str = "serverware.custodyAttemptLedger/v2";
const ATTEMPT_LEDGER_MANIFEST_FILE: &str = "manifest.json";
const ATTEMPT_LEDGER_LOCK_FILE: &str = "ledger.lock";
const MAX_RELEASE_AUTHORIZATION_LIFETIME_MS: u64 = 300_000;
const AUTHORIZATION_RECEIPT_API_VERSION: &str = "serverware.controlPlaneAuthorizationReceipt/v1";
const RELEASE_AUTHORIZATION_DISPATCH_PATH: &str = "/api/data-plane/release-authorizations/dispatch";
const CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV: &str =
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY";
const CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV: &str =
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID";
const CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV: &str =
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID_FILE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: &'static str,
    pub message: String,
}

impl ProtocolError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    DeadlineExceeded,
    EmptyFrame,
    FrameTooLarge { declared: usize },
    TruncatedFrame { expected: usize, received: usize },
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "socket I/O failed: {error}"),
            Self::DeadlineExceeded => write!(formatter, "absolute frame deadline exceeded"),
            Self::EmptyFrame => write!(formatter, "empty frames are not allowed"),
            Self::FrameTooLarge { declared } => write!(
                formatter,
                "declared frame length {declared} exceeds {MAX_FRAME_BYTES} bytes"
            ),
            Self::TruncatedFrame { expected, received } => write!(
                formatter,
                "truncated frame: expected {expected} bytes, received {received}"
            ),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyRequest {
    pub api_version: String,
    pub request_id: String,
    pub boot_id: Option<String>,
    pub operation: String,
    pub params: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelloParams {}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignParams {
    statement: ProxyResponseStatement,
    authorization_binding: ReleaseAuthorizationBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StreamingSignParams {
    statement: StreamingResponseStatement,
    authorization_binding: ReleaseAuthorizationBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyResponseStatement {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub issued_at_unix: u64,
    pub client_nonce: String,
    pub client_request_digest: String,
    pub principal_id: String,
    pub route_id: String,
    pub request_digest: String,
    pub operation_digest: String,
    pub release_authority: ReleaseAuthority,
    pub control_plane_authorization_receipt: ControlPlaneAuthorizationReceipt,
    pub upstream_response: UpstreamResponse,
    pub response: ProxyResponse,
    pub policy_digest: String,
    pub runtime_manifest_digest: String,
    pub data_plane_binary_digest: String,
    pub release_digest: String,
    pub server_instance: ServerInstance,
    pub tls_channel_binding: TlsChannelBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StreamingResponseStatement {
    #[serde(rename = "apiVersion")]
    api_version: String,
    issued_at_unix: u64,
    client_nonce: String,
    client_request_digest: String,
    principal_id: String,
    route_id: String,
    request_digest: String,
    operation_digest: String,
    release_authority: ReleaseAuthority,
    authorization_binding_validation: AuthorizationBindingValidation,
    control_plane_authorization_receipt: ControlPlaneAuthorizationReceipt,
    control_plane_authorization_receipt_sha256: String,
    upstream_response: StreamingUpstreamResponse,
    released_response: StreamingReleasedResponse,
    policy_digest: String,
    runtime_manifest_digest: String,
    data_plane_binary_digest: String,
    release_digest: String,
    server_instance: ServerInstance,
    tls_channel_binding: StreamingTlsChannelBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorizationBindingValidation {
    status: String,
    binding_commitment: AuthorizationBindingCommitment,
    binding_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorizationBindingCommitment {
    attempt_id: String,
    flow_id: String,
    principal_id: String,
    route_id: String,
    credential_id: String,
    credential_version: u64,
    policy_hash: String,
    request_digest: String,
    operation_digest: String,
    operation_context_digest: String,
    require_jit_grant: bool,
    shared_quotas: Vec<ReleaseAuthorizationBindingQuota>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamingUpstreamResponse {
    status: u16,
    selected_raw_policy_headers_b64: BTreeMap<String, Vec<String>>,
    body_digest: String,
    body_bytes: u64,
    canonical_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamingReleasedResponse {
    status: u16,
    content_type: String,
    selected_wire_headers: StreamingWireHeaders,
    selected_wire_headers_digest: String,
    body_digest: String,
    body_bytes: u64,
    framing: String,
    completion: String,
    trailer_names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamingWireHeaders {
    connection: String,
    #[serde(rename = "content-type")]
    content_type: String,
    trailer: String,
    #[serde(rename = "transfer-encoding")]
    transfer_encoding: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamingTlsChannelBinding {
    #[serde(rename = "type")]
    binding_type: String,
    exporter_label: String,
    value: String,
}

#[derive(Clone, Copy)]
struct ResponseStatementAuthorityView<'a> {
    issued_at_unix: u64,
    principal_id: &'a str,
    route_id: &'a str,
    request_digest: &'a str,
    operation_digest: &'a str,
    release_authority: &'a ReleaseAuthority,
    control_plane_authorization_receipt: &'a ControlPlaneAuthorizationReceipt,
    policy_digest: &'a str,
    release_digest: &'a str,
}

impl<'a> From<&'a ProxyResponseStatement> for ResponseStatementAuthorityView<'a> {
    fn from(statement: &'a ProxyResponseStatement) -> Self {
        Self {
            issued_at_unix: statement.issued_at_unix,
            principal_id: &statement.principal_id,
            route_id: &statement.route_id,
            request_digest: &statement.request_digest,
            operation_digest: &statement.operation_digest,
            release_authority: &statement.release_authority,
            control_plane_authorization_receipt: &statement.control_plane_authorization_receipt,
            policy_digest: &statement.policy_digest,
            release_digest: &statement.release_digest,
        }
    }
}

impl<'a> From<&'a StreamingResponseStatement> for ResponseStatementAuthorityView<'a> {
    fn from(statement: &'a StreamingResponseStatement) -> Self {
        Self {
            issued_at_unix: statement.issued_at_unix,
            principal_id: &statement.principal_id,
            route_id: &statement.route_id,
            request_digest: &statement.request_digest,
            operation_digest: &statement.operation_digest,
            release_authority: &statement.release_authority,
            control_plane_authorization_receipt: &statement.control_plane_authorization_receipt,
            policy_digest: &statement.policy_digest,
            release_digest: &statement.release_digest,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneAuthorizationReceipt {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub principal_id: String,
    pub route_id: String,
    pub release_authority: ReleaseAuthority,
    pub request: ControlPlaneAuthorizationReceiptRequest,
    pub response: ControlPlaneAuthorizationReceiptResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneAuthorizationReceiptRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub nonce: String,
    pub body_b64: String,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneAuthorizationReceiptResponse {
    pub status: u16,
    pub body_b64: String,
    pub body_sha256: String,
    pub response_signing_key_id: String,
    pub statement_b64: String,
    pub statement_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAuthority {
    pub authority_mode: String,
    pub grant_id: Option<String>,
    pub approval_id: Option<String>,
    pub credential_ref: Option<String>,
    pub credential_version: u64,
    pub request_digest: String,
    pub operation_digest: String,
    pub attempt_id: String,
    pub consumption_identity_digest: String,
    pub authorization_state_at_upstream_dispatch: String,
    pub authorization_state_observed_at_epoch_ms: u64,
    pub reservation_expires_at_epoch_ms: Option<u64>,
    pub dispatch_expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseAuthorizationBinding {
    attempt_id: String,
    flow_id: String,
    principal_id: String,
    route_id: String,
    credential_id: String,
    credential_version: u64,
    policy_hash: String,
    request_digest: String,
    operation_digest: Option<String>,
    operation_context: Value,
    require_jit_grant: bool,
    shared_quotas: Vec<ReleaseAuthorizationBindingQuota>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum RateLimitWindowKind {
    Fixed,
    UtcDay,
    UtcIsoWeek,
    UtcMonth,
}

impl RateLimitWindowKind {
    fn is_calendar(&self) -> bool {
        self != &Self::Fixed
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseAuthorizationBindingQuota {
    counter_key: String,
    constraint_id: String,
    operation: Option<String>,
    window_kind: RateLimitWindowKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_seconds: Option<u64>,
    max_count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamResponse {
    pub status: u16,
    pub selected_raw_policy_headers_b64: BTreeMap<String, Vec<String>>,
    pub body_digest: String,
    pub canonical_digest: String,
}

#[derive(Serialize)]
struct CanonicalUpstreamResponse<'a> {
    status: u16,
    selected_raw_policy_headers_b64: &'a BTreeMap<String, Vec<String>>,
    body_digest: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyResponse {
    pub status: u16,
    pub selected_headers: BTreeMap<String, String>,
    pub selected_headers_digest: String,
    pub body_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerInstance {
    pub id: String,
    pub identity_digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsChannelBinding {
    #[serde(rename = "type")]
    pub binding_type: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DispatchRequestBody {
    api_version: String,
    attempt_id: String,
    binding_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DispatchResponseBody {
    api_version: String,
    ok: bool,
    authorized: bool,
    state: String,
    reason: String,
    attempt_id: String,
    binding_digest: String,
    idempotent_replay: bool,
    grant_id: Option<String>,
    approval_request_id: Option<String>,
    approval_status: Option<String>,
    approval_expires_at: Option<String>,
    approval_created: Option<bool>,
    reservation_expires_at_epoch_ms: Option<u64>,
    dispatch_started_at_epoch_ms: Option<u64>,
    dispatch_expires_at_epoch_ms: Option<u64>,
    completion_outcome: Option<String>,
    retry_after_seconds: u64,
    quotas: Vec<DispatchQuota>,
    store: DispatchStore,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct DispatchQuota {
    counter_key: Option<String>,
    constraint_id: Option<String>,
    operation: Option<String>,
    window_start_epoch_ms: Option<u64>,
    window_end_epoch_ms: Option<u64>,
    window_kind: Option<RateLimitWindowKind>,
    calendar_window: Option<RateLimitWindowKind>,
    window_seconds: Option<u64>,
    max: Option<u64>,
    count: Option<u64>,
    remaining: Option<u64>,
    reservation_state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)]
struct DispatchStore {
    backend: Option<String>,
    ha: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedResponseStatement {
    version: String,
    issued_at_ms: u64,
    request: SignedResponseRequest,
    status_code: u16,
    body_sha256: String,
    nonce: Option<String>,
    response_signing_key_id: String,
    context: SignedResponseContext,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedResponseRequest {
    method: String,
    path: String,
    query_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedResponseContext {
    runtime_manifest_digest: String,
    policy_bundle_digest: String,
    provenance_digest: Option<String>,
    image_signatures_digest: Option<String>,
    source_tree_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustodyResponse<'a> {
    api_version: &'static str,
    request_id: &'a str,
    boot_id: &'a str,
    operation: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HelloResult<'a> {
    public_key_pem: &'a str,
    key_id: &'a str,
    control_plane_response_signing_key_id: Option<&'a str>,
    capabilities: [&'static str; 3],
    limits: RuntimeLimits,
    hardware_proof: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeLimits {
    max_frame_bytes: usize,
    io_deadline_ms: u128,
    max_concurrent_connections: usize,
    max_requests_per_boot: usize,
    max_statement_age_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignResult<'a> {
    statement_digest: String,
    signature: String,
    key_id: &'a str,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttemptBindingPayload {
    api_version: String,
    attempt_id: String,
    statement_digest: String,
    retain_until_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttemptBindingRecord {
    payload: AttemptBindingPayload,
    checksum: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttemptLedgerManifestPayload {
    api_version: String,
    commit_sequence: u64,
    active_binding_count: usize,
    active_bindings_accumulator: String,
    pruned_through_epoch_ms: u64,
    max_observed_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttemptLedgerManifestRecord {
    payload: AttemptLedgerManifestPayload,
    checksum: String,
}

struct AttemptStatementLedger {
    directory: Option<PathBuf>,
    _lock_file: Option<fs::File>,
    bindings: BTreeMap<String, AttemptBindingPayload>,
    expiry_index: BTreeSet<(u64, String)>,
    manifest: AttemptLedgerManifestPayload,
    max_bindings: usize,
    poisoned: bool,
}

pub struct CustodyRuntime {
    boot_id: String,
    signing_key: SigningKey,
    public_key_pem: String,
    key_id: String,
    control_plane_response_verifying_key: Option<VerifyingKey>,
    control_plane_response_signing_key_id: Option<String>,
    seen_request_ids: Mutex<HashSet<String>>,
    response_proof_validation: Mutex<()>,
    attempt_statement_ledger: Mutex<AttemptStatementLedger>,
}

impl CustodyRuntime {
    pub fn initialize_attempt_ledger_directory(directory: &Path) -> Result<(), ProtocolError> {
        AttemptStatementLedger::initialize(directory)
    }

    pub fn generate(attempt_ledger_directory: &Path) -> Result<Self, ProtocolError> {
        Self::generate_with_configured_control_plane_response_key(
            configured_control_plane_response_verifying_key()?,
            attempt_ledger_directory,
        )
    }

    fn generate_with_configured_control_plane_response_key(
        control_plane_response_verifying_key: Option<VerifyingKey>,
        attempt_ledger_directory: &Path,
    ) -> Result<Self, ProtocolError> {
        let control_plane_response_verifying_key = control_plane_response_verifying_key
            .ok_or_else(|| {
                ProtocolError::new(
                    "invalid_control_plane_response_key_configuration",
                    format!(
                        "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} and exactly one pinned key ID source are required"
                    ),
                )
            })?;
        Self::generate_with_optional_control_plane_response_key(
            Some(control_plane_response_verifying_key),
            AttemptStatementLedger::open(attempt_ledger_directory)?,
        )
    }

    pub fn generate_with_control_plane_response_public_key(
        control_plane_response_verifying_key: VerifyingKey,
        expected_key_id: &str,
        attempt_ledger_directory: &Path,
    ) -> Result<Self, ProtocolError> {
        validate_pinned_control_plane_response_key(
            &control_plane_response_verifying_key,
            expected_key_id,
        )?;
        Self::generate_with_optional_control_plane_response_key(
            Some(control_plane_response_verifying_key),
            AttemptStatementLedger::open(attempt_ledger_directory)?,
        )
    }

    fn generate_with_optional_control_plane_response_key(
        control_plane_response_verifying_key: Option<VerifyingKey>,
        attempt_statement_ledger: AttemptStatementLedger,
    ) -> Result<Self, ProtocolError> {
        let random = SystemRandom::new();
        let mut seed = [0u8; ED25519_SEED_BYTES];
        let mut boot_id_bytes = [0u8; BOOT_ID_BYTES];
        random.fill(&mut seed).map_err(|_| {
            ProtocolError::new("entropy_unavailable", "generate Ed25519 signing key")
        })?;
        if random.fill(&mut boot_id_bytes).is_err() {
            seed.zeroize();
            return Err(ProtocolError::new(
                "entropy_unavailable",
                "generate custody runtime boot ID",
            ));
        }
        let runtime = Self::from_secret_material_with_ledger(
            seed,
            boot_id_bytes,
            control_plane_response_verifying_key,
            attempt_statement_ledger,
        );
        seed.zeroize();
        boot_id_bytes.zeroize();
        Ok(runtime)
    }

    fn from_secret_material_with_ledger(
        mut signing_seed: [u8; ED25519_SEED_BYTES],
        boot_id_bytes: [u8; BOOT_ID_BYTES],
        control_plane_response_verifying_key: Option<VerifyingKey>,
        attempt_statement_ledger: AttemptStatementLedger,
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();
        let public_key = signing_key.verifying_key().to_bytes();
        let spki_der = ed25519_spki_der(&public_key);
        let control_plane_response_signing_key_id = control_plane_response_verifying_key
            .as_ref()
            .map(control_plane_response_key_id);
        Self {
            boot_id: general_purpose::URL_SAFE_NO_PAD.encode(boot_id_bytes),
            signing_key,
            public_key_pem: pem_public_key(&spki_der),
            key_id: sha256_prefixed(&spki_der),
            control_plane_response_verifying_key,
            control_plane_response_signing_key_id,
            seen_request_ids: Mutex::new(HashSet::new()),
            response_proof_validation: Mutex::new(()),
            attempt_statement_ledger: Mutex::new(attempt_statement_ledger),
        }
    }

    #[cfg(test)]
    fn from_secret_material(
        signing_seed: [u8; ED25519_SEED_BYTES],
        boot_id_bytes: [u8; BOOT_ID_BYTES],
        control_plane_response_verifying_key: Option<VerifyingKey>,
    ) -> Self {
        Self::from_secret_material_with_ledger(
            signing_seed,
            boot_id_bytes,
            control_plane_response_verifying_key,
            AttemptStatementLedger::in_memory(),
        )
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn handle_canonical_request(&self, request_bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let request: CustodyRequest = decode_canonical_json(request_bytes)?;
        validate_request_id(&request.request_id)?;
        validate_operation_label(&request.operation)?;

        let outcome = self.process_request(&request);
        let response = match outcome {
            Ok(result) => CustodyResponse {
                api_version: PROTOCOL_API_VERSION,
                request_id: &request.request_id,
                boot_id: &self.boot_id,
                operation: &request.operation,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => CustodyResponse {
                api_version: PROTOCOL_API_VERSION,
                request_id: &request.request_id,
                boot_id: &self.boot_id,
                operation: &request.operation,
                ok: false,
                result: None,
                error: Some(ErrorBody {
                    code: error.code,
                    message: error.message,
                }),
            },
        };
        canonical_json_bytes(&response)
    }

    fn process_request(&self, request: &CustodyRequest) -> Result<Value, ProtocolError> {
        if request.api_version != PROTOCOL_API_VERSION {
            return Err(ProtocolError::new(
                "unsupported_api_version",
                "apiVersion must be serverware.custodyProtocol/v1",
            ));
        }

        match request.operation.as_str() {
            HELLO_OPERATION => {
                if request.boot_id.is_some() {
                    return Err(ProtocolError::new(
                        "unexpected_boot_id",
                        "hello/v1 requires bootId to be null",
                    ));
                }
                from_value_strict::<HelloParams>(request.params.clone(), "hello/v1 params")?;
                serde_json::to_value(HelloResult {
                    public_key_pem: &self.public_key_pem,
                    key_id: &self.key_id,
                    control_plane_response_signing_key_id: self
                        .control_plane_response_signing_key_id
                        .as_deref(),
                    capabilities: [
                        HELLO_OPERATION,
                        RESPONSE_PROOF_SIGN_OPERATION,
                        STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
                    ],
                    limits: RuntimeLimits {
                        max_frame_bytes: MAX_FRAME_BYTES,
                        io_deadline_ms: IO_DEADLINE.as_millis(),
                        max_concurrent_connections: MAX_CONCURRENT_CONNECTIONS,
                        max_requests_per_boot: MAX_REQUESTS_PER_BOOT,
                        max_statement_age_seconds: MAX_STATEMENT_AGE_SECONDS,
                    },
                    hardware_proof: false,
                })
                .map_err(|error| {
                    ProtocolError::new(
                        "internal_serialization_error",
                        format!("serialize hello response: {error}"),
                    )
                })
            }
            RESPONSE_PROOF_SIGN_OPERATION => {
                self.validate_sign_request_envelope(request, RESPONSE_PROOF_SIGN_OPERATION)?;
                let params = from_value_strict::<SignParams>(
                    request.params.clone(),
                    "responseProof.sign/v2 params",
                )?;
                let control_plane_response_verifying_key = self
                    .control_plane_response_verifying_key
                    .as_ref()
                    .ok_or_else(|| {
                        ProtocolError::new(
                            "control_plane_response_key_unavailable",
                            "responseProof.sign/v2 requires a pinned control-plane response public key",
                        )
                })?;
                let _validation = self.response_proof_validation.lock().map_err(|_| {
                    ProtocolError::new(
                        "internal_state_error",
                        "response proof validation serialization is unavailable",
                    )
                })?;
                let validation_epoch_ms = current_epoch_ms()?;
                let validated = (|| {
                    validate_response_statement_with_control_plane_response_key_at(
                        &params.statement,
                        control_plane_response_verifying_key,
                        validation_epoch_ms,
                    )?;
                    let authority_view = ResponseStatementAuthorityView::from(&params.statement);
                    validate_release_authorization_binding(
                        &authority_view,
                        &params.authorization_binding,
                    )?;
                    let canonical_statement = canonical_json_bytes(&params.statement)?;
                    let statement_digest = sha256_prefixed(&canonical_statement);
                    let retain_until_epoch_ms = params
                        .statement
                        .release_authority
                        .dispatch_expires_at_epoch_ms;
                    Ok::<_, ProtocolError>((
                        canonical_statement,
                        statement_digest,
                        retain_until_epoch_ms,
                    ))
                })();
                let (canonical_statement, statement_digest, retain_until_epoch_ms) = match validated
                {
                    Ok(validated) => validated,
                    Err(error) => {
                        self.observe_attempt_ledger_clock(validation_epoch_ms)?;
                        return Err(error);
                    }
                };
                self.sign_canonical_statement(
                    &params.statement.release_authority.attempt_id,
                    canonical_statement,
                    statement_digest,
                    retain_until_epoch_ms,
                    validation_epoch_ms,
                )
            }
            STREAMING_RESPONSE_PROOF_SIGN_OPERATION => {
                self.validate_sign_request_envelope(
                    request,
                    STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
                )?;
                let params = from_value_strict::<StreamingSignParams>(
                    request.params.clone(),
                    "streamingResponseProof.sign/v1 params",
                )?;
                let control_plane_response_verifying_key = self
                    .control_plane_response_verifying_key
                    .as_ref()
                    .ok_or_else(|| {
                        ProtocolError::new(
                            "control_plane_response_key_unavailable",
                            "streamingResponseProof.sign/v1 requires a pinned control-plane response public key",
                        )
                    })?;
                let _validation = self.response_proof_validation.lock().map_err(|_| {
                    ProtocolError::new(
                        "internal_state_error",
                        "response proof validation serialization is unavailable",
                    )
                })?;
                let validation_epoch_ms = current_epoch_ms()?;
                let validated = (|| {
                    validate_streaming_response_statement_with_control_plane_response_key_at(
                        &params.statement,
                        &params.authorization_binding,
                        control_plane_response_verifying_key,
                        validation_epoch_ms,
                    )?;
                    let canonical_statement = canonical_json_bytes(&params.statement)?;
                    let statement_digest = sha256_prefixed(&canonical_statement);
                    Ok::<_, ProtocolError>((
                        canonical_statement,
                        statement_digest,
                        params.statement.release_authority.dispatch_expires_at_epoch_ms,
                    ))
                })();
                let (canonical_statement, statement_digest, retain_until_epoch_ms) =
                    match validated {
                        Ok(validated) => validated,
                        Err(error) => {
                            self.observe_attempt_ledger_clock(validation_epoch_ms)?;
                            return Err(error);
                        }
                    };
                self.sign_canonical_statement(
                    &params.statement.release_authority.attempt_id,
                    canonical_statement,
                    statement_digest,
                    retain_until_epoch_ms,
                    validation_epoch_ms,
                )
            }
            _ => Err(ProtocolError::new(
                "unknown_operation",
                "operation must be hello/v1, responseProof.sign/v2, or streamingResponseProof.sign/v1",
            )),
        }
    }

    fn validate_sign_request_envelope(
        &self,
        request: &CustodyRequest,
        operation: &str,
    ) -> Result<(), ProtocolError> {
        self.claim_request_id(&request.request_id)?;
        let Some(boot_id) = request.boot_id.as_deref() else {
            return Err(ProtocolError::new(
                "missing_boot_id",
                format!("{operation} requires the current bootId"),
            ));
        };
        validate_boot_id(boot_id)?;
        if boot_id != self.boot_id {
            return Err(ProtocolError::new(
                "cross_boot_request",
                "request bootId does not match the current custody runtime boot",
            ));
        }
        Ok(())
    }

    fn sign_canonical_statement(
        &self,
        attempt_id: &str,
        canonical_statement: Vec<u8>,
        statement_digest: String,
        retain_until_epoch_ms: u64,
        validation_epoch_ms: u64,
    ) -> Result<Value, ProtocolError> {
        self.claim_attempt_statement_digest(
            attempt_id,
            &statement_digest,
            retain_until_epoch_ms,
            validation_epoch_ms,
        )?;
        let signature = self.signing_key.sign(&canonical_statement);
        serde_json::to_value(SignResult {
            statement_digest,
            signature: format!(
                "ed25519:{}",
                general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
            ),
            key_id: &self.key_id,
        })
        .map_err(|error| {
            ProtocolError::new(
                "internal_serialization_error",
                format!("serialize signing response: {error}"),
            )
        })
    }

    fn claim_request_id(&self, request_id: &str) -> Result<(), ProtocolError> {
        let mut seen = self.seen_request_ids.lock().map_err(|_| {
            ProtocolError::new(
                "internal_state_error",
                "request replay state is unavailable",
            )
        })?;
        if seen.contains(request_id) {
            return Err(ProtocolError::new(
                "replayed_request_id",
                "requestId was already used during this boot",
            ));
        }
        if seen.len() >= MAX_REQUESTS_PER_BOOT {
            return Err(ProtocolError::new(
                "request_id_capacity_exhausted",
                "runtime requestId capacity is exhausted for this boot",
            ));
        }
        seen.insert(request_id.to_string());
        Ok(())
    }

    fn claim_attempt_statement_digest(
        &self,
        attempt_id: &str,
        statement_digest: &str,
        retain_until_epoch_ms: u64,
        minimum_epoch_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.claim_attempt_statement_digest_with_clock(
            attempt_id,
            statement_digest,
            retain_until_epoch_ms,
            minimum_epoch_ms,
            current_epoch_ms,
        )
    }

    fn claim_attempt_statement_digest_with_clock(
        &self,
        attempt_id: &str,
        statement_digest: &str,
        retain_until_epoch_ms: u64,
        minimum_epoch_ms: u64,
        clock: impl FnOnce() -> Result<u64, ProtocolError>,
    ) -> Result<(), ProtocolError> {
        let mut ledger = self.attempt_statement_ledger.lock().map_err(|_| {
            ProtocolError::new(
                "internal_state_error",
                "attempt statement binding state is unavailable",
            )
        })?;
        let now_epoch_ms = match clock() {
            Ok(now_epoch_ms) => now_epoch_ms,
            Err(error) => {
                ledger.advance_max_observed_time(minimum_epoch_ms)?;
                return Err(error);
            }
        };
        if now_epoch_ms < minimum_epoch_ms {
            ledger.advance_max_observed_time(minimum_epoch_ms)?;
            return Err(attempt_ledger_error(
                "attempt_ledger_clock_rollback",
                format!(
                    "wall clock {now_epoch_ms} moved backward after statement validation at {minimum_epoch_ms}"
                ),
            ));
        }
        ledger.claim(
            attempt_id,
            statement_digest,
            retain_until_epoch_ms,
            now_epoch_ms,
        )
    }

    fn observe_attempt_ledger_clock(&self, observed_epoch_ms: u64) -> Result<(), ProtocolError> {
        let mut ledger = self.attempt_statement_ledger.lock().map_err(|_| {
            ProtocolError::new(
                "internal_state_error",
                "attempt statement binding state is unavailable",
            )
        })?;
        ledger.advance_max_observed_time(observed_epoch_ms)
    }
}

impl AttemptStatementLedger {
    #[cfg(test)]
    fn in_memory() -> Self {
        Self {
            directory: None,
            _lock_file: None,
            bindings: BTreeMap::new(),
            expiry_index: BTreeSet::new(),
            manifest: empty_attempt_ledger_manifest(),
            max_bindings: MAX_ATTEMPT_STATEMENT_BINDINGS,
            poisoned: false,
        }
    }

    fn open(directory: &Path) -> Result<Self, ProtocolError> {
        Self::open_with_limit(directory, MAX_ATTEMPT_STATEMENT_BINDINGS)
    }

    fn initialize(directory: &Path) -> Result<(), ProtocolError> {
        validate_attempt_ledger_directory(directory)?;
        let _lock_file = open_attempt_ledger_lock(directory)?;
        for entry in fs::read_dir(directory).map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("list ledger directory: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                attempt_ledger_error("attempt_ledger_io", format!("read ledger entry: {error}"))
            })?;
            let name = entry.file_name();
            if name == ATTEMPT_LEDGER_LOCK_FILE {
                continue;
            }
            if name == ATTEMPT_LEDGER_MANIFEST_FILE {
                return Err(attempt_ledger_error(
                    "attempt_ledger_already_initialized",
                    format!(
                        "attempt ledger directory {} is already initialized",
                        directory.display()
                    ),
                ));
            }
            return Err(attempt_ledger_error(
                "attempt_ledger_corrupt",
                "uninitialized ledger directory contains unexpected state",
            ));
        }
        persist_attempt_ledger_manifest(directory, &empty_attempt_ledger_manifest())
    }

    fn open_with_limit(directory: &Path, max_bindings: usize) -> Result<Self, ProtocolError> {
        Self::open_with_limit_at(directory, max_bindings, current_epoch_ms()?)
    }

    fn open_with_limit_at(
        directory: &Path,
        max_bindings: usize,
        now_epoch_ms: u64,
    ) -> Result<Self, ProtocolError> {
        validate_attempt_ledger_directory(directory)?;
        let lock_file = open_attempt_ledger_lock(directory)?;
        let manifest_path = directory.join(ATTEMPT_LEDGER_MANIFEST_FILE);
        let mut binding_paths = Vec::new();
        let mut orphan_temporary_paths = Vec::new();
        let mut manifest_present = false;
        for entry in fs::read_dir(directory).map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("list ledger directory: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                attempt_ledger_error("attempt_ledger_io", format!("read ledger entry: {error}"))
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(attempt_ledger_error(
                    "attempt_ledger_corrupt",
                    "ledger directory contains a non-UTF-8 entry name",
                ));
            };
            match name {
                ATTEMPT_LEDGER_LOCK_FILE => {}
                ATTEMPT_LEDGER_MANIFEST_FILE => manifest_present = true,
                _ if parse_attempt_binding_filename(name).is_some() => {
                    if binding_paths.len() >= max_bindings {
                        return Err(attempt_ledger_error(
                            "attempt_statement_capacity_exhausted",
                            format!("ledger contains more than {max_bindings} binding records"),
                        ));
                    }
                    binding_paths.push(entry.path());
                }
                _ if parse_attempt_ledger_temporary_filename(name) => {
                    orphan_temporary_paths.push(entry.path());
                }
                _ => {
                    return Err(attempt_ledger_error(
                        "attempt_ledger_corrupt",
                        format!("ledger directory contains unexpected entry: {name}"),
                    ));
                }
            }
        }
        if !orphan_temporary_paths.is_empty() {
            for path in orphan_temporary_paths {
                remove_orphan_attempt_ledger_temporary(&path)?;
            }
            sync_directory(directory)?;
        }
        if !manifest_present {
            return Err(attempt_ledger_error(
                "attempt_ledger_not_initialized",
                "attempt ledger manifest is missing; normal runtime startup never creates fresh state",
            ));
        }

        let manifest = load_attempt_ledger_manifest(&manifest_path)?;
        if now_epoch_ms < manifest.max_observed_epoch_ms {
            return Err(attempt_ledger_error(
                "attempt_ledger_clock_rollback",
                format!(
                    "wall clock {now_epoch_ms} precedes durable observation high-water mark {}",
                    manifest.max_observed_epoch_ms
                ),
            ));
        }

        binding_paths.sort();
        let mut bindings = BTreeMap::new();
        let mut expiry_index = BTreeSet::new();
        let mut active_accumulator = [0u8; 32];
        let mut stale_paths = Vec::new();
        for path in binding_paths {
            let record = load_attempt_binding_record(&path)?;
            let filename = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    attempt_ledger_error(
                        "attempt_ledger_corrupt",
                        "binding record has an invalid filename",
                    )
                })?;
            if parse_attempt_binding_filename(filename).as_deref()
                != Some(record.payload.attempt_id.as_str())
            {
                return Err(attempt_ledger_error(
                    "attempt_ledger_corrupt",
                    format!("binding filename does not match its attempt ID: {filename}"),
                ));
            }
            if record.payload.retain_until_epoch_ms <= manifest.pruned_through_epoch_ms {
                stale_paths.push(path);
                continue;
            }
            if bindings
                .insert(record.payload.attempt_id.clone(), record.payload.clone())
                .is_some()
            {
                return Err(attempt_ledger_error(
                    "attempt_ledger_corrupt",
                    "ledger contains a duplicate attempt binding",
                ));
            }
            expiry_index.insert((
                record.payload.retain_until_epoch_ms,
                record.payload.attempt_id.clone(),
            ));
            xor_accumulator(&mut active_accumulator, checksum_bytes(&record.checksum)?);
        }
        if manifest.active_binding_count != bindings.len()
            || manifest.active_bindings_accumulator
                != general_purpose::URL_SAFE_NO_PAD.encode(active_accumulator)
        {
            return Err(attempt_ledger_error(
                "attempt_ledger_corrupt",
                "ledger manifest does not match the active binding record set",
            ));
        }

        for path in stale_paths {
            fs::remove_file(&path).map_err(|error| {
                attempt_ledger_error(
                    "attempt_ledger_io",
                    format!("remove durably pruned binding {}: {error}", path.display()),
                )
            })?;
        }
        sync_directory(directory)?;

        let mut ledger = Self {
            directory: Some(directory.to_path_buf()),
            _lock_file: Some(lock_file),
            bindings,
            expiry_index,
            manifest,
            max_bindings,
            poisoned: false,
        };
        ledger.prune_expired(now_epoch_ms)?;
        ledger.advance_max_observed_time(now_epoch_ms)?;
        Ok(ledger)
    }

    fn claim(
        &mut self,
        attempt_id: &str,
        statement_digest: &str,
        retain_until_epoch_ms: u64,
        now_epoch_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.ensure_available()?;
        if now_epoch_ms < self.manifest.max_observed_epoch_ms {
            return Err(attempt_ledger_error(
                "attempt_ledger_clock_rollback",
                format!(
                    "wall clock {now_epoch_ms} precedes durable observation high-water mark {}",
                    self.manifest.max_observed_epoch_ms
                ),
            ));
        }
        self.prune_expired(now_epoch_ms)?;
        if let Some(existing_statement_digest) = self
            .bindings
            .get(attempt_id)
            .map(|existing| existing.statement_digest.clone())
        {
            self.advance_max_observed_time(now_epoch_ms)?;
            if existing_statement_digest != statement_digest {
                return Err(ProtocolError::new(
                    "attempt_statement_substitution",
                    "release_authority.attempt_id is durably bound to a different canonical statement digest",
                ));
            }
            return Ok(());
        }
        if retain_until_epoch_ms <= now_epoch_ms {
            self.advance_max_observed_time(now_epoch_ms)?;
            return Err(ProtocolError::new(
                "attempt_statement_expired",
                "release authorization expired before its attempt binding could be committed",
            ));
        }
        if self.bindings.len() >= self.max_bindings {
            self.advance_max_observed_time(now_epoch_ms)?;
            return Err(ProtocolError::new(
                "attempt_statement_capacity_exhausted",
                "runtime attempt statement binding capacity is exhausted by unexpired receipts",
            ));
        }

        let payload = AttemptBindingPayload {
            api_version: ATTEMPT_LEDGER_API_VERSION.to_string(),
            attempt_id: attempt_id.to_string(),
            statement_digest: statement_digest.to_string(),
            retain_until_epoch_ms,
        };
        let checksum = checksum_payload(&payload)?;
        let mut next_manifest = self.manifest.clone();
        next_manifest.commit_sequence =
            next_manifest
                .commit_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    attempt_ledger_error(
                        "attempt_ledger_corrupt",
                        "ledger commit sequence is exhausted",
                    )
                })?;
        next_manifest.active_binding_count = next_manifest
            .active_binding_count
            .checked_add(1)
            .ok_or_else(|| {
                attempt_ledger_error("attempt_ledger_corrupt", "ledger binding count overflow")
            })?;
        let mut accumulator = decode_accumulator(&next_manifest.active_bindings_accumulator)?;
        xor_accumulator(&mut accumulator, checksum_bytes(&checksum)?);
        next_manifest.active_bindings_accumulator =
            general_purpose::URL_SAFE_NO_PAD.encode(accumulator);
        next_manifest.max_observed_epoch_ms = now_epoch_ms;
        if let Some(directory) = self.directory.as_deref() {
            if let Err(error) = persist_attempt_binding_record(directory, &payload, &checksum) {
                self.poisoned = true;
                return Err(error);
            }
            if let Err(error) = persist_attempt_ledger_manifest(directory, &next_manifest) {
                self.poisoned = true;
                return Err(error);
            }
        }

        self.manifest = next_manifest;
        self.expiry_index
            .insert((retain_until_epoch_ms, attempt_id.to_string()));
        self.bindings.insert(attempt_id.to_string(), payload);
        Ok(())
    }

    fn prune_expired(&mut self, now_epoch_ms: u64) -> Result<(), ProtocolError> {
        self.ensure_available()?;
        let expired = self
            .expiry_index
            .iter()
            .take_while(|(expires_at, _)| *expires_at <= now_epoch_ms)
            .cloned()
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return Ok(());
        }

        let mut next_manifest = self.manifest.clone();
        next_manifest.commit_sequence =
            next_manifest
                .commit_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    attempt_ledger_error(
                        "attempt_ledger_corrupt",
                        "ledger commit sequence is exhausted",
                    )
                })?;
        next_manifest.pruned_through_epoch_ms = next_manifest
            .pruned_through_epoch_ms
            .max(expired.last().expect("non-empty expiry list").0);
        next_manifest.max_observed_epoch_ms = now_epoch_ms;
        let mut accumulator = decode_accumulator(&next_manifest.active_bindings_accumulator)?;
        for (_, attempt_id) in &expired {
            let binding = self.bindings.get(attempt_id).ok_or_else(|| {
                attempt_ledger_error(
                    "attempt_ledger_corrupt",
                    "expiry index references a missing binding",
                )
            })?;
            xor_accumulator(
                &mut accumulator,
                checksum_bytes(&checksum_payload(binding)?)?,
            );
        }
        next_manifest.active_binding_count = next_manifest
            .active_binding_count
            .checked_sub(expired.len())
            .ok_or_else(|| {
                attempt_ledger_error("attempt_ledger_corrupt", "ledger binding count underflow")
            })?;
        next_manifest.active_bindings_accumulator =
            general_purpose::URL_SAFE_NO_PAD.encode(accumulator);
        if let Some(directory) = self.directory.as_deref() {
            if let Err(error) = persist_attempt_ledger_manifest(directory, &next_manifest) {
                self.poisoned = true;
                return Err(error);
            }
            self.manifest = next_manifest.clone();
            for (_, attempt_id) in &expired {
                let path = directory.join(attempt_binding_filename(attempt_id)?);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        self.poisoned = true;
                        return Err(attempt_ledger_error(
                            "attempt_ledger_io",
                            format!("remove expired binding {}: {error}", path.display()),
                        ));
                    }
                }
            }
            if let Err(error) = sync_directory(directory) {
                self.poisoned = true;
                return Err(error);
            }
        }

        self.manifest = next_manifest;
        for entry in expired {
            self.expiry_index.remove(&entry);
            self.bindings.remove(&entry.1);
        }
        Ok(())
    }

    fn advance_max_observed_time(&mut self, now_epoch_ms: u64) -> Result<(), ProtocolError> {
        self.ensure_available()?;
        if now_epoch_ms <= self.manifest.max_observed_epoch_ms {
            return Ok(());
        }
        let mut next_manifest = self.manifest.clone();
        next_manifest.commit_sequence =
            next_manifest
                .commit_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    attempt_ledger_error(
                        "attempt_ledger_corrupt",
                        "ledger commit sequence is exhausted",
                    )
                })?;
        next_manifest.max_observed_epoch_ms = now_epoch_ms;
        if let Some(directory) = self.directory.as_deref() {
            if let Err(error) = persist_attempt_ledger_manifest(directory, &next_manifest) {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.manifest = next_manifest;
        Ok(())
    }

    fn ensure_available(&self) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(attempt_ledger_error(
                "attempt_ledger_unavailable",
                "attempt ledger requires runtime restart after an incomplete durable update",
            ));
        }
        Ok(())
    }
}

fn empty_attempt_ledger_manifest() -> AttemptLedgerManifestPayload {
    AttemptLedgerManifestPayload {
        api_version: ATTEMPT_LEDGER_API_VERSION.to_string(),
        commit_sequence: 0,
        active_binding_count: 0,
        active_bindings_accumulator: general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]),
        pruned_through_epoch_ms: 0,
        max_observed_epoch_ms: 0,
    }
}

fn current_epoch_ms() -> Result<u64, ProtocolError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            attempt_ledger_error(
                "attempt_ledger_clock_rollback",
                "system clock precedes the Unix epoch",
            )
        })?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| {
        attempt_ledger_error(
            "attempt_ledger_clock_invalid",
            "system clock exceeds the supported epoch range",
        )
    })
}

fn attempt_ledger_error(code: &'static str, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

fn validate_attempt_ledger_directory(directory: &Path) -> Result<(), ProtocolError> {
    if !directory.is_absolute() {
        return Err(attempt_ledger_error(
            "invalid_attempt_ledger_configuration",
            "attempt ledger directory must be an absolute path",
        ));
    }
    let mut current = PathBuf::new();
    for component in directory.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(component) => current.push(component),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(attempt_ledger_error(
                    "invalid_attempt_ledger_configuration",
                    "attempt ledger directory must be a normalized absolute path",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            attempt_ledger_error(
                "invalid_attempt_ledger_configuration",
                format!(
                    "inspect attempt ledger ancestor {}: {error}",
                    current.display()
                ),
            )
        })?;
        if !metadata.file_type().is_dir() {
            return Err(attempt_ledger_error(
                "invalid_attempt_ledger_configuration",
                format!(
                    "attempt ledger ancestor {} must be a non-symlink directory",
                    current.display()
                ),
            ));
        }
        if current != directory && metadata.mode() & 0o022 != 0 {
            return Err(attempt_ledger_error(
                "invalid_attempt_ledger_configuration",
                format!(
                    "attempt ledger ancestor {} must not be group- or other-writable",
                    current.display()
                ),
            ));
        }
    }
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        attempt_ledger_error(
            "invalid_attempt_ledger_configuration",
            format!("inspect attempt ledger directory: {error}"),
        )
    })?;
    // SAFETY: geteuid has no memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    // SAFETY: getegid has no memory-safety preconditions.
    let effective_gid = unsafe { libc::getegid() };
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid
        || metadata.gid() != effective_gid
        || metadata.mode() & 0o7777 != ATTEMPT_LEDGER_DIRECTORY_MODE
    {
        return Err(attempt_ledger_error(
            "invalid_attempt_ledger_configuration",
            format!(
                "attempt ledger directory {} must be a non-symlink directory owned by UID {} and GID {} with mode {:04o}",
                directory.display(),
                effective_uid,
                effective_gid,
                ATTEMPT_LEDGER_DIRECTORY_MODE
            ),
        ));
    }
    Ok(())
}

fn open_attempt_ledger_lock(directory: &Path) -> Result<fs::File, ProtocolError> {
    let path = directory.join(ATTEMPT_LEDGER_LOCK_FILE);
    let existed = fs::symlink_metadata(&path).is_ok();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(ATTEMPT_LEDGER_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            attempt_ledger_error(
                "invalid_attempt_ledger_configuration",
                format!("open attempt ledger lock: {error}"),
            )
        })?;
    validate_attempt_ledger_file_metadata(&file, &path, 0)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(attempt_ledger_error(
            "attempt_ledger_locked",
            format!(
                "attempt ledger directory {} is already locked by another runtime: {}",
                directory.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    if !existed {
        sync_directory(directory)?;
    }
    Ok(file)
}

fn load_attempt_ledger_manifest(
    path: &Path,
) -> Result<AttemptLedgerManifestPayload, ProtocolError> {
    Ok(load_attempt_ledger_manifest_record(path)?.payload)
}

fn load_attempt_ledger_manifest_record(
    path: &Path,
) -> Result<AttemptLedgerManifestRecord, ProtocolError> {
    let bytes = read_attempt_ledger_file(path, MAX_ATTEMPT_LEDGER_MANIFEST_BYTES)?;
    let record: AttemptLedgerManifestRecord = decode_canonical_json(&bytes).map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("decode ledger manifest: {error}"),
        )
    })?;
    validate_attempt_ledger_manifest_record(&record)?;
    Ok(record)
}

fn validate_attempt_ledger_manifest_record(
    record: &AttemptLedgerManifestRecord,
) -> Result<(), ProtocolError> {
    if record.payload.api_version != ATTEMPT_LEDGER_API_VERSION
        || record.payload.max_observed_epoch_ms < record.payload.pruned_through_epoch_ms
        || record.checksum != checksum_payload(&record.payload)?
    {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            "ledger manifest version or checksum is invalid",
        ));
    }
    decode_accumulator(&record.payload.active_bindings_accumulator)?;
    Ok(())
}

fn load_attempt_binding_record(path: &Path) -> Result<AttemptBindingRecord, ProtocolError> {
    let bytes = read_attempt_ledger_file(path, MAX_ATTEMPT_LEDGER_RECORD_BYTES)?;
    let record: AttemptBindingRecord = decode_canonical_json(&bytes).map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("decode binding record {}: {error}", path.display()),
        )
    })?;
    validate_attempt_binding_record(&record, &path.display().to_string())?;
    Ok(record)
}

fn validate_attempt_binding_record(
    record: &AttemptBindingRecord,
    label: &str,
) -> Result<(), ProtocolError> {
    if record.payload.api_version != ATTEMPT_LEDGER_API_VERSION
        || record.payload.retain_until_epoch_ms == 0
        || record.checksum != checksum_payload(&record.payload)?
    {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("binding record {label} is invalid"),
        ));
    }
    validate_sha256_digest("ledger attempt_id", &record.payload.attempt_id)
        .map_err(|error| attempt_ledger_error("attempt_ledger_corrupt", error.message))?;
    validate_sha256_digest("ledger statement_digest", &record.payload.statement_digest)
        .map_err(|error| attempt_ledger_error("attempt_ledger_corrupt", error.message))?;
    Ok(())
}

fn read_attempt_ledger_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("open ledger file {}: {error}", path.display()),
            )
        })?;
    let initial = validate_attempt_ledger_file_metadata(&file, path, max_bytes)?;
    let initial_modified = initial.modified().ok();
    let mut bytes = Vec::with_capacity(initial.len() as usize);
    let mut reader = file.take((max_bytes + 1) as u64);
    reader.read_to_end(&mut bytes).map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_io",
            format!("read ledger file {}: {error}", path.display()),
        )
    })?;
    if bytes.len() > max_bytes {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("ledger file {} exceeds {max_bytes} bytes", path.display()),
        ));
    }
    let final_metadata = reader.get_ref().metadata().map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_io",
            format!("reinspect ledger file {}: {error}", path.display()),
        )
    })?;
    if final_metadata.len() != initial.len()
        || final_metadata.len() != bytes.len() as u64
        || initial_modified
            .zip(final_metadata.modified().ok())
            .is_some_and(|(before, after)| before != after)
    {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("ledger file {} changed while loading", path.display()),
        ));
    }
    Ok(bytes)
}

fn validate_attempt_ledger_file_metadata(
    file: &fs::File,
    path: &Path,
    max_bytes: usize,
) -> Result<fs::Metadata, ProtocolError> {
    let metadata = file.metadata().map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_io",
            format!("inspect ledger file {}: {error}", path.display()),
        )
    })?;
    // SAFETY: geteuid has no memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    // SAFETY: getegid has no memory-safety preconditions.
    let effective_gid = unsafe { libc::getegid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.gid() != effective_gid
        || metadata.mode() & 0o7777 != ATTEMPT_LEDGER_FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() > max_bytes as u64
    {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!(
                "ledger file {} must be a single-link regular file owned by UID {} and GID {} with mode {:04o} and at most {max_bytes} bytes",
                path.display(),
                effective_uid,
                effective_gid,
                ATTEMPT_LEDGER_FILE_MODE
            ),
        ));
    }
    Ok(metadata)
}

fn remove_orphan_attempt_ledger_temporary(path: &Path) -> Result<(), ProtocolError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_corrupt",
                format!(
                    "open orphan ledger temporary file {} without following links: {error}",
                    path.display()
                ),
            )
        })?;
    let opened = validate_attempt_ledger_file_metadata(
        &file,
        path,
        MAX_ATTEMPT_LEDGER_RECORD_BYTES.max(MAX_ATTEMPT_LEDGER_MANIFEST_BYTES),
    )?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!(
                "reinspect orphan ledger temporary file {}: {error}",
                path.display()
            ),
        )
    })?;
    if path_metadata.dev() != opened.dev()
        || path_metadata.ino() != opened.ino()
        || path_metadata.nlink() != opened.nlink()
    {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!(
                "orphan ledger temporary file changed before cleanup: {}",
                path.display()
            ),
        ));
    }
    fs::remove_file(path).map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_io",
            format!(
                "remove validated orphan ledger temporary file {}: {error}",
                path.display()
            ),
        )
    })
}

fn persist_attempt_binding_record(
    directory: &Path,
    payload: &AttemptBindingPayload,
    checksum: &str,
) -> Result<(), ProtocolError> {
    let path = directory.join(attempt_binding_filename(&payload.attempt_id)?);
    if fs::symlink_metadata(&path).is_ok() {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("unexpected existing binding record {}", path.display()),
        ));
    }
    let record = AttemptBindingRecord {
        payload: payload.clone(),
        checksum: checksum.to_string(),
    };
    write_atomic_ledger_file(&path, &canonical_json_bytes(&record)?, false)
}

fn persist_attempt_ledger_manifest(
    directory: &Path,
    payload: &AttemptLedgerManifestPayload,
) -> Result<(), ProtocolError> {
    let record = AttemptLedgerManifestRecord {
        payload: payload.clone(),
        checksum: checksum_payload(payload)?,
    };
    write_atomic_ledger_file(
        &directory.join(ATTEMPT_LEDGER_MANIFEST_FILE),
        &canonical_json_bytes(&record)?,
        true,
    )
}

fn write_atomic_ledger_file(path: &Path, bytes: &[u8], replace: bool) -> Result<(), ProtocolError> {
    let directory = path.parent().ok_or_else(|| {
        attempt_ledger_error("attempt_ledger_io", "ledger file has no parent directory")
    })?;
    if !replace && fs::symlink_metadata(path).is_ok() {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            format!("refusing to replace ledger file {}", path.display()),
        ));
    }
    if replace {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let existing = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|error| {
                        attempt_ledger_error(
                            "attempt_ledger_io",
                            format!("open existing ledger file {}: {error}", path.display()),
                        )
                    })?;
                validate_attempt_ledger_file_metadata(
                    &existing,
                    path,
                    MAX_ATTEMPT_LEDGER_MANIFEST_BYTES,
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(attempt_ledger_error(
                    "attempt_ledger_io",
                    format!("inspect ledger file {}: {error}", path.display()),
                ));
            }
        }
    }

    let mut random_bytes = [0u8; 16];
    SystemRandom::new().fill(&mut random_bytes).map_err(|_| {
        attempt_ledger_error("entropy_unavailable", "generate ledger temporary filename")
    })?;
    let temporary_path = directory.join(format!(
        ".ledger-tmp-{}-{}",
        std::process::id(),
        hex::encode(random_bytes)
    ));
    let result = (|| {
        let mut temporary = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(ATTEMPT_LEDGER_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)
            .map_err(|error| {
                attempt_ledger_error(
                    "attempt_ledger_io",
                    format!("create ledger temporary file: {error}"),
                )
            })?;
        temporary.write_all(bytes).map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("write ledger temporary file: {error}"),
            )
        })?;
        temporary.sync_all().map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("synchronize ledger temporary file: {error}"),
            )
        })?;
        drop(temporary);
        if !replace && fs::symlink_metadata(path).is_ok() {
            return Err(attempt_ledger_error(
                "attempt_ledger_corrupt",
                format!("refusing to replace ledger file {}", path.display()),
            ));
        }
        fs::rename(&temporary_path, path).map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("atomically publish ledger file {}: {error}", path.display()),
            )
        })?;
        sync_directory(directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn sync_directory(directory: &Path) -> Result<(), ProtocolError> {
    let directory_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|error| {
            attempt_ledger_error(
                "attempt_ledger_io",
                format!("open ledger directory for synchronization: {error}"),
            )
        })?;
    directory_file.sync_all().map_err(|error| {
        attempt_ledger_error(
            "attempt_ledger_io",
            format!("synchronize ledger directory: {error}"),
        )
    })
}

fn checksum_payload<T: Serialize>(payload: &T) -> Result<String, ProtocolError> {
    Ok(sha256_prefixed(&canonical_json_bytes(payload)?))
}

fn checksum_bytes(checksum: &str) -> Result<[u8; 32], ProtocolError> {
    validate_sha256_digest("ledger checksum", checksum)
        .map_err(|error| attempt_ledger_error("attempt_ledger_corrupt", error.message))?;
    let decoded = hex::decode(&checksum[7..]).map_err(|_| {
        attempt_ledger_error("attempt_ledger_corrupt", "ledger checksum is not valid hex")
    })?;
    decoded.try_into().map_err(|_| {
        attempt_ledger_error(
            "attempt_ledger_corrupt",
            "ledger checksum has an invalid length",
        )
    })
}

fn decode_accumulator(value: &str) -> Result<[u8; 32], ProtocolError> {
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| {
            attempt_ledger_error(
                "attempt_ledger_corrupt",
                "ledger binding accumulator is not canonical base64url",
            )
        })?;
    if general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(attempt_ledger_error(
            "attempt_ledger_corrupt",
            "ledger binding accumulator is not canonical base64url",
        ));
    }
    decoded.try_into().map_err(|_| {
        attempt_ledger_error(
            "attempt_ledger_corrupt",
            "ledger binding accumulator must be 32 bytes",
        )
    })
}

fn xor_accumulator(accumulator: &mut [u8; 32], value: [u8; 32]) {
    for (target, source) in accumulator.iter_mut().zip(value) {
        *target ^= source;
    }
}

fn attempt_binding_filename(attempt_id: &str) -> Result<String, ProtocolError> {
    validate_sha256_digest("release_authority.attempt_id", attempt_id)?;
    Ok(format!("binding-{}.json", &attempt_id[7..]))
}

fn parse_attempt_binding_filename(filename: &str) -> Option<String> {
    let digest = filename.strip_prefix("binding-")?.strip_suffix(".json")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(format!("sha256:{digest}"))
}

fn parse_attempt_ledger_temporary_filename(filename: &str) -> bool {
    let Some(value) = filename.strip_prefix(".ledger-tmp-") else {
        return false;
    };
    let Some((process_id, nonce)) = value.split_once('-') else {
        return false;
    };
    process_id
        .parse::<u32>()
        .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == process_id)
        && nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn configured_control_plane_response_verifying_key() -> Result<Option<VerifyingKey>, ProtocolError>
{
    configured_control_plane_response_verifying_key_from_values(
        env::var_os(CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV),
        env::var_os(CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV),
        env::var_os(CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV),
    )
}

fn configured_control_plane_response_verifying_key_from_values(
    public_key_path: Option<OsString>,
    expected_key_id: Option<OsString>,
    expected_key_id_file: Option<OsString>,
) -> Result<Option<VerifyingKey>, ProtocolError> {
    let (public_key_path, expected_key_id, key_id_source) = match (
        public_key_path,
        expected_key_id,
        expected_key_id_file,
    ) {
        (None, None, None) => return Ok(None),
        (Some(public_key_path), Some(expected_key_id), None) => {
            let expected_key_id = expected_key_id.into_string().map_err(|_| {
                ProtocolError::new(
                    "invalid_control_plane_response_key_configuration",
                    format!("{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} must be valid UTF-8"),
                )
            })?;
            (
                public_key_path,
                expected_key_id,
                CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV,
            )
        }
        (Some(public_key_path), None, Some(expected_key_id_file)) => (
            public_key_path,
            read_control_plane_response_public_key_id(Path::new(&expected_key_id_file))?,
            CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV,
        ),
        _ => {
            return Err(ProtocolError::new(
                "invalid_control_plane_response_key_configuration",
                format!(
                    "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} must be configured with exactly one of {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} or {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV}"
                ),
            ))
        }
    };
    let public_key_pem = read_control_plane_response_public_key_pem(Path::new(&public_key_path))?;
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem).map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} must contain an Ed25519 SubjectPublicKeyInfo PEM: {error}"
            ),
        )
    })?;
    validate_pinned_control_plane_response_key_from_source(
        &verifying_key,
        &expected_key_id,
        key_id_source,
    )?;
    Ok(Some(verifying_key))
}

fn read_control_plane_response_public_key_pem(path: &Path) -> Result<String, ProtocolError> {
    read_control_plane_response_configuration_file(
        path,
        CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV,
        MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES,
    )
}

fn read_control_plane_response_public_key_id(path: &Path) -> Result<String, ProtocolError> {
    let contents = read_control_plane_response_configuration_file(
        path,
        CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV,
        MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_BYTES,
    )?;
    contents
        .strip_suffix('\n')
        .map(str::to_string)
        .ok_or_else(|| {
            ProtocolError::new(
                "invalid_control_plane_response_key_configuration",
                format!(
                    "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_FILE_ENV} must contain one newline-terminated canonical lowercase sha256 digest"
                ),
            )
        })
}

fn read_control_plane_response_configuration_file(
    path: &Path,
    configuration_name: &'static str,
    max_bytes: usize,
) -> Result<String, ProtocolError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            ProtocolError::new(
                "invalid_control_plane_response_key_configuration",
                format!("open {configuration_name}: {error}"),
            )
        })?;
    let initial_metadata = file.metadata().map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("inspect {configuration_name}: {error}"),
        )
    })?;
    if !initial_metadata.is_file() {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{configuration_name} must be a regular file"),
        ));
    }
    if initial_metadata.len() > max_bytes as u64 {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{configuration_name} exceeds {max_bytes} bytes"),
        ));
    }

    let initial_modified = initial_metadata.modified().ok();
    let mut bytes = Vec::with_capacity(initial_metadata.len() as usize);
    let mut bounded_reader = file.take((max_bytes + 1) as u64);
    bounded_reader.read_to_end(&mut bytes).map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("read {configuration_name}: {error}"),
        )
    })?;
    if bytes.len() > max_bytes {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{configuration_name} exceeds {max_bytes} bytes"),
        ));
    }

    let final_metadata = bounded_reader.get_ref().metadata().map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("reinspect {configuration_name}: {error}"),
        )
    })?;
    let modified_during_read = initial_modified
        .zip(final_metadata.modified().ok())
        .is_some_and(|(initial, final_value)| initial != final_value);
    if !final_metadata.is_file()
        || final_metadata.len() != initial_metadata.len()
        || final_metadata.len() != bytes.len() as u64
        || modified_during_read
    {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{configuration_name} changed while it was being loaded"),
        ));
    }

    String::from_utf8(bytes).map_err(|_| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{configuration_name} must contain valid UTF-8"),
        )
    })
}

fn validate_pinned_control_plane_response_key(
    verifying_key: &VerifyingKey,
    expected_key_id: &str,
) -> Result<(), ProtocolError> {
    validate_pinned_control_plane_response_key_from_source(
        verifying_key,
        expected_key_id,
        CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV,
    )
}

fn validate_pinned_control_plane_response_key_from_source(
    verifying_key: &VerifyingKey,
    expected_key_id: &str,
    key_id_source: &'static str,
) -> Result<(), ProtocolError> {
    if expected_key_id.len() != 71
        || !expected_key_id.starts_with("sha256:")
        || !expected_key_id[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{key_id_source} must be a canonical lowercase sha256 digest"),
        ));
    }
    let actual_key_id = control_plane_response_key_id(verifying_key);
    if expected_key_id != actual_key_id {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{key_id_source} does not match the configured Ed25519 public key"),
        ));
    }
    Ok(())
}

fn control_plane_response_key_id(verifying_key: &VerifyingKey) -> String {
    sha256_prefixed(&ed25519_spki_der(verifying_key.as_bytes()))
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(value).map_err(|error| {
        ProtocolError::new(
            "json_serialization_error",
            format!("convert value to canonical JSON: {error}"),
        )
    })?;
    serde_json::to_vec(&value).map_err(|error| {
        ProtocolError::new(
            "json_serialization_error",
            format!("serialize canonical JSON: {error}"),
        )
    })
}

pub fn decode_canonical_json<T>(bytes: &[u8]) -> Result<T, ProtocolError>
where
    T: for<'de> Deserialize<'de>,
{
    let value = parse_json_without_duplicate_keys(bytes)?;
    let canonical = serde_json::to_vec(&value).map_err(|error| {
        ProtocolError::new(
            "json_serialization_error",
            format!("re-serialize canonical JSON: {error}"),
        )
    })?;
    if bytes != canonical {
        return Err(ProtocolError::new(
            "noncanonical_json",
            "frame payload must be compact canonical JSON with lexicographically sorted object keys",
        ));
    }
    serde_json::from_value(value).map_err(|error| {
        ProtocolError::new("invalid_request", format!("decode typed request: {error}"))
    })
}

fn parse_json_without_duplicate_keys(bytes: &[u8]) -> Result<Value, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue
        .deserialize(&mut deserializer)
        .map_err(|error| ProtocolError::new("invalid_json", error.to_string()))?;
    deserializer.end().map_err(|error| {
        ProtocolError::new("invalid_json", format!("trailing JSON data: {error}"))
    })?;
    Ok(value)
}

struct UniqueValue;

impl<'de> DeserializeSeed<'de> for UniqueValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        UniqueValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(UniqueValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            let value = map.next_value_seed(UniqueValue)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn from_value_strict<T>(value: Value, label: &str) -> Result<T, ProtocolError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|error| {
        ProtocolError::new("invalid_operation_params", format!("{label}: {error}"))
    })
}

pub fn validate_response_statement(
    statement: &ProxyResponseStatement,
) -> Result<(), ProtocolError> {
    validate_response_statement_inner(statement, None, current_epoch_ms()?)
}

pub fn validate_response_statement_with_control_plane_response_key(
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    validate_response_statement_with_control_plane_response_key_at(
        statement,
        control_plane_response_verifying_key,
        current_epoch_ms()?,
    )
}

fn validate_response_statement_with_control_plane_response_key_at(
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: &VerifyingKey,
    now_epoch_ms: u64,
) -> Result<(), ProtocolError> {
    validate_response_statement_inner(
        statement,
        Some(control_plane_response_verifying_key),
        now_epoch_ms,
    )
}

fn validate_response_statement_inner(
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: Option<&VerifyingKey>,
    now_epoch_ms: u64,
) -> Result<(), ProtocolError> {
    if statement.api_version != RESPONSE_STATEMENT_API_VERSION {
        return Err(invalid_statement(
            "apiVersion must be serverware.proxyResponseStatement/v2",
        ));
    }
    let now = now_epoch_ms / 1000;
    if statement.issued_at_unix > now.saturating_add(30)
        || now.saturating_sub(statement.issued_at_unix) > MAX_STATEMENT_AGE_SECONDS
    {
        return Err(invalid_statement(
            "issued_at_unix is outside the allowed clock window",
        ));
    }
    validate_base64url(
        "client_nonce",
        &statement.client_nonce,
        MIN_CLIENT_NONCE_BYTES,
        MAX_CLIENT_NONCE_BYTES,
    )?;
    validate_bounded_identity("principal_id", &statement.principal_id)?;
    validate_bounded_identity("route_id", &statement.route_id)?;
    for (name, digest) in [
        ("client_request_digest", &statement.client_request_digest),
        ("request_digest", &statement.request_digest),
        ("operation_digest", &statement.operation_digest),
        (
            "release_authority.request_digest",
            &statement.release_authority.request_digest,
        ),
        (
            "release_authority.operation_digest",
            &statement.release_authority.operation_digest,
        ),
        (
            "release_authority.consumption_identity_digest",
            &statement.release_authority.consumption_identity_digest,
        ),
        (
            "release_authority.request_digest",
            &statement.release_authority.request_digest,
        ),
        (
            "release_authority.operation_digest",
            &statement.release_authority.operation_digest,
        ),
        (
            "release_authority.consumption_identity_digest",
            &statement.release_authority.consumption_identity_digest,
        ),
        (
            "upstream_response.body_digest",
            &statement.upstream_response.body_digest,
        ),
        (
            "upstream_response.canonical_digest",
            &statement.upstream_response.canonical_digest,
        ),
        ("response.body_digest", &statement.response.body_digest),
        (
            "response.selected_headers_digest",
            &statement.response.selected_headers_digest,
        ),
        ("policy_digest", &statement.policy_digest),
        (
            "runtime_manifest_digest",
            &statement.runtime_manifest_digest,
        ),
        (
            "data_plane_binary_digest",
            &statement.data_plane_binary_digest,
        ),
        ("release_digest", &statement.release_digest),
        (
            "server_instance.identity_digest",
            &statement.server_instance.identity_digest,
        ),
    ] {
        validate_sha256_digest(name, digest)?;
    }
    if !(200..300).contains(&statement.response.status) {
        return Err(invalid_statement(
            "response.status must be a successful HTTP status",
        ));
    }
    let authority_view = ResponseStatementAuthorityView::from(statement);
    validate_release_authority(&authority_view)?;
    validate_control_plane_authorization_receipt(
        &authority_view,
        control_plane_response_verifying_key,
        now_epoch_ms,
    )?;
    if statement.upstream_response.status != statement.response.status {
        return Err(invalid_statement(
            "upstream_response.status must match response.status",
        ));
    }
    validate_upstream_response(&statement.upstream_response)?;
    validate_selected_headers(statement)?;
    validate_server_instance(&statement.server_instance)?;
    if statement.tls_channel_binding.binding_type != "tls-exporter" {
        return Err(invalid_statement(
            "tls_channel_binding.type must be tls-exporter",
        ));
    }
    validate_base64url(
        "tls_channel_binding.value",
        &statement.tls_channel_binding.value,
        TLS_EXPORTER_BYTES,
        TLS_EXPORTER_BYTES,
    )?;
    Ok(())
}

fn validate_streaming_response_statement_with_control_plane_response_key_at(
    statement: &StreamingResponseStatement,
    authorization_binding: &ReleaseAuthorizationBinding,
    control_plane_response_verifying_key: &VerifyingKey,
    now_epoch_ms: u64,
) -> Result<(), ProtocolError> {
    if statement.api_version != STREAMING_RESPONSE_STATEMENT_API_VERSION {
        return Err(invalid_statement(
            "apiVersion must be serverware.streamingResponseStatement/v1",
        ));
    }
    let now = now_epoch_ms / 1000;
    if statement.issued_at_unix == 0
        || statement.issued_at_unix > now.saturating_add(30)
        || now.saturating_sub(statement.issued_at_unix) > MAX_STATEMENT_AGE_SECONDS
    {
        return Err(invalid_statement(
            "issued_at_unix is outside the allowed clock window",
        ));
    }
    validate_base64url("client_nonce", &statement.client_nonce, 32, 32)?;
    validate_streaming_identifier("principal_id", &statement.principal_id)?;
    validate_streaming_identifier("route_id", &statement.route_id)?;
    for (name, digest) in [
        ("client_request_digest", &statement.client_request_digest),
        ("request_digest", &statement.request_digest),
        ("operation_digest", &statement.operation_digest),
        (
            "control_plane_authorization_receipt_sha256",
            &statement.control_plane_authorization_receipt_sha256,
        ),
        (
            "authorization_binding_validation.binding_digest",
            &statement.authorization_binding_validation.binding_digest,
        ),
        (
            "upstream_response.body_digest",
            &statement.upstream_response.body_digest,
        ),
        (
            "upstream_response.canonical_digest",
            &statement.upstream_response.canonical_digest,
        ),
        (
            "released_response.selected_wire_headers_digest",
            &statement.released_response.selected_wire_headers_digest,
        ),
        (
            "released_response.body_digest",
            &statement.released_response.body_digest,
        ),
        ("policy_digest", &statement.policy_digest),
        (
            "runtime_manifest_digest",
            &statement.runtime_manifest_digest,
        ),
        (
            "data_plane_binary_digest",
            &statement.data_plane_binary_digest,
        ),
        ("release_digest", &statement.release_digest),
        (
            "server_instance.identity_digest",
            &statement.server_instance.identity_digest,
        ),
    ] {
        validate_sha256_digest(name, digest)?;
    }

    let authority_view = ResponseStatementAuthorityView::from(statement);
    validate_release_authority(&authority_view)?;
    validate_streaming_release_identifiers(statement, authorization_binding)?;
    validate_control_plane_authorization_receipt(
        &authority_view,
        Some(control_plane_response_verifying_key),
        now_epoch_ms,
    )?;
    let receipt_digest = sha256_prefixed(&canonical_json_bytes(
        &statement.control_plane_authorization_receipt,
    )?);
    if statement.control_plane_authorization_receipt_sha256 != receipt_digest {
        return Err(invalid_statement(
            "control_plane_authorization_receipt_sha256 does not match the receipt",
        ));
    }
    validate_release_authorization_binding(&authority_view, authorization_binding)?;
    validate_streaming_authorization_binding(statement, authorization_binding)?;
    validate_streaming_upstream_response(&statement.upstream_response)?;
    validate_streaming_released_response(&statement.released_response)?;
    if statement.upstream_response.status != statement.released_response.status {
        return Err(invalid_statement(
            "upstream_response.status must match released_response.status",
        ));
    }
    validate_streaming_server_instance(&statement.server_instance)?;
    if statement.tls_channel_binding.binding_type != "tls-exporter"
        || statement.tls_channel_binding.exporter_label != "EXPORTER-Serverware-Proxy-Stream-v1"
    {
        return Err(invalid_statement(
            "tls_channel_binding must use the streaming TLS exporter domain",
        ));
    }
    validate_base64url(
        "tls_channel_binding.value",
        &statement.tls_channel_binding.value,
        TLS_EXPORTER_BYTES,
        TLS_EXPORTER_BYTES,
    )?;
    Ok(())
}

fn validate_streaming_identifier(name: &str, value: &str) -> Result<(), ProtocolError> {
    validate_bounded_identity(name, value)?;
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(invalid_statement(format!(
            "{name} is not a canonical streaming-proof identifier"
        )));
    }
    Ok(())
}

fn validate_streaming_release_identifiers(
    statement: &StreamingResponseStatement,
    binding: &ReleaseAuthorizationBinding,
) -> Result<(), ProtocolError> {
    for (name, value) in [
        (
            "release_authority.grant_id",
            statement.release_authority.grant_id.as_deref(),
        ),
        (
            "release_authority.approval_id",
            statement.release_authority.approval_id.as_deref(),
        ),
        (
            "release_authority.credential_ref",
            statement.release_authority.credential_ref.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_streaming_identifier(name, value)?;
        }
    }
    validate_streaming_identifier("binding.principal_id", &binding.principal_id)?;
    validate_streaming_identifier("binding.route_id", &binding.route_id)?;
    if !binding.credential_id.is_empty() {
        validate_streaming_identifier("binding.credential_id", &binding.credential_id)?;
    }
    for quota in &binding.shared_quotas {
        validate_streaming_identifier("binding.quota.constraint_id", &quota.constraint_id)?;
        if let Some(operation) = quota.operation.as_deref() {
            validate_streaming_identifier("binding.quota.operation", operation)?;
        }
    }
    Ok(())
}

fn validate_streaming_authorization_binding(
    statement: &StreamingResponseStatement,
    binding: &ReleaseAuthorizationBinding,
) -> Result<(), ProtocolError> {
    let operation_digest = binding.operation_digest.clone().ok_or_else(|| {
        invalid_statement("streaming authorization binding is missing operation_digest")
    })?;
    let operation_context_digest = sha256_prefixed(&canonical_json_ensure_ascii_bytes(
        &binding.operation_context,
    )?);
    let expected_commitment = AuthorizationBindingCommitment {
        attempt_id: binding.attempt_id.clone(),
        flow_id: binding.flow_id.clone(),
        principal_id: binding.principal_id.clone(),
        route_id: binding.route_id.clone(),
        credential_id: binding.credential_id.clone(),
        credential_version: binding.credential_version,
        policy_hash: binding.policy_hash.clone(),
        request_digest: binding.request_digest.clone(),
        operation_digest,
        operation_context_digest,
        require_jit_grant: binding.require_jit_grant,
        shared_quotas: binding.shared_quotas.clone(),
    };
    let binding_digest = sha256_prefixed(&canonical_json_ensure_ascii_bytes(binding)?);
    let validation = &statement.authorization_binding_validation;
    if validation.status != "validated"
        || validation.binding_digest != binding_digest
        || validation.binding_digest != statement.release_authority.consumption_identity_digest
        || validation.binding_commitment != expected_commitment
    {
        return Err(invalid_statement(
            "authorization_binding_validation does not match the release binding",
        ));
    }
    Ok(())
}

fn validate_streaming_upstream_response(
    upstream: &StreamingUpstreamResponse,
) -> Result<(), ProtocolError> {
    if !(200..300).contains(&upstream.status) {
        return Err(invalid_statement(
            "upstream_response.status must be a successful HTTP status",
        ));
    }
    validate_raw_policy_headers(&upstream.selected_raw_policy_headers_b64)?;
    let canonical = canonical_json_bytes(&StreamingUpstreamResponseDigest {
        status: upstream.status,
        selected_raw_policy_headers_b64: &upstream.selected_raw_policy_headers_b64,
        body_digest: &upstream.body_digest,
        body_bytes: upstream.body_bytes,
    })?;
    if upstream.canonical_digest != sha256_prefixed(&canonical) {
        return Err(invalid_statement(
            "upstream_response.canonical_digest does not match the streaming upstream binding",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct StreamingUpstreamResponseDigest<'a> {
    status: u16,
    selected_raw_policy_headers_b64: &'a BTreeMap<String, Vec<String>>,
    body_digest: &'a str,
    body_bytes: u64,
}

fn validate_streaming_released_response(
    released: &StreamingReleasedResponse,
) -> Result<(), ProtocolError> {
    if !(200..300).contains(&released.status) {
        return Err(invalid_statement(
            "released_response.status must be a successful HTTP status",
        ));
    }
    if released.content_type.is_empty()
        || released.content_type.len() > 1024
        || released
            .content_type
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(invalid_statement(
            "released_response.content_type is invalid",
        ));
    }
    let headers = &released.selected_wire_headers;
    if headers.connection != "close"
        || headers.content_type != released.content_type
        || headers.trailer != "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256"
        || headers.transfer_encoding != "chunked"
    {
        return Err(invalid_statement(
            "released_response.selected_wire_headers are not the exact streaming proof framing",
        ));
    }
    let selected_wire_headers_digest =
        sha256_prefixed(&canonical_json_bytes(&released.selected_wire_headers)?);
    if released.selected_wire_headers_digest != selected_wire_headers_digest {
        return Err(invalid_statement(
            "released_response.selected_wire_headers_digest does not match selected_wire_headers",
        ));
    }
    if released.framing != "http1.1-chunked-trailers"
        || released.completion != "normal-eof"
        || released.trailer_names
            != [
                "X-Serverware-Stream-Proof-B64".to_string(),
                "X-Serverware-Stream-Proof-SHA256".to_string(),
            ]
    {
        return Err(invalid_statement(
            "released_response completion framing is invalid",
        ));
    }
    Ok(())
}

fn validate_streaming_server_instance(instance: &ServerInstance) -> Result<(), ProtocolError> {
    if !instance.id.starts_with("spiffe://") || !(10..=256).contains(&instance.id.len()) {
        return Err(invalid_statement(
            "server_instance.id must be a bounded SPIFFE ID",
        ));
    }
    validate_streaming_identifier("server_instance.id", &instance.id)?;
    validate_server_instance(instance)
}

fn validate_release_authority(
    statement: &ResponseStatementAuthorityView<'_>,
) -> Result<(), ProtocolError> {
    let authority = &statement.release_authority;
    if authority.authority_mode != "atomic" {
        return Err(invalid_statement(
            "release_authority.authority_mode must be atomic",
        ));
    }
    for (name, value) in [
        ("release_authority.grant_id", authority.grant_id.as_deref()),
        (
            "release_authority.approval_id",
            authority.approval_id.as_deref(),
        ),
        (
            "release_authority.credential_ref",
            authority.credential_ref.as_deref(),
        ),
        (
            "release_authority.attempt_id",
            Some(authority.attempt_id.as_str()),
        ),
    ] {
        if value.is_some_and(|value| {
            value.is_empty()
                || value != value.trim()
                || value.len() > 256
                || value.chars().any(char::is_control)
        }) {
            return Err(invalid_statement(format!("{name} is invalid")));
        }
    }
    if authority.grant_id.is_some() != authority.approval_id.is_some() {
        return Err(invalid_statement(
            "release_authority grant_id and approval_id must be paired",
        ));
    }
    if authority.credential_ref.is_some() != (authority.credential_version > 0) {
        return Err(invalid_statement(
            "release_authority credential_ref and credential_version are inconsistent",
        ));
    }
    validate_sha256_digest("release_authority.attempt_id", &authority.attempt_id)?;
    if authority.request_digest != statement.request_digest
        || authority.operation_digest != statement.operation_digest
    {
        return Err(invalid_statement(
            "release_authority request or operation digest mismatch",
        ));
    }
    if authority.authorization_state_at_upstream_dispatch != "dispatching" {
        return Err(invalid_statement(
            "release_authority.authorization_state_at_upstream_dispatch must be dispatching",
        ));
    }
    let statement_end_epoch_ms = statement
        .issued_at_unix
        .saturating_add(1)
        .saturating_mul(1000)
        .saturating_sub(1);
    if authority.authorization_state_observed_at_epoch_ms == 0
        || authority.authorization_state_observed_at_epoch_ms > statement_end_epoch_ms
        || authority.dispatch_expires_at_epoch_ms
            <= authority.authorization_state_observed_at_epoch_ms
        || authority
            .reservation_expires_at_epoch_ms
            .is_some_and(|expires_at| {
                authority.authorization_state_observed_at_epoch_ms >= expires_at
            })
    {
        return Err(invalid_statement(
            "release_authority historical authorization observation is temporally invalid",
        ));
    }
    let maximum_expiry = authority
        .authorization_state_observed_at_epoch_ms
        .saturating_add(MAX_RELEASE_AUTHORIZATION_LIFETIME_MS);
    if authority.dispatch_expires_at_epoch_ms > maximum_expiry
        || authority
            .reservation_expires_at_epoch_ms
            .is_some_and(|expires_at| expires_at > maximum_expiry)
    {
        return Err(invalid_statement(
            "release_authority expiry exceeds the bounded response-proof authorization lifetime",
        ));
    }
    Ok(())
}

fn canonical_json_ensure_ascii_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let encoded = String::from_utf8(canonical_json_bytes(value)?).map_err(|_| {
        ProtocolError::new(
            "json_serialization_error",
            "canonical JSON serialization did not produce UTF-8",
        )
    })?;
    let mut ascii = String::with_capacity(encoded.len());
    for character in encoded.chars() {
        let codepoint = character as u32;
        if codepoint <= 0x7f {
            ascii.push(character);
        } else if codepoint <= 0xffff {
            ascii.push_str(&format!("\\u{codepoint:04x}"));
        } else {
            let supplementary = codepoint - 0x1_0000;
            let high = 0xd800 + (supplementary >> 10);
            let low = 0xdc00 + (supplementary & 0x3ff);
            ascii.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
        }
    }
    Ok(ascii.into_bytes())
}

fn validate_release_authorization_binding(
    statement: &ResponseStatementAuthorityView<'_>,
    binding: &ReleaseAuthorizationBinding,
) -> Result<(), ProtocolError> {
    let authority = &statement.release_authority;
    let expected_credential_id = authority.credential_ref.as_deref().unwrap_or("");
    if binding.attempt_id != authority.attempt_id
        || binding.flow_id != authority.attempt_id
        || binding.principal_id != statement.principal_id
        || binding.route_id != statement.route_id
        || binding.credential_id != expected_credential_id
        || binding.credential_version != authority.credential_version
        || binding.policy_hash != statement.policy_digest
        || binding.request_digest != statement.request_digest
        || binding.operation_digest.as_deref() != Some(statement.operation_digest)
    {
        return Err(invalid_statement(
            "release authorization binding claim substitution",
        ));
    }
    if !binding.operation_context.is_object() {
        return Err(invalid_statement(
            "release authorization binding operation_context must be an object",
        ));
    }
    let mut previous_counter_key = None;
    for quota in &binding.shared_quotas {
        validate_sha256_digest(
            "release authorization binding shared quota counter_key",
            &quota.counter_key,
        )?;
        validate_bounded_identity(
            "release authorization binding shared quota constraint_id",
            &quota.constraint_id,
        )?;
        if let Some(operation) = quota.operation.as_deref() {
            validate_bounded_identity(
                "release authorization binding shared quota operation",
                operation,
            )?;
        }
        if match quota.window_kind {
            RateLimitWindowKind::Fixed => !quota
                .window_seconds
                .is_some_and(|value| (1..=31_536_000).contains(&value)),
            _ => quota.window_seconds.is_some(),
        } || !(1..=1_000_000_000).contains(&quota.max_count)
        {
            return Err(invalid_statement(
                "release authorization binding shared quota bounds are invalid",
            ));
        }
        if previous_counter_key.is_some_and(|previous| previous >= quota.counter_key.as_str()) {
            return Err(invalid_statement(
                "release authorization binding shared quotas are not canonically ordered",
            ));
        }
        previous_counter_key = Some(quota.counter_key.as_str());
    }
    validate_dispatch_quotas_against_binding(statement, binding)?;
    let canonical_binding = canonical_json_ensure_ascii_bytes(binding)?;
    if canonical_binding.len() > MAX_RELEASE_AUTHORIZATION_BINDING_BYTES {
        return Err(invalid_statement(format!(
            "release authorization binding exceeds {MAX_RELEASE_AUTHORIZATION_BINDING_BYTES} bytes"
        )));
    }
    if sha256_prefixed(&canonical_binding) != authority.consumption_identity_digest {
        return Err(invalid_statement(
            "release authorization binding digest mismatch",
        ));
    }
    Ok(())
}

fn custody_utc_epoch_ms(timestamp: OffsetDateTime) -> Result<u64, ProtocolError> {
    u64::try_from(timestamp.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| invalid_statement("calendar quota boundary is outside the supported epoch"))
}

fn custody_calendar_window_bounds(
    kind: &RateLimitWindowKind,
    epoch_ms: u64,
) -> Result<(u64, u64), ProtocolError> {
    if !kind.is_calendar() {
        return Err(invalid_statement(
            "fixed quota window has no calendar boundaries",
        ));
    }
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_ms) * 1_000_000)
        .map_err(|_| {
            invalid_statement("calendar quota timestamp is outside the supported epoch")
        })?;
    let date = timestamp.date();
    let start_date = match kind {
        RateLimitWindowKind::UtcDay => date,
        RateLimitWindowKind::UtcIsoWeek => {
            date - TimeDuration::days(i64::from(date.weekday().number_days_from_monday()))
        }
        RateLimitWindowKind::UtcMonth => Date::from_calendar_date(date.year(), date.month(), 1)
            .map_err(|_| invalid_statement("calendar quota month start is invalid"))?,
        RateLimitWindowKind::Fixed => unreachable!("calendar kind checked above"),
    };
    let end_date = match kind {
        RateLimitWindowKind::UtcDay => start_date
            .next_day()
            .ok_or_else(|| invalid_statement("calendar quota day end is outside range"))?,
        RateLimitWindowKind::UtcIsoWeek => start_date
            .checked_add(TimeDuration::days(7))
            .ok_or_else(|| invalid_statement("calendar quota week end is outside range"))?,
        RateLimitWindowKind::UtcMonth => {
            let (year, month) = if start_date.month() == Month::December {
                (
                    start_date.year().checked_add(1).ok_or_else(|| {
                        invalid_statement("calendar quota month end is outside range")
                    })?,
                    Month::January,
                )
            } else {
                (
                    start_date.year(),
                    Month::try_from(u8::from(start_date.month()) + 1)
                        .map_err(|_| invalid_statement("calendar quota month end is invalid"))?,
                )
            };
            Date::from_calendar_date(year, month, 1)
                .map_err(|_| invalid_statement("calendar quota month end is invalid"))?
        }
        RateLimitWindowKind::Fixed => unreachable!("calendar kind checked above"),
    };
    Ok((
        custody_utc_epoch_ms(start_date.midnight().assume_utc())?,
        custody_utc_epoch_ms(end_date.midnight().assume_utc())?,
    ))
}

fn validate_dispatch_quotas_against_binding(
    statement: &ResponseStatementAuthorityView<'_>,
    binding: &ReleaseAuthorizationBinding,
) -> Result<(), ProtocolError> {
    let response_body = decode_receipt_base64url(
        "receipt.response.body_b64",
        &statement
            .control_plane_authorization_receipt
            .response
            .body_b64,
        MAX_AUTHORIZATION_RECEIPT_BODY_BYTES,
    )?;
    let response_value = parse_json_without_duplicate_keys(&response_body)
        .map_err(|error| invalid_statement(format!("dispatch response body: {error}")))?;
    let dispatch_response: DispatchResponseBody = serde_json::from_value(response_value)
        .map_err(|error| invalid_statement(format!("dispatch response body: {error}")))?;
    if dispatch_response.quotas.len() != binding.shared_quotas.len() {
        return Err(invalid_statement(
            "dispatch quota set does not match the release binding",
        ));
    }
    let reservation_expires_at_epoch_ms = dispatch_response
        .reservation_expires_at_epoch_ms
        .ok_or_else(|| invalid_statement("dispatch response is missing reservation expiry"))?;
    let dispatch_started_at_epoch_ms = dispatch_response
        .dispatch_started_at_epoch_ms
        .ok_or_else(|| invalid_statement("dispatch response is missing dispatch start"))?;
    let mut previous_counter_key: Option<&str> = None;
    for actual in &dispatch_response.quotas {
        let counter_key = actual
            .counter_key
            .as_deref()
            .ok_or_else(|| invalid_statement("dispatch quota counter key is missing or invalid"))?;
        validate_sha256_digest("dispatch quota counter key", counter_key)?;
        if previous_counter_key.is_some_and(|previous| previous >= counter_key) {
            return Err(invalid_statement("dispatch quotas are not uniquely sorted"));
        }
        previous_counter_key = Some(counter_key);
    }
    for (actual, expected) in dispatch_response.quotas.iter().zip(&binding.shared_quotas) {
        let counter_key = actual
            .counter_key
            .as_deref()
            .expect("dispatch quota key was validated above");
        let actual_kind = actual
            .window_kind
            .as_ref()
            .unwrap_or(&RateLimitWindowKind::Fixed);
        if counter_key != expected.counter_key
            || actual.constraint_id.as_deref() != Some(expected.constraint_id.as_str())
            || actual.operation != expected.operation
            || actual_kind != &expected.window_kind
            || actual.window_seconds != expected.window_seconds
            || actual.max != Some(expected.max_count)
        {
            return Err(invalid_statement("dispatch quota claim substitution"));
        }
        let window_start_epoch_ms = actual
            .window_start_epoch_ms
            .ok_or_else(|| invalid_statement("dispatch quota window start is missing"))?;
        let window_end_epoch_ms = match expected.window_kind {
            RateLimitWindowKind::Fixed => {
                if actual.calendar_window.is_some() {
                    return Err(invalid_statement(
                        "dispatch fixed quota has a calendar descriptor",
                    ));
                }
                let calculated = window_start_epoch_ms
                    .checked_add(expected.window_seconds.unwrap_or_default() * 1000)
                    .ok_or_else(|| invalid_statement("dispatch fixed quota window overflows"))?;
                if actual
                    .window_end_epoch_ms
                    .is_some_and(|window_end| window_end != calculated)
                {
                    return Err(invalid_statement(
                        "dispatch fixed quota window end is inconsistent",
                    ));
                }
                calculated
            }
            _ => {
                let window_end_epoch_ms = actual.window_end_epoch_ms.ok_or_else(|| {
                    invalid_statement("dispatch calendar quota window end is missing")
                })?;
                if actual.window_kind.as_ref() != Some(&expected.window_kind)
                    || actual.calendar_window.as_ref() != Some(&expected.window_kind)
                    || custody_calendar_window_bounds(&expected.window_kind, window_start_epoch_ms)?
                        != (window_start_epoch_ms, window_end_epoch_ms)
                {
                    return Err(invalid_statement(
                        "dispatch calendar quota boundaries are not exact",
                    ));
                }
                window_end_epoch_ms
            }
        };
        let count = actual
            .count
            .filter(|count| *count <= expected.max_count)
            .ok_or_else(|| invalid_statement("dispatch quota count is missing or invalid"))?;
        if actual.remaining != Some(expected.max_count - count)
            || actual.reservation_state.as_deref() != Some("reserved")
            || dispatch_started_at_epoch_ms < window_start_epoch_ms
            || dispatch_started_at_epoch_ms >= window_end_epoch_ms
            || expected.window_kind.is_calendar()
                && reservation_expires_at_epoch_ms > window_end_epoch_ms
        {
            return Err(invalid_statement(
                "dispatch quota lifecycle evidence is invalid",
            ));
        }
    }
    Ok(())
}

fn decode_receipt_base64url(
    name: &str,
    value: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ProtocolError> {
    if value.contains('=') {
        return Err(invalid_statement(format!(
            "{name} must use unpadded base64url"
        )));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| invalid_statement(format!("{name} is not valid base64url")))?;
    if decoded.len() > max_bytes || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(invalid_statement(format!(
            "{name} is too large or not canonical base64url"
        )));
    }
    Ok(decoded)
}

fn validate_control_plane_authorization_receipt(
    statement: &ResponseStatementAuthorityView<'_>,
    control_plane_response_verifying_key: Option<&VerifyingKey>,
    now_epoch_ms: u64,
) -> Result<(), ProtocolError> {
    let receipt = &statement.control_plane_authorization_receipt;
    if receipt.api_version != AUTHORIZATION_RECEIPT_API_VERSION
        || receipt.kind != "ControlPlaneAuthorizationReceipt"
        || receipt.principal_id != statement.principal_id
        || receipt.route_id != statement.route_id
        || &receipt.release_authority != statement.release_authority
    {
        return Err(invalid_statement(
            "control-plane authorization receipt authority substitution",
        ));
    }
    validate_bounded_identity("receipt.principal_id", &receipt.principal_id)?;
    validate_bounded_identity("receipt.route_id", &receipt.route_id)?;
    let request = &receipt.request;
    if request.method != "POST"
        || request.path != RELEASE_AUTHORIZATION_DISPATCH_PATH
        || !request.query.is_empty()
    {
        return Err(invalid_statement(
            "control-plane authorization receipt request context mismatch",
        ));
    }
    validate_base64url("receipt.request.nonce", &request.nonce, 32, 32)?;
    validate_sha256_digest("receipt.request.body_sha256", &request.body_sha256)?;
    let request_body =
        decode_receipt_base64url("receipt.request.body_b64", &request.body_b64, 4 * 1024)?;
    if request.body_sha256 != sha256_prefixed(&request_body) {
        return Err(invalid_statement(
            "control-plane authorization receipt request body digest mismatch",
        ));
    }
    let dispatch_request: DispatchRequestBody = decode_canonical_json(&request_body)
        .map_err(|error| invalid_statement(format!("dispatch request body: {error}")))?;
    if dispatch_request.api_version != "serverware.releaseAuthorizationDispatch/v1"
        || dispatch_request.attempt_id != statement.release_authority.attempt_id
        || dispatch_request.binding_digest
            != statement.release_authority.consumption_identity_digest
    {
        return Err(invalid_statement(
            "control-plane authorization receipt dispatch request mismatch",
        ));
    }
    let response = &receipt.response;
    if response.status != 200 {
        return Err(invalid_statement(
            "control-plane authorization receipt response status mismatch",
        ));
    }
    validate_sha256_digest("receipt.response.body_sha256", &response.body_sha256)?;
    validate_sha256_digest(
        "receipt.response.response_signing_key_id",
        &response.response_signing_key_id,
    )?;
    if let Some(control_plane_response_verifying_key) = control_plane_response_verifying_key {
        if response.response_signing_key_id
            != control_plane_response_key_id(control_plane_response_verifying_key)
        {
            return Err(invalid_statement(
                "control-plane authorization receipt response key does not match the pinned control-plane response public key",
            ));
        }
    }
    validate_sha256_digest(
        "receipt.response.statement_sha256",
        &response.statement_sha256,
    )?;
    let response_body = decode_receipt_base64url(
        "receipt.response.body_b64",
        &response.body_b64,
        MAX_AUTHORIZATION_RECEIPT_BODY_BYTES,
    )?;
    if response.body_sha256 != sha256_prefixed(&response_body) {
        return Err(invalid_statement(
            "control-plane authorization receipt response body digest mismatch",
        ));
    }
    let response_value = parse_json_without_duplicate_keys(&response_body)
        .map_err(|error| invalid_statement(format!("dispatch response body: {error}")))?;
    let dispatch_response: DispatchResponseBody = serde_json::from_value(response_value)
        .map_err(|error| invalid_statement(format!("dispatch response body: {error}")))?;
    let dispatch_started_at_epoch_ms = dispatch_response
        .dispatch_started_at_epoch_ms
        .ok_or_else(|| invalid_statement("dispatch response is missing dispatch start"))?;
    let dispatch_expires_at_epoch_ms = dispatch_response
        .dispatch_expires_at_epoch_ms
        .ok_or_else(|| invalid_statement("dispatch response is missing dispatch expiry"))?;
    let reservation_expires_at_epoch_ms = dispatch_response
        .reservation_expires_at_epoch_ms
        .ok_or_else(|| invalid_statement("dispatch response is missing reservation expiry"))?;
    if dispatch_response.api_version != "serverware.releaseAuthorization/v1"
        || !dispatch_response.ok
        || !dispatch_response.authorized
        || dispatch_response.state != "dispatching"
        || dispatch_response.reason != "dispatching"
        || dispatch_response.completion_outcome.is_some()
        || dispatch_response.retry_after_seconds != 0
        || dispatch_response.approval_status.is_some()
        || dispatch_response.approval_expires_at.is_some()
        || dispatch_response.approval_created.is_some()
        || dispatch_response.grant_id != statement.release_authority.grant_id
        || dispatch_response.approval_request_id != statement.release_authority.approval_id
        || dispatch_response.attempt_id != statement.release_authority.attempt_id
        || dispatch_response.binding_digest
            != statement.release_authority.consumption_identity_digest
        || Some(reservation_expires_at_epoch_ms)
            != statement.release_authority.reservation_expires_at_epoch_ms
        || dispatch_expires_at_epoch_ms != statement.release_authority.dispatch_expires_at_epoch_ms
        || dispatch_started_at_epoch_ms
            != statement
                .release_authority
                .authorization_state_observed_at_epoch_ms
        || dispatch_started_at_epoch_ms >= dispatch_expires_at_epoch_ms
        || dispatch_started_at_epoch_ms >= reservation_expires_at_epoch_ms
    {
        return Err(invalid_statement(
            "control-plane authorization receipt body and authority mismatch",
        ));
    }
    let _bounded_nested_contract = (
        dispatch_response.idempotent_replay,
        dispatch_response.quotas.len(),
        dispatch_response.store.ha,
    );

    let statement_bytes = decode_receipt_base64url(
        "receipt.response.statement_b64",
        &response.statement_b64,
        MAX_SIGNED_RESPONSE_STATEMENT_BYTES,
    )?;
    if response.statement_sha256 != sha256_prefixed(&statement_bytes) {
        return Err(invalid_statement(
            "control-plane authorization receipt statement digest mismatch",
        ));
    }
    let signed_statement: SignedResponseStatement = decode_canonical_json(&statement_bytes)
        .map_err(|error| invalid_statement(format!("signed dispatch statement: {error}")))?;
    if signed_statement.version != "serverware.responseSignature/v2"
        || signed_statement.nonce.as_deref() != Some(request.nonce.as_str())
        || signed_statement.request.method != request.method
        || signed_statement.request.path != request.path
        || signed_statement.request.query_sha256 != sha256_prefixed(request.query.as_bytes())
        || signed_statement.status_code != response.status
        || signed_statement.body_sha256 != response.body_sha256
        || signed_statement.response_signing_key_id != response.response_signing_key_id
    {
        return Err(invalid_statement(
            "control-plane authorization receipt signed statement mismatch",
        ));
    }
    for (name, digest) in [
        (
            "receipt.response.context.runtime_manifest_digest",
            Some(&signed_statement.context.runtime_manifest_digest),
        ),
        (
            "receipt.response.context.policy_bundle_digest",
            Some(&signed_statement.context.policy_bundle_digest),
        ),
        (
            "receipt.response.context.provenance_digest",
            signed_statement.context.provenance_digest.as_ref(),
        ),
        (
            "receipt.response.context.image_signatures_digest",
            signed_statement.context.image_signatures_digest.as_ref(),
        ),
        (
            "receipt.response.context.source_tree_digest",
            signed_statement.context.source_tree_digest.as_ref(),
        ),
    ] {
        if let Some(digest) = digest {
            validate_sha256_digest(name, digest)?;
        }
    }
    // The receipt measures the control plane, while the proxy response statement measures the
    // decision gate. The pinned control-plane signature authenticates the former; equating the two
    // would collapse two distinct service identities into one impossible runtime measurement.
    if signed_statement.context.policy_bundle_digest != statement.policy_digest {
        return Err(invalid_statement(
            "control-plane authorization receipt policy context mismatch",
        ));
    }
    if signed_statement.context.provenance_digest.as_deref() != Some(statement.release_digest) {
        return Err(invalid_statement(
            "control-plane authorization receipt provenance context mismatch",
        ));
    }
    let statement_end_epoch_ms = statement
        .issued_at_unix
        .saturating_add(1)
        .saturating_mul(1000)
        .saturating_sub(1);
    if signed_statement.issued_at_ms < dispatch_started_at_epoch_ms
        || signed_statement.issued_at_ms >= dispatch_expires_at_epoch_ms
        || signed_statement.issued_at_ms >= reservation_expires_at_epoch_ms
        || signed_statement.issued_at_ms > statement_end_epoch_ms
        || statement_end_epoch_ms.saturating_sub(dispatch_started_at_epoch_ms)
            > MAX_STATEMENT_AGE_SECONDS.saturating_mul(1000)
        || dispatch_expires_at_epoch_ms <= now_epoch_ms
    {
        return Err(invalid_statement(
            "control-plane authorization receipt temporal relation is invalid",
        ));
    }
    let signature = response
        .signature
        .strip_prefix("ed25519:")
        .ok_or_else(|| invalid_statement("receipt response signature must use ed25519"))?;
    let signature_bytes = decode_receipt_base64url(
        "receipt.response.signature",
        signature,
        Signature::BYTE_SIZE,
    )?;
    let signature_bytes: [u8; Signature::BYTE_SIZE] = signature_bytes
        .try_into()
        .map_err(|_| invalid_statement("receipt response signature must be 64 bytes"))?;
    if let Some(control_plane_response_verifying_key) = control_plane_response_verifying_key {
        control_plane_response_verifying_key
            .verify_strict(&statement_bytes, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| {
                invalid_statement(
                    "control-plane authorization receipt response signature verification failed",
                )
            })?;
    }
    Ok(())
}

fn validate_upstream_response(upstream: &UpstreamResponse) -> Result<(), ProtocolError> {
    validate_raw_policy_headers(&upstream.selected_raw_policy_headers_b64)?;
    let canonical = CanonicalUpstreamResponse {
        status: upstream.status,
        selected_raw_policy_headers_b64: &upstream.selected_raw_policy_headers_b64,
        body_digest: &upstream.body_digest,
    };
    let digest = sha256_prefixed(&canonical_json_bytes(&canonical)?);
    if upstream.canonical_digest != digest {
        return Err(invalid_statement(
            "upstream_response.canonical_digest does not match the canonical upstream response binding",
        ));
    }
    Ok(())
}

fn validate_raw_policy_headers(
    selected_raw_policy_headers_b64: &BTreeMap<String, Vec<String>>,
) -> Result<(), ProtocolError> {
    const REQUIRED_HEADERS: [&str; 3] = ["content-encoding", "content-length", "content-type"];
    const ALLOWED_HEADERS: [&str; 9] = [
        "cache-control",
        "content-encoding",
        "content-language",
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "retry-after",
        "www-authenticate",
    ];
    if REQUIRED_HEADERS
        .iter()
        .any(|name| !selected_raw_policy_headers_b64.contains_key(*name))
    {
        return Err(invalid_statement(
            "upstream_response.selected_raw_policy_headers_b64 is missing a required header",
        ));
    }
    for (name, values) in selected_raw_policy_headers_b64 {
        if !ALLOWED_HEADERS.contains(&name.as_str()) {
            return Err(invalid_statement(format!(
                "upstream_response.selected_raw_policy_headers_b64 contains unsupported header {name}"
            )));
        }
        if values.len() > MAX_RAW_HEADER_VALUES {
            return Err(invalid_statement(format!(
                "upstream_response selected raw header {name} has too many values"
            )));
        }
        for value in values {
            validate_base64url(
                &format!("upstream_response.selected_raw_policy_headers_b64.{name}"),
                value,
                0,
                MAX_HEADER_VALUE_BYTES,
            )?;
        }
    }
    Ok(())
}

fn validate_selected_headers(statement: &ProxyResponseStatement) -> Result<(), ProtocolError> {
    const REQUIRED_HEADERS: [&str; 6] = [
        "content-length",
        "x-serverware-client-request-digest",
        "x-serverware-policy-hash",
        "x-serverware-request-digest",
        "x-serverware-operation-digest",
        "x-serverware-response-body-sha256",
    ];
    for required in REQUIRED_HEADERS {
        if !statement.response.selected_headers.contains_key(required) {
            return Err(invalid_statement(format!(
                "response.selected_headers is missing {required}"
            )));
        }
    }
    for (name, value) in &statement.response.selected_headers {
        if !REQUIRED_HEADERS.contains(&name.as_str()) && name != "content-type" {
            return Err(invalid_statement(format!(
                "response.selected_headers contains unsupported header {name}"
            )));
        }
        if value.is_empty()
            || value.len() > MAX_HEADER_VALUE_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid_statement(format!(
                "response.selected_headers value for {name} is invalid"
            )));
        }
    }
    let content_length = statement
        .response
        .selected_headers
        .get("content-length")
        .expect("required header checked above");
    if !is_canonical_decimal(content_length) {
        return Err(invalid_statement(
            "response selected content-length is not canonical decimal",
        ));
    }
    for (header, expected) in [
        (
            "x-serverware-client-request-digest",
            &statement.client_request_digest,
        ),
        ("x-serverware-request-digest", &statement.request_digest),
        ("x-serverware-operation-digest", &statement.operation_digest),
        ("x-serverware-policy-hash", &statement.policy_digest),
        (
            "x-serverware-response-body-sha256",
            &statement.response.body_digest,
        ),
    ] {
        if statement.response.selected_headers.get(header) != Some(expected) {
            return Err(invalid_statement(format!(
                "response selected header {header} does not match its statement field"
            )));
        }
    }
    let selected_headers_digest =
        sha256_prefixed(&canonical_json_bytes(&statement.response.selected_headers)?);
    if statement.response.selected_headers_digest != selected_headers_digest {
        return Err(invalid_statement(
            "response.selected_headers_digest does not match selected_headers",
        ));
    }
    Ok(())
}

fn validate_server_instance(instance: &ServerInstance) -> Result<(), ProtocolError> {
    if instance.id.is_empty()
        || instance.id.len() > MAX_SERVER_INSTANCE_ID_BYTES
        || instance.id.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_statement("server_instance.id is invalid"));
    }
    if instance.identity_digest != sha256_prefixed(instance.id.as_bytes()) {
        return Err(invalid_statement(
            "server_instance.identity_digest does not match server_instance.id",
        ));
    }
    Ok(())
}

fn validate_bounded_identity(name: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err(invalid_statement(format!("{name} is invalid")));
    }
    Ok(())
}

fn validate_sha256_digest(name: &str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_statement(format!(
            "{name} must be canonical lowercase sha256"
        )));
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), ProtocolError> {
    validate_base64url(
        "requestId",
        request_id,
        MIN_REQUEST_ID_BYTES,
        MAX_REQUEST_ID_BYTES,
    )
    .map_err(|_| {
        ProtocolError::new(
            "invalid_request_id",
            "requestId must be canonical unpadded base64url containing 16 to 64 bytes",
        )
    })
}

fn validate_boot_id(boot_id: &str) -> Result<(), ProtocolError> {
    validate_base64url("bootId", boot_id, BOOT_ID_BYTES, BOOT_ID_BYTES).map_err(|_| {
        ProtocolError::new(
            "invalid_boot_id",
            "bootId must be canonical unpadded base64url containing 32 bytes",
        )
    })
}

fn validate_operation_label(operation: &str) -> Result<(), ProtocolError> {
    if operation.is_empty()
        || operation.len() > MAX_OPERATION_BYTES
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-'))
    {
        return Err(ProtocolError::new(
            "invalid_operation",
            "operation is not a bounded protocol operation label",
        ));
    }
    Ok(())
}

fn validate_base64url(
    name: &str,
    value: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<(), ProtocolError> {
    if value.contains('=') {
        return Err(invalid_statement(format!(
            "{name} must use unpadded base64url"
        )));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| invalid_statement(format!("{name} is not valid base64url")))?;
    if !(min_bytes..=max_bytes).contains(&decoded.len())
        || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(invalid_statement(format!(
            "{name} is not canonical base64url of the required length"
        )));
    }
    Ok(())
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
}

fn invalid_statement(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new("invalid_response_statement", message)
}

fn ed25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    let mut spki_der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki_der.extend_from_slice(public_key);
    spki_der
}

fn pem_public_key(spki_der: &[u8]) -> String {
    let encoded = general_purpose::STANDARD.encode(spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), WireError> {
    let mut received = 0;
    while received < buffer.len() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(WireError::DeadlineExceeded);
        };
        if remaining.is_zero() {
            return Err(WireError::DeadlineExceeded);
        }
        match stream.read(&mut buffer[received..]) {
            Ok(0) => {
                return Err(WireError::TruncatedFrame {
                    expected: buffer.len(),
                    received,
                });
            }
            Ok(count) => received += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(WireError::DeadlineExceeded);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(error) => return Err(WireError::Io(error)),
        }
    }
    Ok(())
}

pub fn read_frame(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>, WireError> {
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let mut length_bytes = [0u8; 4];
    read_exact_until(stream, &mut length_bytes, deadline)?;
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared == 0 {
        return Err(WireError::EmptyFrame);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { declared });
    }
    let mut payload = vec![0u8; declared];
    read_exact_until(stream, &mut payload, deadline)?;
    Ok(payload)
}

pub fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    timeout: Duration,
) -> Result<(), WireError> {
    if payload.is_empty() {
        return Err(WireError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge {
            declared: payload.len(),
        });
    }
    let length = u32::try_from(payload.len()).expect("frame cap fits in u32");
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let mut written = 0;
    while written < frame.len() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(WireError::DeadlineExceeded);
        };
        if remaining.is_zero() {
            return Err(WireError::DeadlineExceeded);
        }
        match stream.write(&frame[written..]) {
            Ok(0) => return Err(WireError::Io(io::ErrorKind::WriteZero.into())),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(WireError::DeadlineExceeded);
                }
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(error) => return Err(WireError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const CONTROL_PLANE_RESPONSE_SIGNING_SEED: [u8; 32] = [19u8; 32];

    fn control_plane_response_signing_key() -> SigningKey {
        SigningKey::from_bytes(&CONTROL_PLANE_RESPONSE_SIGNING_SEED)
    }

    fn pinned_control_plane_response_verifying_key() -> VerifyingKey {
        control_plane_response_signing_key().verifying_key()
    }

    fn runtime() -> CustodyRuntime {
        CustodyRuntime::from_secret_material(
            [7u8; 32],
            [9u8; 32],
            Some(pinned_control_plane_response_verifying_key()),
        )
    }

    fn unconfigured_runtime() -> CustodyRuntime {
        CustodyRuntime::from_secret_material([7u8; 32], [9u8; 32], None)
    }

    fn validate_test_statement(statement: &ProxyResponseStatement) -> Result<(), ProtocolError> {
        validate_response_statement_with_control_plane_response_key(
            statement,
            &pinned_control_plane_response_verifying_key(),
        )
    }

    fn request_id(byte: u8) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn digest(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn uninitialized_ledger_directory(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "serverware-ledger-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create ledger fixture directory");
        fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(ATTEMPT_LEDGER_DIRECTORY_MODE),
        )
        .expect("protect ledger fixture directory");
        fs::canonicalize(directory).expect("canonical ledger fixture directory")
    }

    fn ledger_directory(label: &str) -> PathBuf {
        let directory = uninitialized_ledger_directory(label);
        CustodyRuntime::initialize_attempt_ledger_directory(&directory)
            .expect("initialize ledger fixture directory");
        directory
    }

    fn persistent_runtime(directory: &Path, signing_byte: u8, boot_byte: u8) -> CustodyRuntime {
        CustodyRuntime::from_secret_material_with_ledger(
            [signing_byte; 32],
            [boot_byte; 32],
            Some(pinned_control_plane_response_verifying_key()),
            AttemptStatementLedger::open(directory).expect("open persistent attempt ledger"),
        )
    }

    fn statement() -> ProxyResponseStatement {
        statement_signed_by(&control_plane_response_signing_key())
    }

    fn statement_signed_by(response_signing_key: &SigningKey) -> ProxyResponseStatement {
        let issued_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let client_request_digest = digest(1);
        let request_digest = digest(2);
        let operation_digest = digest(3);
        let policy_digest = digest(4);
        let body_digest = digest(5);
        let runtime_manifest_digest = digest(6);
        let control_plane_runtime_manifest_digest = digest(19);
        let release_digest = digest(8);
        let principal_id = "agent:custody-test".to_string();
        let route_id = "route:custody-test".to_string();
        let attempt_id = digest(11);
        let authorization_binding = ReleaseAuthorizationBinding {
            attempt_id: attempt_id.clone(),
            flow_id: attempt_id.clone(),
            principal_id: principal_id.clone(),
            route_id: route_id.clone(),
            credential_id: "credential:custody-test".to_string(),
            credential_version: 7,
            policy_hash: policy_digest.clone(),
            request_digest: request_digest.clone(),
            operation_digest: Some(operation_digest.clone()),
            operation_context: json!({"operation":"custody.test"}),
            require_jit_grant: true,
            shared_quotas: Vec::new(),
        };
        let binding_digest = sha256_prefixed(
            &canonical_json_ensure_ascii_bytes(&authorization_binding)
                .expect("canonical authorization binding"),
        );
        let mut selected_headers = BTreeMap::new();
        selected_headers.insert("content-length".to_string(), "17".to_string());
        selected_headers.insert("content-type".to_string(), "application/json".to_string());
        selected_headers.insert(
            "x-serverware-client-request-digest".to_string(),
            client_request_digest.clone(),
        );
        selected_headers.insert(
            "x-serverware-operation-digest".to_string(),
            operation_digest.clone(),
        );
        selected_headers.insert(
            "x-serverware-policy-hash".to_string(),
            policy_digest.clone(),
        );
        selected_headers.insert(
            "x-serverware-request-digest".to_string(),
            request_digest.clone(),
        );
        selected_headers.insert(
            "x-serverware-response-body-sha256".to_string(),
            body_digest.clone(),
        );
        let selected_headers_digest =
            sha256_prefixed(&canonical_json_bytes(&selected_headers).expect("canonical headers"));
        let selected_raw_policy_headers_b64 = BTreeMap::from([
            ("content-encoding".to_string(), Vec::new()),
            (
                "content-length".to_string(),
                vec![general_purpose::URL_SAFE_NO_PAD.encode(b"17")],
            ),
            (
                "content-type".to_string(),
                vec![general_purpose::URL_SAFE_NO_PAD.encode(b"application/json")],
            ),
        ]);
        let upstream_body_digest = digest(10);
        let upstream_canonical_digest = sha256_prefixed(
            &canonical_json_bytes(&CanonicalUpstreamResponse {
                status: 200,
                selected_raw_policy_headers_b64: &selected_raw_policy_headers_b64,
                body_digest: &upstream_body_digest,
            })
            .expect("canonical upstream response"),
        );
        let instance_id = "spiffe://dev.serverware/decision-gate/test".to_string();
        let dispatch_started_at_epoch_ms = issued_at_unix * 1000;
        let dispatch_expires_at_epoch_ms = dispatch_started_at_epoch_ms + 30_000;
        let reservation_expires_at_epoch_ms = dispatch_started_at_epoch_ms + 30_000;
        let release_authority = ReleaseAuthority {
            authority_mode: "atomic".to_string(),
            grant_id: Some("grant:custody-test".to_string()),
            approval_id: Some("approval:custody-test".to_string()),
            credential_ref: Some("credential:custody-test".to_string()),
            credential_version: 7,
            request_digest: request_digest.clone(),
            operation_digest: operation_digest.clone(),
            attempt_id,
            consumption_identity_digest: binding_digest,
            authorization_state_at_upstream_dispatch: "dispatching".to_string(),
            authorization_state_observed_at_epoch_ms: dispatch_started_at_epoch_ms,
            reservation_expires_at_epoch_ms: Some(reservation_expires_at_epoch_ms),
            dispatch_expires_at_epoch_ms,
        };
        let dispatch_body = canonical_json_bytes(&json!({
            "apiVersion":"serverware.releaseAuthorization/v1",
            "ok":true,
            "authorized":true,
            "state":"dispatching",
            "reason":"dispatching",
            "attemptId":release_authority.attempt_id.clone(),
            "bindingDigest":release_authority.consumption_identity_digest.clone(),
            "idempotentReplay":false,
            "grantId":release_authority.grant_id.clone(),
            "approvalRequestId":release_authority.approval_id.clone(),
            "reservationExpiresAtEpochMs":reservation_expires_at_epoch_ms,
            "dispatchStartedAtEpochMs":dispatch_started_at_epoch_ms,
            "dispatchExpiresAtEpochMs":dispatch_expires_at_epoch_ms,
            "completionOutcome":null,
            "retryAfterSeconds":0,
            "quotas":[],
            "store":{"backend":"sqlite","ha":false},
        }))
        .expect("dispatch body");
        let response_nonce = general_purpose::URL_SAFE_NO_PAD.encode([13u8; 32]);
        let response_signing_key_id =
            control_plane_response_key_id(&response_signing_key.verifying_key());
        let signed_response_statement = SignedResponseStatement {
            version: "serverware.responseSignature/v2".to_string(),
            issued_at_ms: dispatch_started_at_epoch_ms,
            request: SignedResponseRequest {
                method: "POST".to_string(),
                path: RELEASE_AUTHORIZATION_DISPATCH_PATH.to_string(),
                query_sha256: sha256_prefixed(b""),
            },
            status_code: 200,
            body_sha256: sha256_prefixed(&dispatch_body),
            nonce: Some(response_nonce.clone()),
            response_signing_key_id: response_signing_key_id.clone(),
            context: SignedResponseContext {
                runtime_manifest_digest: control_plane_runtime_manifest_digest,
                policy_bundle_digest: policy_digest.clone(),
                provenance_digest: Some(release_digest.clone()),
                image_signatures_digest: Some(digest(17)),
                source_tree_digest: Some(digest(18)),
            },
        };
        let signed_response_statement =
            canonical_json_bytes(&signed_response_statement).expect("signed response statement");
        let signed_response_signature = response_signing_key.sign(&signed_response_statement);
        let dispatch_request_body = canonical_json_bytes(&DispatchRequestBody {
            api_version: "serverware.releaseAuthorizationDispatch/v1".to_string(),
            attempt_id: release_authority.attempt_id.clone(),
            binding_digest: release_authority.consumption_identity_digest.clone(),
        })
        .expect("dispatch request body");
        let control_plane_authorization_receipt = ControlPlaneAuthorizationReceipt {
            api_version: AUTHORIZATION_RECEIPT_API_VERSION.to_string(),
            kind: "ControlPlaneAuthorizationReceipt".to_string(),
            principal_id: principal_id.clone(),
            route_id: route_id.clone(),
            release_authority: release_authority.clone(),
            request: ControlPlaneAuthorizationReceiptRequest {
                method: "POST".to_string(),
                path: RELEASE_AUTHORIZATION_DISPATCH_PATH.to_string(),
                query: String::new(),
                nonce: response_nonce,
                body_b64: general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_request_body),
                body_sha256: sha256_prefixed(&dispatch_request_body),
            },
            response: ControlPlaneAuthorizationReceiptResponse {
                status: 200,
                body_b64: general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_body),
                body_sha256: sha256_prefixed(&dispatch_body),
                response_signing_key_id,
                statement_b64: general_purpose::URL_SAFE_NO_PAD.encode(&signed_response_statement),
                statement_sha256: sha256_prefixed(&signed_response_statement),
                signature: format!(
                    "ed25519:{}",
                    general_purpose::URL_SAFE_NO_PAD.encode(signed_response_signature.to_bytes())
                ),
            },
        };
        ProxyResponseStatement {
            api_version: RESPONSE_STATEMENT_API_VERSION.to_string(),
            issued_at_unix,
            client_nonce: general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]),
            client_request_digest,
            principal_id,
            route_id,
            request_digest: request_digest.clone(),
            operation_digest: operation_digest.clone(),
            release_authority,
            control_plane_authorization_receipt,
            upstream_response: UpstreamResponse {
                status: 200,
                selected_raw_policy_headers_b64,
                body_digest: upstream_body_digest,
                canonical_digest: upstream_canonical_digest,
            },
            response: ProxyResponse {
                status: 200,
                selected_headers,
                selected_headers_digest,
                body_digest,
            },
            policy_digest,
            runtime_manifest_digest,
            data_plane_binary_digest: digest(7),
            release_digest,
            server_instance: ServerInstance {
                identity_digest: sha256_prefixed(instance_id.as_bytes()),
                id: instance_id,
            },
            tls_channel_binding: TlsChannelBinding {
                binding_type: "tls-exporter".to_string(),
                value: general_purpose::URL_SAFE_NO_PAD.encode([12u8; 32]),
            },
        }
    }

    fn set_reservation_expiry_and_resign(
        statement: &mut ProxyResponseStatement,
        reservation_expires_at_epoch_ms: u64,
    ) {
        statement.release_authority.reservation_expires_at_epoch_ms =
            Some(reservation_expires_at_epoch_ms);
        statement
            .control_plane_authorization_receipt
            .release_authority = statement.release_authority.clone();

        let response = &mut statement.control_plane_authorization_receipt.response;
        let dispatch_body = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.body_b64)
            .expect("decode dispatch response body");
        let mut dispatch_body: Value =
            decode_canonical_json(&dispatch_body).expect("decode canonical dispatch response body");
        dispatch_body["reservationExpiresAtEpochMs"] = Value::from(reservation_expires_at_epoch_ms);
        let dispatch_body = canonical_json_bytes(&dispatch_body).expect("encode dispatch body");
        response.body_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&dispatch_body);
        response.body_sha256 = sha256_prefixed(&dispatch_body);

        let signed_statement = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.statement_b64)
            .expect("decode signed dispatch statement");
        let mut signed_statement: SignedResponseStatement =
            decode_canonical_json(&signed_statement).expect("decode signed dispatch statement");
        signed_statement.body_sha256 = response.body_sha256.clone();
        let signed_statement =
            canonical_json_bytes(&signed_statement).expect("encode signed dispatch statement");
        let signature = control_plane_response_signing_key().sign(&signed_statement);
        response.statement_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signed_statement);
        response.statement_sha256 = sha256_prefixed(&signed_statement);
        response.signature = format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
    }

    fn authorization_binding_for_statement(
        statement: &ProxyResponseStatement,
    ) -> ReleaseAuthorizationBinding {
        ReleaseAuthorizationBinding {
            attempt_id: statement.release_authority.attempt_id.clone(),
            flow_id: statement.release_authority.attempt_id.clone(),
            principal_id: statement.principal_id.clone(),
            route_id: statement.route_id.clone(),
            credential_id: statement
                .release_authority
                .credential_ref
                .clone()
                .unwrap_or_default(),
            credential_version: statement.release_authority.credential_version,
            policy_hash: statement.policy_digest.clone(),
            request_digest: statement.request_digest.clone(),
            operation_digest: Some(statement.operation_digest.clone()),
            operation_context: json!({"operation":"custody.test"}),
            require_jit_grant: statement.release_authority.grant_id.is_some(),
            shared_quotas: Vec::new(),
        }
    }

    fn streaming_statement() -> (StreamingResponseStatement, ReleaseAuthorizationBinding) {
        let buffered = statement();
        let authorization_binding = authorization_binding_for_statement(&buffered);
        let binding_digest = sha256_prefixed(
            &canonical_json_ensure_ascii_bytes(&authorization_binding)
                .expect("canonical streaming authorization binding"),
        );
        let binding_commitment = AuthorizationBindingCommitment {
            attempt_id: authorization_binding.attempt_id.clone(),
            flow_id: authorization_binding.flow_id.clone(),
            principal_id: authorization_binding.principal_id.clone(),
            route_id: authorization_binding.route_id.clone(),
            credential_id: authorization_binding.credential_id.clone(),
            credential_version: authorization_binding.credential_version,
            policy_hash: authorization_binding.policy_hash.clone(),
            request_digest: authorization_binding.request_digest.clone(),
            operation_digest: authorization_binding
                .operation_digest
                .clone()
                .expect("streaming operation digest"),
            operation_context_digest: sha256_prefixed(
                &canonical_json_ensure_ascii_bytes(&authorization_binding.operation_context)
                    .expect("canonical streaming operation context"),
            ),
            require_jit_grant: authorization_binding.require_jit_grant,
            shared_quotas: authorization_binding.shared_quotas.clone(),
        };
        let selected_raw_policy_headers_b64 = buffered
            .upstream_response
            .selected_raw_policy_headers_b64
            .clone();
        let upstream_body_digest = buffered.upstream_response.body_digest.clone();
        let upstream_body_bytes = 23;
        let upstream_canonical_digest = sha256_prefixed(
            &canonical_json_bytes(&StreamingUpstreamResponseDigest {
                status: buffered.upstream_response.status,
                selected_raw_policy_headers_b64: &selected_raw_policy_headers_b64,
                body_digest: &upstream_body_digest,
                body_bytes: upstream_body_bytes,
            })
            .expect("canonical streaming upstream response"),
        );
        let content_type = "application/json".to_string();
        let selected_wire_headers = StreamingWireHeaders {
            connection: "close".to_string(),
            content_type: content_type.clone(),
            trailer: "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256".to_string(),
            transfer_encoding: "chunked".to_string(),
        };
        let selected_wire_headers_digest = sha256_prefixed(
            &canonical_json_bytes(&selected_wire_headers)
                .expect("canonical streaming response wire headers"),
        );
        let control_plane_authorization_receipt_sha256 = sha256_prefixed(
            &canonical_json_bytes(&buffered.control_plane_authorization_receipt)
                .expect("canonical streaming authorization receipt"),
        );

        let streaming = StreamingResponseStatement {
            api_version: STREAMING_RESPONSE_STATEMENT_API_VERSION.to_string(),
            issued_at_unix: buffered.issued_at_unix,
            client_nonce: buffered.client_nonce.clone(),
            client_request_digest: buffered.client_request_digest.clone(),
            principal_id: buffered.principal_id.clone(),
            route_id: buffered.route_id.clone(),
            request_digest: buffered.request_digest.clone(),
            operation_digest: buffered.operation_digest.clone(),
            release_authority: buffered.release_authority.clone(),
            authorization_binding_validation: AuthorizationBindingValidation {
                status: "validated".to_string(),
                binding_commitment,
                binding_digest,
            },
            control_plane_authorization_receipt: buffered
                .control_plane_authorization_receipt
                .clone(),
            control_plane_authorization_receipt_sha256,
            upstream_response: StreamingUpstreamResponse {
                status: buffered.upstream_response.status,
                selected_raw_policy_headers_b64,
                body_digest: upstream_body_digest,
                body_bytes: upstream_body_bytes,
                canonical_digest: upstream_canonical_digest,
            },
            released_response: StreamingReleasedResponse {
                status: buffered.response.status,
                content_type,
                selected_wire_headers,
                selected_wire_headers_digest,
                body_digest: buffered.response.body_digest.clone(),
                body_bytes: 17,
                framing: "http1.1-chunked-trailers".to_string(),
                completion: "normal-eof".to_string(),
                trailer_names: vec![
                    "X-Serverware-Stream-Proof-B64".to_string(),
                    "X-Serverware-Stream-Proof-SHA256".to_string(),
                ],
            },
            policy_digest: buffered.policy_digest.clone(),
            runtime_manifest_digest: buffered.runtime_manifest_digest.clone(),
            data_plane_binary_digest: buffered.data_plane_binary_digest.clone(),
            release_digest: buffered.release_digest.clone(),
            server_instance: buffered.server_instance.clone(),
            tls_channel_binding: StreamingTlsChannelBinding {
                binding_type: "tls-exporter".to_string(),
                exporter_label: "EXPORTER-Serverware-Proxy-Stream-v1".to_string(),
                value: buffered.tls_channel_binding.value.clone(),
            },
        };
        (streaming, authorization_binding)
    }

    fn validate_test_streaming_statement(
        statement: &StreamingResponseStatement,
        authorization_binding: &ReleaseAuthorizationBinding,
    ) -> Result<(), ProtocolError> {
        validate_streaming_response_statement_with_control_plane_response_key_at(
            statement,
            authorization_binding,
            &pinned_control_plane_response_verifying_key(),
            statement.issued_at_unix * 1000,
        )
    }

    #[test]
    fn custody_proof_binding_rejects_calendar_dispatch_quota_tampering() {
        let mut statement = statement();
        let mut binding = authorization_binding_for_statement(&statement);
        let quota = ReleaseAuthorizationBindingQuota {
            counter_key: digest(21),
            constraint_id: "quota:utc-day".to_string(),
            operation: Some("custody.test".to_string()),
            window_kind: RateLimitWindowKind::UtcDay,
            window_seconds: None,
            max_count: 5,
        };
        binding.shared_quotas = vec![quota.clone()];
        statement.release_authority.consumption_identity_digest = sha256_prefixed(
            &canonical_json_ensure_ascii_bytes(&binding).expect("calendar binding digest"),
        );
        let dispatch_started_at_epoch_ms = statement
            .release_authority
            .authorization_state_observed_at_epoch_ms;
        let (window_start_epoch_ms, window_end_epoch_ms) =
            custody_calendar_window_bounds(&quota.window_kind, dispatch_started_at_epoch_ms)
                .expect("calendar bounds");
        let response_body = canonical_json_bytes(&json!({
            "apiVersion":"serverware.releaseAuthorization/v1",
            "ok":true,
            "authorized":true,
            "state":"dispatching",
            "reason":"dispatching",
            "attemptId":statement.release_authority.attempt_id,
            "bindingDigest":statement.release_authority.consumption_identity_digest,
            "idempotentReplay":false,
            "grantId":statement.release_authority.grant_id,
            "approvalRequestId":statement.release_authority.approval_id,
            "reservationExpiresAtEpochMs":statement.release_authority.reservation_expires_at_epoch_ms,
            "dispatchStartedAtEpochMs":dispatch_started_at_epoch_ms,
            "dispatchExpiresAtEpochMs":statement.release_authority.dispatch_expires_at_epoch_ms,
            "completionOutcome":null,
            "retryAfterSeconds":0,
            "quotas":[{
                "counterKey":quota.counter_key,
                "constraintId":quota.constraint_id,
                "operation":quota.operation,
                "windowStartEpochMs":window_start_epoch_ms,
                "windowEndEpochMs":window_end_epoch_ms,
                "windowKind":"utcDay",
                "calendarWindow":"utcDay",
                "max":5,
                "count":1,
                "remaining":4,
                "reservationState":"reserved"
            }],
            "store":{"backend":"sqlite","ha":false}
        }))
        .expect("calendar dispatch body");
        statement
            .control_plane_authorization_receipt
            .response
            .body_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&response_body);
        validate_release_authorization_binding(
            &ResponseStatementAuthorityView::from(&statement),
            &binding,
        )
        .expect("exact calendar dispatch quota proof binding");

        let mut tampered: Value =
            parse_json_without_duplicate_keys(&response_body).expect("dispatch body JSON");
        tampered["quotas"][0]
            .as_object_mut()
            .expect("quota object")
            .remove("windowEndEpochMs");
        statement
            .control_plane_authorization_receipt
            .response
            .body_b64 = general_purpose::URL_SAFE_NO_PAD
            .encode(canonical_json_bytes(&tampered).expect("tampered dispatch body"));
        assert!(validate_release_authorization_binding(
            &ResponseStatementAuthorityView::from(&statement),
            &binding,
        )
        .expect_err("calendar proof must require the exact window end")
        .message
        .contains("window end is missing"));
    }

    fn request_bytes(
        runtime: &CustodyRuntime,
        id: u8,
        statement: ProxyResponseStatement,
    ) -> Vec<u8> {
        let authorization_binding = authorization_binding_for_statement(&statement);
        canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {
                "statement": statement,
                "authorization_binding": authorization_binding,
            },
            "requestId": request_id(id),
        }))
        .expect("canonical request")
    }

    fn streaming_request_bytes(
        runtime: &CustodyRuntime,
        id: u8,
        statement: StreamingResponseStatement,
        authorization_binding: ReleaseAuthorizationBinding,
    ) -> Vec<u8> {
        canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
            "params": {
                "statement": statement,
                "authorization_binding": authorization_binding,
            },
            "requestId": request_id(id),
        }))
        .expect("canonical streaming request")
    }

    fn response_value(bytes: &[u8]) -> Value {
        decode_canonical_json(bytes).expect("canonical response")
    }

    fn resign_control_plane_response_context(
        statement: &mut ProxyResponseStatement,
        mutate: impl FnOnce(&mut SignedResponseContext),
    ) {
        let response = &mut statement.control_plane_authorization_receipt.response;
        let statement_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.statement_b64)
            .expect("decode signed response statement");
        let mut signed_statement: SignedResponseStatement =
            decode_canonical_json(&statement_bytes).expect("signed response statement");
        mutate(&mut signed_statement.context);
        let statement_bytes =
            canonical_json_bytes(&signed_statement).expect("canonical signed response statement");
        let signature = control_plane_response_signing_key().sign(&statement_bytes);
        response.statement_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&statement_bytes);
        response.statement_sha256 = sha256_prefixed(&statement_bytes);
        response.signature = format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
    }

    #[test]
    fn hello_discloses_only_public_material_capabilities_limits_and_false_hardware_proof() {
        let runtime = runtime();
        let request = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(1),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&request).expect("request"))
                .expect("hello response"),
        );
        assert_eq!(response["ok"], true);
        assert_eq!(response["bootId"], runtime.boot_id());
        assert_eq!(response["result"]["hardwareProof"], false);
        assert_eq!(
            response["result"]["limits"]["maxFrameBytes"],
            MAX_FRAME_BYTES
        );
        assert!(response["result"]["publicKeyPem"]
            .as_str()
            .expect("public key")
            .starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(
            response["result"]["controlPlaneResponseSigningKeyId"],
            control_plane_response_key_id(&pinned_control_plane_response_verifying_key())
        );
        let result = response["result"].as_object().expect("hello result");
        assert_eq!(
            result.keys().map(String::as_str).collect::<HashSet<_>>(),
            HashSet::from([
                "capabilities",
                "controlPlaneResponseSigningKeyId",
                "hardwareProof",
                "keyId",
                "limits",
                "publicKeyPem",
            ])
        );
        let serialized = String::from_utf8(canonical_json_bytes(&response).expect("response"))
            .expect("UTF-8 response");
        assert!(!serialized.to_ascii_lowercase().contains("private"));
        assert!(!serialized.contains(&general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32])));
    }

    #[test]
    fn repeated_hello_is_accounting_neutral_and_request_id_remains_available_for_sign() {
        let runtime = runtime();
        let repeated_request_id = request_id(2);
        let request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": repeated_request_id,
        }))
        .expect("canonical hello request");
        let replay_state_before = runtime
            .seen_request_ids
            .lock()
            .expect("request replay state")
            .clone();
        let ledger_state_before = {
            let ledger = runtime
                .attempt_statement_ledger
                .lock()
                .expect("attempt statement ledger");
            (
                canonical_json_bytes(&ledger.bindings).expect("canonical ledger bindings"),
                ledger.expiry_index.clone(),
                canonical_json_bytes(&ledger.manifest).expect("canonical ledger manifest"),
            )
        };

        for _ in 0..3 {
            let response = response_value(
                &runtime
                    .handle_canonical_request(&request)
                    .expect("repeated hello response"),
            );
            assert_eq!(response["ok"], true, "unexpected response: {response}");
        }

        assert_eq!(
            *runtime
                .seen_request_ids
                .lock()
                .expect("request replay state"),
            replay_state_before,
            "hello must not consume sign requestId capacity"
        );
        let ledger = runtime
            .attempt_statement_ledger
            .lock()
            .expect("attempt statement ledger");
        assert_eq!(
            canonical_json_bytes(&ledger.bindings).expect("canonical ledger bindings"),
            ledger_state_before.0
        );
        assert_eq!(ledger.expiry_index, ledger_state_before.1);
        assert_eq!(
            canonical_json_bytes(&ledger.manifest).expect("canonical ledger manifest"),
            ledger_state_before.2
        );
        drop(ledger);

        let sign_response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 2, statement()))
                .expect("sign response using the hello requestId"),
        );
        assert_eq!(
            sign_response["ok"], true,
            "hello requestId must remain available for signing: {sign_response}"
        );
    }

    #[test]
    fn configured_response_key_loader_rejects_oversized_and_non_utf8_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "serverware-custody-response-key-{}-{unique}.pem",
            std::process::id()
        ));

        fs::write(
            &path,
            vec![b'A'; MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES + 1],
        )
        .expect("write oversized key fixture");
        let oversized_error = read_control_plane_response_public_key_pem(&path)
            .expect_err("oversized key file must fail closed");
        assert_eq!(
            oversized_error.code,
            "invalid_control_plane_response_key_configuration"
        );
        assert!(oversized_error.message.contains("exceeds 1024 bytes"));

        fs::write(&path, [0xff]).expect("write non-UTF8 key fixture");
        let encoding_error = read_control_plane_response_public_key_pem(&path)
            .expect_err("non-UTF8 key file must fail closed");
        assert_eq!(
            encoding_error.code,
            "invalid_control_plane_response_key_configuration"
        );
        assert!(encoding_error.message.contains("valid UTF-8"));

        fs::remove_file(path).expect("remove key fixture");
    }

    #[test]
    fn configured_response_key_accepts_exactly_one_inline_or_file_key_id() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let public_key_path = env::temp_dir().join(format!(
            "serverware-control-plane-response-key-{}-{unique}.pem",
            std::process::id()
        ));
        let key_id_path = env::temp_dir().join(format!(
            "serverware-control-plane-response-key-id-{}-{unique}",
            std::process::id()
        ));
        let verifying_key = pinned_control_plane_response_verifying_key();
        let key_id = control_plane_response_key_id(&verifying_key);
        fs::write(
            &public_key_path,
            pem_public_key(&ed25519_spki_der(verifying_key.as_bytes())),
        )
        .expect("write public key fixture");
        fs::write(&key_id_path, format!("{key_id}\n")).expect("write key ID fixture");

        let inline = configured_control_plane_response_verifying_key_from_values(
            Some(public_key_path.clone().into_os_string()),
            Some(OsString::from(&key_id)),
            None,
        )
        .expect("inline key ID configuration")
        .expect("configured inline verifying key");
        assert_eq!(inline, verifying_key);

        let from_file = configured_control_plane_response_verifying_key_from_values(
            Some(public_key_path.clone().into_os_string()),
            None,
            Some(key_id_path.clone().into_os_string()),
        )
        .expect("file key ID configuration")
        .expect("configured file verifying key");
        assert_eq!(from_file, verifying_key);

        for error in [
            configured_control_plane_response_verifying_key_from_values(
                Some(public_key_path.clone().into_os_string()),
                None,
                None,
            )
            .expect_err("missing key ID source must fail closed"),
            configured_control_plane_response_verifying_key_from_values(
                Some(public_key_path.clone().into_os_string()),
                Some(OsString::from(&key_id)),
                Some(key_id_path.clone().into_os_string()),
            )
            .expect_err("ambiguous key ID sources must fail closed"),
            configured_control_plane_response_verifying_key_from_values(
                None,
                Some(OsString::from(&key_id)),
                None,
            )
            .expect_err("key ID without public key must fail closed"),
        ] {
            assert_eq!(
                error.code,
                "invalid_control_plane_response_key_configuration"
            );
            assert!(error.message.contains("exactly one"));
        }

        fs::remove_file(public_key_path).expect("remove public key fixture");
        fs::remove_file(key_id_path).expect("remove key ID fixture");
    }

    #[test]
    fn configured_response_key_id_file_requires_canonical_newline_terminated_matching_id() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let public_key_path = env::temp_dir().join(format!(
            "serverware-control-plane-response-key-format-{}-{unique}.pem",
            std::process::id()
        ));
        let key_id_path = env::temp_dir().join(format!(
            "serverware-control-plane-response-key-id-format-{}-{unique}",
            std::process::id()
        ));
        let verifying_key = pinned_control_plane_response_verifying_key();
        let key_id = control_plane_response_key_id(&verifying_key);
        fs::write(
            &public_key_path,
            pem_public_key(&ed25519_spki_der(verifying_key.as_bytes())),
        )
        .expect("write public key fixture");

        let load = || {
            configured_control_plane_response_verifying_key_from_values(
                Some(public_key_path.clone().into_os_string()),
                None,
                Some(key_id_path.clone().into_os_string()),
            )
        };

        fs::write(&key_id_path, &key_id).expect("write unterminated key ID fixture");
        assert!(load()
            .expect_err("unterminated key ID must fail closed")
            .message
            .contains("newline-terminated"));

        fs::write(&key_id_path, format!("{}\n", key_id.to_ascii_uppercase()))
            .expect("write uppercase key ID fixture");
        assert!(load()
            .expect_err("uppercase key ID must fail closed")
            .message
            .contains("canonical lowercase"));

        fs::write(&key_id_path, format!("sha256:{}\n", "0".repeat(64)))
            .expect("write mismatched key ID fixture");
        assert!(load()
            .expect_err("mismatched key ID must fail closed")
            .message
            .contains("does not match"));

        fs::write(&key_id_path, [0xff, b'\n']).expect("write non-UTF8 key ID fixture");
        assert!(load()
            .expect_err("non-UTF8 key ID must fail closed")
            .message
            .contains("valid UTF-8"));

        fs::write(&key_id_path, format!("{key_id}\n\n")).expect("write oversized key ID fixture");
        assert!(load()
            .expect_err("multiple-line key ID must fail closed")
            .message
            .contains("exceeds 72 bytes"));

        fs::remove_file(public_key_path).expect("remove public key fixture");
        fs::remove_file(key_id_path).expect("remove key ID fixture");
    }

    #[test]
    fn sign_returns_a_verifiable_signature_over_the_exact_canonical_statement() {
        let runtime = runtime();
        let statement = statement();
        let canonical_statement = canonical_json_bytes(&statement).expect("statement");
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 2, statement))
                .expect("sign response"),
        );
        assert_eq!(response["ok"], true);
        let result = response["result"].as_object().expect("sign result");
        assert_eq!(
            result.keys().map(String::as_str).collect::<HashSet<_>>(),
            HashSet::from(["keyId", "signature", "statementDigest"])
        );
        assert_eq!(
            result["statementDigest"],
            sha256_prefixed(&canonical_statement)
        );
        let signature_text = result["signature"]
            .as_str()
            .expect("signature")
            .strip_prefix("ed25519:")
            .expect("signature prefix");
        let signature_bytes: [u8; 64] = general_purpose::URL_SAFE_NO_PAD
            .decode(signature_text)
            .expect("base64url signature")
            .try_into()
            .expect("signature length");
        let verifying_key = VerifyingKey::from(&SigningKey::from_bytes(&[7u8; 32]));
        verifying_key
            .verify(
                &canonical_statement,
                &Signature::from_bytes(&signature_bytes),
            )
            .expect("valid signature");
    }

    #[test]
    fn streaming_sign_returns_a_verifiable_signature_and_exact_retry_is_idempotent() {
        let runtime = runtime();
        let (statement, authorization_binding) = streaming_statement();
        validate_test_streaming_statement(&statement, &authorization_binding)
            .expect("valid streaming statement fixture");
        let canonical_statement =
            canonical_json_bytes(&statement).expect("canonical streaming statement");
        let expected_digest = sha256_prefixed(&canonical_statement);

        let first = response_value(
            &runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &runtime,
                    42,
                    statement.clone(),
                    authorization_binding.clone(),
                ))
                .expect("streaming sign response"),
        );
        assert_eq!(first["ok"], true, "unexpected response: {first}");
        assert_eq!(first["result"]["statementDigest"], expected_digest);
        let signature_bytes: [u8; 64] = general_purpose::URL_SAFE_NO_PAD
            .decode(
                first["result"]["signature"]
                    .as_str()
                    .expect("signature")
                    .strip_prefix("ed25519:")
                    .expect("signature prefix"),
            )
            .expect("base64url signature")
            .try_into()
            .expect("signature length");
        VerifyingKey::from(&SigningKey::from_bytes(&[7u8; 32]))
            .verify(
                &canonical_statement,
                &Signature::from_bytes(&signature_bytes),
            )
            .expect("valid streaming signature");

        let retry = response_value(
            &runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &runtime,
                    43,
                    statement,
                    authorization_binding,
                ))
                .expect("streaming retry response"),
        );
        assert_eq!(retry["ok"], true, "unexpected retry: {retry}");
        assert_eq!(retry["result"], first["result"]);
    }

    #[test]
    fn streaming_statement_rejects_derived_commitment_and_domain_mutations() {
        let (valid, authorization_binding) = streaming_statement();
        validate_test_streaming_statement(&valid, &authorization_binding)
            .expect("valid streaming fixture");

        let mut wrong_upstream_digest = valid.clone();
        wrong_upstream_digest.upstream_response.body_bytes += 1;
        assert!(
            validate_test_streaming_statement(&wrong_upstream_digest, &authorization_binding,)
                .expect_err("upstream byte-count substitution")
                .message
                .contains("canonical_digest")
        );

        let mut wrong_wire_headers = valid.clone();
        wrong_wire_headers
            .released_response
            .selected_wire_headers
            .transfer_encoding = "identity".to_string();
        assert!(
            validate_test_streaming_statement(&wrong_wire_headers, &authorization_binding)
                .expect_err("wire-header substitution")
                .message
                .contains("exact streaming proof framing")
        );

        let mut wrong_trailers = valid.clone();
        wrong_trailers.released_response.trailer_names.reverse();
        assert!(
            validate_test_streaming_statement(&wrong_trailers, &authorization_binding)
                .expect_err("trailer-order substitution")
                .message
                .contains("completion framing")
        );

        let mut wrong_exporter_domain = valid.clone();
        wrong_exporter_domain.tls_channel_binding.exporter_label =
            "EXPORTER-Serverware-Proxy-v2".to_string();
        assert!(
            validate_test_streaming_statement(&wrong_exporter_domain, &authorization_binding,)
                .expect_err("buffered exporter replay")
                .message
                .contains("streaming TLS exporter domain")
        );

        let mut wrong_binding_commitment = valid.clone();
        wrong_binding_commitment
            .authorization_binding_validation
            .binding_commitment
            .operation_context_digest = digest(99);
        assert!(validate_test_streaming_statement(
            &wrong_binding_commitment,
            &authorization_binding,
        )
        .expect_err("authorization commitment substitution")
        .message
        .contains("does not match the release binding"));

        let mut wrong_receipt_digest = valid;
        wrong_receipt_digest.control_plane_authorization_receipt_sha256 = digest(98);
        assert!(
            validate_test_streaming_statement(&wrong_receipt_digest, &authorization_binding,)
                .expect_err("authorization receipt digest substitution")
                .message
                .contains("does not match the receipt")
        );
    }

    #[test]
    fn shared_attempt_ledger_rejects_buffered_streaming_cross_domain_replay() {
        let buffered_first_runtime = runtime();
        let buffered = statement();
        let (streaming, streaming_binding) = streaming_statement();
        assert_eq!(
            response_value(
                &buffered_first_runtime
                    .handle_canonical_request(
                        &request_bytes(&buffered_first_runtime, 44, buffered,)
                    )
                    .expect("buffered-first response"),
            )["ok"],
            true
        );
        let rejected_streaming = response_value(
            &buffered_first_runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &buffered_first_runtime,
                    45,
                    streaming,
                    streaming_binding,
                ))
                .expect("cross-domain response"),
        );
        assert_eq!(
            rejected_streaming["error"]["code"],
            "attempt_statement_substitution"
        );

        let streaming_first_runtime = runtime();
        let (streaming, streaming_binding) = streaming_statement();
        assert_eq!(
            response_value(
                &streaming_first_runtime
                    .handle_canonical_request(&streaming_request_bytes(
                        &streaming_first_runtime,
                        46,
                        streaming,
                        streaming_binding,
                    ))
                    .expect("streaming-first response"),
            )["ok"],
            true
        );
        let rejected_buffered = response_value(
            &streaming_first_runtime
                .handle_canonical_request(&request_bytes(&streaming_first_runtime, 47, statement()))
                .expect("reverse cross-domain response"),
        );
        assert_eq!(
            rejected_buffered["error"]["code"],
            "attempt_statement_substitution"
        );
    }

    #[test]
    fn concurrent_buffered_and_streaming_attempts_have_one_domain_winner() {
        let runtime = std::sync::Arc::new(runtime());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let buffered_runtime = std::sync::Arc::clone(&runtime);
        let buffered_barrier = std::sync::Arc::clone(&barrier);
        let buffered = std::thread::spawn(move || {
            let request = request_bytes(&buffered_runtime, 51, statement());
            buffered_barrier.wait();
            response_value(
                &buffered_runtime
                    .handle_canonical_request(&request)
                    .expect("concurrent buffered response"),
            )
        });
        let streaming_runtime = std::sync::Arc::clone(&runtime);
        let streaming = std::thread::spawn(move || {
            let (statement, binding) = streaming_statement();
            let request = streaming_request_bytes(&streaming_runtime, 52, statement, binding);
            barrier.wait();
            response_value(
                &streaming_runtime
                    .handle_canonical_request(&request)
                    .expect("concurrent streaming response"),
            )
        });

        let responses = [
            buffered.join().expect("buffered worker"),
            streaming.join().expect("streaming worker"),
        ];
        assert_eq!(
            responses
                .iter()
                .filter(|response| response["ok"] == true)
                .count(),
            1
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| {
                    response["error"]["code"] == "attempt_statement_substitution"
                })
                .count(),
            1
        );
    }

    #[test]
    fn buffered_and_streaming_operations_reject_each_others_statement_types_before_claim() {
        let buffered_operation_runtime = runtime();
        let (streaming, streaming_binding) = streaming_statement();
        let wrong_buffered_request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": buffered_operation_runtime.boot_id(),
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {
                "statement": streaming.clone(),
                "authorization_binding": streaming_binding.clone(),
            },
            "requestId": request_id(53),
        }))
        .expect("canonical cross-operation request");
        let rejected = response_value(
            &buffered_operation_runtime
                .handle_canonical_request(&wrong_buffered_request)
                .expect("buffered operation rejection"),
        );
        assert_eq!(rejected["error"]["code"], "invalid_operation_params");
        assert_eq!(
            response_value(
                &buffered_operation_runtime
                    .handle_canonical_request(&streaming_request_bytes(
                        &buffered_operation_runtime,
                        54,
                        streaming,
                        streaming_binding,
                    ))
                    .expect("valid streaming request after type rejection"),
            )["ok"],
            true,
            "type rejection must not consume the attempt binding"
        );

        let streaming_operation_runtime = runtime();
        let buffered = statement();
        let buffered_binding = authorization_binding_for_statement(&buffered);
        let wrong_streaming_request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": streaming_operation_runtime.boot_id(),
            "operation": STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
            "params": {
                "statement": buffered.clone(),
                "authorization_binding": buffered_binding,
            },
            "requestId": request_id(55),
        }))
        .expect("canonical reverse cross-operation request");
        let rejected = response_value(
            &streaming_operation_runtime
                .handle_canonical_request(&wrong_streaming_request)
                .expect("streaming operation rejection"),
        );
        assert_eq!(rejected["error"]["code"], "invalid_operation_params");
        assert_eq!(
            response_value(
                &streaming_operation_runtime
                    .handle_canonical_request(&request_bytes(
                        &streaming_operation_runtime,
                        56,
                        buffered,
                    ))
                    .expect("valid buffered request after type rejection"),
            )["ok"],
            true,
            "reverse type rejection must not consume the attempt binding"
        );
    }

    #[test]
    fn streaming_attempt_binding_survives_restart_and_invalid_input_does_not_claim_it() {
        let directory = ledger_directory("streaming-restart");
        let (statement, authorization_binding) = streaming_statement();
        let expected_digest =
            sha256_prefixed(&canonical_json_bytes(&statement).expect("canonical statement"));

        let first_runtime = persistent_runtime(&directory, 51, 61);
        let mut invalid = statement.clone();
        invalid.control_plane_authorization_receipt_sha256 = digest(97);
        let rejected = response_value(
            &first_runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &first_runtime,
                    48,
                    invalid,
                    authorization_binding.clone(),
                ))
                .expect("invalid streaming response"),
        );
        assert_eq!(rejected["error"]["code"], "invalid_response_statement");

        let accepted = response_value(
            &first_runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &first_runtime,
                    49,
                    statement.clone(),
                    authorization_binding.clone(),
                ))
                .expect("valid streaming response"),
        );
        assert_eq!(accepted["result"]["statementDigest"], expected_digest);
        drop(first_runtime);

        let second_runtime = persistent_runtime(&directory, 52, 62);
        let retry = response_value(
            &second_runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &second_runtime,
                    49,
                    statement.clone(),
                    authorization_binding.clone(),
                ))
                .expect("restart retry response"),
        );
        assert_eq!(retry["result"]["statementDigest"], expected_digest);

        let mut substituted = statement;
        substituted.client_nonce = general_purpose::URL_SAFE_NO_PAD.encode([96u8; 32]);
        let rejected = response_value(
            &second_runtime
                .handle_canonical_request(&streaming_request_bytes(
                    &second_runtime,
                    50,
                    substituted,
                    authorization_binding,
                ))
                .expect("restart substitution response"),
        );
        assert_eq!(rejected["error"]["code"], "attempt_statement_substitution");

        drop(second_runtime);
        fs::remove_dir_all(directory).expect("remove streaming restart ledger fixture");
    }

    #[test]
    fn receipt_context_distinguishes_control_plane_runtime_and_binds_provenance() {
        let valid = statement();
        let response = &valid.control_plane_authorization_receipt.response;
        let signed_statement_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.statement_b64)
            .expect("decode signed response statement");
        let signed_statement: SignedResponseStatement =
            decode_canonical_json(&signed_statement_bytes).expect("signed response statement");
        assert_ne!(
            signed_statement.context.runtime_manifest_digest, valid.runtime_manifest_digest,
            "control plane and decision gate have distinct runtime measurements"
        );
        validate_test_statement(&valid).expect("distinct signed service measurements are valid");

        let mut provenance_substitution = statement();
        resign_control_plane_response_context(&mut provenance_substitution, |context| {
            context.provenance_digest = Some(digest(91));
        });
        assert!(validate_test_statement(&provenance_substitution)
            .expect_err("provenance substitution must fail")
            .message
            .contains("provenance context mismatch"));

        let mut missing_provenance = statement();
        resign_control_plane_response_context(&mut missing_provenance, |context| {
            context.provenance_digest = None;
        });
        assert!(validate_test_statement(&missing_provenance)
            .expect_err("signed authorization receipt must bind the response release")
            .message
            .contains("provenance context mismatch"));
    }

    #[test]
    fn attempt_binding_is_claimed_only_after_complete_validation() {
        let runtime = runtime();
        let mut invalid = statement();
        invalid.response.selected_headers_digest = digest(92);
        let rejected = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 70, invalid))
                .expect("closed validation response"),
        );
        assert_eq!(rejected["error"]["code"], "invalid_response_statement");
        assert!(
            runtime
                .attempt_statement_ledger
                .lock()
                .expect("attempt statement ledger")
                .manifest
                .max_observed_epoch_ms
                > 0,
            "rejected signing validation must still latch its wall-clock observation"
        );

        let accepted = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 71, statement()))
                .expect("valid signing response"),
        );
        assert_eq!(accepted["ok"], true);
    }

    #[test]
    fn persistent_attempt_binding_survives_restart_and_rejects_substitution() {
        let directory = ledger_directory("restart");
        let original = statement();
        let expected_digest =
            sha256_prefixed(&canonical_json_bytes(&original).expect("canonical statement"));

        let first_runtime = persistent_runtime(&directory, 31, 41);
        let first_response = response_value(
            &first_runtime
                .handle_canonical_request(&request_bytes(&first_runtime, 72, original.clone()))
                .expect("first persistent sign response"),
        );
        assert_eq!(first_response["ok"], true);
        assert_eq!(first_response["result"]["statementDigest"], expected_digest);
        drop(first_runtime);

        let second_runtime = persistent_runtime(&directory, 32, 42);
        let retry_response = response_value(
            &second_runtime
                .handle_canonical_request(&request_bytes(&second_runtime, 72, original.clone()))
                .expect("idempotent restart retry response"),
        );
        assert_eq!(retry_response["ok"], true);
        assert_eq!(retry_response["result"]["statementDigest"], expected_digest);

        let mut substituted = original;
        substituted.client_nonce = general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]);
        let substitution_response = response_value(
            &second_runtime
                .handle_canonical_request(&request_bytes(&second_runtime, 73, substituted))
                .expect("restart substitution response"),
        );
        assert_eq!(substitution_response["ok"], false);
        assert_eq!(
            substitution_response["error"]["code"],
            "attempt_statement_substitution"
        );

        drop(second_runtime);
        fs::remove_dir_all(directory).expect("remove restart ledger fixture");
    }

    #[test]
    fn binding_retention_uses_dispatch_expiry_when_reservation_expires_first() {
        let runtime = runtime();
        let mut slow_response = statement();
        let dispatch_started = slow_response
            .release_authority
            .authorization_state_observed_at_epoch_ms;
        let reservation_expiry = dispatch_started + 1;
        let dispatch_expiry = slow_response.release_authority.dispatch_expires_at_epoch_ms;
        assert!(reservation_expiry < dispatch_expiry);
        set_reservation_expiry_and_resign(&mut slow_response, reservation_expiry);
        validate_test_statement(&slow_response)
            .expect("dispatch receipt remains valid after reservation expiry");

        let attempt_id = slow_response.release_authority.attempt_id.clone();
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 74, slow_response))
                .expect("slow response signing result"),
        );
        assert_eq!(response["ok"], true, "unexpected response: {response}");

        let mut ledger = runtime
            .attempt_statement_ledger
            .lock()
            .expect("attempt statement ledger");
        assert_eq!(
            ledger
                .bindings
                .get(&attempt_id)
                .expect("durable attempt binding")
                .retain_until_epoch_ms,
            dispatch_expiry
        );
        ledger
            .prune_expired(reservation_expiry)
            .expect("reservation-expiry prune attempt");
        assert!(ledger.bindings.contains_key(&attempt_id));
        ledger
            .prune_expired(dispatch_expiry)
            .expect("dispatch-expiry prune");
        assert!(!ledger.bindings.contains_key(&attempt_id));
    }

    #[test]
    fn durable_ledger_reclaims_expired_capacity_and_rejects_clock_rollback() {
        let directory = ledger_directory("retention");
        let first_attempt = digest(51);
        let second_attempt = digest(52);
        let first_statement = digest(53);
        let second_statement = digest(54);

        let mut ledger = AttemptStatementLedger::open_with_limit_at(&directory, 1, 500)
            .expect("open bounded ledger");
        ledger
            .claim(&first_attempt, &first_statement, 1_000, 500)
            .expect("claim first binding");
        assert_eq!(
            ledger
                .claim(&second_attempt, &second_statement, 2_000, 600)
                .expect_err("unexpired binding must hold capacity")
                .code,
            "attempt_statement_capacity_exhausted"
        );
        drop(ledger);

        let observed_time_rollback = AttemptStatementLedger::open_with_limit_at(&directory, 1, 599)
            .err()
            .expect("clock rollback below a non-pruning observation must fail");
        assert_eq!(observed_time_rollback.code, "attempt_ledger_clock_rollback");

        let mut ledger = AttemptStatementLedger::open_with_limit_at(&directory, 1, 1_000)
            .expect("reopen and prune expired binding");
        assert!(!ledger.bindings.contains_key(&first_attempt));
        ledger
            .claim(&second_attempt, &second_statement, 2_000, 1_000)
            .expect("reclaimed capacity accepts new binding");
        drop(ledger);

        let rollback = AttemptStatementLedger::open_with_limit_at(&directory, 1, 999)
            .err()
            .expect("clock rollback below durable observation high-water must fail");
        assert_eq!(rollback.code, "attempt_ledger_clock_rollback");
        fs::remove_dir_all(directory).expect("remove retention ledger fixture");
    }

    #[test]
    fn ledger_initialization_is_explicit_and_cannot_replace_existing_state() {
        let directory = uninitialized_ledger_directory("initialization");
        let missing = AttemptStatementLedger::open(&directory)
            .err()
            .expect("normal startup must reject a missing manifest");
        assert_eq!(missing.code, "attempt_ledger_not_initialized");

        CustodyRuntime::initialize_attempt_ledger_directory(&directory)
            .expect("explicitly initialize ledger");
        let ledger = AttemptStatementLedger::open(&directory).expect("open initialized ledger");
        drop(ledger);
        let repeated = CustodyRuntime::initialize_attempt_ledger_directory(&directory)
            .expect_err("initialization must not replace an existing manifest");
        assert_eq!(repeated.code, "attempt_ledger_already_initialized");

        fs::remove_file(directory.join(ATTEMPT_LEDGER_MANIFEST_FILE))
            .expect("remove manifest to simulate state deletion");
        let deleted = AttemptStatementLedger::open(&directory)
            .err()
            .expect("deleted state must not be silently recreated");
        assert_eq!(deleted.code, "attempt_ledger_not_initialized");
        fs::remove_dir_all(directory).expect("remove initialization ledger fixture");
    }

    #[test]
    fn ledger_startup_cleans_only_validated_orphan_temporary_files() {
        assert!(parse_attempt_ledger_temporary_filename(
            ".ledger-tmp-4294967295-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!parse_attempt_ledger_temporary_filename(
            ".ledger-tmp-000123-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!parse_attempt_ledger_temporary_filename(
            ".ledger-tmp-4294967296-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!parse_attempt_ledger_temporary_filename(
            ".ledger-tmp-0-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        let directory = ledger_directory("orphan-temporary");
        let orphan = directory.join(".ledger-tmp-123-00000000000000000000000000000000");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(ATTEMPT_LEDGER_FILE_MODE)
            .open(&orphan)
            .expect("create orphan ledger temporary");
        file.write_all(b"partial")
            .expect("write orphan ledger temporary");
        file.sync_all().expect("sync orphan ledger temporary");
        drop(file);
        let ledger = AttemptStatementLedger::open(&directory)
            .expect("validated orphan temporary must be cleaned at startup");
        assert!(!orphan.exists());
        drop(ledger);
        fs::remove_dir_all(directory).expect("remove orphan-temporary ledger fixture");

        let unsafe_directory = ledger_directory("unsafe-orphan-temporary");
        let unsafe_orphan =
            unsafe_directory.join(".ledger-tmp-456-11111111111111111111111111111111");
        std::os::unix::fs::symlink(
            unsafe_directory.join(ATTEMPT_LEDGER_MANIFEST_FILE),
            &unsafe_orphan,
        )
        .expect("create symlinked orphan ledger temporary");
        let error = AttemptStatementLedger::open(&unsafe_directory)
            .err()
            .expect("unsafe orphan temporary must fail closed");
        assert_eq!(error.code, "attempt_ledger_corrupt");
        fs::remove_file(unsafe_orphan).expect("remove unsafe orphan temporary");
        fs::remove_dir_all(unsafe_directory).expect("remove unsafe-orphan ledger fixture");
    }

    #[test]
    fn ledger_configuration_rejects_symlinks_and_writable_ancestors() {
        let base = uninitialized_ledger_directory("path-security");
        let real = base.join("real");
        fs::create_dir(&real).expect("create real ledger directory");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))
            .expect("protect real ledger directory");
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&real, &alias).expect("create ledger symlink");
        assert_eq!(
            validate_attempt_ledger_directory(&alias)
                .expect_err("symlinked ledger directory must fail")
                .code,
            "invalid_attempt_ledger_configuration"
        );

        let writable_parent = base.join("writable");
        fs::create_dir(&writable_parent).expect("create writable parent");
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
            .expect("make parent writable");
        let nested = writable_parent.join("ledger");
        fs::create_dir(&nested).expect("create nested ledger");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .expect("protect nested ledger");
        let error = validate_attempt_ledger_directory(&nested)
            .expect_err("writable ancestor must fail closed");
        assert!(error.message.contains("group- or other-writable"));

        fs::remove_dir_all(base).expect("remove path-security fixture");
    }

    #[test]
    fn durable_ledger_rejects_corruption_missing_records_and_competing_runtimes() {
        let locked_directory = ledger_directory("locked");
        let first = AttemptStatementLedger::open(&locked_directory).expect("lock first ledger");
        let lock_error = AttemptStatementLedger::open(&locked_directory)
            .err()
            .expect("second runtime must not share a ledger");
        assert_eq!(lock_error.code, "attempt_ledger_locked");
        drop(first);
        fs::remove_dir_all(locked_directory).expect("remove locked ledger fixture");

        let corrupt_directory = ledger_directory("corrupt");
        let attempt_id = digest(61);
        let mut ledger = AttemptStatementLedger::open_with_limit_at(&corrupt_directory, 4, 100)
            .expect("open corruption ledger");
        ledger
            .claim(&attempt_id, &digest(62), 1_000, 100)
            .expect("persist corruption fixture binding");
        drop(ledger);
        let binding_path = corrupt_directory.join(
            attempt_binding_filename(&attempt_id).expect("corruption fixture binding filename"),
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&binding_path)
            .expect("open binding for corruption")
            .write_all(b"x")
            .expect("corrupt binding record");
        let corrupt_error = AttemptStatementLedger::open_with_limit_at(&corrupt_directory, 4, 100)
            .err()
            .expect("corrupt binding must fail closed");
        assert_eq!(corrupt_error.code, "attempt_ledger_corrupt");
        fs::remove_dir_all(corrupt_directory).expect("remove corrupt ledger fixture");

        let missing_directory = ledger_directory("missing");
        let attempt_id = digest(63);
        let mut ledger = AttemptStatementLedger::open_with_limit_at(&missing_directory, 4, 100)
            .expect("open missing-record ledger");
        ledger
            .claim(&attempt_id, &digest(64), 1_000, 100)
            .expect("persist missing-record fixture binding");
        drop(ledger);
        fs::remove_file(
            missing_directory
                .join(attempt_binding_filename(&attempt_id).expect("missing binding filename")),
        )
        .expect("remove active binding behind manifest");
        let missing_error = AttemptStatementLedger::open_with_limit_at(&missing_directory, 4, 100)
            .err()
            .expect("missing active binding must fail closed");
        assert_eq!(missing_error.code, "attempt_ledger_corrupt");
        fs::remove_dir_all(missing_directory).expect("remove missing ledger fixture");
    }

    #[test]
    fn response_proof_authorization_lifetime_is_bounded() {
        let mut excessive = statement();
        excessive.release_authority.dispatch_expires_at_epoch_ms = excessive
            .release_authority
            .authorization_state_observed_at_epoch_ms
            .saturating_add(MAX_RELEASE_AUTHORIZATION_LIFETIME_MS)
            .saturating_add(1);
        let error = validate_release_authority(&ResponseStatementAuthorityView::from(&excessive))
            .expect_err("far-future dispatch receipt must not pin the ledger indefinitely");
        assert!(error.message.contains("bounded response-proof"));
    }

    #[test]
    fn response_proof_temporal_validation_uses_the_claim_clock_boundary() {
        let statement = statement();
        let expiry = statement.release_authority.dispatch_expires_at_epoch_ms;
        let verifying_key = pinned_control_plane_response_verifying_key();
        validate_response_statement_with_control_plane_response_key_at(
            &statement,
            &verifying_key,
            expiry - 1,
        )
        .expect("receipt remains valid immediately before dispatch expiry");
        let error = validate_response_statement_with_control_plane_response_key_at(
            &statement,
            &verifying_key,
            expiry,
        )
        .expect_err("receipt must fail exactly at dispatch expiry");
        assert!(error.message.contains("temporal relation"));
    }

    #[test]
    fn claim_clock_rollback_latches_the_forward_validation_sample() {
        let runtime = runtime();
        let minimum_epoch_ms = current_epoch_ms()
            .expect("current epoch")
            .checked_add(60_000)
            .expect("future validation sample");
        let error = runtime
            .claim_attempt_statement_digest(
                "attempt-clock-latch",
                &digest(88),
                minimum_epoch_ms + 60_000,
                minimum_epoch_ms,
            )
            .expect_err("backward claim sample must fail closed");
        assert_eq!(error.code, "attempt_ledger_clock_rollback");
        let mut ledger = runtime
            .attempt_statement_ledger
            .lock()
            .expect("attempt statement ledger");
        assert_eq!(ledger.manifest.max_observed_epoch_ms, minimum_epoch_ms);
        let rollback = ledger
            .claim(
                "attempt-after-clock-latch",
                &digest(89),
                minimum_epoch_ms + 60_000,
                minimum_epoch_ms - 1,
            )
            .expect_err("latched forward observation must reject later rollback");
        assert_eq!(rollback.code, "attempt_ledger_clock_rollback");
    }

    #[test]
    fn invalid_claim_clock_latches_the_forward_validation_sample() {
        let runtime = runtime();
        let minimum_epoch_ms = current_epoch_ms()
            .expect("current epoch")
            .checked_add(60_000)
            .expect("future validation sample");
        let error = runtime
            .claim_attempt_statement_digest_with_clock(
                "attempt-invalid-clock-latch",
                &digest(90),
                minimum_epoch_ms + 60_000,
                minimum_epoch_ms,
                || {
                    Err(attempt_ledger_error(
                        "attempt_ledger_clock_rollback",
                        "system clock precedes the Unix epoch",
                    ))
                },
            )
            .expect_err("an invalid claim clock must fail closed");
        assert_eq!(error.code, "attempt_ledger_clock_rollback");
        let ledger = runtime
            .attempt_statement_ledger
            .lock()
            .expect("attempt statement ledger");
        assert_eq!(ledger.manifest.max_observed_epoch_ms, minimum_epoch_ms);
    }

    #[test]
    fn response_proof_clock_sampling_validation_and_claim_are_serialized() {
        let runtime = std::sync::Arc::new(runtime());
        let request = request_bytes(&runtime, 99, statement());
        let validation_guard = runtime
            .response_proof_validation
            .lock()
            .expect("response proof validation lock");
        let worker_runtime = std::sync::Arc::clone(&runtime);
        let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            completed_tx
                .send(worker_runtime.handle_canonical_request(&request))
                .expect("publish serialized validation result");
        });
        assert!(matches!(
            completed_rx.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(validation_guard);
        completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("validation proceeds after serialization lock")
            .expect("serialized response proof request succeeds");
        worker.join().expect("serialized validation worker");
    }

    #[test]
    fn poisoned_ledger_rejects_clock_advancement_without_mutation() {
        let mut ledger = AttemptStatementLedger::in_memory();
        ledger.manifest.max_observed_epoch_ms = 500;
        ledger.poisoned = true;
        let before = ledger.manifest.clone();
        let error = ledger
            .advance_max_observed_time(1_000)
            .expect_err("poisoned ledger must reject every durable operation");
        assert_eq!(error.code, "attempt_ledger_unavailable");
        assert_eq!(ledger.manifest, before);
        assert_eq!(
            ledger
                .prune_expired(1_000)
                .expect_err("poisoned ledger must reject pruning")
                .code,
            "attempt_ledger_unavailable"
        );
    }

    #[test]
    fn identical_attempt_statement_is_idempotently_signed_concurrently() {
        let runtime = std::sync::Arc::new(runtime());
        let statement = statement();
        let expected_digest =
            sha256_prefixed(&canonical_json_bytes(&statement).expect("canonical statement"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let workers = (0..12)
            .map(|index| {
                let runtime = std::sync::Arc::clone(&runtime);
                let barrier = std::sync::Arc::clone(&barrier);
                let statement = statement.clone();
                std::thread::spawn(move || {
                    let request = request_bytes(&runtime, 80 + index, statement);
                    barrier.wait();
                    response_value(
                        &runtime
                            .handle_canonical_request(&request)
                            .expect("idempotent signing response"),
                    )
                })
            })
            .collect::<Vec<_>>();

        let mut signatures = HashSet::new();
        for worker in workers {
            let response = worker.join().expect("signing worker");
            assert_eq!(response["ok"], true, "unexpected response: {response}");
            assert_eq!(response["result"]["statementDigest"], expected_digest);
            signatures.insert(
                response["result"]["signature"]
                    .as_str()
                    .expect("signature")
                    .to_string(),
            );
        }
        assert_eq!(signatures.len(), 1);
    }

    #[test]
    fn concurrent_attempt_statement_substitution_has_one_digest_winner() {
        let runtime = std::sync::Arc::new(runtime());
        let first = statement();
        let mut substituted = first.clone();
        substituted.client_nonce = general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]);
        let first_digest =
            sha256_prefixed(&canonical_json_bytes(&first).expect("first canonical statement"));
        let substituted_digest = sha256_prefixed(
            &canonical_json_bytes(&substituted).expect("substituted canonical statement"),
        );
        assert_ne!(first_digest, substituted_digest);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let workers = (0..16)
            .map(|index| {
                let runtime = std::sync::Arc::clone(&runtime);
                let barrier = std::sync::Arc::clone(&barrier);
                let candidate = if index % 2 == 0 {
                    first.clone()
                } else {
                    substituted.clone()
                };
                std::thread::spawn(move || {
                    let request = request_bytes(&runtime, 100 + index, candidate);
                    barrier.wait();
                    response_value(
                        &runtime
                            .handle_canonical_request(&request)
                            .expect("substitution response"),
                    )
                })
            })
            .collect::<Vec<_>>();

        let mut accepted_digests = HashSet::new();
        let mut accepted = 0;
        let mut rejected = 0;
        for worker in workers {
            let response = worker.join().expect("substitution worker");
            if response["ok"] == true {
                accepted += 1;
                accepted_digests.insert(
                    response["result"]["statementDigest"]
                        .as_str()
                        .expect("statement digest")
                        .to_string(),
                );
            } else {
                rejected += 1;
                assert_eq!(
                    response["error"]["code"], "attempt_statement_substitution",
                    "unexpected rejection: {response}"
                );
            }
        }
        assert_eq!(accepted, 8);
        assert_eq!(rejected, 8);
        assert_eq!(accepted_digests.len(), 1);
        assert!(
            accepted_digests.contains(&first_digest)
                || accepted_digests.contains(&substituted_digest)
        );
    }

    #[test]
    fn release_binding_digest_matches_control_plane_python_canonicalization() {
        let mut binding = authorization_binding_for_statement(&statement());
        binding.operation_context = json!({
            "operation":"custody.test",
            "subject":"caf\u{e9} \u{1f512}",
        });
        let canonical = canonical_json_ensure_ascii_bytes(&binding).expect("canonical binding");
        assert_eq!(
            sha256_prefixed(&canonical),
            "sha256:64e3ba621c285782bbb596e5195aa8867030252d5fd6214d4abc22e3cc097332"
        );
    }

    #[test]
    fn response_proof_signing_rejects_claim_substitution_behind_a_valid_dispatch_receipt() {
        for (index, claim) in [
            "principal",
            "route",
            "credential_id",
            "credential_version",
            "request_digest",
            "operation_digest",
        ]
        .into_iter()
        .enumerate()
        {
            let runtime = runtime();
            let mut substituted = statement();
            match claim {
                "principal" => {
                    substituted.principal_id = "agent:substituted".to_string();
                    substituted.control_plane_authorization_receipt.principal_id =
                        substituted.principal_id.clone();
                }
                "route" => {
                    substituted.route_id = "route:substituted".to_string();
                    substituted.control_plane_authorization_receipt.route_id =
                        substituted.route_id.clone();
                }
                "credential_id" => {
                    substituted.release_authority.credential_ref =
                        Some("credential:substituted".to_string());
                    substituted
                        .control_plane_authorization_receipt
                        .release_authority
                        .credential_ref = substituted.release_authority.credential_ref.clone();
                }
                "credential_version" => {
                    substituted.release_authority.credential_version = 8;
                    substituted
                        .control_plane_authorization_receipt
                        .release_authority
                        .credential_version = 8;
                }
                "request_digest" => {
                    substituted.request_digest = digest(60);
                    substituted.release_authority.request_digest =
                        substituted.request_digest.clone();
                    substituted
                        .control_plane_authorization_receipt
                        .release_authority
                        .request_digest = substituted.request_digest.clone();
                    substituted.response.selected_headers.insert(
                        "x-serverware-request-digest".to_string(),
                        substituted.request_digest.clone(),
                    );
                }
                "operation_digest" => {
                    substituted.operation_digest = digest(61);
                    substituted.release_authority.operation_digest =
                        substituted.operation_digest.clone();
                    substituted
                        .control_plane_authorization_receipt
                        .release_authority
                        .operation_digest = substituted.operation_digest.clone();
                    substituted.response.selected_headers.insert(
                        "x-serverware-operation-digest".to_string(),
                        substituted.operation_digest.clone(),
                    );
                }
                _ => unreachable!(),
            }
            substituted.response.selected_headers_digest = sha256_prefixed(
                &canonical_json_bytes(&substituted.response.selected_headers)
                    .expect("canonical substituted headers"),
            );

            let response = response_value(
                &runtime
                    .handle_canonical_request(&request_bytes(
                        &runtime,
                        40 + index as u8,
                        substituted,
                    ))
                    .expect("closed substitution response"),
            );
            assert_eq!(response["ok"], false, "claim {claim} reached signing");
            assert_eq!(
                response["error"]["code"], "invalid_response_statement",
                "unexpected error for {claim}: {response}"
            );
            assert!(
                response["error"]["message"]
                    .as_str()
                    .expect("substitution error")
                    .contains("release authorization binding digest mismatch"),
                "claim {claim} failed before the cryptographic binding check: {response}"
            );
        }
    }

    #[test]
    fn response_proof_signing_rejects_a_forged_control_plane_response_signature() {
        let runtime = runtime();
        let mut forged = statement();
        let encoded_signature = forged
            .control_plane_authorization_receipt
            .response
            .signature
            .strip_prefix("ed25519:")
            .expect("signature prefix");
        let mut signature_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .expect("signature bytes");
        assert_eq!(signature_bytes.len(), Signature::BYTE_SIZE);
        signature_bytes[0] ^= 1;
        let forged_signature = format!(
            "ed25519:{}",
            general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes)
        );
        forged
            .control_plane_authorization_receipt
            .response
            .signature = forged_signature;

        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 34, forged))
                .expect("closed error response"),
        );
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "invalid_response_statement");
        assert!(response["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("signature verification failed"));
    }

    #[test]
    fn response_proof_signing_rejects_a_valid_signature_from_the_wrong_key() {
        let runtime = runtime();
        let wrong_response_signing_key = SigningKey::from_bytes(&[20u8; 32]);
        let wrong_key_statement = statement_signed_by(&wrong_response_signing_key);

        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 35, wrong_key_statement))
                .expect("closed error response"),
        );
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "invalid_response_statement");
        assert!(response["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("does not match the pinned"));
    }

    #[test]
    fn response_proof_signing_fails_closed_without_a_pinned_response_key() {
        let runtime = unconfigured_runtime();
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 36, statement()))
                .expect("closed error response"),
        );
        assert_eq!(response["ok"], false);
        assert_eq!(
            response["error"]["code"],
            "control_plane_response_key_unavailable"
        );
        assert!(
            CustodyRuntime::generate_with_configured_control_plane_response_key(
                None,
                Path::new("/unused"),
            )
            .err()
            .expect("the production generation path must require a configured key")
            .message
            .contains("required")
        );

        let construction_error = CustodyRuntime::generate_with_control_plane_response_public_key(
            pinned_control_plane_response_verifying_key(),
            &digest(99),
            Path::new("/unused"),
        )
        .err()
        .expect("mismatched configured key ID");
        assert_eq!(
            construction_error.code,
            "invalid_control_plane_response_key_configuration"
        );
    }

    #[test]
    fn custody_signing_rejects_legacy_or_inconsistent_v2_authority() {
        let mut legacy = statement();
        legacy.api_version = "serverware.proxyResponseStatement/v1".to_string();
        assert!(validate_test_statement(&legacy)
            .expect_err("legacy statement must not reach signing")
            .message
            .contains("proxyResponseStatement/v2"));

        let mut partial_grant = statement();
        partial_grant.release_authority.approval_id = None;
        assert!(validate_test_statement(&partial_grant)
            .expect_err("partial grant identity must fail")
            .message
            .contains("must be paired"));

        let mut invalid_attempt = statement();
        invalid_attempt.release_authority.attempt_id = "attempt:not-a-digest".to_string();
        assert!(validate_test_statement(&invalid_attempt)
            .expect_err("attempt identity must be a digest")
            .message
            .contains("canonical lowercase sha256"));

        let mut invalid_credential = statement();
        invalid_credential.release_authority.credential_ref = None;
        assert!(validate_test_statement(&invalid_credential)
            .expect_err("credential identity and version must agree")
            .message
            .contains("inconsistent"));

        let mut wrong_upstream_status = statement();
        wrong_upstream_status.upstream_response.status = 201;
        assert!(validate_test_statement(&wrong_upstream_status)
            .expect_err("upstream and emitted statuses must agree")
            .message
            .contains("must match"));

        let runtime = runtime();
        let mut false_completion_statement =
            serde_json::to_value(statement()).expect("serialize statement");
        let authority = false_completion_statement["release_authority"]
            .as_object_mut()
            .expect("release authority");
        authority.remove("authorization_state_at_upstream_dispatch");
        authority.insert(
            "completion_outcome".to_string(),
            Value::String("forwarded".to_string()),
        );
        let request = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {"statement": false_completion_statement},
            "requestId": request_id(31),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&request).expect("request"))
                .expect("strict error response"),
        );
        assert_eq!(response["error"]["code"], "invalid_operation_params");
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("completion_outcome"));
    }

    #[test]
    fn custody_exposes_exact_buffered_and_streaming_signing_capabilities() {
        let runtime = runtime();
        let hello = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(32),
        });
        let hello_response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&hello).expect("hello request"))
                .expect("hello response"),
        );
        assert_eq!(
            hello_response["result"]["capabilities"],
            json!([
                HELLO_OPERATION,
                RESPONSE_PROOF_SIGN_OPERATION,
                STREAMING_RESPONSE_PROOF_SIGN_OPERATION,
            ])
        );

        let legacy = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": "responseProof.sign/v1",
            "params": {"statement": statement()},
            "requestId": request_id(33),
        });
        let legacy_response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&legacy).expect("legacy request"))
                .expect("legacy response"),
        );
        assert_eq!(legacy_response["error"]["code"], "unknown_operation");
    }

    #[test]
    fn custody_rejects_temporal_and_raw_upstream_header_tampering() {
        let mut expired_at_observation = statement();
        expired_at_observation
            .release_authority
            .reservation_expires_at_epoch_ms = Some(
            expired_at_observation
                .release_authority
                .authorization_state_observed_at_epoch_ms,
        );
        assert!(validate_test_statement(&expired_at_observation)
            .expect_err("expired dispatch observation")
            .message
            .contains("temporally invalid"));

        let mut future_observation = statement();
        future_observation
            .release_authority
            .authorization_state_observed_at_epoch_ms =
            future_observation.issued_at_unix.saturating_add(2) * 1000;
        assert!(validate_test_statement(&future_observation)
            .expect_err("observation after statement issuance")
            .message
            .contains("temporally invalid"));

        let mut tampered_raw_header = statement();
        tampered_raw_header
            .upstream_response
            .selected_raw_policy_headers_b64
            .insert(
                "content-type".to_string(),
                vec![general_purpose::URL_SAFE_NO_PAD.encode(b"text/plain")],
            );
        assert!(validate_test_statement(&tampered_raw_header)
            .expect_err("raw header tamper without digest update")
            .message
            .contains("canonical_digest"));
    }

    #[test]
    fn rejects_duplicate_unknown_and_noncanonical_json_fields() {
        let duplicate = format!(
            "{{\"apiVersion\":\"{PROTOCOL_API_VERSION}\",\"bootId\":null,\"operation\":\"{HELLO_OPERATION}\",\"params\":{{}},\"requestId\":\"{}\",\"requestId\":\"{}\"}}",
            request_id(3),
            request_id(4)
        );
        let error = runtime()
            .handle_canonical_request(duplicate.as_bytes())
            .expect_err("duplicate field");
        assert_eq!(error.code, "invalid_json");
        assert!(error
            .message
            .contains("duplicate JSON object key: requestId"));

        let unknown = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(5),
            "surprise": true,
        });
        let error = runtime()
            .handle_canonical_request(&canonical_json_bytes(&unknown).expect("unknown request"))
            .expect_err("unknown envelope field");
        assert_eq!(error.code, "invalid_request");
        assert!(error.message.contains("unknown field"));

        let noncanonical = format!(
            "{{ \"apiVersion\": \"{PROTOCOL_API_VERSION}\", \"bootId\": null, \"operation\": \"{HELLO_OPERATION}\", \"params\": {{}}, \"requestId\": \"{}\" }}",
            request_id(6)
        );
        assert_eq!(
            runtime()
                .handle_canonical_request(noncanonical.as_bytes())
                .expect_err("noncanonical JSON")
                .code,
            "noncanonical_json"
        );
    }

    #[test]
    fn rejects_unknown_params_operation_cross_boot_and_replayed_ids() {
        let runtime = runtime();
        let hello_with_unknown_param = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {"keyB64": "forbidden"},
            "requestId": request_id(7),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(
                    &canonical_json_bytes(&hello_with_unknown_param).expect("request"),
                )
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "invalid_operation_params");

        let unknown_operation = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": "decrypt/v1",
            "params": {},
            "requestId": request_id(8),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(
                    &canonical_json_bytes(&unknown_operation).expect("request"),
                )
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "unknown_operation");

        let wrong_boot = general_purpose::URL_SAFE_NO_PAD.encode([10u8; 32]);
        assert_ne!(wrong_boot, runtime.boot_id());
        let cross_boot = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": wrong_boot,
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {"statement": statement()},
            "requestId": request_id(9),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&cross_boot).expect("request"))
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "cross_boot_request");

        let replay_bytes = request_bytes(&runtime, 10, statement());
        assert_eq!(
            response_value(
                &runtime
                    .handle_canonical_request(&replay_bytes)
                    .expect("first response")
            )["ok"],
            true
        );
        let response = response_value(
            &runtime
                .handle_canonical_request(&replay_bytes)
                .expect("replay response"),
        );
        assert_eq!(response["error"]["code"], "replayed_request_id");
    }

    #[test]
    fn rejects_noncanonical_request_ids_digests_and_base64() {
        let runtime = runtime();
        let padded_id_request = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": format!("{}=", request_id(11)),
        });
        assert_eq!(
            runtime
                .handle_canonical_request(
                    &canonical_json_bytes(&padded_id_request).expect("request")
                )
                .expect_err("padded request ID")
                .code,
            "invalid_request_id"
        );

        let mut bad_digest = statement();
        bad_digest.policy_digest = bad_digest.policy_digest.to_ascii_uppercase();
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 12, bad_digest))
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "invalid_response_statement");
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("canonical lowercase sha256"));

        let mut padded_nonce = statement();
        padded_nonce.client_nonce.push('=');
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 13, padded_nonce))
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "invalid_response_statement");
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("unpadded base64url"));
    }

    #[test]
    fn rejects_statement_unknown_fields_and_internal_binding_mismatches() {
        let runtime = runtime();
        let mut statement_value = serde_json::to_value(statement()).expect("statement value");
        statement_value
            .as_object_mut()
            .expect("statement object")
            .insert("bytesB64".to_string(), json!("arbitrary"));
        let request = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {"statement": statement_value},
            "requestId": request_id(14),
        });
        let response = response_value(
            &runtime
                .handle_canonical_request(&canonical_json_bytes(&request).expect("request"))
                .expect("error response"),
        );
        assert_eq!(response["error"]["code"], "invalid_operation_params");
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("unknown field"));

        let mut mismatched_headers = statement();
        mismatched_headers
            .response
            .selected_headers
            .insert("x-serverware-policy-hash".to_string(), digest(99));
        mismatched_headers.response.selected_headers_digest = sha256_prefixed(
            &canonical_json_bytes(&mismatched_headers.response.selected_headers)
                .expect("canonical headers"),
        );
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 15, mismatched_headers))
                .expect("error response"),
        );
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("does not match its statement field"));

        let mut mismatched_identity = statement();
        mismatched_identity.server_instance.identity_digest = digest(42);
        let response = response_value(
            &runtime
                .handle_canonical_request(&request_bytes(&runtime, 16, mismatched_identity))
                .expect("error response"),
        );
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("does not match server_instance.id"));
    }

    #[test]
    fn frame_codec_uses_big_endian_length_and_enforces_cap() {
        let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
        let payload = b"{\"a\":1}";
        write_frame(&mut writer, payload, Duration::from_secs(1)).expect("write frame");
        assert_eq!(
            read_frame(&mut reader, Duration::from_secs(1)).expect("read frame"),
            payload
        );

        let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
        writer
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .expect("write oversized header");
        assert!(matches!(
            read_frame(&mut reader, Duration::from_secs(1)),
            Err(WireError::FrameTooLarge { .. })
        ));
    }
}
