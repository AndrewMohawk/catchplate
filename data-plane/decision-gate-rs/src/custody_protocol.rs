use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::{Date, Duration as TimeDuration, Month, OffsetDateTime};
use zeroize::Zeroize;

pub const PROTOCOL_API_VERSION: &str = "serverware.custodyProtocol/v1";
pub const RESPONSE_STATEMENT_API_VERSION: &str = "serverware.proxyResponseStatement/v2";
pub const HELLO_OPERATION: &str = "hello/v1";
pub const RESPONSE_PROOF_SIGN_OPERATION: &str = "responseProof.sign/v2";
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
const AUTHORIZATION_RECEIPT_API_VERSION: &str = "serverware.controlPlaneAuthorizationReceipt/v1";
const RELEASE_AUTHORIZATION_DISPATCH_PATH: &str = "/api/data-plane/release-authorizations/dispatch";
const CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV: &str =
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY";
const CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV: &str =
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID";

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneAuthorizationReceiptRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub nonce: String,
    pub body_b64: String,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
    query: String,
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
    capabilities: [&'static str; 2],
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

pub struct CustodyRuntime {
    boot_id: String,
    signing_key: SigningKey,
    public_key_pem: String,
    key_id: String,
    control_plane_response_verifying_key: Option<VerifyingKey>,
    seen_request_ids: Mutex<HashSet<String>>,
}

impl CustodyRuntime {
    pub fn generate() -> Result<Self, ProtocolError> {
        let control_plane_response_verifying_key =
            configured_control_plane_response_verifying_key()?;
        Self::generate_with_optional_control_plane_response_key(
            control_plane_response_verifying_key,
        )
    }

    pub fn generate_with_control_plane_response_public_key(
        control_plane_response_verifying_key: VerifyingKey,
        expected_key_id: &str,
    ) -> Result<Self, ProtocolError> {
        validate_pinned_control_plane_response_key(
            &control_plane_response_verifying_key,
            expected_key_id,
        )?;
        Self::generate_with_optional_control_plane_response_key(Some(
            control_plane_response_verifying_key,
        ))
    }

    fn generate_with_optional_control_plane_response_key(
        control_plane_response_verifying_key: Option<VerifyingKey>,
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
        let runtime =
            Self::from_secret_material(seed, boot_id_bytes, control_plane_response_verifying_key);
        seed.zeroize();
        boot_id_bytes.zeroize();
        Ok(runtime)
    }

    fn from_secret_material(
        mut signing_seed: [u8; ED25519_SEED_BYTES],
        boot_id_bytes: [u8; BOOT_ID_BYTES],
        control_plane_response_verifying_key: Option<VerifyingKey>,
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();
        let public_key = signing_key.verifying_key().to_bytes();
        let spki_der = ed25519_spki_der(&public_key);
        Self {
            boot_id: general_purpose::URL_SAFE_NO_PAD.encode(boot_id_bytes),
            signing_key,
            public_key_pem: pem_public_key(&spki_der),
            key_id: sha256_prefixed(&spki_der),
            control_plane_response_verifying_key,
            seen_request_ids: Mutex::new(HashSet::new()),
        }
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
        self.claim_request_id(&request.request_id)?;

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
                    capabilities: [HELLO_OPERATION, RESPONSE_PROOF_SIGN_OPERATION],
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
                let Some(boot_id) = request.boot_id.as_deref() else {
                    return Err(ProtocolError::new(
                        "missing_boot_id",
                        "responseProof.sign/v2 requires the current bootId",
                    ));
                };
                validate_boot_id(boot_id)?;
                if boot_id != self.boot_id {
                    return Err(ProtocolError::new(
                        "cross_boot_request",
                        "request bootId does not match the current custody runtime boot",
                    ));
                }
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
                validate_response_statement_with_control_plane_response_key(
                    &params.statement,
                    control_plane_response_verifying_key,
                )?;
                validate_release_authorization_binding(
                    &params.statement,
                    &params.authorization_binding,
                )?;
                let canonical_statement = canonical_json_bytes(&params.statement)?;
                let statement_digest = sha256_prefixed(&canonical_statement);
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
            _ => Err(ProtocolError::new(
                "unknown_operation",
                "operation must be hello/v1 or responseProof.sign/v2",
            )),
        }
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
}

fn configured_control_plane_response_verifying_key() -> Result<Option<VerifyingKey>, ProtocolError>
{
    let (public_key_path, expected_key_id) = match (
        env::var_os(CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV),
        env::var_os(CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV),
    ) {
        (Some(public_key_path), Some(expected_key_id)) => (public_key_path, expected_key_id),
        (None, None) => return Ok(None),
        _ => {
            return Err(ProtocolError::new(
                "invalid_control_plane_response_key_configuration",
                format!(
                    "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} and {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} must be configured together"
                ),
            ))
        }
    };
    let expected_key_id = expected_key_id.into_string().map_err(|_| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} must be valid UTF-8"),
        )
    })?;
    let public_key_pem = read_control_plane_response_public_key_pem(Path::new(&public_key_path))?;
    let verifying_key = VerifyingKey::from_public_key_pem(&public_key_pem).map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} must contain an Ed25519 SubjectPublicKeyInfo PEM: {error}"
            ),
        )
    })?;
    validate_pinned_control_plane_response_key(&verifying_key, &expected_key_id)?;
    Ok(Some(verifying_key))
}

fn read_control_plane_response_public_key_pem(path: &Path) -> Result<String, ProtocolError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            ProtocolError::new(
                "invalid_control_plane_response_key_configuration",
                format!("open {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV}: {error}"),
            )
        })?;
    let initial_metadata = file.metadata().map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("inspect {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV}: {error}"),
        )
    })?;
    if !initial_metadata.is_file() {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} must be a regular file"),
        ));
    }
    if initial_metadata.len() > MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES as u64 {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} exceeds {MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES} bytes"
            ),
        ));
    }

    let initial_modified = initial_metadata.modified().ok();
    let mut bytes = Vec::with_capacity(initial_metadata.len() as usize);
    let mut bounded_reader = file.take((MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES + 1) as u64);
    bounded_reader.read_to_end(&mut bytes).map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("read {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV}: {error}"),
        )
    })?;
    if bytes.len() > MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} exceeds {MAX_CONTROL_PLANE_RESPONSE_PUBLIC_KEY_BYTES} bytes"
            ),
        ));
    }

    let final_metadata = bounded_reader.get_ref().metadata().map_err(|error| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("reinspect {CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV}: {error}"),
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
            format!("{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} changed while it was being loaded"),
        ));
    }

    String::from_utf8(bytes).map_err(|_| {
        ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!("{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ENV} must contain valid UTF-8"),
        )
    })
}

fn validate_pinned_control_plane_response_key(
    verifying_key: &VerifyingKey,
    expected_key_id: &str,
) -> Result<(), ProtocolError> {
    if expected_key_id.len() != 71
        || !expected_key_id.starts_with("sha256:")
        || !expected_key_id[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} must be a canonical lowercase sha256 digest"
            ),
        ));
    }
    let actual_key_id = control_plane_response_key_id(verifying_key);
    if expected_key_id != actual_key_id {
        return Err(ProtocolError::new(
            "invalid_control_plane_response_key_configuration",
            format!(
                "{CONTROL_PLANE_RESPONSE_PUBLIC_KEY_ID_ENV} does not match the configured Ed25519 public key"
            ),
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
    validate_response_statement_inner(statement, None)
}

pub fn validate_response_statement_with_control_plane_response_key(
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    validate_response_statement_inner(statement, Some(control_plane_response_verifying_key))
}

fn validate_response_statement_inner(
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: Option<&VerifyingKey>,
) -> Result<(), ProtocolError> {
    if statement.api_version != RESPONSE_STATEMENT_API_VERSION {
        return Err(invalid_statement(
            "apiVersion must be serverware.proxyResponseStatement/v2",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
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
    validate_release_authority(statement)?;
    validate_control_plane_authorization_receipt(statement, control_plane_response_verifying_key)?;
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

fn validate_release_authority(statement: &ProxyResponseStatement) -> Result<(), ProtocolError> {
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
    statement: &ProxyResponseStatement,
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
        || binding.operation_digest.as_deref() != Some(statement.operation_digest.as_str())
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
    statement: &ProxyResponseStatement,
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
    statement: &ProxyResponseStatement,
    control_plane_response_verifying_key: Option<&VerifyingKey>,
) -> Result<(), ProtocolError> {
    let receipt = &statement.control_plane_authorization_receipt;
    if receipt.api_version != AUTHORIZATION_RECEIPT_API_VERSION
        || receipt.kind != "ControlPlaneAuthorizationReceipt"
        || receipt.principal_id != statement.principal_id
        || receipt.route_id != statement.route_id
        || receipt.release_authority != statement.release_authority
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
    if signed_statement.version != "serverware.responseSignature/v1"
        || signed_statement.nonce.as_deref() != Some(request.nonce.as_str())
        || signed_statement.request.method != request.method
        || signed_statement.request.path != request.path
        || signed_statement.request.query != request.query
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
    if signed_statement.context.policy_bundle_digest != statement.policy_digest {
        return Err(invalid_statement(
            "control-plane authorization receipt policy context mismatch",
        ));
    }
    let statement_end_epoch_ms = statement
        .issued_at_unix
        .saturating_add(1)
        .saturating_mul(1000)
        .saturating_sub(1);
    let now_epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    if signed_statement.issued_at_ms < dispatch_started_at_epoch_ms
        || signed_statement.issued_at_ms >= dispatch_expires_at_epoch_ms
        || signed_statement.issued_at_ms >= reservation_expires_at_epoch_ms
        || signed_statement.issued_at_ms > statement_end_epoch_ms
        || statement_end_epoch_ms.saturating_sub(dispatch_started_at_epoch_ms)
            > MAX_STATEMENT_AGE_SECONDS.saturating_mul(1000)
        || u128::from(dispatch_expires_at_epoch_ms) <= now_epoch_ms
        || u128::from(reservation_expires_at_epoch_ms) <= now_epoch_ms
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
        .any(|name| !upstream.selected_raw_policy_headers_b64.contains_key(*name))
    {
        return Err(invalid_statement(
            "upstream_response.selected_raw_policy_headers_b64 is missing a required header",
        ));
    }
    for (name, values) in &upstream.selected_raw_policy_headers_b64 {
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
            version: "serverware.responseSignature/v1".to_string(),
            issued_at_ms: dispatch_started_at_epoch_ms,
            request: SignedResponseRequest {
                method: "POST".to_string(),
                path: RELEASE_AUTHORIZATION_DISPATCH_PATH.to_string(),
                query: String::new(),
            },
            status_code: 200,
            body_sha256: sha256_prefixed(&dispatch_body),
            nonce: Some(response_nonce.clone()),
            response_signing_key_id: response_signing_key_id.clone(),
            context: SignedResponseContext {
                runtime_manifest_digest: digest(15),
                policy_bundle_digest: policy_digest.clone(),
                provenance_digest: Some(digest(16)),
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
            runtime_manifest_digest: digest(6),
            data_plane_binary_digest: digest(7),
            release_digest: digest(8),
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
        validate_release_authorization_binding(&statement, &binding)
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
        assert!(validate_release_authorization_binding(&statement, &binding)
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

    fn response_value(bytes: &[u8]) -> Value {
        decode_canonical_json(bytes).expect("canonical response")
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
        let result = response["result"].as_object().expect("hello result");
        assert_eq!(
            result.keys().map(String::as_str).collect::<HashSet<_>>(),
            HashSet::from([
                "capabilities",
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

        let construction_error = CustodyRuntime::generate_with_control_plane_response_public_key(
            pinned_control_plane_response_verifying_key(),
            &digest(99),
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
    fn custody_exposes_only_response_proof_sign_v2() {
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
            json!([HELLO_OPERATION, "responseProof.sign/v2"])
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

        let replay_request = json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(10),
        });
        let replay_bytes = canonical_json_bytes(&replay_request).expect("request");
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
