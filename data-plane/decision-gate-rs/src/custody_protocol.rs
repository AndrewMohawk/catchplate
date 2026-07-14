use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const PROTOCOL_API_VERSION: &str = "serverware.custodyProtocol/v1";
pub const RESPONSE_STATEMENT_API_VERSION: &str = "serverware.proxyResponseStatement/v1";
pub const HELLO_OPERATION: &str = "hello/v1";
pub const RESPONSE_PROOF_SIGN_OPERATION: &str = "responseProof.sign/v1";
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
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
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyResponseStatement {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub issued_at_unix: u64,
    pub client_nonce: String,
    pub client_request_digest: String,
    pub request_digest: String,
    pub operation_digest: String,
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
    seen_request_ids: Mutex<HashSet<String>>,
}

impl CustodyRuntime {
    pub fn generate() -> Result<Self, ProtocolError> {
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
        let runtime = Self::from_secret_material(seed, boot_id_bytes);
        seed.zeroize();
        boot_id_bytes.zeroize();
        Ok(runtime)
    }

    fn from_secret_material(
        mut signing_seed: [u8; ED25519_SEED_BYTES],
        boot_id_bytes: [u8; BOOT_ID_BYTES],
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
                        "responseProof.sign/v1 requires the current bootId",
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
                    "responseProof.sign/v1 params",
                )?;
                validate_response_statement(&params.statement)?;
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
                "operation must be hello/v1 or responseProof.sign/v1",
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

fn validate_response_statement(statement: &ProxyResponseStatement) -> Result<(), ProtocolError> {
    if statement.api_version != RESPONSE_STATEMENT_API_VERSION {
        return Err(invalid_statement(
            "apiVersion must be serverware.proxyResponseStatement/v1",
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
    for (name, digest) in [
        ("client_request_digest", &statement.client_request_digest),
        ("request_digest", &statement.request_digest),
        ("operation_digest", &statement.operation_digest),
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
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::json;

    fn runtime() -> CustodyRuntime {
        CustodyRuntime::from_secret_material([7u8; 32], [9u8; 32])
    }

    fn request_id(byte: u8) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn digest(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn statement() -> ProxyResponseStatement {
        let client_request_digest = digest(1);
        let request_digest = digest(2);
        let operation_digest = digest(3);
        let policy_digest = digest(4);
        let body_digest = digest(5);
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
        let instance_id = "spiffe://dev.serverware/decision-gate/test".to_string();
        ProxyResponseStatement {
            api_version: RESPONSE_STATEMENT_API_VERSION.to_string(),
            issued_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
            client_nonce: general_purpose::URL_SAFE_NO_PAD.encode([11u8; 32]),
            client_request_digest,
            request_digest,
            operation_digest,
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

    fn request_bytes(
        runtime: &CustodyRuntime,
        id: u8,
        statement: ProxyResponseStatement,
    ) -> Vec<u8> {
        canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": runtime.boot_id(),
            "operation": RESPONSE_PROOF_SIGN_OPERATION,
            "params": {"statement": statement},
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
