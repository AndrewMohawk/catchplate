#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const PROTOCOL_NAME: &str = "serverware-coder-controller-v11";
pub const CLIENT_INSTALL_PATH: &str =
    "/usr/local/libexec/serverware-coder-controller-client";
pub const DAEMON_INSTALL_PATH: &str =
    "/usr/local/libexec/serverware-coder-controller";
pub const LAUNCHER_INSTALL_PATH: &str =
    "/usr/local/libexec/serverware-coder-controller-launcher";
pub const DEFAULT_SOCKET_PATH: &str = "/run/serverware/coder-controller-v11.sock";
pub const TRUSTED_PLAN_MANIFEST_PATH: &str =
    "/etc/serverware/coder-controller-v11/trusted-plan-manifest-v11.bin";
pub const RECEIPT_PUBLIC_KEY_PATH: &str =
    "/etc/serverware/coder-controller-v11/receipt-public-key.ed25519";
pub const FINAL_VERDICT_PUBLIC_KEY_PATH: &str =
    "/etc/serverware/coder-controller-v11/final-verdict-public-key.ed25519";
pub const REQUESTER_SIGNING_KEY_PATH: &str =
    "/etc/serverware/coder-controller-v11/requester-signing-key.ed25519";
pub const REQUESTER_PUBLIC_KEY_PATH: &str =
    "/etc/serverware/coder-controller-v11/requester-public-key.ed25519";
pub const REQUEST_TEMPLATE_DIRECTORY: &str =
    "/etc/serverware/coder-controller-v11/request-templates";
pub const CONTROLLER_PLAN_API_SOCKET_PATH: &str =
    "/run/serverware/controller-plan-api.sock";
pub const CONTROLLER_DOCKER_PROXY_SOCKET_PATH: &str =
    "/run/serverware/controller-docker-proxy.sock";
pub const CONTROLLER_PLAN_EXECUTOR_SOCKET_PATH: &str =
    "/run/serverware/controller-plan-executor-v11.sock";
pub const CONTROLLER_RECEIPT_AUTHORITY_SOCKET_PATH: &str =
    "/run/serverware/controller-receipt-authority-v11.sock";
pub const LAUNCH_CONTRACT_MAX_BYTES: usize = 1024 * 1024;

pub const FIXED_FRAME_BYTES: usize = 256;
pub const REQUEST_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const RECEIPT_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const CHUNK_MAX_BYTES: u32 = 64 * 1024;
pub const AGGREGATE_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const REQUEST_MAX_CHUNKS: u32 =
    (REQUEST_MAX_BYTES / CHUNK_MAX_BYTES as u64) as u32;
pub const RECEIPT_MAX_CHUNKS: u32 =
    (RECEIPT_MAX_BYTES / CHUNK_MAX_BYTES as u64) as u32;
pub const MAX_DEADLINE_FUTURE_MS: u64 = 4 * 60 * 60 * 1000;
pub const DEV_HELLO_TEXT: &str =
    "serverware-coder-controller-v11/disabled-dev-hello";
pub const DESCENDANT_SOURCE_MOUNTS_MUST_BE_READ_ONLY: bool = true;

const FRAME_MAGIC: [u8; 8] = *b"SWCV11F\0";
const FRAME_VERSION: u16 = 11;
const FRAME_DIGEST_OFFSET: usize = 200;
const FRAME_PADDING_OFFSET: usize = 232;
const CLIENT_SUBMISSION_MAGIC: [u8; 8] = *b"SWCSUB11";
const CLIENT_SUBMISSION_VERSION: u16 = 11;
const LAUNCH_CONTRACT_MAGIC: [u8; 8] = *b"SWLCH11\0";
const LAUNCH_CONTRACT_VERSION: u16 = 11;
const HELLO_MAGIC: [u8; 8] = *b"SWCHEL11";
const HELLO_RESPONSE_MAGIC: [u8; 8] = *b"SWCHRS11";
const SIGNED_RECEIPT_MAGIC: [u8; 8] = *b"SWCRCP11";
const SIGNED_RECEIPT_VERSION: u16 = 11;
const TRUSTED_PLAN_MANIFEST_MAGIC: [u8; 8] = *b"SWTPM11\0";
const TRUSTED_PLAN_MANIFEST_VERSION: u16 = 11;
const PLAN_API_REQUEST_MAGIC: [u8; 8] = *b"SWPLAN11";
const PLAN_API_RESPONSE_MAGIC: [u8; 8] = *b"SWPLRS11";
const RECEIPT_AUTHORITY_REQUEST_MAGIC: [u8; 8] = *b"SWRAUT11";
const ACCEPTANCE_TICKET_REQUEST_MAGIC: [u8; 8] = *b"SWTKRQ11";
const ACCEPTANCE_TICKET_MAGIC: [u8; 8] = *b"SWTICK11";
pub const TRUSTED_PLAN_MANIFEST_BYTES: usize = 440;
pub const PLAN_API_REQUEST_BYTES: usize = 152;
pub const PLAN_API_RESPONSE_BYTES: usize = 176;
pub const PLAN_CAPABILITY_RECORD_BYTES: usize = 184;
pub const RECEIPT_AUTHORITY_REQUEST_BYTES: usize = FIXED_FRAME_BYTES;
pub const ACCEPTANCE_TICKET_REQUEST_BYTES: usize = 120;
pub const ACCEPTANCE_TICKET_BYTES: usize = 264;
pub const CONTROLLER_RECEIPT_BODY_BYTES: usize = 504;
pub const CONTROLLER_RECEIPT_SIGNER_KEY_OFFSET: usize =
    CONTROLLER_RECEIPT_BODY_BYTES;
pub const CONTROLLER_RECEIPT_SIGNATURE_OFFSET: usize =
    CONTROLLER_RECEIPT_SIGNER_KEY_OFFSET + 32;
pub const SIGNED_CONTROLLER_RECEIPT_BYTES: usize =
    CONTROLLER_RECEIPT_SIGNATURE_OFFSET + 64;

pub type Digest = [u8; 32];

#[derive(Debug)]
pub enum ControllerError {
    Invalid(&'static str),
    InvalidOwned(String),
    Rejected(&'static str),
    Unready(Vec<String>),
    Io(io::Error),
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Rejected(message) => formatter.write_str(message),
            Self::InvalidOwned(message) => formatter.write_str(message),
            Self::Unready(reasons) => {
                write!(formatter, "controller hard-unready: {}", reasons.join("; "))
            }
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ControllerError {}

impl From<io::Error> for ControllerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, ControllerError>;

pub fn sha256(bytes: &[u8]) -> Digest {
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub fn ed25519_spki_der_sha256_v11(key: &VerifyingKey) -> Digest {
    let mut spki = [0u8; 44];
    spki[0..12].copy_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
        0x21, 0x00,
    ]);
    spki[12..44].copy_from_slice(key.as_bytes());
    sha256(&spki)
}

pub fn sha256_exact_reader<R: Read>(reader: &mut R, expected_len: u64) -> Result<Digest> {
    let mut hasher = Sha256::new();
    let mut remaining = expected_len;
    let mut chunk = [0u8; CHUNK_MAX_BYTES as usize];
    while remaining != 0 {
        let wanted = (remaining as usize).min(chunk.len());
        let count = reader.read(&mut chunk[..wanted])?;
        if count == 0 {
            return Err(ControllerError::Invalid("stream ended before declared length"));
        }
        hasher.update(&chunk[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(ControllerError::Invalid("stream exceeds declared length"));
    }
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

pub fn constant_time_eq(left: &Digest, right: &Digest) -> bool {
    let mut difference = 0u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

pub fn digest_hex(digest: &Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

const REQUEST_SCHEMA_V11: &str =
    include_str!("../../../schemas/coder-test-controller-request.v1.schema.json");
const RECEIPT_SCHEMA_V11: &str =
    include_str!("../../../schemas/coder-test-controller-receipt.v1.schema.json");
static REQUEST_SCHEMA_VALIDATOR_V11:
    OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();
static RECEIPT_SCHEMA_VALIDATOR_V11:
    OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();

fn schema_validator_v11(
    receipt: bool,
) -> Result<&'static jsonschema::Validator> {
    let (cell, source, label) = if receipt {
        (
            &RECEIPT_SCHEMA_VALIDATOR_V11,
            RECEIPT_SCHEMA_V11,
            "receipt",
        )
    } else {
        (
            &REQUEST_SCHEMA_VALIDATOR_V11,
            REQUEST_SCHEMA_V11,
            "request",
        )
    };
    cell.get_or_init(|| {
        let schema: Value = serde_json::from_str(source)
            .map_err(|error| format!("parse embedded {label} schema: {error}"))?;
        jsonschema::draft202012::options()
            .build(&schema)
            .map_err(|error| format!("compile embedded {label} schema: {error}"))
    })
    .as_ref()
    .map_err(|error| ControllerError::InvalidOwned(error.clone()))
}

fn validate_schema_v11(value: &Value, receipt: bool) -> Result<()> {
    schema_validator_v11(receipt)?
        .validate(value)
        .map_err(|error| {
            ControllerError::InvalidOwned(format!(
                "canonical v11 {} schema validation failed at {}: {error}",
                if receipt { "receipt" } else { "request" },
                error.instance_path(),
            ))
        })
}

pub fn parse_exact_canonical_json_v11(
    bytes: &[u8],
    maximum: usize,
) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ControllerError::Invalid(
            "canonical JSON length is outside its bound",
        ));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        ControllerError::InvalidOwned(format!("parse canonical JSON: {error}"))
    })?;
    let canonical = canonical_json_bytes_v11(&value)?;
    if canonical.as_slice() != bytes {
        return Err(ControllerError::Rejected(
            "JSON is not exact RFC 8785 canonical bytes or contains duplicate keys",
        ));
    }
    Ok(value)
}

pub fn canonical_json_bytes_v11(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json_v11(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json_v11(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_u64() != Some(11) {
                return Err(ControllerError::Rejected(
                    "v11 canonical JSON permits only the integer contractVersion 11",
                ));
            }
            output.extend_from_slice(b"11");
        }
        Value::String(string) => {
            let encoded = serde_json::to_string(string).map_err(|error| {
                ControllerError::InvalidOwned(format!(
                    "serialize canonical JSON string: {error}"
                ))
            })?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json_v11(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|left, right| {
                left.encode_utf16()
                    .collect::<Vec<_>>()
                    .cmp(&right.encode_utf16().collect::<Vec<_>>())
            });
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key).unwrap_or_default();
                if encoded.is_empty() {
                    return Err(ControllerError::Invalid(
                        "canonical JSON key serialization failed",
                    ));
                }
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json_v11(
                    object.get(*key).ok_or(ControllerError::Invalid(
                        "canonical JSON object key disappeared",
                    ))?,
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn lf11(tag: &str, parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(b"serverware/controller/v11/");
    let tag_len = u64::try_from(tag.len())
        .map_err(|_| ControllerError::Invalid("LF11 tag is too long"))?;
    output.extend_from_slice(&tag_len.to_be_bytes());
    output.extend_from_slice(tag.as_bytes());
    for part in parts {
        let length = u64::try_from(part.len())
            .map_err(|_| ControllerError::Invalid("LF11 part is too long"))?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    Ok(output)
}

pub fn h11(tag: &str, parts: &[&[u8]]) -> Result<Digest> {
    Ok(sha256(&lf11(tag, parts)?))
}

fn parse_hex_digest_v11(value: &str) -> Result<Digest> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ControllerError::Invalid(
            "v11 digest is not lowercase SHA-256",
        ));
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = hex_nibble_v11(value.as_bytes()[index * 2])? << 4
            | hex_nibble_v11(value.as_bytes()[index * 2 + 1])?;
    }
    Ok(output)
}

fn hex_nibble_v11(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ControllerError::Invalid("invalid lowercase hexadecimal")),
    }
}

fn decode_base64url_digest_v11(value: &str) -> Result<Digest> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ControllerError::Invalid("v11 base64url value is not canonical")
    })?;
    if decoded.len() != 32
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(ControllerError::Invalid(
            "v11 base64url digest must encode exactly 32 bytes",
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn parse_rfc3339_millis_v11(value: &str) -> Result<u64> {
    if !value.ends_with('Z') {
        return Err(ControllerError::Invalid(
            "v11 timestamp is not canonical UTC",
        ));
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ControllerError::Invalid("invalid v11 RFC3339 timestamp"))?;
    let nanos = timestamp.unix_timestamp_nanos();
    if nanos < 0 {
        return Err(ControllerError::Invalid(
            "v11 timestamp precedes unix epoch",
        ));
    }
    u64::try_from(nanos / 1_000_000)
        .map_err(|_| ControllerError::Invalid("v11 timestamp exceeds u64"))
}

pub fn format_rfc3339_seconds_v11(unix_ms: u64) -> Result<String> {
    let total_seconds = unix_ms / 1_000;
    let days = i64::try_from(total_seconds / 86_400)
        .map_err(|_| ControllerError::Invalid("timestamp day exceeds i64"))?;
    let day_seconds = total_seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    let shifted = days
        .checked_add(719_468)
        .ok_or(ControllerError::Invalid("civil date overflow"))?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (
        day_of_era
            - day_of_era / 1_460
            + day_of_era / 36_524
            - day_of_era / 146_096
    ) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era
        - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    if !(0..=9_999).contains(&year) {
        return Err(ControllerError::Invalid(
            "v11 timestamp year is outside RFC3339 range",
        ));
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn json_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<&'a Value> {
    object
        .get(name)
        .ok_or(ControllerError::Invalid("canonical JSON field is absent"))
}

fn json_object_v11<'a>(
    value: &'a Value,
    label: &'static str,
) -> Result<&'a serde_json::Map<String, Value>> {
    value.as_object().ok_or(ControllerError::Invalid(label))
}

fn json_string_v11<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<&'a str> {
    json_field(object, name)?
        .as_str()
        .ok_or(ControllerError::Invalid(
            "canonical JSON field is not a string",
        ))
}

fn parse_d20_v11(value: &str) -> Result<u64> {
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ControllerError::Invalid(
            "v11 u64 is not exactly 20 decimal digits",
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| ControllerError::Invalid("v11 u64 exceeds uint64"))
}

fn d20_v11(value: u64) -> [u8; 20] {
    let encoded = format!("{value:020}");
    let mut output = [0u8; 20];
    output.copy_from_slice(encoded.as_bytes());
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalFrameKindV11 {
    Request,
    Receipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPreallocationFrameV11 {
    pub kind: CanonicalFrameKindV11,
    pub declared_canonical_bytes: u64,
    pub declared_body_bytes: u64,
    pub frame_deadline: String,
    pub frame_deadline_unix_ms: u64,
    pub envelope_sha256: Digest,
    pub frame_nonce_sha256: Digest,
    pub frame_sha256: Digest,
}

impl CanonicalPreallocationFrameV11 {
    pub fn new(
        kind: CanonicalFrameKindV11,
        declared_canonical_bytes: u64,
        declared_body_bytes: u64,
        frame_deadline: String,
        envelope_sha256: Digest,
        frame_nonce_sha256: Digest,
    ) -> Result<Self> {
        let frame_deadline_unix_ms =
            parse_rfc3339_millis_v11(&frame_deadline)?;
        let mut frame = Self {
            kind,
            declared_canonical_bytes,
            declared_body_bytes,
            frame_deadline,
            frame_deadline_unix_ms,
            envelope_sha256,
            frame_nonce_sha256,
            frame_sha256: [0; 32],
        };
        frame.validate_shape()?;
        frame.frame_sha256 = frame.compute_digest()?;
        Ok(frame)
    }

    pub fn decode(bytes: &[u8; FIXED_FRAME_BYTES]) -> Result<Self> {
        let kind = if &bytes[0..24] == b"SERVERWARE-CONTROLLER\0\0\0" {
            CanonicalFrameKindV11::Request
        } else if &bytes[0..24] == b"SERVERWARE-RECEIPT\0\0\0\0\0\0" {
            CanonicalFrameKindV11::Receipt
        } else {
            return Err(ControllerError::Invalid(
                "canonical v11 frame magic is invalid",
            ));
        };
        if u16::from_be_bytes([bytes[24], bytes[25]]) != 11
            || u16::from_be_bytes([bytes[26], bytes[27]]) != 1
            || u32::from_be_bytes(
                bytes[28..32]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid("invalid frame header"))?,
            ) != 256
            || bytes[216..].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "canonical v11 frame header or padding is invalid",
            ));
        }
        let deadline_end = bytes[184..216]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| 184 + offset)
            .unwrap_or(216);
        if bytes[deadline_end..216].iter().any(|byte| *byte != 0) {
            return Err(ControllerError::Invalid(
                "canonical v11 frame deadline padding is invalid",
            ));
        }
        let frame_deadline = std::str::from_utf8(&bytes[184..deadline_end])
            .map_err(|_| ControllerError::Invalid("frame deadline is not UTF-8"))?
            .to_owned();
        let frame = Self {
            kind,
            declared_canonical_bytes: read_u64(bytes, 32),
            declared_body_bytes: read_u64(bytes, 48),
            frame_deadline_unix_ms:
                parse_rfc3339_millis_v11(&frame_deadline)?,
            frame_deadline,
            envelope_sha256: copy_digest(&bytes[88..120]),
            frame_nonce_sha256: copy_digest(&bytes[120..152]),
            frame_sha256: copy_digest(&bytes[152..184]),
        };
        frame.validate_wire_limits(bytes)?;
        if !constant_time_eq(&frame.compute_digest()?, &frame.frame_sha256) {
            return Err(ControllerError::Rejected(
                "canonical v11 frame digest mismatch",
            ));
        }
        Ok(frame)
    }

    pub fn encode(&self) -> Result<[u8; FIXED_FRAME_BYTES]> {
        self.validate_shape()?;
        if !constant_time_eq(&self.compute_digest()?, &self.frame_sha256) {
            return Err(ControllerError::Rejected(
                "canonical v11 frame digest is stale",
            ));
        }
        let mut bytes = [0u8; FIXED_FRAME_BYTES];
        match self.kind {
            CanonicalFrameKindV11::Request => {
                bytes[0..24].copy_from_slice(b"SERVERWARE-CONTROLLER\0\0\0")
            }
            CanonicalFrameKindV11::Receipt => {
                bytes[0..24]
                    .copy_from_slice(b"SERVERWARE-RECEIPT\0\0\0\0\0\0")
            }
        }
        bytes[24..26].copy_from_slice(&11u16.to_be_bytes());
        bytes[26..28].copy_from_slice(&1u16.to_be_bytes());
        bytes[28..32].copy_from_slice(&256u32.to_be_bytes());
        bytes[32..40].copy_from_slice(
            &self.declared_canonical_bytes.to_be_bytes(),
        );
        bytes[40..48].copy_from_slice(&self.maximum_canonical_bytes().to_be_bytes());
        bytes[48..56].copy_from_slice(&self.declared_body_bytes.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.maximum_body_bytes().to_be_bytes());
        bytes[64..72].copy_from_slice(&(CHUNK_MAX_BYTES as u64).to_be_bytes());
        bytes[72..80].copy_from_slice(
            &(self.maximum_chunk_count() as u64).to_be_bytes(),
        );
        bytes[80..88].copy_from_slice(&AGGREGATE_MAX_BYTES.to_be_bytes());
        bytes[88..120].copy_from_slice(&self.envelope_sha256);
        bytes[120..152].copy_from_slice(&self.frame_nonce_sha256);
        bytes[152..184].copy_from_slice(&self.frame_sha256);
        bytes[184..184 + self.frame_deadline.len()]
            .copy_from_slice(self.frame_deadline.as_bytes());
        Ok(bytes)
    }

    pub fn verify_receive_deadline(
        &self,
        received_at_unix_ms: u64,
    ) -> Result<()> {
        if received_at_unix_ms > self.frame_deadline_unix_ms
            || self
                .frame_deadline_unix_ms
                .saturating_sub(received_at_unix_ms)
                > 30_000
        {
            return Err(ControllerError::Rejected(
                "canonical v11 frame deadline is expired or too far in the future",
            ));
        }
        Ok(())
    }

    pub fn verify_json_projection(&self, root: &Value) -> Result<()> {
        let root = json_object_v11(root, "canonical v11 root is not an object")?;
        let frame_name = match self.kind {
            CanonicalFrameKindV11::Request => "preAllocationFrame",
            CanonicalFrameKindV11::Receipt => "receiptPreAllocationFrame",
        };
        let frame = json_object_v11(
            json_field(root, frame_name)?,
            "canonical v11 frame projection is not an object",
        )?;
        let (
            expected_magic,
            canonical_name,
            maximum_canonical_name,
            body_name,
            maximum_body_name,
            aggregate_name,
            envelope_name,
        ) = match self.kind {
            CanonicalFrameKindV11::Request => (
                "SERVERWARE-CONTROLLER",
                "declaredCanonicalRequestBytes",
                "maximumCanonicalRequestBytes",
                "declaredEnvelopeBytes",
                "maximumEnvelopeBytes",
                "maximumAggregateRetrievedBytes",
                "requestEnvelopeSha256",
            ),
            CanonicalFrameKindV11::Receipt => (
                "SERVERWARE-RECEIPT",
                "declaredCanonicalReceiptBytes",
                "maximumCanonicalReceiptBytes",
                "declaredReceiptBodyBytes",
                "maximumReceiptBodyBytes",
                "maximumAggregateReceivedBytes",
                "receiptEnvelopeSha256",
            ),
        };
        let exact = [
            ("frameVersion", "11".to_owned()),
            ("magic", expected_magic.to_owned()),
            (
                "transport",
                "ROOT_OWNED_PEERCRED_SEQPACKET".to_owned(),
            ),
            ("fixedHeaderBytes", format!("{:020}", FIXED_FRAME_BYTES)),
            (
                canonical_name,
                format!("{:020}", self.declared_canonical_bytes),
            ),
            (
                maximum_canonical_name,
                format!("{:020}", self.maximum_canonical_bytes()),
            ),
            (
                body_name,
                format!("{:020}", self.declared_body_bytes),
            ),
            (
                maximum_body_name,
                format!("{:020}", self.maximum_body_bytes()),
            ),
            (
                "streamChunkBytes",
                format!("{:020}", CHUNK_MAX_BYTES),
            ),
            (
                "maximumStreamChunkCount",
                format!("{:020}", self.maximum_chunk_count()),
            ),
            (
                aggregate_name,
                format!("{:020}", AGGREGATE_MAX_BYTES),
            ),
            ("frameDeadline", self.frame_deadline.clone()),
            (envelope_name, digest_hex(&self.envelope_sha256)),
            (
                "frameNonceSha256",
                digest_hex(&self.frame_nonce_sha256),
            ),
            ("frameSha256", digest_hex(&self.frame_sha256)),
        ];
        for (name, expected) in exact {
            if json_string_v11(frame, name)? != expected {
                return Err(ControllerError::Rejected(
                    "canonical v11 frame JSON projection differs from wire bytes",
                ));
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.declared_canonical_bytes == 0
            || self.declared_canonical_bytes > self.maximum_canonical_bytes()
            || self.declared_body_bytes == 0
            || self.declared_body_bytes > self.maximum_body_bytes()
            || self.envelope_sha256 == [0; 32]
            || self.frame_nonce_sha256 == [0; 32]
            || self.frame_deadline.len() < 20
            || self.frame_deadline.len() > 32
            || parse_rfc3339_millis_v11(&self.frame_deadline)?
                != self.frame_deadline_unix_ms
        {
            return Err(ControllerError::Invalid(
                "canonical v11 frame violates fixed limits",
            ));
        }
        Ok(())
    }

    fn validate_wire_limits(
        &self,
        bytes: &[u8; FIXED_FRAME_BYTES],
    ) -> Result<()> {
        self.validate_shape()?;
        if read_u64(bytes, 40) != self.maximum_canonical_bytes()
            || read_u64(bytes, 56) != self.maximum_body_bytes()
            || read_u64(bytes, 64) != CHUNK_MAX_BYTES as u64
            || read_u64(bytes, 72) != self.maximum_chunk_count() as u64
            || read_u64(bytes, 80) != AGGREGATE_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "canonical v11 frame limits differ from the contract",
            ));
        }
        Ok(())
    }

    fn maximum_canonical_bytes(&self) -> u64 {
        match self.kind {
            CanonicalFrameKindV11::Request => REQUEST_MAX_BYTES,
            CanonicalFrameKindV11::Receipt => RECEIPT_MAX_BYTES,
        }
    }

    fn maximum_body_bytes(&self) -> u64 {
        self.maximum_canonical_bytes()
    }

    fn maximum_chunk_count(&self) -> u32 {
        match self.kind {
            CanonicalFrameKindV11::Request => REQUEST_MAX_CHUNKS,
            CanonicalFrameKindV11::Receipt => RECEIPT_MAX_CHUNKS,
        }
    }

    fn compute_digest(&self) -> Result<Digest> {
        let fixed = d20_v11(FIXED_FRAME_BYTES as u64);
        let declared_canonical = d20_v11(self.declared_canonical_bytes);
        let maximum_canonical = d20_v11(self.maximum_canonical_bytes());
        let declared_body = d20_v11(self.declared_body_bytes);
        let maximum_body = d20_v11(self.maximum_body_bytes());
        let chunk = d20_v11(CHUNK_MAX_BYTES as u64);
        let chunk_count = d20_v11(self.maximum_chunk_count() as u64);
        let aggregate = d20_v11(AGGREGATE_MAX_BYTES);
        let (tag, magic) = match self.kind {
            CanonicalFrameKindV11::Request => {
                ("pre-allocation-frame", b"SERVERWARE-CONTROLLER".as_slice())
            }
            CanonicalFrameKindV11::Receipt => (
                "receipt-pre-allocation-frame",
                b"SERVERWARE-RECEIPT".as_slice(),
            ),
        };
        h11(
            tag,
            &[
                b"11",
                magic,
                b"ROOT_OWNED_PEERCRED_SEQPACKET",
                &fixed,
                &declared_canonical,
                &maximum_canonical,
                &declared_body,
                &maximum_body,
                &chunk,
                &chunk_count,
                &aggregate,
                self.frame_deadline.as_bytes(),
                &self.envelope_sha256,
                &self.frame_nonce_sha256,
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalControllerRequestV11 {
    exact_bytes: Arc<Vec<u8>>,
    root: Value,
    pub lane: Lane,
    pub raw_nonce: Digest,
    pub request_id: Digest,
    pub request_id_text: String,
    pub accepted_at: String,
    pub deadline_unix_ms: u64,
    pub request_envelope_sha256: Digest,
    pub plan_configuration_sha256: Digest,
    pub source_tree_sha256: Digest,
    pub requester_key_leaf_sha256: Digest,
    pub signer_spki_der_sha256: Digest,
}

impl CanonicalControllerRequestV11 {
    pub fn parse_and_verify(
        exact_bytes: Vec<u8>,
        frame: &CanonicalPreallocationFrameV11,
        requester_key: &VerifyingKey,
        expected_requester_spki_der_sha256: Digest,
        expected_accepted_at: Option<&str>,
    ) -> Result<Self> {
        if frame.kind != CanonicalFrameKindV11::Request {
            return Err(ControllerError::Invalid(
                "receipt frame cannot carry a controller request",
            ));
        }
        let root = parse_exact_canonical_json_v11(
            &exact_bytes,
            REQUEST_MAX_BYTES as usize,
        )?;
        validate_schema_v11(&root, false)?;
        frame.verify_json_projection(&root)?;
        if frame.declared_canonical_bytes != exact_bytes.len() as u64 {
            return Err(ControllerError::Rejected(
                "request frame length differs from exact canonical root",
            ));
        }
        let root_object =
            json_object_v11(&root, "controller request root is not an object")?;
        let declared_root_length =
            parse_d20_v11(json_string_v11(root_object, "requestCanonicalBytes")?)?;
        if declared_root_length != exact_bytes.len() as u64 {
            return Err(ControllerError::Rejected(
                "requestCanonicalBytes differs from exact canonical root",
            ));
        }
        let envelope = json_object_v11(
            json_field(root_object, "requestEnvelope")?,
            "request envelope is not an object",
        )?;
        let envelope_bytes =
            canonical_json_bytes_v11(json_field(root_object, "requestEnvelope")?)?;
        if frame.declared_body_bytes != envelope_bytes.len() as u64 {
            return Err(ControllerError::Rejected(
                "request declaredEnvelopeBytes differs from JCS(requestEnvelope)",
            ));
        }
        let domain = json_string_v11(envelope, "domain")?;
        let payload = json_field(envelope, "payload")?;
        let payload_object =
            json_object_v11(payload, "request payload is not an object")?;
        let payload_bytes = canonical_json_bytes_v11(payload)?;
        let payload_sha256 = h11(
            "payload",
            &[domain.as_bytes(), payload_bytes.as_slice()],
        )?;
        let declared_payload_sha256 =
            parse_hex_digest_v11(json_string_v11(envelope, "payloadSha256")?)?;
        if !constant_time_eq(&payload_sha256, &declared_payload_sha256) {
            return Err(ControllerError::Rejected(
                "request payload digest does not match H11 payload projection",
            ));
        }
        let signature = json_object_v11(
            json_field(envelope, "signature")?,
            "request signature is not an object",
        )?;
        verify_signature_object_v11(
            signature,
            domain,
            payload_sha256,
            requester_key,
            "requester",
            expected_requester_spki_der_sha256,
            expected_accepted_at,
        )?;
        let envelope_sha256 = h11(
            "typed-envelope",
            &[
                domain.as_bytes(),
                &payload_sha256,
                canonical_json_bytes_v11(json_field(envelope, "signature")?)?
                    .as_slice(),
            ],
        )?;
        let declared_envelope_sha256 = parse_hex_digest_v11(
            json_string_v11(root_object, "requestEnvelopeSha256")?,
        )?;
        if !constant_time_eq(&envelope_sha256, &declared_envelope_sha256)
            || !constant_time_eq(
                &envelope_sha256,
                &frame.envelope_sha256,
            )
        {
            return Err(ControllerError::Rejected(
                "request envelope digest differs from root or frame",
            ));
        }
        let selected_stage = json_object_v11(
            json_field(payload_object, "selectedStage")?,
            "selected stage is not an object",
        )?;
        let lane = Lane::parse_frozen_flags(
            &format!(
                "--operation={}",
                json_string_v11(selected_stage, "operation")?
            ),
            &format!(
                "--plan={}",
                json_string_v11(selected_stage, "planStageLabel")?
            ),
        )?;
        let expected_domain = match lane.plan {
            Plan::Build => "serverware/request-build/v11",
            Plan::UnitNoBuild => "serverware/request-unit/v11",
            Plan::IntegrationNoBuild => {
                "serverware/request-integration/v11"
            }
            Plan::E2eNoBuild => "serverware/request-e2e/v11",
            Plan::AttestationNoBuild => {
                "serverware/request-attestation/v11"
            }
        };
        if domain != expected_domain {
            return Err(ControllerError::Rejected(
                "request domain does not match its fixed stage",
            ));
        }
        let replay = json_object_v11(
            json_field(payload_object, "replayIdentity")?,
            "request replay identity is not an object",
        )?;
        let raw_nonce =
            decode_base64url_digest_v11(json_string_v11(replay, "nonce")?)?;
        if !constant_time_eq(&sha256(&raw_nonce), &frame.frame_nonce_sha256) {
            return Err(ControllerError::Rejected(
                "request frame nonce digest differs from signed replay nonce",
            ));
        }
        let requester_key_leaf_sha256 = parse_hex_digest_v11(
            json_string_v11(payload_object, "requesterKeyLeafSha256")?,
        )?;
        if json_string_v11(replay, "requesterKeyLeafSha256")?
            != digest_hex(&requester_key_leaf_sha256)
            || json_string_v11(signature, "signerKeyLeafSha256")?
                != digest_hex(&requester_key_leaf_sha256)
        {
            return Err(ControllerError::Rejected(
                "request replay, payload, and signer key leaf differ",
            ));
        }
        let request_id_text =
            json_string_v11(replay, "requestId")?.to_owned();
        let request_id = h11(
            "replay/request-id",
            &[
                &requester_key_leaf_sha256,
                request_id_text.as_bytes(),
            ],
        )?;
        let nonce_replay = h11(
            "replay/nonce",
            &[&requester_key_leaf_sha256, &raw_nonce],
        )?;
        if json_string_v11(replay, "requestIdReplayKeySha256")?
                != digest_hex(&request_id)
            || json_string_v11(replay, "nonceReplayKeySha256")?
                != digest_hex(&nonce_replay)
        {
            return Err(ControllerError::Rejected(
                "request replay keys do not match the v11 projections",
            ));
        }
        let requested_at = parse_rfc3339_millis_v11(json_string_v11(
            payload_object,
            "requestedAt",
        )?)?;
        let deadline_text = json_string_v11(payload_object, "deadline")?;
        let deadline_unix_ms = parse_rfc3339_millis_v11(deadline_text)?;
        let signed_at = parse_rfc3339_millis_v11(json_string_v11(
            signature,
            "signedAt",
        )?)?;
        if requested_at > signed_at
            || frame.frame_deadline_unix_ms > deadline_unix_ms
            || signed_at > deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "request time ordering violates the v11 contract",
            ));
        }
        let plan_configuration_sha256 = parse_hex_digest_v11(
            json_string_v11(payload_object, "planConfigurationSha256")?,
        )?;
        let source = json_object_v11(
            json_field(payload_object, "source")?,
            "request source identity is not an object",
        )?;
        let source_tree_sha256 =
            parse_hex_digest_v11(json_string_v11(source, "treeSha256")?)?;
        Ok(Self {
            exact_bytes: Arc::new(exact_bytes),
            root,
            lane,
            raw_nonce,
            request_id,
            request_id_text,
            accepted_at: json_string_v11(signature, "acceptedAt")?.to_owned(),
            deadline_unix_ms,
            request_envelope_sha256: envelope_sha256,
            plan_configuration_sha256,
            source_tree_sha256,
            requester_key_leaf_sha256,
            signer_spki_der_sha256: expected_requester_spki_der_sha256,
        })
    }

    pub fn exact_bytes(&self) -> &[u8] {
        self.exact_bytes.as_slice()
    }

    pub fn root(&self) -> &Value {
        &self.root
    }
}

fn verify_signature_object_v11(
    signature: &serde_json::Map<String, Value>,
    expected_domain: &str,
    payload_sha256: Digest,
    verifying_key: &VerifyingKey,
    expected_role: &str,
    expected_spki_der_sha256: Digest,
    expected_accepted_at: Option<&str>,
) -> Result<()> {
    if json_string_v11(signature, "signatureVersion")? != "11"
        || json_string_v11(signature, "domain")? != expected_domain
        || json_string_v11(signature, "payloadSha256")?
            != digest_hex(&payload_sha256)
        || json_string_v11(signature, "signerRole")? != expected_role
        || json_string_v11(signature, "signerSpkiDerSha256")?
            != digest_hex(&expected_spki_der_sha256)
    {
        return Err(ControllerError::Rejected(
            "v11 signature identity or payload binding differs",
        ));
    }
    let signed_at = json_string_v11(signature, "signedAt")?;
    let accepted_at = json_string_v11(signature, "acceptedAt")?;
    if expected_accepted_at
        .is_some_and(|expected| expected != accepted_at)
    {
        return Err(ControllerError::Rejected(
            "v11 signature acceptedAt differs from the controller ticket",
        ));
    }
    let signed_at_ms = parse_rfc3339_millis_v11(signed_at)?;
    let accepted_at_ms = parse_rfc3339_millis_v11(accepted_at)?;
    if signed_at_ms > accepted_at_ms
        || accepted_at_ms.saturating_sub(signed_at_ms) > 30_000
    {
        return Err(ControllerError::Rejected(
            "v11 signature time interval is invalid",
        ));
    }
    let signer_principal = json_string_v11(signature, "signerPrincipalId")?;
    let signer_key_id = json_string_v11(signature, "signerKeyId")?;
    let signer_key_leaf =
        parse_hex_digest_v11(json_string_v11(signature, "signerKeyLeafSha256")?)?;
    let signed = lf11(
        "signature",
        &[
            b"11",
            expected_domain.as_bytes(),
            &payload_sha256,
            signed_at.as_bytes(),
            accepted_at.as_bytes(),
            expected_role.as_bytes(),
            signer_principal.as_bytes(),
            signer_key_id.as_bytes(),
            &signer_key_leaf,
            &expected_spki_der_sha256,
        ],
    )?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(json_string_v11(signature, "signatureBase64url")?)
        .map_err(|_| ControllerError::Invalid("invalid v11 Ed25519 signature"))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ControllerError::Invalid("invalid v11 Ed25519 signature length"))?;
    verifying_key
        .verify_strict(&signed, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| ControllerError::Rejected("v11 Ed25519 signature is invalid"))
}

pub struct BuiltCanonicalControllerRequestV11 {
    pub frame: CanonicalPreallocationFrameV11,
    pub request: CanonicalControllerRequestV11,
}

pub fn build_signed_request_from_template_v11(
    template_bytes: &[u8],
    lane: Lane,
    raw_nonce: Digest,
    accepted_at: &str,
    frame_deadline: &str,
    request_deadline: &str,
    requester_signing_key: &SigningKey,
    expected_requester_spki_der_sha256: Digest,
) -> Result<BuiltCanonicalControllerRequestV11> {
    if raw_nonce == [0; 32] {
        return Err(ControllerError::Invalid(
            "canonical request nonce is empty",
        ));
    }
    let accepted_at_ms = parse_rfc3339_millis_v11(accepted_at)?;
    let frame_deadline_ms = parse_rfc3339_millis_v11(frame_deadline)?;
    let request_deadline_ms = parse_rfc3339_millis_v11(request_deadline)?;
    if accepted_at_ms > frame_deadline_ms
        || frame_deadline_ms.saturating_sub(accepted_at_ms) > 30_000
        || frame_deadline_ms > request_deadline_ms
    {
        return Err(ControllerError::Rejected(
            "controller ticket deadlines violate the v11 ordering",
        ));
    }
    let mut root = parse_exact_canonical_json_v11(
        template_bytes,
        REQUEST_MAX_BYTES as usize,
    )?;
    let request_id_text = uuid_v4_from_bytes_v11(&raw_nonce[0..16])?;
    let requester_key_leaf_sha256 = {
        let root_object = json_object_v11(
            &root,
            "request template root is not an object",
        )?;
        let envelope = json_object_v11(
            json_field(root_object, "requestEnvelope")?,
            "request template envelope is not an object",
        )?;
        let payload = json_object_v11(
            json_field(envelope, "payload")?,
            "request template payload is not an object",
        )?;
        parse_hex_digest_v11(json_string_v11(
            payload,
            "requesterKeyLeafSha256",
        )?)?
    };
    let request_id_replay = h11(
        "replay/request-id",
        &[
            &requester_key_leaf_sha256,
            request_id_text.as_bytes(),
        ],
    )?;
    let nonce_replay = h11(
        "replay/nonce",
        &[&requester_key_leaf_sha256, &raw_nonce],
    )?;
    {
        let root_object = root.as_object_mut().ok_or(
            ControllerError::Invalid("request template root is not mutable"),
        )?;
        let envelope = root_object
            .get_mut("requestEnvelope")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template envelope is not mutable",
            ))?;
        let payload = envelope
            .get_mut("payload")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template payload is not mutable",
            ))?;
        let selected = payload
            .get("selectedStage")
            .and_then(Value::as_object)
            .ok_or(ControllerError::Invalid(
                "request template selected stage is absent",
            ))?;
        let template_lane = Lane::parse_frozen_flags(
            &format!(
                "--operation={}",
                json_string_v11(selected, "operation")?
            ),
            &format!(
                "--plan={}",
                json_string_v11(selected, "planStageLabel")?
            ),
        )?;
        if template_lane != lane {
            return Err(ControllerError::Rejected(
                "request template does not match the selected fixed lane",
            ));
        }
        payload.insert(
            "requestedAt".to_owned(),
            Value::String(accepted_at.to_owned()),
        );
        payload.insert(
            "deadline".to_owned(),
            Value::String(request_deadline.to_owned()),
        );
        let replay = payload
            .get_mut("replayIdentity")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template replay identity is absent",
            ))?;
        replay.insert(
            "requestId".to_owned(),
            Value::String(request_id_text.clone()),
        );
        replay.insert(
            "nonce".to_owned(),
            Value::String(URL_SAFE_NO_PAD.encode(raw_nonce)),
        );
        replay.insert(
            "requesterKeyLeafSha256".to_owned(),
            Value::String(digest_hex(&requester_key_leaf_sha256)),
        );
        replay.insert(
            "requestIdReplayKeySha256".to_owned(),
            Value::String(digest_hex(&request_id_replay)),
        );
        replay.insert(
            "nonceReplayKeySha256".to_owned(),
            Value::String(digest_hex(&nonce_replay)),
        );
        if lane.plan == Plan::AttestationNoBuild {
            patch_attestation_challenge_v11(
                payload,
                raw_nonce,
                accepted_at,
                request_deadline,
                requester_key_leaf_sha256,
            )?;
        }
    }
    let (domain, payload_sha256) = {
        let root_object =
            json_object_v11(&root, "request template root is not an object")?;
        let envelope = json_object_v11(
            json_field(root_object, "requestEnvelope")?,
            "request template envelope is not an object",
        )?;
        let domain = json_string_v11(envelope, "domain")?.to_owned();
        let payload = json_field(envelope, "payload")?;
        let payload_bytes = canonical_json_bytes_v11(payload)?;
        (
            domain.clone(),
            h11("payload", &[domain.as_bytes(), &payload_bytes])?,
        )
    };
    {
        let root_object = root.as_object_mut().ok_or(
            ControllerError::Invalid("request template root is not mutable"),
        )?;
        let envelope = root_object
            .get_mut("requestEnvelope")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template envelope is not mutable",
            ))?;
        envelope.insert(
            "payloadSha256".to_owned(),
            Value::String(digest_hex(&payload_sha256)),
        );
        let signature = envelope
            .get_mut("signature")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template signature is absent",
            ))?;
        sign_signature_object_v11(
            signature,
            &domain,
            payload_sha256,
            accepted_at,
            accepted_at,
            requester_signing_key,
            expected_requester_spki_der_sha256,
        )?;
    }
    let envelope_sha256 = {
        let root_object =
            json_object_v11(&root, "request template root is not an object")?;
        let envelope = json_object_v11(
            json_field(root_object, "requestEnvelope")?,
            "request template envelope is not an object",
        )?;
        let signature_bytes =
            canonical_json_bytes_v11(json_field(envelope, "signature")?)?;
        h11(
            "typed-envelope",
            &[domain.as_bytes(), &payload_sha256, &signature_bytes],
        )?
    };
    {
        let root_object = root.as_object_mut().ok_or(
            ControllerError::Invalid("request template root is not mutable"),
        )?;
        root_object.insert(
            "requestEnvelopeSha256".to_owned(),
            Value::String(digest_hex(&envelope_sha256)),
        );
        root_object.insert(
            "requestCanonicalBytes".to_owned(),
            Value::String("00000000000000000000".to_owned()),
        );
        let envelope_bytes =
            canonical_json_bytes_v11(json_field(root_object, "requestEnvelope")?)?;
        let frame = root_object
            .get_mut("preAllocationFrame")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template frame projection is absent",
            ))?;
        set_frame_projection_placeholder_v11(
            frame,
            CanonicalFrameKindV11::Request,
            0,
            envelope_bytes.len() as u64,
            frame_deadline,
            envelope_sha256,
            sha256(&raw_nonce),
        );
    }
    let placeholder_bytes = canonical_json_bytes_v11(&root)?;
    let declared_canonical = placeholder_bytes.len() as u64;
    let envelope_bytes = {
        let root_object =
            json_object_v11(&root, "request template root is not an object")?;
        canonical_json_bytes_v11(json_field(root_object, "requestEnvelope")?)?
    };
    let frame = CanonicalPreallocationFrameV11::new(
        CanonicalFrameKindV11::Request,
        declared_canonical,
        envelope_bytes.len() as u64,
        frame_deadline.to_owned(),
        envelope_sha256,
        sha256(&raw_nonce),
    )?;
    {
        let root_object = root.as_object_mut().ok_or(
            ControllerError::Invalid("request template root is not mutable"),
        )?;
        root_object.insert(
            "requestCanonicalBytes".to_owned(),
            Value::String(format!("{declared_canonical:020}")),
        );
        let frame_projection = root_object
            .get_mut("preAllocationFrame")
            .and_then(Value::as_object_mut)
            .ok_or(ControllerError::Invalid(
                "request template frame projection is absent",
            ))?;
        set_frame_projection_placeholder_v11(
            frame_projection,
            CanonicalFrameKindV11::Request,
            declared_canonical,
            envelope_bytes.len() as u64,
            frame_deadline,
            envelope_sha256,
            sha256(&raw_nonce),
        );
        frame_projection.insert(
            "frameSha256".to_owned(),
            Value::String(digest_hex(&frame.frame_sha256)),
        );
    }
    let exact_bytes = canonical_json_bytes_v11(&root)?;
    if exact_bytes.len() as u64 != declared_canonical {
        return Err(ControllerError::Rejected(
            "request canonical length changed after fixed-width projection",
        ));
    }
    let request = CanonicalControllerRequestV11::parse_and_verify(
        exact_bytes,
        &frame,
        &requester_signing_key.verifying_key(),
        expected_requester_spki_der_sha256,
        Some(accepted_at),
    )?;
    Ok(BuiltCanonicalControllerRequestV11 { frame, request })
}

fn sign_signature_object_v11(
    signature: &mut serde_json::Map<String, Value>,
    domain: &str,
    payload_sha256: Digest,
    signed_at: &str,
    accepted_at: &str,
    signing_key: &SigningKey,
    expected_spki_der_sha256: Digest,
) -> Result<()> {
    signature.insert(
        "signatureVersion".to_owned(),
        Value::String("11".to_owned()),
    );
    signature.insert("domain".to_owned(), Value::String(domain.to_owned()));
    signature.insert(
        "payloadSha256".to_owned(),
        Value::String(digest_hex(&payload_sha256)),
    );
    signature.insert(
        "signedAt".to_owned(),
        Value::String(signed_at.to_owned()),
    );
    signature.insert(
        "acceptedAt".to_owned(),
        Value::String(accepted_at.to_owned()),
    );
    let role = json_string_v11(signature, "signerRole")?.to_owned();
    let principal =
        json_string_v11(signature, "signerPrincipalId")?.to_owned();
    let key_id = json_string_v11(signature, "signerKeyId")?.to_owned();
    let key_leaf = parse_hex_digest_v11(json_string_v11(
        signature,
        "signerKeyLeafSha256",
    )?)?;
    if json_string_v11(signature, "signerSpkiDerSha256")?
        != digest_hex(&expected_spki_der_sha256)
    {
        return Err(ControllerError::Rejected(
            "request template signer SPKI pin differs",
        ));
    }
    let signed = lf11(
        "signature",
        &[
            b"11",
            domain.as_bytes(),
            &payload_sha256,
            signed_at.as_bytes(),
            accepted_at.as_bytes(),
            role.as_bytes(),
            principal.as_bytes(),
            key_id.as_bytes(),
            &key_leaf,
            &expected_spki_der_sha256,
        ],
    )?;
    signature.insert(
        "signatureBase64url".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(signing_key.sign(&signed).to_bytes())),
    );
    Ok(())
}

fn set_frame_projection_placeholder_v11(
    frame: &mut serde_json::Map<String, Value>,
    kind: CanonicalFrameKindV11,
    canonical_bytes: u64,
    body_bytes: u64,
    deadline: &str,
    envelope_sha256: Digest,
    nonce_sha256: Digest,
) {
    let (
        magic,
        canonical_name,
        maximum_canonical_name,
        body_name,
        maximum_body_name,
        aggregate_name,
        envelope_name,
        maximum,
        chunks,
    ) = match kind {
        CanonicalFrameKindV11::Request => (
            "SERVERWARE-CONTROLLER",
            "declaredCanonicalRequestBytes",
            "maximumCanonicalRequestBytes",
            "declaredEnvelopeBytes",
            "maximumEnvelopeBytes",
            "maximumAggregateRetrievedBytes",
            "requestEnvelopeSha256",
            REQUEST_MAX_BYTES,
            REQUEST_MAX_CHUNKS,
        ),
        CanonicalFrameKindV11::Receipt => (
            "SERVERWARE-RECEIPT",
            "declaredCanonicalReceiptBytes",
            "maximumCanonicalReceiptBytes",
            "declaredReceiptBodyBytes",
            "maximumReceiptBodyBytes",
            "maximumAggregateReceivedBytes",
            "receiptEnvelopeSha256",
            RECEIPT_MAX_BYTES,
            RECEIPT_MAX_CHUNKS,
        ),
    };
    let entries = [
        ("frameVersion", "11".to_owned()),
        ("magic", magic.to_owned()),
        (
            "transport",
            "ROOT_OWNED_PEERCRED_SEQPACKET".to_owned(),
        ),
        ("fixedHeaderBytes", format!("{:020}", FIXED_FRAME_BYTES)),
        (canonical_name, format!("{canonical_bytes:020}")),
        (maximum_canonical_name, format!("{maximum:020}")),
        (body_name, format!("{body_bytes:020}")),
        (maximum_body_name, format!("{maximum:020}")),
        ("streamChunkBytes", format!("{:020}", CHUNK_MAX_BYTES)),
        ("maximumStreamChunkCount", format!("{chunks:020}")),
        (aggregate_name, format!("{AGGREGATE_MAX_BYTES:020}")),
        ("frameDeadline", deadline.to_owned()),
        (envelope_name, digest_hex(&envelope_sha256)),
        ("frameNonceSha256", digest_hex(&nonce_sha256)),
        ("frameSha256", "0".repeat(64)),
    ];
    for (name, value) in entries {
        frame.insert(name.to_owned(), Value::String(value));
    }
}

fn patch_attestation_challenge_v11(
    payload: &mut serde_json::Map<String, Value>,
    request_nonce: Digest,
    issued_at: &str,
    expires_at: &str,
    requester_key_leaf_sha256: Digest,
) -> Result<()> {
    let challenge_nonce = h11(
        "attestation/client-challenge",
        &[&request_nonce],
    )?;
    let challenge_id = uuid_v4_from_bytes_v11(&challenge_nonce[0..16])?;
    let challenge_nonce_sha256 = h11(
        "attestation/challenge-nonce",
        &[&challenge_nonce],
    )?;
    let pipeline_plan = json_object_v11(
        json_field(payload, "pipelinePlanEnvelope")?,
        "pipeline plan envelope is absent",
    )?;
    let pipeline_plan_payload = json_object_v11(
        json_field(pipeline_plan, "payload")?,
        "pipeline plan payload is absent",
    )?;
    let pipeline_id = json_string_v11(pipeline_plan_payload, "pipelineId")?;
    let goal_id = json_string_v11(pipeline_plan_payload, "goalId")?;
    let selected_stage = json_field(payload, "selectedStage")?;
    let source = json_object_v11(
        json_field(payload, "source")?,
        "attestation source is absent",
    )?;
    let target = json_object_v11(
        json_field(payload, "executionTarget")?,
        "attestation execution target is absent",
    )?;
    let source_commit =
        parse_hex_digest_v11(json_string_v11(source, "commitSha256")?)?;
    let source_tree =
        parse_hex_digest_v11(json_string_v11(source, "treeSha256")?)?;
    let source_archive =
        parse_hex_digest_v11(json_string_v11(source, "archiveSha256")?)?;
    let runtime_image =
        parse_hex_digest_v11(json_string_v11(target, "runtimeImageSha256")?)?;
    let plan_configuration = parse_hex_digest_v11(json_string_v11(
        payload,
        "planConfigurationSha256",
    )?)?;
    let attestation_policy = parse_hex_digest_v11(json_string_v11(
        pipeline_plan_payload,
        "attestationPolicySha256",
    )?)?;
    let selected_stage_bytes = canonical_json_bytes_v11(selected_stage)?;
    let subject = h11(
        "attestation/pre-execution-subject",
        &[
            pipeline_id.as_bytes(),
            goal_id.as_bytes(),
            &selected_stage_bytes,
            &source_commit,
            &source_tree,
            &source_archive,
            &runtime_image,
            &plan_configuration,
            &attestation_policy,
        ],
    )?;
    let consumption = h11(
        "attestation/challenge-consumption-key",
        &[
            &requester_key_leaf_sha256,
            pipeline_id.as_bytes(),
            goal_id.as_bytes(),
            &selected_stage_bytes,
            challenge_id.as_bytes(),
            &challenge_nonce_sha256,
            &subject,
            issued_at.as_bytes(),
            expires_at.as_bytes(),
        ],
    )?;
    let challenge = payload
        .get_mut("attestationChallenge")
        .and_then(Value::as_object_mut)
        .ok_or(ControllerError::Invalid(
            "attestation request template lacks its challenge",
        ))?;
    challenge.insert(
        "challengeId".to_owned(),
        Value::String(challenge_id),
    );
    challenge.insert(
        "challengeNonceBase64url".to_owned(),
        Value::String(URL_SAFE_NO_PAD.encode(challenge_nonce)),
    );
    challenge.insert(
        "challengeConsumptionKeySha256".to_owned(),
        Value::String(digest_hex(&consumption)),
    );
    challenge.insert(
        "preExecutionChallengeSubjectSha256".to_owned(),
        Value::String(digest_hex(&subject)),
    );
    challenge.insert(
        "issuedAt".to_owned(),
        Value::String(issued_at.to_owned()),
    );
    challenge.insert(
        "notBefore".to_owned(),
        Value::String(issued_at.to_owned()),
    );
    challenge.insert(
        "expiresAt".to_owned(),
        Value::String(expires_at.to_owned()),
    );
    Ok(())
}

fn uuid_v4_from_bytes_v11(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 16 {
        return Err(ControllerError::Invalid(
            "UUID source must contain exactly 16 bytes",
        ));
    }
    let mut value = [0u8; 16];
    value.copy_from_slice(bytes);
    value[6] = (value[6] & 0x0f) | 0x40;
    value[8] = (value[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        value[9],
        value[10],
        value[11],
        value[12],
        value[13],
        value[14],
        value[15],
    ))
}

#[derive(Clone, Debug)]
pub struct CanonicalControllerReceiptV11 {
    exact_bytes: Arc<Vec<u8>>,
    root: Value,
    pub receipt_variant: String,
    pub verdict: String,
    pub request_envelope_sha256: Option<Digest>,
    pub receipt_envelope_sha256: Digest,
    pub receipt_body_sha256: Digest,
    pub receipt_authentication_envelope_sha256: Digest,
    pub final_verdict_envelope_sha256: Digest,
}

impl CanonicalControllerReceiptV11 {
    pub fn parse_and_verify(
        exact_bytes: Vec<u8>,
        frame: &CanonicalPreallocationFrameV11,
        receipt_key: &VerifyingKey,
        receipt_spki_der_sha256: Digest,
        final_verdict_key: &VerifyingKey,
        final_verdict_spki_der_sha256: Digest,
        expected_request_envelope_sha256: Digest,
        expected_frame_nonce_sha256: Digest,
    ) -> Result<Self> {
        if frame.kind != CanonicalFrameKindV11::Receipt {
            return Err(ControllerError::Invalid(
                "request frame cannot carry a controller receipt",
            ));
        }
        let root = parse_exact_canonical_json_v11(
            &exact_bytes,
            RECEIPT_MAX_BYTES as usize,
        )?;
        validate_schema_v11(&root, true)?;
        frame.verify_json_projection(&root)?;
        if frame.declared_canonical_bytes != exact_bytes.len() as u64
            || !constant_time_eq(
                &frame.frame_nonce_sha256,
                &expected_frame_nonce_sha256,
            )
        {
            return Err(ControllerError::Rejected(
                "receipt frame length or request nonce binding differs",
            ));
        }
        let root_object =
            json_object_v11(&root, "controller receipt root is not an object")?;
        if parse_d20_v11(json_string_v11(
            root_object,
            "receiptCanonicalBytes",
        )?)? != exact_bytes.len() as u64
        {
            return Err(ControllerError::Rejected(
                "receiptCanonicalBytes differs from exact canonical root",
            ));
        }
        let body = json_field(root_object, "receiptBody")?;
        let body_object =
            json_object_v11(body, "controller receipt body is not an object")?;
        let body_bytes = canonical_json_bytes_v11(body)?;
        if frame.declared_body_bytes != body_bytes.len() as u64 {
            return Err(ControllerError::Rejected(
                "receipt body length differs from its frame declaration",
            ));
        }
        let receipt_body_sha256 = h11("receipt/body", &[&body_bytes])?;
        if json_string_v11(root_object, "receiptBodySha256")?
            != digest_hex(&receipt_body_sha256)
        {
            return Err(ControllerError::Rejected(
                "receipt body digest differs from its H11 projection",
            ));
        }
        let receipt_authentication = json_object_v11(
            json_field(root_object, "receiptAuthenticationEnvelope")?,
            "receipt authentication envelope is not an object",
        )?;
        let receipt_authentication_envelope_sha256 =
            verify_typed_envelope_v11(
                receipt_authentication,
                "serverware/receipt-authentication/v11",
                "controllerReceipt",
                receipt_key,
                receipt_spki_der_sha256,
            )?;
        if json_string_v11(
            root_object,
            "receiptAuthenticationEnvelopeSha256",
        )? != digest_hex(&receipt_authentication_envelope_sha256)
        {
            return Err(ControllerError::Rejected(
                "receipt authentication envelope digest differs",
            ));
        }
        let final_verdict = json_object_v11(
            json_field(root_object, "finalVerdictEnvelope")?,
            "final verdict envelope is not an object",
        )?;
        let final_verdict_envelope_sha256 = verify_typed_envelope_v11(
            final_verdict,
            "serverware/final-verdict/v11",
            "finalVerdictCheckpoint",
            final_verdict_key,
            final_verdict_spki_der_sha256,
        )?;
        if json_string_v11(root_object, "finalVerdictEnvelopeSha256")?
            != digest_hex(&final_verdict_envelope_sha256)
        {
            return Err(ControllerError::Rejected(
                "final verdict envelope digest differs",
            ));
        }
        let receipt_envelope_sha256 = h11(
            "receipt/root",
            &[
                b"11",
                &receipt_body_sha256,
                &receipt_authentication_envelope_sha256,
                &final_verdict_envelope_sha256,
            ],
        )?;
        if json_string_v11(root_object, "receiptEnvelopeSha256")?
                != digest_hex(&receipt_envelope_sha256)
            || !constant_time_eq(
                &receipt_envelope_sha256,
                &frame.envelope_sha256,
            )
        {
            return Err(ControllerError::Rejected(
                "receipt root digest differs from root or frame",
            ));
        }
        let request_envelope_sha256 = body_object
            .get("request")
            .and_then(Value::as_object)
            .and_then(|request| request.get("requestEnvelopeSha256"))
            .and_then(Value::as_str)
            .map(parse_hex_digest_v11)
            .transpose()?;
        if request_envelope_sha256.is_some_and(|request| {
            !constant_time_eq(
                &request,
                &expected_request_envelope_sha256,
            )
        }) {
            return Err(ControllerError::Rejected(
                "receipt references another canonical request",
            ));
        }
        let receipt_variant =
            json_string_v11(body_object, "receiptVariant")?.to_owned();
        let verdict = json_string_v11(body_object, "verdict")?.to_owned();
        let final_payload = json_object_v11(
            json_field(final_verdict, "payload")?,
            "final verdict payload is not an object",
        )?;
        if json_string_v11(final_payload, "verdict")? != verdict {
            return Err(ControllerError::Rejected(
                "receipt body and final verdict classifications differ",
            ));
        }
        Ok(Self {
            exact_bytes: Arc::new(exact_bytes),
            root,
            receipt_variant,
            verdict,
            request_envelope_sha256,
            receipt_envelope_sha256,
            receipt_body_sha256,
            receipt_authentication_envelope_sha256,
            final_verdict_envelope_sha256,
        })
    }

    pub fn exact_bytes(&self) -> &[u8] {
        self.exact_bytes.as_slice()
    }

    pub fn root(&self) -> &Value {
        &self.root
    }
}

fn verify_typed_envelope_v11(
    envelope: &serde_json::Map<String, Value>,
    expected_domain: &str,
    expected_role: &str,
    verifying_key: &VerifyingKey,
    expected_spki_der_sha256: Digest,
) -> Result<Digest> {
    if json_string_v11(envelope, "domain")? != expected_domain {
        return Err(ControllerError::Rejected(
            "typed envelope domain differs",
        ));
    }
    let payload = json_field(envelope, "payload")?;
    let payload_bytes = canonical_json_bytes_v11(payload)?;
    let payload_sha256 = h11(
        "payload",
        &[expected_domain.as_bytes(), &payload_bytes],
    )?;
    if json_string_v11(envelope, "payloadSha256")?
        != digest_hex(&payload_sha256)
    {
        return Err(ControllerError::Rejected(
            "typed envelope payload digest differs",
        ));
    }
    let signature = json_object_v11(
        json_field(envelope, "signature")?,
        "typed envelope signature is not an object",
    )?;
    verify_signature_object_v11(
        signature,
        expected_domain,
        payload_sha256,
        verifying_key,
        expected_role,
        expected_spki_der_sha256,
        None,
    )?;
    let signature_bytes =
        canonical_json_bytes_v11(json_field(envelope, "signature")?)?;
    h11(
        "typed-envelope",
        &[
            expected_domain.as_bytes(),
            &payload_sha256,
            &signature_bytes,
        ],
    )
}

pub fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControllerError::Invalid("system time precedes unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| ControllerError::Invalid("system time exceeds u64"))
}

pub fn bounded_deadline(duration: Duration) -> Result<u64> {
    let millis: u64 = duration
        .as_millis()
        .try_into()
        .map_err(|_| ControllerError::Invalid("deadline duration exceeds u64"))?;
    if millis == 0 || millis > MAX_DEADLINE_FUTURE_MS {
        return Err(ControllerError::Invalid("deadline is outside the v11 bound"));
    }
    now_unix_ms()?
        .checked_add(millis)
        .ok_or(ControllerError::Invalid("deadline overflow"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    Request = 2,
    Receipt = 3,
    Error = 4,
}

impl FrameKind {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Request),
            3 => Ok(Self::Receipt),
            4 => Ok(Self::Error),
            _ => Err(ControllerError::Invalid("unknown v11 frame kind")),
        }
    }

    fn limits(self) -> (u64, u32) {
        match self {
            Self::Receipt | Self::Error => (RECEIPT_MAX_BYTES, RECEIPT_MAX_CHUNKS),
            Self::Hello | Self::Request => (REQUEST_MAX_BYTES, REQUEST_MAX_CHUNKS),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    Build,
    RunNoBuild,
}

impl Operation {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::RunNoBuild => "runNoBuild",
        }
    }

    pub fn parse_flag(value: &str) -> Result<Self> {
        match value {
            "--operation=build" => Ok(Self::Build),
            "--operation=runNoBuild" => Ok(Self::RunNoBuild),
            _ => Err(ControllerError::Invalid("operation flag is not frozen v11 syntax")),
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Build => 1,
            Self::RunNoBuild => 2,
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Build),
            2 => Ok(Self::RunNoBuild),
            _ => Err(ControllerError::Invalid("unknown operation code")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Plan {
    Build,
    UnitNoBuild,
    IntegrationNoBuild,
    E2eNoBuild,
    AttestationNoBuild,
}

impl Plan {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Build => "serverware-build-v1",
            Self::UnitNoBuild => "serverware-unit-no-build-v1",
            Self::IntegrationNoBuild => "serverware-integration-no-build-v1",
            Self::E2eNoBuild => "serverware-e2e-no-build-v1",
            Self::AttestationNoBuild => "serverware-attestation-no-build-v1",
        }
    }

    pub fn parse_flag(value: &str) -> Result<Self> {
        let label = value
            .strip_prefix("--plan=")
            .ok_or(ControllerError::Invalid("plan flag is not frozen v11 syntax"))?;
        match label {
            "serverware-build-v1" => Ok(Self::Build),
            "serverware-unit-no-build-v1" => Ok(Self::UnitNoBuild),
            "serverware-integration-no-build-v1" => Ok(Self::IntegrationNoBuild),
            "serverware-e2e-no-build-v1" => Ok(Self::E2eNoBuild),
            "serverware-attestation-no-build-v1" => Ok(Self::AttestationNoBuild),
            _ => Err(ControllerError::Invalid("plan is not in the v11 allowlist")),
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Build => 1,
            Self::UnitNoBuild => 2,
            Self::IntegrationNoBuild => 3,
            Self::E2eNoBuild => 4,
            Self::AttestationNoBuild => 5,
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Build),
            2 => Ok(Self::UnitNoBuild),
            3 => Ok(Self::IntegrationNoBuild),
            4 => Ok(Self::E2eNoBuild),
            5 => Ok(Self::AttestationNoBuild),
            _ => Err(ControllerError::Invalid("unknown plan code")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Lane {
    pub operation: Operation,
    pub plan: Plan,
}

impl Lane {
    pub fn checked(operation: Operation, plan: Plan) -> Result<Self> {
        if !matches!(
            (operation, plan),
            (Operation::Build, Plan::Build)
                | (Operation::RunNoBuild, Plan::UnitNoBuild)
                | (Operation::RunNoBuild, Plan::IntegrationNoBuild)
                | (Operation::RunNoBuild, Plan::E2eNoBuild)
                | (Operation::RunNoBuild, Plan::AttestationNoBuild)
        ) {
            return Err(ControllerError::Invalid("operation/plan pair is not allowed"));
        }
        Ok(Self { operation, plan })
    }

    pub fn parse_frozen_flags(operation: &str, plan: &str) -> Result<Self> {
        Self::checked(Operation::parse_flag(operation)?, Plan::parse_flag(plan)?)
    }

    fn encode(self) -> (u8, u8) {
        (self.operation.code(), self.plan.code())
    }

    fn decode(operation: u8, plan: u8) -> Result<Self> {
        Self::checked(Operation::from_code(operation)?, Plan::from_code(plan)?)
    }
}

pub const FIXED_PLAN_ORDER: [Plan; 5] = [
    Plan::Build,
    Plan::UnitNoBuild,
    Plan::IntegrationNoBuild,
    Plan::E2eNoBuild,
    Plan::AttestationNoBuild,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceTicketRequestV11 {
    pub lane: Lane,
    pub requested_timeout_ms: u64,
    pub raw_nonce: Digest,
    pub peer_binding_sha256: Digest,
    pub request_sha256: Digest,
}

impl AcceptanceTicketRequestV11 {
    pub fn new(
        lane: Lane,
        requested_timeout_ms: u64,
        raw_nonce: Digest,
        peer_binding_sha256: Digest,
    ) -> Result<Self> {
        if requested_timeout_ms == 0
            || requested_timeout_ms > MAX_DEADLINE_FUTURE_MS
            || raw_nonce == [0; 32]
            || peer_binding_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "acceptance ticket request lacks a bounded binding",
            ));
        }
        let mut request = Self {
            lane: Lane::checked(lane.operation, lane.plan)?,
            requested_timeout_ms,
            raw_nonce,
            peer_binding_sha256,
            request_sha256: [0; 32],
        };
        request.request_sha256 = sha256(&request.encode_with_digest([0; 32]));
        Ok(request)
    }

    pub fn encode(&self) -> [u8; ACCEPTANCE_TICKET_REQUEST_BYTES] {
        self.encode_with_digest(self.request_sha256)
    }

    fn encode_with_digest(
        &self,
        digest: Digest,
    ) -> [u8; ACCEPTANCE_TICKET_REQUEST_BYTES] {
        let mut bytes = [0u8; ACCEPTANCE_TICKET_REQUEST_BYTES];
        bytes[0..8].copy_from_slice(&ACCEPTANCE_TICKET_REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        let (operation, plan) = self.lane.encode();
        bytes[10] = operation;
        bytes[11] = plan;
        bytes[16..24].copy_from_slice(&self.requested_timeout_ms.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.raw_nonce);
        bytes[56..88].copy_from_slice(&self.peer_binding_sha256);
        bytes[88..120].copy_from_slice(&digest);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ACCEPTANCE_TICKET_REQUEST_BYTES
            || bytes[0..8] != ACCEPTANCE_TICKET_REQUEST_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "invalid acceptance ticket request",
            ));
        }
        let request = Self {
            lane: Lane::decode(bytes[10], bytes[11])?,
            requested_timeout_ms: read_u64_slice(bytes, 16)?,
            raw_nonce: copy_digest(&bytes[24..56]),
            peer_binding_sha256: copy_digest(&bytes[56..88]),
            request_sha256: copy_digest(&bytes[88..120]),
        };
        let expected = sha256(&request.encode_with_digest([0; 32]));
        if request.requested_timeout_ms == 0
            || request.requested_timeout_ms > MAX_DEADLINE_FUTURE_MS
            || request.raw_nonce == [0; 32]
            || request.peer_binding_sha256 == [0; 32]
            || !constant_time_eq(&expected, &request.request_sha256)
        {
            return Err(ControllerError::Rejected(
                "acceptance ticket request binding is invalid",
            ));
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceTicketV11 {
    pub lane: Lane,
    pub accepted_at_unix_ms: u64,
    pub frame_deadline_unix_ms: u64,
    pub request_deadline_unix_ms: u64,
    pub raw_nonce: Digest,
    pub peer_binding_sha256: Digest,
    pub config_sha256: Digest,
    pub ticket_sha256: Digest,
    pub signer_public_key: Digest,
    pub signature: [u8; 64],
}

impl AcceptanceTicketV11 {
    pub fn sign(
        request: &AcceptanceTicketRequestV11,
        accepted_at_unix_ms: u64,
        frame_deadline_unix_ms: u64,
        request_deadline_unix_ms: u64,
        config_sha256: Digest,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        if accepted_at_unix_ms == 0
            || frame_deadline_unix_ms < accepted_at_unix_ms
            || frame_deadline_unix_ms.saturating_sub(accepted_at_unix_ms)
                > 30_000
            || request_deadline_unix_ms < frame_deadline_unix_ms
            || request_deadline_unix_ms
                .saturating_sub(accepted_at_unix_ms)
                > request.requested_timeout_ms
            || config_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "acceptance ticket deadline or config binding is invalid",
            ));
        }
        let signer_public_key = *signing_key.verifying_key().as_bytes();
        let mut ticket = Self {
            lane: request.lane,
            accepted_at_unix_ms,
            frame_deadline_unix_ms,
            request_deadline_unix_ms,
            raw_nonce: request.raw_nonce,
            peer_binding_sha256: request.peer_binding_sha256,
            config_sha256,
            ticket_sha256: [0; 32],
            signer_public_key,
            signature: [0; 64],
        };
        ticket.ticket_sha256 =
            sha256(&ticket.encode_signed_prefix_with_digest([0; 32]));
        ticket.signature = signing_key
            .sign(&ticket.encode_signed_prefix_with_digest(
                ticket.ticket_sha256,
            ))
            .to_bytes();
        Ok(ticket)
    }

    pub fn encode(&self) -> [u8; ACCEPTANCE_TICKET_BYTES] {
        let mut bytes = [0u8; ACCEPTANCE_TICKET_BYTES];
        bytes[..200].copy_from_slice(
            &self.encode_signed_prefix_with_digest(self.ticket_sha256),
        );
        bytes[200..264].copy_from_slice(&self.signature);
        bytes
    }

    fn encode_signed_prefix_with_digest(
        &self,
        digest: Digest,
    ) -> [u8; 200] {
        let mut bytes = [0u8; 200];
        bytes[0..8].copy_from_slice(&ACCEPTANCE_TICKET_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        let (operation, plan) = self.lane.encode();
        bytes[10] = operation;
        bytes[11] = plan;
        bytes[16..24].copy_from_slice(&self.accepted_at_unix_ms.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.frame_deadline_unix_ms.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.request_deadline_unix_ms.to_be_bytes());
        bytes[40..72].copy_from_slice(&self.raw_nonce);
        bytes[72..104].copy_from_slice(&self.peer_binding_sha256);
        bytes[104..136].copy_from_slice(&self.config_sha256);
        bytes[136..168].copy_from_slice(&digest);
        bytes[168..200].copy_from_slice(&self.signer_public_key);
        bytes
    }

    pub fn decode_and_verify(
        bytes: &[u8],
        verifying_key: &VerifyingKey,
        expected_request: &AcceptanceTicketRequestV11,
    ) -> Result<Self> {
        if bytes.len() != ACCEPTANCE_TICKET_BYTES
            || bytes[0..8] != ACCEPTANCE_TICKET_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid("invalid acceptance ticket"));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[200..264]);
        let ticket = Self {
            lane: Lane::decode(bytes[10], bytes[11])?,
            accepted_at_unix_ms: read_u64_slice(bytes, 16)?,
            frame_deadline_unix_ms: read_u64_slice(bytes, 24)?,
            request_deadline_unix_ms: read_u64_slice(bytes, 32)?,
            raw_nonce: copy_digest(&bytes[40..72]),
            peer_binding_sha256: copy_digest(&bytes[72..104]),
            config_sha256: copy_digest(&bytes[104..136]),
            ticket_sha256: copy_digest(&bytes[136..168]),
            signer_public_key: copy_digest(&bytes[168..200]),
            signature,
        };
        let expected_ticket_sha256 =
            sha256(&ticket.encode_signed_prefix_with_digest([0; 32]));
        if ticket.lane != expected_request.lane
            || ticket.raw_nonce != expected_request.raw_nonce
            || ticket.peer_binding_sha256
                != expected_request.peer_binding_sha256
            || ticket.signer_public_key != *verifying_key.as_bytes()
            || ticket.accepted_at_unix_ms == 0
            || ticket.frame_deadline_unix_ms < ticket.accepted_at_unix_ms
            || ticket
                .frame_deadline_unix_ms
                .saturating_sub(ticket.accepted_at_unix_ms)
                > 30_000
            || ticket.request_deadline_unix_ms
                < ticket.frame_deadline_unix_ms
            || ticket
                .request_deadline_unix_ms
                .saturating_sub(ticket.accepted_at_unix_ms)
                > expected_request.requested_timeout_ms
            || !constant_time_eq(
                &ticket.ticket_sha256,
                &expected_ticket_sha256,
            )
        {
            return Err(ControllerError::Rejected(
                "acceptance ticket request binding is invalid",
            ));
        }
        verifying_key
            .verify_strict(
                &ticket.encode_signed_prefix_with_digest(
                    ticket.ticket_sha256,
                ),
                &Signature::from_bytes(&ticket.signature),
            )
            .map_err(|_| {
                ControllerError::Rejected(
                    "acceptance ticket signature is invalid",
                )
            })?;
        Ok(ticket)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanApiModeV11 {
    Bootstrap,
    Execute,
}

impl PlanApiModeV11 {
    fn code(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Execute => 2,
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Execute),
            _ => Err(ControllerError::Invalid("unknown plan API mode")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanApiRequestV11 {
    pub mode: PlanApiModeV11,
    pub lane: Lane,
    pub deadline_unix_ms: u64,
    pub one_use_capability: Digest,
    pub request_nonce: Digest,
    pub expected_daemon_identity_sha256: Digest,
    pub request_sha256: Digest,
}

impl PlanApiRequestV11 {
    pub fn new(
        mode: PlanApiModeV11,
        lane: Lane,
        deadline_unix_ms: u64,
        one_use_capability: Digest,
        request_nonce: Digest,
        expected_daemon_identity_sha256: Digest,
    ) -> Result<Self> {
        if deadline_unix_ms == 0
            || one_use_capability == [0; 32]
            || request_nonce == [0; 32]
            || expected_daemon_identity_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "plan API request lacks a required binding",
            ));
        }
        let mut request = Self {
            mode,
            lane: Lane::checked(lane.operation, lane.plan)?,
            deadline_unix_ms,
            one_use_capability,
            request_nonce,
            expected_daemon_identity_sha256,
            request_sha256: [0; 32],
        };
        request.request_sha256 = sha256(&request.encode_with_digest([0; 32]));
        Ok(request)
    }

    pub fn encode(&self) -> [u8; PLAN_API_REQUEST_BYTES] {
        self.encode_with_digest(self.request_sha256)
    }

    fn encode_with_digest(&self, digest: Digest) -> [u8; PLAN_API_REQUEST_BYTES] {
        let mut bytes = [0u8; PLAN_API_REQUEST_BYTES];
        bytes[0..8].copy_from_slice(&PLAN_API_REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        bytes[10] = self.mode.code();
        let (operation, plan) = self.lane.encode();
        bytes[11] = operation;
        bytes[12] = plan;
        bytes[16..24].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.one_use_capability);
        bytes[56..88].copy_from_slice(&self.request_nonce);
        bytes[88..120]
            .copy_from_slice(&self.expected_daemon_identity_sha256);
        bytes[120..152].copy_from_slice(&digest);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PLAN_API_REQUEST_BYTES
            || bytes[0..8] != PLAN_API_REQUEST_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[13..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid("invalid plan API request"));
        }
        let request = Self {
            mode: PlanApiModeV11::from_code(bytes[10])?,
            lane: Lane::decode(bytes[11], bytes[12])?,
            deadline_unix_ms: read_u64_slice(bytes, 16)?,
            one_use_capability: copy_digest(&bytes[24..56]),
            request_nonce: copy_digest(&bytes[56..88]),
            expected_daemon_identity_sha256: copy_digest(&bytes[88..120]),
            request_sha256: copy_digest(&bytes[120..152]),
        };
        let expected = sha256(&request.encode_with_digest([0; 32]));
        if request.deadline_unix_ms == 0
            || request.one_use_capability == [0; 32]
            || request.request_nonce == [0; 32]
            || request.expected_daemon_identity_sha256 == [0; 32]
            || !constant_time_eq(&expected, &request.request_sha256)
        {
            return Err(ControllerError::Rejected(
                "plan API request binding is invalid",
            ));
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanApiResponseV11 {
    pub lane: Lane,
    pub request_sha256: Digest,
    pub request_nonce: Digest,
    pub daemon_identity_sha256: Digest,
    pub evidence_sha256: Digest,
    pub exit_status: i32,
    pub response_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAuthorityRequestV11 {
    pub lane: Lane,
    pub deadline_unix_ms: u64,
    pub canonical_request_bytes: u64,
    pub terminal_evidence_bytes: u64,
    pub request_envelope_sha256: Digest,
    pub frame_nonce_sha256: Digest,
    pub canonical_request_sha256: Digest,
    pub terminal_evidence_sha256: Digest,
    pub daemon_identity_sha256: Digest,
    pub request_sha256: Digest,
}

impl ReceiptAuthorityRequestV11 {
    pub fn new(
        lane: Lane,
        deadline_unix_ms: u64,
        canonical_request_bytes: u64,
        terminal_evidence_bytes: u64,
        request_envelope_sha256: Digest,
        frame_nonce_sha256: Digest,
        canonical_request_sha256: Digest,
        terminal_evidence_sha256: Digest,
        daemon_identity_sha256: Digest,
    ) -> Result<Self> {
        if deadline_unix_ms == 0
            || canonical_request_bytes == 0
            || canonical_request_bytes > REQUEST_MAX_BYTES
            || terminal_evidence_bytes == 0
            || terminal_evidence_bytes > RECEIPT_MAX_BYTES
            || canonical_request_bytes
                .checked_add(terminal_evidence_bytes)
                .ok_or(ControllerError::Invalid(
                    "receipt authority aggregate length overflow",
                ))?
                > AGGREGATE_MAX_BYTES
            || request_envelope_sha256 == [0; 32]
            || frame_nonce_sha256 == [0; 32]
            || canonical_request_sha256 == [0; 32]
            || terminal_evidence_sha256 == [0; 32]
            || daemon_identity_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "receipt authority request violates fixed v11 bounds",
            ));
        }
        let mut request = Self {
            lane: Lane::checked(lane.operation, lane.plan)?,
            deadline_unix_ms,
            canonical_request_bytes,
            terminal_evidence_bytes,
            request_envelope_sha256,
            frame_nonce_sha256,
            canonical_request_sha256,
            terminal_evidence_sha256,
            daemon_identity_sha256,
            request_sha256: [0; 32],
        };
        request.request_sha256 =
            sha256(&request.encode_with_digest([0; 32]));
        Ok(request)
    }

    pub fn encode(&self) -> [u8; RECEIPT_AUTHORITY_REQUEST_BYTES] {
        self.encode_with_digest(self.request_sha256)
    }

    fn encode_with_digest(
        &self,
        digest: Digest,
    ) -> [u8; RECEIPT_AUTHORITY_REQUEST_BYTES] {
        let mut bytes = [0u8; RECEIPT_AUTHORITY_REQUEST_BYTES];
        bytes[0..8].copy_from_slice(&RECEIPT_AUTHORITY_REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        let (operation, plan) = self.lane.encode();
        bytes[10] = operation;
        bytes[11] = plan;
        bytes[16..24].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[24..32].copy_from_slice(
            &self.canonical_request_bytes.to_be_bytes(),
        );
        bytes[32..40].copy_from_slice(
            &self.terminal_evidence_bytes.to_be_bytes(),
        );
        bytes[40..72].copy_from_slice(&self.request_envelope_sha256);
        bytes[72..104].copy_from_slice(&self.frame_nonce_sha256);
        bytes[104..136].copy_from_slice(&self.canonical_request_sha256);
        bytes[136..168].copy_from_slice(&self.terminal_evidence_sha256);
        bytes[168..200].copy_from_slice(&self.daemon_identity_sha256);
        bytes[200..232].copy_from_slice(&digest);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECEIPT_AUTHORITY_REQUEST_BYTES
            || bytes[0..8] != RECEIPT_AUTHORITY_REQUEST_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[12..16].iter().any(|byte| *byte != 0)
            || bytes[232..].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "invalid receipt authority request",
            ));
        }
        let request = Self {
            lane: Lane::decode(bytes[10], bytes[11])?,
            deadline_unix_ms: read_u64_slice(bytes, 16)?,
            canonical_request_bytes: read_u64_slice(bytes, 24)?,
            terminal_evidence_bytes: read_u64_slice(bytes, 32)?,
            request_envelope_sha256: copy_digest(&bytes[40..72]),
            frame_nonce_sha256: copy_digest(&bytes[72..104]),
            canonical_request_sha256: copy_digest(&bytes[104..136]),
            terminal_evidence_sha256: copy_digest(&bytes[136..168]),
            daemon_identity_sha256: copy_digest(&bytes[168..200]),
            request_sha256: copy_digest(&bytes[200..232]),
        };
        let rebuilt = Self::new(
            request.lane,
            request.deadline_unix_ms,
            request.canonical_request_bytes,
            request.terminal_evidence_bytes,
            request.request_envelope_sha256,
            request.frame_nonce_sha256,
            request.canonical_request_sha256,
            request.terminal_evidence_sha256,
            request.daemon_identity_sha256,
        )?;
        if !constant_time_eq(
            &request.request_sha256,
            &rebuilt.request_sha256,
        ) {
            return Err(ControllerError::Rejected(
                "receipt authority request digest differs",
            ));
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCapabilityRecordV11 {
    pub mode: PlanApiModeV11,
    pub lane: Lane,
    pub deadline_unix_ms: u64,
    pub capability_sha256: Digest,
    pub request_binding_sha256: Digest,
    pub daemon_identity_sha256: Digest,
    pub artifact_seal_sha256: Digest,
    pub record_sha256: Digest,
}

impl PlanCapabilityRecordV11 {
    pub fn new(
        mode: PlanApiModeV11,
        lane: Lane,
        deadline_unix_ms: u64,
        capability_sha256: Digest,
        request_binding_sha256: Digest,
        daemon_identity_sha256: Digest,
        artifact_seal_sha256: Digest,
    ) -> Result<Self> {
        if deadline_unix_ms == 0
            || capability_sha256 == [0; 32]
            || request_binding_sha256 == [0; 32]
            || daemon_identity_sha256 == [0; 32]
            || artifact_seal_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "plan capability record lacks a required binding",
            ));
        }
        let mut record = Self {
            mode,
            lane: Lane::checked(lane.operation, lane.plan)?,
            deadline_unix_ms,
            capability_sha256,
            request_binding_sha256,
            daemon_identity_sha256,
            artifact_seal_sha256,
            record_sha256: [0; 32],
        };
        record.record_sha256 = sha256(&record.encode_with_digest([0; 32]));
        Ok(record)
    }

    pub fn encode(&self) -> [u8; PLAN_CAPABILITY_RECORD_BYTES] {
        self.encode_with_digest(self.record_sha256)
    }

    fn encode_with_digest(
        &self,
        digest: Digest,
    ) -> [u8; PLAN_CAPABILITY_RECORD_BYTES] {
        let mut bytes = [0u8; PLAN_CAPABILITY_RECORD_BYTES];
        bytes[0..8].copy_from_slice(b"SWPLCP11");
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        bytes[10] = self.mode.code();
        let (operation, plan) = self.lane.encode();
        bytes[11] = operation;
        bytes[12] = plan;
        bytes[16..24].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.capability_sha256);
        bytes[56..88].copy_from_slice(&self.request_binding_sha256);
        bytes[88..120].copy_from_slice(&self.daemon_identity_sha256);
        bytes[120..152].copy_from_slice(&self.artifact_seal_sha256);
        bytes[152..184].copy_from_slice(&digest);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PLAN_CAPABILITY_RECORD_BYTES
            || &bytes[0..8] != b"SWPLCP11"
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[13..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "invalid plan capability record",
            ));
        }
        let record = Self {
            mode: PlanApiModeV11::from_code(bytes[10])?,
            lane: Lane::decode(bytes[11], bytes[12])?,
            deadline_unix_ms: read_u64_slice(bytes, 16)?,
            capability_sha256: copy_digest(&bytes[24..56]),
            request_binding_sha256: copy_digest(&bytes[56..88]),
            daemon_identity_sha256: copy_digest(&bytes[88..120]),
            artifact_seal_sha256: copy_digest(&bytes[120..152]),
            record_sha256: copy_digest(&bytes[152..184]),
        };
        let expected = sha256(&record.encode_with_digest([0; 32]));
        if record.deadline_unix_ms == 0
            || record.capability_sha256 == [0; 32]
            || record.request_binding_sha256 == [0; 32]
            || record.daemon_identity_sha256 == [0; 32]
            || record.artifact_seal_sha256 == [0; 32]
            || !constant_time_eq(&expected, &record.record_sha256)
        {
            return Err(ControllerError::Rejected(
                "plan capability record binding is invalid",
            ));
        }
        Ok(record)
    }
}

impl PlanApiResponseV11 {
    pub fn new(
        lane: Lane,
        request_sha256: Digest,
        request_nonce: Digest,
        daemon_identity_sha256: Digest,
        evidence_sha256: Digest,
        exit_status: i32,
    ) -> Result<Self> {
        if request_sha256 == [0; 32]
            || request_nonce == [0; 32]
            || daemon_identity_sha256 == [0; 32]
            || evidence_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "plan API response lacks a required binding",
            ));
        }
        let mut response = Self {
            lane: Lane::checked(lane.operation, lane.plan)?,
            request_sha256,
            request_nonce,
            daemon_identity_sha256,
            evidence_sha256,
            exit_status,
            response_sha256: [0; 32],
        };
        response.response_sha256 =
            sha256(&response.encode_with_digest([0; 32]));
        Ok(response)
    }

    pub fn encode(&self) -> [u8; PLAN_API_RESPONSE_BYTES] {
        self.encode_with_digest(self.response_sha256)
    }

    fn encode_with_digest(&self, digest: Digest) -> [u8; PLAN_API_RESPONSE_BYTES] {
        let mut bytes = [0u8; PLAN_API_RESPONSE_BYTES];
        bytes[0..8].copy_from_slice(&PLAN_API_RESPONSE_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        let (operation, plan) = self.lane.encode();
        bytes[10] = operation;
        bytes[11] = plan;
        bytes[12..16].copy_from_slice(&self.exit_status.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.request_sha256);
        bytes[48..80].copy_from_slice(&self.request_nonce);
        bytes[80..112].copy_from_slice(&self.daemon_identity_sha256);
        bytes[112..144].copy_from_slice(&self.evidence_sha256);
        bytes[144..176].copy_from_slice(&digest);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PLAN_API_RESPONSE_BYTES
            || bytes[0..8] != PLAN_API_RESPONSE_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
        {
            return Err(ControllerError::Invalid("invalid plan API response"));
        }
        let response = Self {
            lane: Lane::decode(bytes[10], bytes[11])?,
            exit_status: i32::from_be_bytes(
                bytes[12..16]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid("invalid plan API status"))?,
            ),
            request_sha256: copy_digest(&bytes[16..48]),
            request_nonce: copy_digest(&bytes[48..80]),
            daemon_identity_sha256: copy_digest(&bytes[80..112]),
            evidence_sha256: copy_digest(&bytes[112..144]),
            response_sha256: copy_digest(&bytes[144..176]),
        };
        let expected = sha256(&response.encode_with_digest([0; 32]));
        if !constant_time_eq(&expected, &response.response_sha256) {
            return Err(ControllerError::Rejected(
                "plan API response digest mismatch",
            ));
        }
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedPlanBindingV11 {
    pub plan: Plan,
    pub fixed_launch_command_identity_sha256: Digest,
    pub binding_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPlanManifestV11 {
    pub config_sha256: Digest,
    pub bindings: [TrustedPlanBindingV11; 5],
    pub table_sha256: Digest,
}

pub fn trusted_plan_binding_sha256(
    config_sha256: Digest,
    plan: Plan,
    fixed_launch_command_identity_sha256: Digest,
) -> Digest {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(
        b"serverware-controller-v11/trusted-plan-binding\0",
    );
    bytes.extend_from_slice(&config_sha256);
    bytes.push(plan.code());
    bytes.extend_from_slice(&fixed_launch_command_identity_sha256);
    sha256(&bytes)
}

pub fn trusted_plan_table_sha256(
    config_sha256: Digest,
    bindings: &[TrustedPlanBindingV11; 5],
) -> Result<Digest> {
    if config_sha256 == [0; 32] {
        return Err(ControllerError::Rejected(
            "trusted plan table config digest is empty",
        ));
    }
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(
        b"serverware-controller-v11/trusted-plan-table\0",
    );
    bytes.extend_from_slice(&config_sha256);
    for (index, binding) in bindings.iter().enumerate() {
        if binding.plan != FIXED_PLAN_ORDER[index]
            || binding.binding_sha256 == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "trusted plan table binding is empty or out of fixed order",
            ));
        }
        bytes.extend_from_slice(&binding.binding_sha256);
    }
    Ok(sha256(&bytes))
}

impl TrustedPlanManifestV11 {
    pub fn new(
        config_sha256: Digest,
        fixed_launch_command_identities: [Digest; 5],
    ) -> Result<Self> {
        if config_sha256 == [0; 32]
            || fixed_launch_command_identities
                .iter()
                .any(|digest| *digest == [0; 32])
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest contains an empty digest",
            ));
        }
        let bindings = std::array::from_fn(|index| {
            let plan = FIXED_PLAN_ORDER[index];
            let command = fixed_launch_command_identities[index];
            TrustedPlanBindingV11 {
                plan,
                fixed_launch_command_identity_sha256: command,
                binding_sha256: trusted_plan_binding_sha256(
                    config_sha256,
                    plan,
                    command,
                ),
            }
        });
        let manifest = Self {
            config_sha256,
            table_sha256:
                trusted_plan_table_sha256(config_sha256, &bindings)?,
            bindings,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "trusted plan manifest config digest is empty",
            ));
        }
        for (index, binding) in self.bindings.iter().enumerate() {
            let expected_plan = FIXED_PLAN_ORDER[index];
            if binding.plan != expected_plan
                || binding.fixed_launch_command_identity_sha256 == [0; 32]
                || binding.binding_sha256 == [0; 32]
                || binding.binding_sha256
                    != trusted_plan_binding_sha256(
                        self.config_sha256,
                        expected_plan,
                        binding.fixed_launch_command_identity_sha256,
                    )
            {
                return Err(ControllerError::Rejected(
                    "trusted plan manifest binding is invalid or out of order",
                ));
            }
        }
        if self.table_sha256 == [0; 32]
            || self.table_sha256
                != trusted_plan_table_sha256(
                    self.config_sha256,
                    &self.bindings,
                )?
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest table digest is invalid",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; TRUSTED_PLAN_MANIFEST_BYTES]> {
        self.validate()?;
        let mut bytes = [0u8; TRUSTED_PLAN_MANIFEST_BYTES];
        bytes[0..8].copy_from_slice(&TRUSTED_PLAN_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(
            &TRUSTED_PLAN_MANIFEST_VERSION.to_be_bytes(),
        );
        bytes[10..12].copy_from_slice(
            &(TRUSTED_PLAN_MANIFEST_BYTES as u16).to_be_bytes(),
        );
        bytes[12..14].copy_from_slice(&(self.bindings.len() as u16).to_be_bytes());
        bytes[16..48].copy_from_slice(&self.config_sha256);
        for (index, binding) in self.bindings.iter().enumerate() {
            let offset = 48 + index * 72;
            bytes[offset] = binding.plan.code();
            bytes[offset + 8..offset + 40].copy_from_slice(
                &binding.fixed_launch_command_identity_sha256,
            );
            bytes[offset + 40..offset + 72]
                .copy_from_slice(&binding.binding_sha256);
        }
        bytes[408..440].copy_from_slice(&self.table_sha256);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TRUSTED_PLAN_MANIFEST_BYTES
            || bytes[0..8] != TRUSTED_PLAN_MANIFEST_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]])
                != TRUSTED_PLAN_MANIFEST_VERSION
            || u16::from_be_bytes([bytes[10], bytes[11]]) as usize
                != TRUSTED_PLAN_MANIFEST_BYTES
            || u16::from_be_bytes([bytes[12], bytes[13]]) != 5
            || bytes[14..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "trusted plan manifest header is not canonical v11",
            ));
        }
        let mut bindings = [TrustedPlanBindingV11 {
            plan: Plan::Build,
            fixed_launch_command_identity_sha256: [0; 32],
            binding_sha256: [0; 32],
        }; 5];
        for index in 0..5 {
            let offset = 48 + index * 72;
            if bytes[offset + 1..offset + 8]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ControllerError::Invalid(
                    "trusted plan manifest entry padding is nonzero",
                ));
            }
            bindings[index] = TrustedPlanBindingV11 {
                plan: Plan::from_code(bytes[offset])?,
                fixed_launch_command_identity_sha256: copy_digest(
                    &bytes[offset + 8..offset + 40],
                ),
                binding_sha256: copy_digest(
                    &bytes[offset + 40..offset + 72],
                ),
            };
        }
        let manifest = Self {
            config_sha256: copy_digest(&bytes[16..48]),
            bindings,
            table_sha256: copy_digest(&bytes[408..440]),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn manifest_sha256(&self) -> Result<Digest> {
        Ok(sha256(&self.encode()?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReceiptTerminal {
    Success = 1,
    Failure = 2,
    Unknown = 3,
}

impl ReceiptTerminal {
    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Success),
            2 => Ok(Self::Failure),
            3 => Ok(Self::Unknown),
            _ => Err(ControllerError::Invalid("unknown signed receipt terminal")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AttestationScope {
    TrustedHostNoTee = 1,
}

impl AttestationScope {
    pub fn exact_label(self) -> &'static str {
        match self {
            Self::TrustedHostNoTee => {
                "trusted-host/process-and-artifact-measurements/no-tee"
            }
        }
    }

    fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::TrustedHostNoTee),
            _ => Err(ControllerError::Invalid(
                "unknown or overstated receipt attestation scope",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerReceiptBody {
    pub terminal: ReceiptTerminal,
    pub lane: Lane,
    pub attestation_scope: AttestationScope,
    pub deadline_unix_ms: u64,
    pub acceptance_fence: u64,
    pub acceptance_generation: u64,
    pub build_fence: u64,
    pub build_reservation_generation: u64,
    pub request_id: Digest,
    pub exact_signed_request_sha256: Digest,
    pub nonce_sha256: Digest,
    pub observed_source_sha256: Digest,
    pub current_lane_command_sha256: Digest,
    pub committed_build_command_sha256: Digest,
    pub acceptance_identity_sha256: Digest,
    pub build_reservation_identity_sha256: Digest,
    pub config_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub fixed_plan_manifest_sha256: Digest,
    pub evidence_closure_sha256: Digest,
    pub terminal_evidence_sha256: Digest,
    pub attestation_scope_measurement_sha256: Digest,
}

impl ControllerReceiptBody {
    pub const ENCODED_BYTES: usize = CONTROLLER_RECEIPT_BODY_BYTES;

    fn validate(&self) -> Result<()> {
        Lane::checked(self.lane.operation, self.lane.plan)?;
        let build_binding_absent = self.build_fence == 0
            && self.build_reservation_generation == 0
            && self.committed_build_command_sha256 == [0; 32]
            && self.build_reservation_identity_sha256 == [0; 32];
        let build_binding_complete = self.build_fence != 0
            && self.build_reservation_generation != 0
            && self.committed_build_command_sha256 != [0; 32]
            && self.build_reservation_identity_sha256 != [0; 32];
        if self.deadline_unix_ms == 0
            || self.acceptance_fence == 0
            || self.acceptance_generation == 0
            || [
                self.request_id,
                self.exact_signed_request_sha256,
                self.nonce_sha256,
                self.observed_source_sha256,
                self.current_lane_command_sha256,
                self.acceptance_identity_sha256,
                self.config_sha256,
                self.provider_manifest_sha256,
                self.fixed_plan_manifest_sha256,
                self.evidence_closure_sha256,
                self.terminal_evidence_sha256,
                self.attestation_scope_measurement_sha256,
            ]
            .iter()
            .any(|digest| *digest == [0; 32])
            || (!build_binding_absent && !build_binding_complete)
            || (self.terminal == ReceiptTerminal::Success
                && !build_binding_complete)
        {
            return Err(ControllerError::Rejected(
                "signed controller receipt has an empty mandatory binding",
            ));
        }
        if self.attestation_scope != AttestationScope::TrustedHostNoTee {
            return Err(ControllerError::Rejected(
                "trusted-host receipt cannot claim TEE attestation",
            ));
        }
        Ok(())
    }

    fn encode_canonical(&self) -> Result<[u8; Self::ENCODED_BYTES]> {
        self.validate()?;
        let mut bytes = [0u8; Self::ENCODED_BYTES];
        bytes[0..8].copy_from_slice(&SIGNED_RECEIPT_MAGIC);
        bytes[8..10].copy_from_slice(&SIGNED_RECEIPT_VERSION.to_be_bytes());
        bytes[10] = self.terminal as u8;
        bytes[11] = self.lane.operation.code();
        bytes[12] = self.lane.plan.code();
        bytes[13] = self.attestation_scope as u8;
        bytes[16..24].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.acceptance_fence.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.acceptance_generation.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.build_fence.to_be_bytes());
        bytes[48..56].copy_from_slice(
            &self.build_reservation_generation.to_be_bytes(),
        );
        let digests = [
            self.request_id,
            self.exact_signed_request_sha256,
            self.nonce_sha256,
            self.observed_source_sha256,
            self.current_lane_command_sha256,
            self.committed_build_command_sha256,
            self.acceptance_identity_sha256,
            self.build_reservation_identity_sha256,
            self.config_sha256,
            self.provider_manifest_sha256,
            self.fixed_plan_manifest_sha256,
            self.evidence_closure_sha256,
            self.terminal_evidence_sha256,
            self.attestation_scope_measurement_sha256,
        ];
        for (index, digest) in digests.iter().enumerate() {
            let offset = 56 + index * 32;
            bytes[offset..offset + 32].copy_from_slice(digest);
        }
        Ok(bytes)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_BYTES
            || bytes[0..8] != SIGNED_RECEIPT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]])
                != SIGNED_RECEIPT_VERSION
            || bytes[14..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "invalid signed controller receipt prefix",
            ));
        }
        let body = Self {
            terminal: ReceiptTerminal::from_code(bytes[10])?,
            lane: Lane::decode(bytes[11], bytes[12])?,
            attestation_scope: AttestationScope::from_code(bytes[13])?,
            deadline_unix_ms: read_u64_slice(bytes, 16)?,
            acceptance_fence: read_u64_slice(bytes, 24)?,
            acceptance_generation: read_u64_slice(bytes, 32)?,
            build_fence: read_u64_slice(bytes, 40)?,
            build_reservation_generation: read_u64_slice(bytes, 48)?,
            request_id: copy_digest(&bytes[56..88]),
            exact_signed_request_sha256: copy_digest(&bytes[88..120]),
            nonce_sha256: copy_digest(&bytes[120..152]),
            observed_source_sha256: copy_digest(&bytes[152..184]),
            current_lane_command_sha256: copy_digest(&bytes[184..216]),
            committed_build_command_sha256: copy_digest(&bytes[216..248]),
            acceptance_identity_sha256: copy_digest(&bytes[248..280]),
            build_reservation_identity_sha256: copy_digest(&bytes[280..312]),
            config_sha256: copy_digest(&bytes[312..344]),
            provider_manifest_sha256: copy_digest(&bytes[344..376]),
            fixed_plan_manifest_sha256: copy_digest(&bytes[376..408]),
            evidence_closure_sha256: copy_digest(&bytes[408..440]),
            terminal_evidence_sha256: copy_digest(&bytes[440..472]),
            attestation_scope_measurement_sha256:
                copy_digest(&bytes[472..504]),
        };
        body.validate()?;
        Ok(body)
    }
}

#[derive(Clone, Debug)]
pub struct SignedControllerReceipt {
    pub body: ControllerReceiptBody,
    pub signer_key_sha256: Digest,
    pub signature: [u8; 64],
}

impl SignedControllerReceipt {
    pub fn sign(body: ControllerReceiptBody, signing_key: &SigningKey) -> Result<Self> {
        let canonical = body.encode_canonical()?;
        let verifying_key = signing_key.verifying_key();
        let signer_key_sha256 = sha256(verifying_key.as_bytes());
        if signer_key_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "receipt signer key measurement is empty",
            ));
        }
        let mut signed = Vec::with_capacity(canonical.len() + 32);
        signed.extend_from_slice(&canonical);
        signed.extend_from_slice(&signer_key_sha256);
        let signature: Signature = signing_key.sign(&signed);
        Ok(Self {
            body,
            signer_key_sha256,
            signature: signature.to_bytes(),
        })
    }

    pub fn encode(&self) -> Result<[u8; SIGNED_CONTROLLER_RECEIPT_BYTES]> {
        let canonical = self.body.encode_canonical()?;
        if self.signer_key_sha256 == [0; 32] {
            return Err(ControllerError::Rejected(
                "receipt signer key measurement is empty",
            ));
        }
        let mut bytes = [0u8; SIGNED_CONTROLLER_RECEIPT_BYTES];
        bytes[..ControllerReceiptBody::ENCODED_BYTES]
            .copy_from_slice(&canonical);
        bytes[CONTROLLER_RECEIPT_SIGNER_KEY_OFFSET
            ..CONTROLLER_RECEIPT_SIGNATURE_OFFSET]
            .copy_from_slice(&self.signer_key_sha256);
        bytes[CONTROLLER_RECEIPT_SIGNATURE_OFFSET
            ..SIGNED_CONTROLLER_RECEIPT_BYTES]
            .copy_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNED_CONTROLLER_RECEIPT_BYTES {
            return Err(ControllerError::Invalid(
                "signed controller receipt length is not fixed v11 length",
            ));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(
            &bytes[CONTROLLER_RECEIPT_SIGNATURE_OFFSET
                ..SIGNED_CONTROLLER_RECEIPT_BYTES],
        );
        Ok(Self {
            body: ControllerReceiptBody::decode_canonical(
                &bytes[..CONTROLLER_RECEIPT_BODY_BYTES],
            )?,
            signer_key_sha256: copy_digest(
                &bytes[CONTROLLER_RECEIPT_SIGNER_KEY_OFFSET
                    ..CONTROLLER_RECEIPT_SIGNATURE_OFFSET],
            ),
            signature,
        })
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<VerifiedSignedControllerReceipt> {
        let expected_key_sha256 = sha256(verifying_key.as_bytes());
        if !constant_time_eq(&expected_key_sha256, &self.signer_key_sha256) {
            return Err(ControllerError::Rejected(
                "signed receipt key does not match measured trusted-host key",
            ));
        }
        let canonical = self.body.encode_canonical()?;
        let mut signed = Vec::with_capacity(canonical.len() + 32);
        signed.extend_from_slice(&canonical);
        signed.extend_from_slice(&self.signer_key_sha256);
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&signed, &signature)
            .map_err(|_| ControllerError::Rejected(
                "signed controller receipt signature is invalid",
            ))?;
        Ok(VerifiedSignedControllerReceipt {
            body: self.body.clone(),
            wire_sha256: sha256(&self.encode()?),
            _seal: capability_seal::Seal,
        })
    }

    pub fn verify_for_request(
        &self,
        verifying_key: &VerifyingKey,
        lane: Lane,
        expected_request_id: Digest,
        expected_exact_signed_request_sha256: Digest,
        nonce_sha256: Digest,
        deadline_unix_ms: u64,
        expected_fixed_plan_manifest_sha256: Digest,
    ) -> Result<VerifiedSignedControllerReceipt> {
        let verified = self.verify(verifying_key)?;
        if verified.body.lane != lane
            || verified.body.request_id != expected_request_id
            || verified.body.exact_signed_request_sha256
                != expected_exact_signed_request_sha256
            || verified.body.nonce_sha256 != nonce_sha256
            || verified.body.deadline_unix_ms != deadline_unix_ms
            || verified.body.fixed_plan_manifest_sha256
                != expected_fixed_plan_manifest_sha256
        {
            return Err(ControllerError::Rejected(
                "signed controller receipt does not bind the client request",
            ));
        }
        Ok(verified)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSignedControllerReceipt {
    body: ControllerReceiptBody,
    wire_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedSignedControllerReceipt {
    pub fn body(&self) -> &ControllerReceiptBody {
        &self.body
    }

    pub fn wire_sha256(&self) -> Digest {
        self.wire_sha256
    }
}

fn read_u64_slice(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ControllerError::Invalid("truncated v11 integer"))?;
    let mut encoded = [0u8; 8];
    encoded.copy_from_slice(value);
    Ok(u64::from_be_bytes(encoded))
}

#[derive(Clone, Debug)]
pub struct PreallocationFrame {
    pub kind: FrameKind,
    pub lane: Option<Lane>,
    pub declared_canonical_bytes: u64,
    pub max_canonical_bytes: u64,
    pub declared_envelope_bytes: u64,
    pub max_envelope_bytes: u64,
    pub chunk_max_bytes: u32,
    pub max_chunk_count: u32,
    pub aggregate_max_bytes: u64,
    pub deadline_unix_ms: u64,
    pub envelope_sha256: Digest,
    pub nonce_sha256: Digest,
    pub peer_binding_sha256: Digest,
    pub request_id: Digest,
    pub frame_sha256: Digest,
}

impl PreallocationFrame {
    pub fn new(
        kind: FrameKind,
        lane: Option<Lane>,
        canonical_bytes: u64,
        envelope_bytes: &[u8],
        raw_nonce: &Digest,
        peer_binding_sha256: Digest,
        request_id: Digest,
        deadline_unix_ms: u64,
    ) -> Result<Self> {
        validate_kind_lane(kind, lane)?;
        let (max_bytes, max_chunks) = kind.limits();
        let declared_envelope_bytes: u64 = envelope_bytes
            .len()
            .try_into()
            .map_err(|_| ControllerError::Invalid("envelope length exceeds u64"))?;
        let mut frame = Self {
            kind,
            lane,
            declared_canonical_bytes: canonical_bytes,
            max_canonical_bytes: max_bytes,
            declared_envelope_bytes,
            max_envelope_bytes: max_bytes,
            chunk_max_bytes: CHUNK_MAX_BYTES,
            max_chunk_count: max_chunks,
            aggregate_max_bytes: AGGREGATE_MAX_BYTES,
            deadline_unix_ms,
            envelope_sha256: sha256(envelope_bytes),
            nonce_sha256: sha256(raw_nonce),
            peer_binding_sha256,
            request_id,
            frame_sha256: [0; 32],
        };
        frame.validate_shape()?;
        frame.frame_sha256 = sha256(&frame.encode_with_digest([0; 32]));
        Ok(frame)
    }

    pub fn decode(bytes: &[u8; FIXED_FRAME_BYTES]) -> Result<Self> {
        if bytes[0..8] != FRAME_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != FRAME_VERSION
            || bytes[13] != 0
            || u16::from_be_bytes([bytes[14], bytes[15]]) as usize != FIXED_FRAME_BYTES
            || bytes[FRAME_PADDING_OFFSET..].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid("invalid fixed v11 frame prefix or padding"));
        }
        let kind = FrameKind::from_code(bytes[10])?;
        let lane = if bytes[11] == 0 && bytes[12] == 0 {
            None
        } else {
            Some(Lane::decode(bytes[11], bytes[12])?)
        };
        validate_kind_lane(kind, lane)?;
        let frame = Self {
            kind,
            lane,
            declared_canonical_bytes: read_u64(bytes, 16),
            max_canonical_bytes: read_u64(bytes, 24),
            declared_envelope_bytes: read_u64(bytes, 32),
            max_envelope_bytes: read_u64(bytes, 40),
            chunk_max_bytes: read_u32(bytes, 48),
            max_chunk_count: read_u32(bytes, 52),
            aggregate_max_bytes: read_u64(bytes, 56),
            deadline_unix_ms: read_u64(bytes, 64),
            envelope_sha256: copy_digest(&bytes[72..104]),
            nonce_sha256: copy_digest(&bytes[104..136]),
            peer_binding_sha256: copy_digest(&bytes[136..168]),
            request_id: copy_digest(&bytes[168..200]),
            frame_sha256: copy_digest(&bytes[200..232]),
        };
        frame.validate_shape()?;
        let expected = sha256(&frame.encode_with_digest([0; 32]));
        if !constant_time_eq(&expected, &frame.frame_sha256) {
            return Err(ControllerError::Invalid("fixed frame digest mismatch"));
        }
        Ok(frame)
    }

    pub fn encode(&self) -> [u8; FIXED_FRAME_BYTES] {
        self.encode_with_digest(self.frame_sha256)
    }

    fn encode_with_digest(&self, digest: Digest) -> [u8; FIXED_FRAME_BYTES] {
        let mut bytes = [0u8; FIXED_FRAME_BYTES];
        bytes[0..8].copy_from_slice(&FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&FRAME_VERSION.to_be_bytes());
        bytes[10] = self.kind as u8;
        if let Some(lane) = self.lane {
            let (operation, plan) = lane.encode();
            bytes[11] = operation;
            bytes[12] = plan;
        }
        bytes[14..16].copy_from_slice(&(FIXED_FRAME_BYTES as u16).to_be_bytes());
        bytes[16..24].copy_from_slice(&self.declared_canonical_bytes.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.max_canonical_bytes.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.declared_envelope_bytes.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.max_envelope_bytes.to_be_bytes());
        bytes[48..52].copy_from_slice(&self.chunk_max_bytes.to_be_bytes());
        bytes[52..56].copy_from_slice(&self.max_chunk_count.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.aggregate_max_bytes.to_be_bytes());
        bytes[64..72].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[72..104].copy_from_slice(&self.envelope_sha256);
        bytes[104..136].copy_from_slice(&self.nonce_sha256);
        bytes[136..168].copy_from_slice(&self.peer_binding_sha256);
        bytes[168..200].copy_from_slice(&self.request_id);
        bytes[FRAME_DIGEST_OFFSET..FRAME_DIGEST_OFFSET + 32].copy_from_slice(&digest);
        bytes
    }

    fn validate_shape(&self) -> Result<()> {
        let (required_max, required_chunks) = self.kind.limits();
        if self.max_canonical_bytes != required_max
            || self.max_envelope_bytes != required_max
            || self.chunk_max_bytes != CHUNK_MAX_BYTES
            || self.max_chunk_count != required_chunks
            || self.aggregate_max_bytes != AGGREGATE_MAX_BYTES
            || self.declared_canonical_bytes > self.max_canonical_bytes
            || self.declared_envelope_bytes > self.max_envelope_bytes
            || self.declared_envelope_bytes > self.declared_canonical_bytes
            || chunks_for(self.declared_envelope_bytes) > self.max_chunk_count
            || self.envelope_sha256 == [0; 32]
            || self.nonce_sha256 == [0; 32]
            || self.peer_binding_sha256 == [0; 32]
            || self.request_id == [0; 32]
        {
            return Err(ControllerError::Invalid("fixed frame violates v11 limits"));
        }
        Ok(())
    }

    pub fn verify_before_body(
        &self,
        expected_peer_binding: &Digest,
        now_ms: u64,
    ) -> Result<()> {
        if !constant_time_eq(&self.peer_binding_sha256, expected_peer_binding) {
            return Err(ControllerError::Rejected("frame peer binding mismatch"));
        }
        if self.deadline_unix_ms < now_ms
            || self.deadline_unix_ms.saturating_sub(now_ms) > MAX_DEADLINE_FUTURE_MS
        {
            return Err(ControllerError::Rejected("frame deadline is invalid"));
        }
        Ok(())
    }

    pub fn verify_envelope_digest(&self, actual: &Digest) -> Result<()> {
        if !constant_time_eq(&self.envelope_sha256, actual) {
            return Err(ControllerError::Rejected("envelope digest mismatch"));
        }
        Ok(())
    }

    pub fn verify_raw_nonce(&self, raw_nonce: &Digest) -> Result<()> {
        if !constant_time_eq(&self.nonce_sha256, &sha256(raw_nonce)) {
            return Err(ControllerError::Rejected("raw nonce does not match frame digest"));
        }
        Ok(())
    }
}

fn validate_kind_lane(kind: FrameKind, lane: Option<Lane>) -> Result<()> {
    match (kind, lane) {
        (FrameKind::Hello, None) => Ok(()),
        (FrameKind::Request | FrameKind::Receipt | FrameKind::Error, Some(lane)) => {
            Lane::checked(lane.operation, lane.plan).map(|_| ())
        }
        _ => Err(ControllerError::Invalid("frame kind/lane combination is invalid")),
    }
}

fn chunks_for(bytes: u64) -> u32 {
    if bytes == 0 {
        0
    } else {
        ((bytes - 1) / CHUNK_MAX_BYTES as u64 + 1) as u32
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn copy_digest(bytes: &[u8]) -> Digest {
    let mut output = [0u8; 32];
    output.copy_from_slice(bytes);
    output
}

pub fn peer_binding(pid: u32, uid: u32, gid: u32, pidfd_identity: &str) -> Digest {
    let mut bytes = Vec::with_capacity(64 + pidfd_identity.len());
    bytes.extend_from_slice(b"serverware-controller-v11/peer\0");
    bytes.extend_from_slice(&pid.to_be_bytes());
    bytes.extend_from_slice(&uid.to_be_bytes());
    bytes.extend_from_slice(&gid.to_be_bytes());
    bytes.extend_from_slice(&(pidfd_identity.len() as u64).to_be_bytes());
    bytes.extend_from_slice(pidfd_identity.as_bytes());
    sha256(&bytes)
}

#[derive(Clone, Debug)]
pub struct ClientSubmission {
    pub(crate) lane: Lane,
    pub(crate) raw_nonce: Digest,
    pub(crate) request_id: Digest,
    pub(crate) deadline_unix_ms: u64,
    pub(crate) config_sha256: Digest,
    pub(crate) signer_public_key: Digest,
    pub(crate) peer_binding_sha256: Digest,
    pub(crate) canonical_request_envelope_sha256: Digest,
    pub(crate) plan_configuration_sha256: Digest,
    pub(crate) source_tree_sha256: Digest,
    pub(crate) signature: [u8; 64],
}

impl ClientSubmission {
    pub const SIGNED_PREFIX_BYTES: usize = 280;
    pub const ENCODED_BYTES: usize = Self::SIGNED_PREFIX_BYTES + 64;

    fn request_id(
        lane: Lane,
        raw_nonce: Digest,
        deadline_unix_ms: u64,
        config_sha256: Digest,
        signer_public_key: Digest,
        peer_binding_sha256: Digest,
    ) -> Digest {
        let mut identity = Vec::with_capacity(160);
        identity.extend_from_slice(
            b"serverware-controller-v11/canonical-client-request-id\0",
        );
        identity.push(lane.operation.code());
        identity.push(lane.plan.code());
        identity.extend_from_slice(&raw_nonce);
        identity.extend_from_slice(&deadline_unix_ms.to_be_bytes());
        identity.extend_from_slice(&config_sha256);
        identity.extend_from_slice(&signer_public_key);
        identity.extend_from_slice(&peer_binding_sha256);
        sha256(&identity)
    }

    pub fn sign(
        lane: Lane,
        raw_nonce: Digest,
        deadline_unix_ms: u64,
        config_sha256: Digest,
        peer_binding_sha256: Digest,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let signer_public_key = *signing_key.verifying_key().as_bytes();
        let request_id = Self::request_id(
            lane,
            raw_nonce,
            deadline_unix_ms,
            config_sha256,
            signer_public_key,
            peer_binding_sha256,
        );
        Self::sign_internal(
            lane,
            raw_nonce,
            request_id,
            deadline_unix_ms,
            config_sha256,
            peer_binding_sha256,
            request_id,
            config_sha256,
            request_id,
            signing_key,
        )
    }

    pub fn sign_internal(
        lane: Lane,
        raw_nonce: Digest,
        request_id: Digest,
        deadline_unix_ms: u64,
        config_sha256: Digest,
        peer_binding_sha256: Digest,
        canonical_request_envelope_sha256: Digest,
        plan_configuration_sha256: Digest,
        source_tree_sha256: Digest,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        if deadline_unix_ms == 0
            || config_sha256 == [0; 32]
            || peer_binding_sha256 == [0; 32]
            || request_id == [0; 32]
            || canonical_request_envelope_sha256 == [0; 32]
            || plan_configuration_sha256 == [0; 32]
            || source_tree_sha256 == [0; 32]
        {
            return Err(ControllerError::Invalid(
                "signed client request lacks deadline or config binding",
            ));
        }
        let signer_public_key = *signing_key.verifying_key().as_bytes();
        let mut submission = Self {
            lane,
            raw_nonce,
            request_id,
            deadline_unix_ms,
            config_sha256,
            signer_public_key,
            peer_binding_sha256,
            canonical_request_envelope_sha256,
            plan_configuration_sha256,
            source_tree_sha256,
            signature: [0; 64],
        };
        submission.signature = signing_key
            .sign(&submission.encode_signed_prefix())
            .to_bytes();
        Ok(submission)
    }

    fn encode_signed_prefix(&self) -> [u8; Self::SIGNED_PREFIX_BYTES] {
        let mut bytes = [0u8; Self::SIGNED_PREFIX_BYTES];
        bytes[0..8].copy_from_slice(&CLIENT_SUBMISSION_MAGIC);
        bytes[8..10].copy_from_slice(&CLIENT_SUBMISSION_VERSION.to_be_bytes());
        bytes[10] = self.lane.operation.code();
        bytes[11] = self.lane.plan.code();
        bytes[16..24].copy_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.raw_nonce);
        bytes[56..88].copy_from_slice(&self.request_id);
        bytes[88..120].copy_from_slice(&self.config_sha256);
        bytes[120..152].copy_from_slice(&self.signer_public_key);
        bytes[152..184].copy_from_slice(&self.peer_binding_sha256);
        bytes[184..216]
            .copy_from_slice(&self.canonical_request_envelope_sha256);
        bytes[216..248].copy_from_slice(&self.plan_configuration_sha256);
        bytes[248..280].copy_from_slice(&self.source_tree_sha256);
        bytes
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0u8; Self::ENCODED_BYTES];
        bytes[..Self::SIGNED_PREFIX_BYTES]
            .copy_from_slice(&self.encode_signed_prefix());
        bytes[Self::SIGNED_PREFIX_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn decode_and_verify(
        bytes: &[u8],
        authorized_key: &VerifyingKey,
        expected_deadline_unix_ms: u64,
        expected_config_sha256: Digest,
        expected_peer_binding_sha256: Digest,
    ) -> Result<Self> {
        if bytes.len() != Self::ENCODED_BYTES
            || bytes[0..8] != CLIENT_SUBMISSION_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]])
                != CLIENT_SUBMISSION_VERSION
            || bytes[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid("invalid client submission envelope"));
        }
        let lane = Lane::decode(bytes[10], bytes[11])?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[Self::SIGNED_PREFIX_BYTES..]);
        let submission = Self {
            lane,
            deadline_unix_ms: read_u64(bytes, 16),
            raw_nonce: copy_digest(&bytes[24..56]),
            request_id: copy_digest(&bytes[56..88]),
            config_sha256: copy_digest(&bytes[88..120]),
            signer_public_key: copy_digest(&bytes[120..152]),
            peer_binding_sha256: copy_digest(&bytes[152..184]),
            canonical_request_envelope_sha256: copy_digest(&bytes[184..216]),
            plan_configuration_sha256: copy_digest(&bytes[216..248]),
            source_tree_sha256: copy_digest(&bytes[248..280]),
            signature,
        };
        if submission.request_id == [0; 32]
            || submission.canonical_request_envelope_sha256 == [0; 32]
            || submission.plan_configuration_sha256 == [0; 32]
            || submission.source_tree_sha256 == [0; 32]
            || submission.deadline_unix_ms != expected_deadline_unix_ms
            || submission.config_sha256 != expected_config_sha256
            || submission.signer_public_key != *authorized_key.as_bytes()
            || submission.peer_binding_sha256
                != expected_peer_binding_sha256
        {
            return Err(ControllerError::Rejected("client request ID is not canonical"));
        }
        authorized_key
            .verify_strict(
                &submission.encode_signed_prefix(),
                &Signature::from_bytes(&submission.signature),
            )
            .map_err(|_| {
                ControllerError::Rejected(
                    "canonical client request signature is invalid",
                )
            })?;
        Ok(submission)
    }

    pub fn exact_signed_request_sha256(&self) -> Digest {
        self.canonical_request_envelope_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchFileIdentityV11 {
    pub device: u64,
    pub inode: u64,
    pub generation: u64,
    pub mode: u32,
    pub owner_uid: u32,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchClosureMemberV11 {
    pub path: PathBuf,
    pub executable: bool,
    pub identity: LaunchFileIdentityV11,
    pub content_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchContractV11 {
    pub lane: Lane,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub deadline_unix_ms: u64,
    pub command_identity_sha256: Digest,
    pub executable_closure_sha256: Digest,
    pub sandbox_profile_sha256: Digest,
    pub primary_executable: PathBuf,
    pub cwd: PathBuf,
    pub source_root: PathBuf,
    pub controller_plan_api_socket: PathBuf,
    pub artifact_roots: Vec<PathBuf>,
    pub argv: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
    pub closure: Vec<LaunchClosureMemberV11>,
}

impl LaunchContractV11 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&LAUNCH_CONTRACT_MAGIC);
        bytes.extend_from_slice(&LAUNCH_CONTRACT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let (operation, plan) = self.lane.encode();
        bytes.push(operation);
        bytes.push(plan);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.peer_uid.to_be_bytes());
        bytes.extend_from_slice(&self.peer_gid.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_unix_ms.to_be_bytes());
        bytes.extend_from_slice(&self.command_identity_sha256);
        bytes.extend_from_slice(&self.executable_closure_sha256);
        bytes.extend_from_slice(&self.sandbox_profile_sha256);
        push_launch_bytes(&mut bytes, self.primary_executable.as_os_str().as_bytes())?;
        push_launch_bytes(&mut bytes, self.cwd.as_os_str().as_bytes())?;
        push_launch_bytes(&mut bytes, self.source_root.as_os_str().as_bytes())?;
        push_launch_bytes(
            &mut bytes,
            self.controller_plan_api_socket.as_os_str().as_bytes(),
        )?;
        push_launch_count(&mut bytes, self.artifact_roots.len())?;
        for path in &self.artifact_roots {
            push_launch_bytes(&mut bytes, path.as_os_str().as_bytes())?;
        }
        push_launch_count(&mut bytes, self.argv.len())?;
        for value in &self.argv {
            push_launch_bytes(&mut bytes, value)?;
        }
        push_launch_count(&mut bytes, self.env.len())?;
        for value in &self.env {
            push_launch_bytes(&mut bytes, value)?;
        }
        push_launch_count(&mut bytes, self.closure.len())?;
        for member in &self.closure {
            bytes.push(u8::from(member.executable));
            bytes.extend_from_slice(&[0; 7]);
            bytes.extend_from_slice(&member.identity.device.to_be_bytes());
            bytes.extend_from_slice(&member.identity.inode.to_be_bytes());
            bytes.extend_from_slice(&member.identity.generation.to_be_bytes());
            bytes.extend_from_slice(&member.identity.mode.to_be_bytes());
            bytes.extend_from_slice(&member.identity.owner_uid.to_be_bytes());
            bytes.extend_from_slice(&member.identity.size.to_be_bytes());
            bytes.extend_from_slice(&member.content_sha256);
            push_launch_bytes(&mut bytes, member.path.as_os_str().as_bytes())?;
        }
        if bytes.len() > LAUNCH_CONTRACT_MAX_BYTES {
            return Err(ControllerError::Rejected(
                "launch contract exceeds its fixed bound",
            ));
        }
        let length = u32::try_from(bytes.len())
            .map_err(|_| ControllerError::Invalid("launch contract length exceeds u32"))?;
        bytes[10..14].copy_from_slice(&length.to_be_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 132
            || bytes.len() > LAUNCH_CONTRACT_MAX_BYTES
            || bytes[0..8] != LAUNCH_CONTRACT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != LAUNCH_CONTRACT_VERSION
            || u32::from_be_bytes(
                bytes[10..14]
                    .try_into()
                    .map_err(|_| ControllerError::Invalid("truncated launch length"))?,
            ) as usize
                != bytes.len()
            || bytes[16..20].iter().any(|byte| *byte != 0)
        {
            return Err(ControllerError::Invalid(
                "launch contract header is noncanonical",
            ));
        }
        let lane = Lane::decode(bytes[14], bytes[15])?;
        let peer_uid = read_launch_u32(bytes, 20)?;
        let peer_gid = read_launch_u32(bytes, 24)?;
        let deadline_unix_ms = read_u64_slice(bytes, 28)?;
        let command_identity_sha256 = copy_digest(&bytes[36..68]);
        let executable_closure_sha256 = copy_digest(&bytes[68..100]);
        let sandbox_profile_sha256 = copy_digest(&bytes[100..132]);
        let mut cursor = 132;
        let primary_executable =
            PathBuf::from(std::ffi::OsString::from_vec(read_launch_bytes(bytes, &mut cursor)?));
        let cwd =
            PathBuf::from(std::ffi::OsString::from_vec(read_launch_bytes(bytes, &mut cursor)?));
        let source_root =
            PathBuf::from(std::ffi::OsString::from_vec(read_launch_bytes(bytes, &mut cursor)?));
        let controller_plan_api_socket =
            PathBuf::from(std::ffi::OsString::from_vec(read_launch_bytes(
                bytes,
                &mut cursor,
            )?));
        let artifact_count = read_launch_count(bytes, &mut cursor)?;
        let mut artifact_roots = Vec::with_capacity(artifact_count);
        for _ in 0..artifact_count {
            artifact_roots.push(PathBuf::from(std::ffi::OsString::from_vec(
                read_launch_bytes(bytes, &mut cursor)?,
            )));
        }
        let argv_count = read_launch_count(bytes, &mut cursor)?;
        let mut argv = Vec::with_capacity(argv_count);
        for _ in 0..argv_count {
            argv.push(read_launch_bytes(bytes, &mut cursor)?);
        }
        let env_count = read_launch_count(bytes, &mut cursor)?;
        let mut env = Vec::with_capacity(env_count);
        for _ in 0..env_count {
            env.push(read_launch_bytes(bytes, &mut cursor)?);
        }
        let closure_count = read_launch_count(bytes, &mut cursor)?;
        let mut closure = Vec::with_capacity(closure_count);
        for _ in 0..closure_count {
            let executable_flag = *bytes
                .get(cursor)
                .ok_or(ControllerError::Invalid("truncated closure flag"))?;
            if executable_flag > 1 {
                return Err(ControllerError::Invalid(
                    "closure member flag is noncanonical",
                ));
            }
            let executable = executable_flag == 1;
            if bytes
                .get(cursor + 1..cursor + 8)
                .ok_or(ControllerError::Invalid("truncated closure padding"))?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(ControllerError::Invalid(
                    "closure member padding is noncanonical",
                ));
            }
            cursor += 8;
            let identity = LaunchFileIdentityV11 {
                device: read_launch_u64_cursor(bytes, &mut cursor)?,
                inode: read_launch_u64_cursor(bytes, &mut cursor)?,
                generation: read_launch_u64_cursor(bytes, &mut cursor)?,
                mode: read_launch_u32_cursor(bytes, &mut cursor)?,
                owner_uid: read_launch_u32_cursor(bytes, &mut cursor)?,
                size: read_launch_u64_cursor(bytes, &mut cursor)?,
            };
            let digest_end = cursor
                .checked_add(32)
                .ok_or(ControllerError::Invalid("closure digest overflow"))?;
            let content_sha256 = copy_digest(
                bytes
                    .get(cursor..digest_end)
                    .ok_or(ControllerError::Invalid("truncated closure digest"))?,
            );
            cursor = digest_end;
            let path = PathBuf::from(std::ffi::OsString::from_vec(
                read_launch_bytes(bytes, &mut cursor)?,
            ));
            closure.push(LaunchClosureMemberV11 {
                path,
                executable,
                identity,
                content_sha256,
            });
        }
        if cursor != bytes.len() {
            return Err(ControllerError::Invalid(
                "launch contract has trailing bytes",
            ));
        }
        let contract = Self {
            lane,
            peer_uid,
            peer_gid,
            deadline_unix_ms,
            command_identity_sha256,
            executable_closure_sha256,
            sandbox_profile_sha256,
            primary_executable,
            cwd,
            source_root,
            controller_plan_api_socket,
            artifact_roots,
            argv,
            env,
            closure,
        };
        contract.validate()?;
        Ok(contract)
    }

    fn validate(&self) -> Result<()> {
        if self.deadline_unix_ms == 0
            || self.command_identity_sha256 == [0; 32]
            || self.executable_closure_sha256 == [0; 32]
            || self.sandbox_profile_sha256 == [0; 32]
            || !self.primary_executable.is_absolute()
            || !self.cwd.is_absolute()
            || !self.source_root.is_absolute()
            || self.controller_plan_api_socket
                != PathBuf::from(CONTROLLER_PLAN_API_SOCKET_PATH)
            || self.argv.is_empty()
            || self.closure.is_empty()
            || self.argv.iter().chain(self.env.iter()).any(|value| {
                value.is_empty() || value.contains(&0)
            })
            || self
                .artifact_roots
                .iter()
                .chain(self.closure.iter().map(|member| &member.path))
                .any(|path| !path.is_absolute())
            || !self.closure.iter().any(|member| {
                member.executable && member.path == self.primary_executable
            })
        {
            return Err(ControllerError::Rejected(
                "launch contract violates fixed v11 invariants",
            ));
        }
        Ok(())
    }
}

fn push_launch_count(bytes: &mut Vec<u8>, count: usize) -> Result<()> {
    let count = u32::try_from(count)
        .map_err(|_| ControllerError::Invalid("launch count exceeds u32"))?;
    bytes.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn push_launch_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    push_launch_count(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

fn read_launch_count(bytes: &[u8], cursor: &mut usize) -> Result<usize> {
    Ok(read_launch_u32_cursor(bytes, cursor)? as usize)
}

fn read_launch_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let length = read_launch_count(bytes, cursor)?;
    let end = cursor
        .checked_add(length)
        .ok_or(ControllerError::Invalid("launch field length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ControllerError::Invalid("truncated launch field"))?
        .to_vec();
    *cursor = end;
    Ok(value)
}

fn read_launch_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ControllerError::Invalid("truncated launch u32"))?;
    Ok(u32::from_be_bytes(
        value
            .try_into()
            .map_err(|_| ControllerError::Invalid("invalid launch u32"))?,
    ))
}

fn read_launch_u32_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let value = read_launch_u32(bytes, *cursor)?;
    *cursor += 4;
    Ok(value)
}

fn read_launch_u64_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let value = read_u64_slice(bytes, *cursor)?;
    *cursor += 8;
    Ok(value)
}

#[derive(Clone, Debug)]
pub struct HelloEnvelope {
    pub raw_nonce: Digest,
    pub request_id: Digest,
}

impl HelloEnvelope {
    pub const ENCODED_BYTES: usize = 72;

    pub fn new(raw_nonce: Digest) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(b"serverware-controller-v11/hello\0");
        bytes.extend_from_slice(&raw_nonce);
        Self {
            raw_nonce,
            request_id: sha256(&bytes),
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0u8; Self::ENCODED_BYTES];
        bytes[0..8].copy_from_slice(&HELLO_MAGIC);
        bytes[8..40].copy_from_slice(&self.raw_nonce);
        bytes[40..72].copy_from_slice(&self.request_id);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_BYTES || bytes[0..8] != HELLO_MAGIC {
            return Err(ControllerError::Invalid("invalid hello envelope"));
        }
        let value = Self {
            raw_nonce: copy_digest(&bytes[8..40]),
            request_id: copy_digest(&bytes[40..72]),
        };
        if value.request_id != Self::new(value.raw_nonce).request_id {
            return Err(ControllerError::Rejected("hello request ID is not canonical"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct HelloResponse {
    pub raw_nonce: Digest,
    pub request_id: Digest,
    pub message: String,
}

impl HelloResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let message_len: u16 = self
            .message
            .len()
            .try_into()
            .map_err(|_| ControllerError::Invalid("hello response is too large"))?;
        let mut bytes = Vec::with_capacity(74 + self.message.len());
        bytes.extend_from_slice(&HELLO_RESPONSE_MAGIC);
        bytes.extend_from_slice(&self.raw_nonce);
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&message_len.to_be_bytes());
        bytes.extend_from_slice(self.message.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 74 || bytes[0..8] != HELLO_RESPONSE_MAGIC {
            return Err(ControllerError::Invalid("invalid hello response"));
        }
        let message_len = u16::from_be_bytes([bytes[72], bytes[73]]) as usize;
        if bytes.len() != 74 + message_len {
            return Err(ControllerError::Invalid("hello response length mismatch"));
        }
        let message = std::str::from_utf8(&bytes[74..])
            .map_err(|_| ControllerError::Invalid("hello response is not UTF-8"))?
            .to_owned();
        Ok(Self {
            raw_nonce: copy_digest(&bytes[8..40]),
            request_id: copy_digest(&bytes[40..72]),
            message,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ImmutableControllerConfig {
    pub config_sha256: Digest,
    pub socket_path: PathBuf,
    pub socket_uid: u32,
    pub socket_gid: u32,
    pub socket_mode: u32,
    pub allowed_uids: BTreeSet<u32>,
    pub allowed_gids: BTreeSet<u32>,
    pub max_connections: usize,
    pub first_frame_timeout_ms: u64,
}

impl ImmutableControllerConfig {
    pub fn validate_disabled(&self) -> Result<()> {
        if !self.socket_path.is_absolute()
            || self.config_sha256 == [0; 32]
            || self.allowed_uids.is_empty()
            || self.allowed_gids.is_empty()
            || self.socket_mode & !0o777 != 0
            || self.socket_mode & 0o007 != 0
            || self.max_connections == 0
            || self.max_connections > 256
            || !(100..=10_000).contains(&self.first_frame_timeout_ms)
        {
            return Err(ControllerError::Invalid("disabled controller config is unsafe"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct EvidenceReference {
    pub namespace: String,
    pub object_id: String,
    pub length: u64,
    pub object_sha256: Digest,
    pub chunk_root_sha256: Digest,
    pub retention_commitment_sha256: Digest,
    pub availability_commitment_sha256: Digest,
    pub reference_sha256: Digest,
}

impl EvidenceReference {
    pub fn canonical_digest(&self) -> Digest {
        let mut bytes =
            Vec::with_capacity(192 + self.namespace.len() + self.object_id.len());
        bytes.extend_from_slice(b"serverware-controller-v11/evidence-reference\0");
        bytes.extend_from_slice(&(self.namespace.len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.namespace.as_bytes());
        bytes.extend_from_slice(&(self.object_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.object_id.as_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.object_sha256);
        bytes.extend_from_slice(&self.chunk_root_sha256);
        bytes.extend_from_slice(&self.retention_commitment_sha256);
        bytes.extend_from_slice(&self.availability_commitment_sha256);
        sha256(&bytes)
    }

    pub fn validate(&self) -> Result<()> {
        if self.namespace.is_empty()
            || self.object_id.is_empty()
            || self.object_sha256 == [0; 32]
            || self.chunk_root_sha256 == [0; 32]
            || self.retention_commitment_sha256 == [0; 32]
            || self.availability_commitment_sha256 == [0; 32]
            || self.reference_sha256 == [0; 32]
            || self.canonical_digest() != self.reference_sha256
        {
            return Err(ControllerError::Rejected(
                "evidence reference canonical binding is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RawSignedRequest {
    pub exact_canonical_bytes: EvidenceReference,
    pub signed_envelope: EvidenceReference,
    pub signature_evidence: EvidenceReference,
    pub request_id: Digest,
    pub request_sha256: Digest,
    pub nonce_sha256: Digest,
    pub peer_binding_sha256: Digest,
    pub deadline_unix_ms: u64,
    pub lane: Lane,
    pub config_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct RawProviderSet {
    pub manifest: EvidenceReference,
    pub executable_bytes: Vec<EvidenceReference>,
    pub measurements: Vec<EvidenceReference>,
    pub process_identities: Vec<EvidenceReference>,
    pub trust_and_revocation: Vec<EvidenceReference>,
    pub freshness: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct RawSourceSnapshot {
    pub source_root: PathBuf,
    pub root_identity: EvidenceReference,
    pub recursive_manifest: EvidenceReference,
    pub observed_source_sha256: Digest,
    pub immutable_snapshot: EvidenceReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RetainedExecutableFdMode {
    OPath = 1,
    ReadOnly = 2,
}

#[derive(Clone, Debug)]
pub struct FixedPlanLaunchEntry {
    pub plan: Plan,
    pub canonical_executable: PathBuf,
    pub canonical_cwd: PathBuf,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub executable_generation: u64,
    pub executable_content_sha256: Digest,
    pub cwd_device: u64,
    pub cwd_inode: u64,
    pub cwd_generation: u64,
    pub immutable_argv: Vec<Vec<u8>>,
    pub immutable_env: Vec<(Vec<u8>, Vec<u8>)>,
    pub openat2_resolution: EvidenceReference,
    pub file_identity: EvidenceReference,
    pub cwd_identity: EvidenceReference,
    pub retained_fd_mode: RetainedExecutableFdMode,
    pub retained_fd_evidence: EvidenceReference,
    pub retained_executable_fd: Arc<OwnedFd>,
    pub execveat_token: EvidenceReference,
}

impl FixedPlanLaunchEntry {
    pub fn canonical_identity_sha256(&self) -> Result<Digest> {
        validate_absolute_normalized_path(&self.canonical_executable)?;
        validate_absolute_normalized_path(&self.canonical_cwd)?;
        self.openat2_resolution.validate()?;
        self.file_identity.validate()?;
        self.cwd_identity.validate()?;
        self.retained_fd_evidence.validate()?;
        self.execveat_token.validate()?;
        if self.executable_device == 0
            || self.executable_inode == 0
            || self.executable_generation == 0
            || self.executable_content_sha256 == [0; 32]
            || self.cwd_device == 0
            || self.cwd_inode == 0
            || self.cwd_generation == 0
            || self.immutable_argv.is_empty()
            || self.immutable_argv[0].as_slice()
                != self.canonical_executable.as_os_str().as_bytes()
            || self.immutable_argv.len() > 256
            || self.immutable_env.len() > 512
        {
            return Err(ControllerError::Rejected(
                "fixed plan launch entry has an empty file or process binding",
            ));
        }
        let process_bytes = self
            .immutable_argv
            .iter()
            .map(Vec::len)
            .chain(
                self.immutable_env
                    .iter()
                    .map(|(name, value)| name.len().saturating_add(value.len())),
            )
            .try_fold(0usize, |total, length| total.checked_add(length))
            .ok_or(ControllerError::Rejected(
                "fixed plan argv and environment size overflow",
            ))?;
        if process_bytes > 1024 * 1024 {
            return Err(ControllerError::Rejected(
                "fixed plan argv and environment exceed fixed v11 cap",
            ));
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"serverware-controller-v11/fixed-plan-launch\0");
        bytes.push(self.plan.code());
        encode_path_component(&mut bytes, &self.canonical_executable);
        encode_path_component(&mut bytes, &self.canonical_cwd);
        bytes.extend_from_slice(&self.executable_device.to_be_bytes());
        bytes.extend_from_slice(&self.executable_inode.to_be_bytes());
        bytes.extend_from_slice(&self.executable_generation.to_be_bytes());
        bytes.extend_from_slice(&self.executable_content_sha256);
        bytes.extend_from_slice(&self.cwd_device.to_be_bytes());
        bytes.extend_from_slice(&self.cwd_inode.to_be_bytes());
        bytes.extend_from_slice(&self.cwd_generation.to_be_bytes());
        bytes.push(self.retained_fd_mode as u8);
        bytes.extend_from_slice(
            &self.openat2_resolution.reference_sha256,
        );
        bytes.extend_from_slice(&self.file_identity.reference_sha256);
        bytes.extend_from_slice(&self.cwd_identity.reference_sha256);
        bytes.extend_from_slice(&self.retained_fd_evidence.reference_sha256);
        bytes.extend_from_slice(&self.execveat_token.reference_sha256);
        bytes.extend_from_slice(&(self.immutable_argv.len() as u64).to_be_bytes());
        for argument in &self.immutable_argv {
            validate_exec_component(argument, false)?;
            encode_bytes_component(&mut bytes, argument);
        }
        bytes.extend_from_slice(&(self.immutable_env.len() as u64).to_be_bytes());
        let mut previous_name: Option<&[u8]> = None;
        for (name, value) in &self.immutable_env {
            validate_exec_component(name, true)?;
            validate_exec_component(value, false)?;
            if previous_name.is_some_and(|previous| previous >= name.as_slice()) {
                return Err(ControllerError::Rejected(
                    "fixed plan environment is not strictly sorted and unique",
                ));
            }
            previous_name = Some(name);
            encode_bytes_component(&mut bytes, name);
            encode_bytes_component(&mut bytes, value);
        }
        Ok(sha256(&bytes))
    }
}

#[derive(Clone, Debug)]
pub struct RawFixedPlanLaunchTable {
    pub table_evidence: EvidenceReference,
    pub selected_plan: Plan,
    pub entries: Vec<FixedPlanLaunchEntry>,
}

#[derive(Clone, Debug)]
pub struct RawTrustedPlanManifest {
    pub path: PathBuf,
    pub manifest: TrustedPlanManifestV11,
    pub exact_bytes: EvidenceReference,
    pub file_identity: EvidenceReference,
    pub root_owned_immutable: EvidenceReference,
}

impl RawTrustedPlanManifest {
    fn validate_against_launch_table(
        &self,
        config_sha256: Digest,
        launch_table: &RawFixedPlanLaunchTable,
    ) -> Result<Digest> {
        if self.path.as_path() != Path::new(TRUSTED_PLAN_MANIFEST_PATH) {
            return Err(ControllerError::Rejected(
                "trusted plan manifest is not loaded from the fixed root path",
            ));
        }
        self.manifest.validate()?;
        self.exact_bytes.validate()?;
        self.file_identity.validate()?;
        self.root_owned_immutable.validate()?;
        let manifest_sha256 = self.manifest.manifest_sha256()?;
        if manifest_sha256 == [0; 32]
            || self.manifest.config_sha256 != config_sha256
            || self.exact_bytes.length != TRUSTED_PLAN_MANIFEST_BYTES as u64
            || self.exact_bytes.object_sha256 != manifest_sha256
            || launch_table.entries.len() != FIXED_PLAN_ORDER.len()
        {
            return Err(ControllerError::Rejected(
                "trusted plan manifest does not bind config or exact bytes",
            ));
        }
        for (index, plan) in FIXED_PLAN_ORDER.iter().enumerate() {
            let entry = launch_table
                .entries
                .iter()
                .find(|entry| entry.plan == *plan)
                .ok_or(ControllerError::Rejected(
                    "trusted plan manifest lacks a fixed launch entry",
                ))?;
            if self.manifest.bindings[index].plan != *plan
                || self.manifest.bindings[index]
                    .fixed_launch_command_identity_sha256
                    != entry.canonical_identity_sha256()?
            {
                return Err(ControllerError::Rejected(
                    "trusted plan binding does not match fixed launch identity",
                ));
            }
        }
        Ok(manifest_sha256)
    }
}

impl RawFixedPlanLaunchTable {
    fn selected_entry(&self, lane: Lane) -> Result<&FixedPlanLaunchEntry> {
        self.table_evidence.validate()?;
        if self.entries.len() != 5 || self.selected_plan != lane.plan {
            return Err(ControllerError::Rejected(
                "fixed plan launch table is incomplete or selects the wrong plan",
            ));
        }
        for plan in FIXED_PLAN_ORDER {
            if self.entries.iter().filter(|entry| entry.plan == plan).count() != 1 {
                return Err(ControllerError::Rejected(
                    "fixed plan launch table must contain each v11 plan exactly once",
                ));
            }
        }
        let mut table_bytes = Vec::with_capacity(256);
        table_bytes.extend_from_slice(
            b"serverware-controller-v11/fixed-plan-table\0",
        );
        table_bytes.push(self.selected_plan.code());
        for plan in FIXED_PLAN_ORDER {
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.plan == plan)
                .ok_or(ControllerError::Rejected(
                    "fixed plan launch table entry disappeared",
                ))?;
            table_bytes.extend_from_slice(
                &entry.canonical_identity_sha256()?,
            );
        }
        if self.table_evidence.object_sha256 != sha256(&table_bytes) {
            return Err(ControllerError::Rejected(
                "fixed plan launch table evidence does not bind exact entries",
            ));
        }
        let selected = self
            .entries
            .iter()
            .find(|entry| entry.plan == self.selected_plan)
            .ok_or(ControllerError::Rejected(
                "fixed plan launch table lacks selected plan",
            ))?;
        selected.canonical_identity_sha256()?;
        Ok(selected)
    }
}

#[derive(Clone, Debug)]
pub struct RawFixedLaunch {
    pub cgroup_path: PathBuf,
    pub mandatory_denied_socket_paths: Vec<PathBuf>,
    pub descendant_source_mounts_read_only: bool,
    pub current_lane_command_identity: EvidenceReference,
    pub executable_identity: EvidenceReference,
    pub import_closure: EvidenceReference,
    pub sandbox_policy: EvidenceReference,
    pub no_build_policy: EvidenceReference,
    pub fixed_plan_table: RawFixedPlanLaunchTable,
    pub trusted_plan_manifest: RawTrustedPlanManifest,
}

#[derive(Clone, Debug)]
pub struct RawPreExecutionEvidence {
    pub config: EvidenceReference,
    pub request: RawSignedRequest,
    pub providers: RawProviderSet,
    pub source: RawSourceSnapshot,
    pub launch: RawFixedLaunch,
}

#[derive(Clone, Debug)]
pub struct NativePreExecutionDecision {
    pub exact_provider_bytes_and_measurements: bool,
    pub provider_process_identity: bool,
    pub provider_trust_revocation_freshness: bool,
    pub exact_signed_request_schema_and_bytes: bool,
    pub root_owned_immutable_config: bool,
    pub observed_immutable_source_snapshot: bool,
    pub opened_executable_file_identity: bool,
    pub fixed_root_trust_manifest_path_and_identity: bool,
    pub root_owned_immutable_trust_manifest: bool,
    pub exact_config_and_five_plan_bindings: bool,
    pub exact_fixed_plan_table: bool,
    pub canonical_openat2_path_and_cwd: bool,
    pub opened_cwd_file_identity: bool,
    pub retained_executable_fd: bool,
    pub device_inode_generation_content: bool,
    pub immutable_argv_env: bool,
    pub execveat_without_reresolution: bool,
    pub current_lane_command_and_import_closure: bool,
    pub sandbox_and_no_build_policy: bool,
    pub container_socket_connect_guard: bool,
    pub decision_sha256: Digest,
}

impl NativePreExecutionDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_provider_bytes_and_measurements
            && self.provider_process_identity
            && self.provider_trust_revocation_freshness
            && self.exact_signed_request_schema_and_bytes
            && self.root_owned_immutable_config
            && self.observed_immutable_source_snapshot
            && self.opened_executable_file_identity
            && self.fixed_root_trust_manifest_path_and_identity
            && self.root_owned_immutable_trust_manifest
            && self.exact_config_and_five_plan_bindings
            && self.exact_fixed_plan_table
            && self.canonical_openat2_path_and_cwd
            && self.opened_cwd_file_identity
            && self.retained_executable_fd
            && self.device_inode_generation_content
            && self.immutable_argv_env
            && self.execveat_without_reresolution
            && self.current_lane_command_and_import_closure
            && self.sandbox_and_no_build_policy
            && self.container_socket_connect_guard
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "native pre-execution verifier did not prove every invariant",
            ))
        }
    }
}

mod capability_seal {
    #[derive(Clone, Debug)]
    pub struct Seal;
}

#[derive(Clone, Debug)]
pub struct VerifiedProviderCapability {
    manifest_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedProviderCapability {
    pub fn manifest_sha256(&self) -> Digest {
        self.manifest_sha256
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedRequestCapability {
    request_id: Digest,
    request_sha256: Digest,
    nonce_sha256: Digest,
    peer_binding_sha256: Digest,
    deadline_unix_ms: u64,
    lane: Lane,
    config_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedRequestCapability {
    pub fn request_id(&self) -> Digest {
        self.request_id
    }

    pub fn request_sha256(&self) -> Digest {
        self.request_sha256
    }

    pub fn nonce_sha256(&self) -> Digest {
        self.nonce_sha256
    }

    pub fn peer_binding_sha256(&self) -> Digest {
        self.peer_binding_sha256
    }

    pub fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }

    pub fn lane(&self) -> Lane {
        self.lane
    }

    pub fn config_sha256(&self) -> Digest {
        self.config_sha256
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSourceCapability {
    observed_source_sha256: Digest,
    root_identity_sha256: Digest,
    source_root: PathBuf,
    source_root_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedSourceCapability {
    pub fn observed_source_sha256(&self) -> Digest {
        self.observed_source_sha256
    }

    pub fn root_identity_sha256(&self) -> Digest {
        self.root_identity_sha256
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn source_root_sha256(&self) -> Digest {
        self.source_root_sha256
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedLaunchCapability {
    current_lane_command_identity_sha256: Digest,
    fixed_plan_launch_sha256: Digest,
    fixed_plan_manifest_sha256: Digest,
    canonical_executable: PathBuf,
    canonical_cwd: PathBuf,
    executable_device: u64,
    executable_inode: u64,
    executable_generation: u64,
    executable_content_sha256: Digest,
    cwd_device: u64,
    cwd_inode: u64,
    cwd_generation: u64,
    cwd_identity: EvidenceReference,
    immutable_argv: Vec<Vec<u8>>,
    immutable_env: Vec<(Vec<u8>, Vec<u8>)>,
    retained_fd_mode: RetainedExecutableFdMode,
    retained_executable_fd: Arc<OwnedFd>,
    execveat_token: EvidenceReference,
    cgroup_path: PathBuf,
    mandatory_denied_socket_paths: Vec<PathBuf>,
    descendant_source_mounts_read_only: bool,
    no_build: bool,
    _seal: capability_seal::Seal,
}

#[derive(Clone, Debug)]
pub struct VerifiedPreExecution {
    pub providers: VerifiedProviderCapability,
    pub request: VerifiedRequestCapability,
    pub source: VerifiedSourceCapability,
    pub launch: VerifiedLaunchCapability,
    decision_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedPreExecution {
    pub fn lane(&self) -> Lane {
        self.request.lane
    }

    pub fn observed_source_sha256(&self) -> Digest {
        self.source.observed_source_sha256
    }

    pub fn request_sha256(&self) -> Digest {
        self.request.request_sha256
    }

    pub fn source_root(&self) -> &Path {
        &self.source.source_root
    }

    pub fn source_root_sha256(&self) -> Digest {
        self.source.source_root_sha256
    }

    pub fn current_lane_command_identity_sha256(&self) -> Digest {
        self.launch.current_lane_command_identity_sha256
    }

    pub fn fixed_plan_launch_sha256(&self) -> Digest {
        self.launch.fixed_plan_launch_sha256
    }

    pub fn fixed_plan_manifest_sha256(&self) -> Digest {
        self.launch.fixed_plan_manifest_sha256
    }

    pub(crate) fn retained_executable_fd(&self) -> &OwnedFd {
        self.launch.retained_executable_fd.as_ref()
    }

    pub(crate) fn canonical_executable(&self) -> &Path {
        &self.launch.canonical_executable
    }

    pub(crate) fn canonical_cwd(&self) -> &Path {
        &self.launch.canonical_cwd
    }

    pub(crate) fn immutable_argv(&self) -> &[Vec<u8>] {
        &self.launch.immutable_argv
    }

    pub(crate) fn immutable_env(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.launch.immutable_env
    }

    pub(crate) fn retained_fd_mode(&self) -> RetainedExecutableFdMode {
        self.launch.retained_fd_mode
    }

    pub(crate) fn executable_file_identity(
        &self,
    ) -> (u64, u64, u64, Digest) {
        (
            self.launch.executable_device,
            self.launch.executable_inode,
            self.launch.executable_generation,
            self.launch.executable_content_sha256,
        )
    }

    pub(crate) fn cwd_file_identity(&self) -> (u64, u64, u64, Digest) {
        (
            self.launch.cwd_device,
            self.launch.cwd_inode,
            self.launch.cwd_generation,
            self.launch.cwd_identity.reference_sha256,
        )
    }

    pub(crate) fn execveat_token(&self) -> &EvidenceReference {
        &self.launch.execveat_token
    }

    pub(crate) fn execveat_token_sha256(&self) -> Digest {
        self.launch.execveat_token.reference_sha256
    }

    pub fn cgroup_path(&self) -> &Path {
        &self.launch.cgroup_path
    }

    pub fn mandatory_denied_socket_paths(&self) -> &[PathBuf] {
        &self.launch.mandatory_denied_socket_paths
    }

    pub fn descendant_source_mounts_read_only(&self) -> bool {
        self.launch.descendant_source_mounts_read_only
    }

    pub fn decision_sha256(&self) -> Digest {
        self.decision_sha256
    }
}

pub fn mandatory_denied_socket_paths() -> Vec<PathBuf> {
    [
        "/run/containerd/containerd.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/containerd/containerd.sock",
        "/var/run/docker.sock",
        "/var/run/podman/podman.sock",
    ]
    .iter()
    .map(|path| PathBuf::from(*path))
    .collect()
}

#[cfg(unix)]
fn canonical_path_digest(path: &Path) -> Digest {
    let bytes = path.as_os_str().as_bytes();
    let mut canonical = Vec::with_capacity(64 + bytes.len());
    canonical.extend_from_slice(b"serverware-controller-v11/absolute-path\0");
    canonical.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    canonical.extend_from_slice(bytes);
    sha256(&canonical)
}

#[cfg(unix)]
fn encode_path_component(output: &mut Vec<u8>, path: &Path) {
    encode_bytes_component(output, path.as_os_str().as_bytes());
}

fn encode_bytes_component(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_exec_component(value: &[u8], environment_name: bool) -> Result<()> {
    if value.len() > 64 * 1024
        || value.contains(&0)
        || (environment_name
            && (value.is_empty() || value.contains(&b'=')))
    {
        return Err(ControllerError::Rejected(
            "fixed plan argv or environment component is invalid",
        ));
    }
    Ok(())
}

pub trait PinnedNativeVerifier: Send + Sync {
    fn verify_pre_execution(
        &self,
        raw: &RawPreExecutionEvidence,
    ) -> Result<NativePreExecutionDecision>;
    fn verify_acceptance_cas_claim(
        &self,
        input: &AtomicAcceptanceInput,
        pre_execution: &VerifiedPreExecution,
        raw: &RawAcceptanceCasClaim,
    ) -> Result<NativeAcceptanceCasDecision>;
    fn verify_build_reservation_claim(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawBuildReservationClaim,
    ) -> Result<NativeBuildReservationDecision>;
    fn verify_supervisor_execution_gate(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawSupervisorPreparedExecution,
    ) -> Result<NativeSupervisorExecutionGateDecision>;
    fn verify_containment_terminal(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawContainmentTerminal,
    ) -> Result<NativeContainmentDecision>;
    fn verify_execution_closure(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawExecutionClosure,
    ) -> Result<NativeExecutionDecision>;
    fn verify_build_closure(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawBuildClosure,
    ) -> Result<NativeBuildDecision>;
    fn verify_committed_build_success(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed: &CommittedBuildSuccess,
    ) -> Result<NativeCommittedBuildDecision>;
    fn verify_build_terminal(
        &self,
        reservation: &BuildReservation,
        committed: &CommittedBuildTerminal,
    ) -> Result<NativeBuildTerminalDecision>;
    fn verify_build_terminal_source(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed: &CommittedBuildTerminal,
    ) -> Result<NativeBuildTerminalDecision>;
    fn verify_no_build_installation(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed_build: &VerifiedBuildClosure,
        raw: &RawNoBuildInstallation,
    ) -> Result<NativeNoBuildDecision>;
    fn verify_membership_and_receipt(
        &self,
        execution: &VerifiedExecutionCapability,
        raw: &RawFinalCandidate,
    ) -> Result<NativeFinalDecision>;
    fn verify_publication_candidate(
        &self,
        final_candidate: &VerifiedFinalCandidate,
        exact_receipt_bytes: &EvidenceReference,
        final_evidence_closure: &EvidenceReference,
        acceptance_claim: &EvidenceReference,
        signed_time_order: &EvidenceReference,
    ) -> Result<NativePublicationDecision>;
    fn verify_receipt_provider_call(
        &self,
        body: &ControllerReceiptBody,
        artifact: &SignedReceiptArtifact,
    ) -> Result<NativeReceiptProviderCallDecision>;
    fn verify_exact_replay(
        &self,
        replay: &CommittedReplay,
    ) -> Result<NativeReplayDecision>;
}

pub struct BootstrapVerifierHandle {
    verifier: Box<dyn PinnedNativeVerifier>,
    measured_executable_sha256: Digest,
    measured_process_identity_sha256: Digest,
    measured_receipt_key_sha256: Digest,
    measured_config_sha256: Digest,
    measured_provider_manifest_sha256: Digest,
    attestation_sha256: Digest,
    attestation_scope: AttestationScope,
    receipt_verifying_key: VerifyingKey,
    _seal: capability_seal::Seal,
}

#[derive(Clone, Debug)]
pub(crate) struct TrustedHostBootstrapMeasurements {
    pub verifier_executable_sha256: Digest,
    pub controller_process_identity_sha256: Digest,
    pub receipt_verifying_key_sha256: Digest,
    pub immutable_config_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub attestation_evidence_sha256: Digest,
    pub measurement_bundle_sha256: Digest,
}

pub(crate) fn trusted_host_measurement_bundle_sha256(
    measurements: &TrustedHostBootstrapMeasurements,
) -> Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(
        b"serverware-controller-v11/trusted-host-measurements/no-tee\0",
    );
    bytes.extend_from_slice(&measurements.verifier_executable_sha256);
    bytes.extend_from_slice(
        &measurements.controller_process_identity_sha256,
    );
    bytes.extend_from_slice(&measurements.receipt_verifying_key_sha256);
    bytes.extend_from_slice(&measurements.immutable_config_sha256);
    bytes.extend_from_slice(&measurements.provider_manifest_sha256);
    bytes.extend_from_slice(&measurements.attestation_evidence_sha256);
    sha256(&bytes)
}

impl BootstrapVerifierHandle {
    pub(crate) fn measured_trusted_host(
        verifier: Box<dyn PinnedNativeVerifier>,
        receipt_verifying_key: VerifyingKey,
        measurements: TrustedHostBootstrapMeasurements,
    ) -> Result<Self> {
        if [
            measurements.verifier_executable_sha256,
            measurements.controller_process_identity_sha256,
            measurements.receipt_verifying_key_sha256,
            measurements.immutable_config_sha256,
            measurements.provider_manifest_sha256,
            measurements.attestation_evidence_sha256,
            measurements.measurement_bundle_sha256,
        ]
        .iter()
        .any(|measurement| *measurement == [0; 32])
            || sha256(receipt_verifying_key.as_bytes())
                != measurements.receipt_verifying_key_sha256
            || trusted_host_measurement_bundle_sha256(&measurements)
                != measurements.measurement_bundle_sha256
        {
            return Err(ControllerError::Unready(vec![
                "trusted-host bootstrap measurements are incomplete or key-mismatched"
                    .to_owned(),
            ]));
        }
        Ok(Self {
            verifier,
            measured_executable_sha256:
                measurements.verifier_executable_sha256,
            measured_process_identity_sha256:
                measurements.controller_process_identity_sha256,
            measured_receipt_key_sha256:
                measurements.receipt_verifying_key_sha256,
            measured_config_sha256: measurements.immutable_config_sha256,
            measured_provider_manifest_sha256:
                measurements.provider_manifest_sha256,
            attestation_sha256: measurements.measurement_bundle_sha256,
            attestation_scope: AttestationScope::TrustedHostNoTee,
            receipt_verifying_key,
            _seal: capability_seal::Seal,
        })
    }

    pub fn verify_pre_execution(
        &self,
        raw: &RawPreExecutionEvidence,
    ) -> Result<VerifiedPreExecution> {
        if self.measured_executable_sha256 == [0; 32]
            || self.measured_process_identity_sha256 == [0; 32]
            || self.measured_receipt_key_sha256 == [0; 32]
            || self.measured_config_sha256 == [0; 32]
            || self.measured_provider_manifest_sha256 == [0; 32]
            || self.attestation_sha256 == [0; 32]
        {
            return Err(ControllerError::Unready(vec![
                "bootstrap verifier handle is not measured".to_owned(),
            ]));
        }
        for object in pre_execution_objects(raw) {
            object.validate()?;
        }
        if raw.request.request_sha256 == [0; 32]
            || raw.request.request_id == [0; 32]
            || raw.request.nonce_sha256 == [0; 32]
            || raw.request.peer_binding_sha256 == [0; 32]
            || raw.request.config_sha256 != raw.config.object_sha256
            || raw.config.object_sha256 != self.measured_config_sha256
            || raw.providers.manifest.object_sha256 == [0; 32]
            || raw.providers.manifest.object_sha256
                != self.measured_provider_manifest_sha256
            || raw.source.observed_source_sha256 == [0; 32]
            || raw
                .launch
                .current_lane_command_identity
                .object_sha256
                == [0; 32]
        {
            return Err(ControllerError::Rejected(
                "pre-execution evidence has an empty or inconsistent binding",
            ));
        }
        validate_absolute_normalized_path(&raw.source.source_root)?;
        validate_absolute_normalized_path(&raw.launch.cgroup_path)?;
        let baseline_denials = mandatory_denied_socket_paths();
        if raw.launch.mandatory_denied_socket_paths.is_empty()
            || raw.launch.mandatory_denied_socket_paths.len() > 256
            || !baseline_denials.iter().all(|required| {
                raw.launch.mandatory_denied_socket_paths.contains(required)
            })
            || !raw.launch.descendant_source_mounts_read_only
        {
            return Err(ControllerError::Rejected(
                "fixed launch does not carry the mandatory sandbox policy",
            ));
        }
        let mut unique_denials = BTreeSet::new();
        for path in &raw.launch.mandatory_denied_socket_paths {
            validate_absolute_normalized_path(path)?;
            if !unique_denials.insert(path.as_os_str().as_bytes().to_vec()) {
                return Err(ControllerError::Rejected(
                    "fixed launch contains duplicate denied socket paths",
                ));
            }
        }
        let selected_plan = raw
            .launch
            .fixed_plan_table
            .selected_entry(raw.request.lane)?;
        let selected_plan_sha256 = selected_plan.canonical_identity_sha256()?;
        if selected_plan_sha256
                != raw
                    .launch
                    .current_lane_command_identity
                    .object_sha256
            || selected_plan.file_identity.reference_sha256
                != raw.launch.executable_identity.reference_sha256
        {
            return Err(ControllerError::Rejected(
                "fixed plan launch does not bind current command and executable evidence",
            ));
        }
        let fixed_plan_manifest_sha256 = raw
            .launch
            .trusted_plan_manifest
            .validate_against_launch_table(
                raw.config.object_sha256,
                &raw.launch.fixed_plan_table,
            )?;
        let decision = self.verifier.verify_pre_execution(raw)?;
        decision.require_all()?;
        Ok(VerifiedPreExecution {
            providers: VerifiedProviderCapability {
                manifest_sha256: raw.providers.manifest.reference_sha256,
                _seal: capability_seal::Seal,
            },
            request: VerifiedRequestCapability {
                request_id: raw.request.request_id,
                request_sha256: raw.request.request_sha256,
                nonce_sha256: raw.request.nonce_sha256,
                peer_binding_sha256: raw.request.peer_binding_sha256,
                deadline_unix_ms: raw.request.deadline_unix_ms,
                lane: raw.request.lane,
                config_sha256: raw.request.config_sha256,
                _seal: capability_seal::Seal,
            },
            source: VerifiedSourceCapability {
                observed_source_sha256: raw.source.observed_source_sha256,
                root_identity_sha256: raw.source.root_identity.reference_sha256,
                source_root: raw.source.source_root.clone(),
                source_root_sha256: canonical_path_digest(&raw.source.source_root),
                _seal: capability_seal::Seal,
            },
            launch: VerifiedLaunchCapability {
                current_lane_command_identity_sha256: selected_plan_sha256,
                fixed_plan_launch_sha256:
                    raw.launch.fixed_plan_table.table_evidence.reference_sha256,
                fixed_plan_manifest_sha256,
                canonical_executable:
                    selected_plan.canonical_executable.clone(),
                canonical_cwd: selected_plan.canonical_cwd.clone(),
                executable_device: selected_plan.executable_device,
                executable_inode: selected_plan.executable_inode,
                executable_generation: selected_plan.executable_generation,
                executable_content_sha256:
                    selected_plan.executable_content_sha256,
                cwd_device: selected_plan.cwd_device,
                cwd_inode: selected_plan.cwd_inode,
                cwd_generation: selected_plan.cwd_generation,
                cwd_identity: selected_plan.cwd_identity.clone(),
                immutable_argv: selected_plan.immutable_argv.clone(),
                immutable_env: selected_plan.immutable_env.clone(),
                retained_fd_mode: selected_plan.retained_fd_mode,
                retained_executable_fd:
                    selected_plan.retained_executable_fd.clone(),
                execveat_token: selected_plan.execveat_token.clone(),
                cgroup_path: raw.launch.cgroup_path.clone(),
                mandatory_denied_socket_paths: raw
                    .launch
                    .mandatory_denied_socket_paths
                    .clone(),
                descendant_source_mounts_read_only:
                    DESCENDANT_SOURCE_MOUNTS_MUST_BE_READ_ONLY,
                no_build: raw.request.lane.operation == Operation::RunNoBuild,
                _seal: capability_seal::Seal,
            },
            decision_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    pub fn verify_supervisor_execution_gate(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawSupervisorPreparedExecution,
    ) -> Result<VerifiedSupervisorExecutionAuthorization> {
        raw.child.validate_supervisor_binding(pre_execution)?;
        raw.capabilities
            .preparation_provider_call
            .validate_against(pre_execution)?;
        raw.shared_state_machine_measurement.validate()?;
        for object in supervisor_capability_objects(&raw.capabilities) {
            object.validate()?;
        }
        let registration_binding_sha256 =
            raw.child.registration_binding_sha256();
        let expected_preparation_transition_sha256 =
            supervisor_state_transition_sha256(
                raw.shared_state_machine_identity_sha256,
                registration_binding_sha256,
                pre_execution.request.request_sha256,
                pre_execution.launch.fixed_plan_manifest_sha256,
                [0; 32],
                [0; 32],
                SupervisorStatePhase::Prepared,
            );
        if raw.shared_state_machine_identity_sha256 == [0; 32]
            || raw.preparation_transition_sha256 == [0; 32]
            || raw.preparation_transition_sha256
                != expected_preparation_transition_sha256
            || raw.shared_state_machine_measurement.object_sha256
                != raw.shared_state_machine_identity_sha256
            || raw
            .capabilities
            .preparation_provider_call
            .result_or_terminal_binding
            .object_sha256
                != registration_binding_sha256
        {
            return Err(ControllerError::Rejected(
                "supervisor preparation worker did not bind the registered child",
            ));
        }
        let decision = self
            .verifier
            .verify_supervisor_execution_gate(pre_execution, raw)?;
        decision.require_all()?;
        Ok(VerifiedSupervisorExecutionAuthorization {
            decision_sha256: decision.decision_sha256,
            registration_binding_sha256,
            shared_state_machine_identity_sha256:
                raw.shared_state_machine_identity_sha256,
            preparation_transition_sha256:
                raw.preparation_transition_sha256,
            _seal: capability_seal::Seal,
        })
    }

    pub fn verify_containment_terminal(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: &RawContainmentTerminal,
    ) -> Result<VerifiedContainmentCleanup> {
        raw.provider_call.validate_against(pre_execution)?;
        for object in containment_objects(raw) {
            object.validate()?;
        }
        if raw.shared_state_machine_identity_sha256 == [0; 32]
            || raw.predecessor_transition_sha256 == [0; 32]
            || raw.state_machine_transition_sha256 == [0; 32]
            || raw
            .provider_call
            .result_or_terminal_binding
            .object_sha256
            != containment_terminal_result_sha256(raw)
        {
            return Err(ControllerError::Rejected(
                "containment provider result binding is not canonical",
            ));
        }
        let decision = self
            .verifier
            .verify_containment_terminal(pre_execution, raw)?;
        decision.require_all()?;
        Ok(VerifiedContainmentCleanup {
            terminal_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    pub fn verify_signed_controller_receipt(
        &self,
        exact_wire_bytes: &[u8],
    ) -> Result<VerifiedSignedControllerReceipt> {
        let receipt = SignedControllerReceipt::decode(exact_wire_bytes)?;
        if receipt.body.attestation_scope != self.attestation_scope
            || receipt.body.attestation_scope_measurement_sha256
                != self.attestation_sha256
            || receipt.signer_key_sha256 != self.measured_receipt_key_sha256
        {
            return Err(ControllerError::Rejected(
                "signed receipt exceeds measured trusted-host attestation scope",
            ));
        }
        receipt.verify(&self.receipt_verifying_key)
    }

    fn verify_signed_receipt_artifact(
        &self,
        expected_body: &ControllerReceiptBody,
        artifact: SignedReceiptArtifact,
    ) -> Result<VerifiedTypedReceiptCapability> {
        let exact_receipt_bytes = artifact.signed_receipt.encode()?.to_vec();
        let verified = self
            .verify_signed_controller_receipt(&exact_receipt_bytes)?;
        if verified.body() != expected_body {
            return Err(ControllerError::Rejected(
                "receipt signer changed the controller-verified body",
            ));
        }
        artifact.exact_receipt.validate()?;
        if artifact.exact_receipt.length
                != exact_receipt_bytes.len() as u64
            || artifact.exact_receipt.object_sha256
                != verified.wire_sha256()
            || artifact.exact_receipt.length > RECEIPT_MAX_BYTES
        {
            return Err(ControllerError::Rejected(
                "signed receipt evidence does not bind exact verified wire bytes",
            ));
        }
        artifact
            .provider_call
            .validate_against_receipt_body(expected_body)?;
        if artifact
            .provider_call
            .result_or_terminal_binding
            .object_sha256
            != verified.wire_sha256()
        {
            return Err(ControllerError::Rejected(
                "receipt signer worker result does not bind exact wire bytes",
            ));
        }
        let provider_call_decision = self
            .verifier
            .verify_receipt_provider_call(expected_body, &artifact)?;
        provider_call_decision.require_all()?;
        Ok(VerifiedTypedReceiptCapability {
            terminal: expected_body.terminal,
            body: expected_body.clone(),
            exact_receipt: artifact.exact_receipt,
            exact_receipt_bytes,
            wire_sha256: verified.wire_sha256(),
            provider_call: artifact.provider_call,
            provider_call_verification_sha256:
                provider_call_decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_acceptance_cas_claim(
        &self,
        input: &AtomicAcceptanceInput,
        pre_execution: &VerifiedPreExecution,
        raw: RawAcceptanceCasClaim,
    ) -> Result<AcceptanceLease> {
        raw.signed_cas_claim.validate()?;
        raw.current_trust_checkpoint.validate()?;
        raw.current_revocation_checkpoint.validate()?;
        raw.freshness_evidence.validate()?;
        raw.one_use_fence_evidence.validate()?;
        if raw.fence == 0
            || raw.acceptance_identity_sha256 == [0; 32]
            || raw.generation == 0
            || raw.acceptance_sha256 == [0; 32]
            || raw.exact_input_sha256 != atomic_acceptance_input_sha256(input)
            || input.request_id != pre_execution.request.request_id
            || input.exact_signed_request_sha256
                != pre_execution.request.request_sha256
            || input.current_lane_command_identity_sha256
                != pre_execution.launch.current_lane_command_identity_sha256
            || input.fixed_plan_manifest_sha256
                != pre_execution.launch.fixed_plan_manifest_sha256
        {
            return Err(ControllerError::Rejected(
                "raw acceptance CAS claim does not exactly bind verified input",
            ));
        }
        let decision = self.verifier.verify_acceptance_cas_claim(
            input,
            pre_execution,
            &raw,
        )?;
        if !(decision.signed_cas_claim
            && decision.exact_acceptance_input
            && decision.current_trust
            && decision.not_revoked
            && decision.fresh_before_deadline
            && decision.exact_one_use_fence
            && decision.exact_identity_and_generation
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected acceptance CAS capability",
            ));
        }
        Ok(AcceptanceLease {
            fence: raw.fence,
            acceptance_identity_sha256: raw.acceptance_identity_sha256,
            generation: raw.generation,
            acceptance_sha256: raw.acceptance_sha256,
            claim_evidence: raw.signed_cas_claim.clone(),
            claim_objects: vec![
                raw.signed_cas_claim,
                raw.current_trust_checkpoint,
                raw.current_revocation_checkpoint,
                raw.freshness_evidence,
                raw.one_use_fence_evidence,
            ],
            verification_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_build_reservation_claim(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: RawBuildReservationClaim,
    ) -> Result<BuildReservation> {
        raw.signed_cas_claim.validate()?;
        raw.current_trust_checkpoint.validate()?;
        raw.current_revocation_checkpoint.validate()?;
        raw.freshness_evidence.validate()?;
        raw.one_use_fence_evidence.validate()?;
        if pre_execution.lane().operation != Operation::Build
            || raw.fence == 0
            || raw.reservation_identity_sha256 == [0; 32]
            || raw.generation == 0
            || raw.observed_source_sha256
                != pre_execution.source.observed_source_sha256
            || raw.config_sha256 != pre_execution.request.config_sha256
            || raw.provider_manifest_sha256
                != pre_execution.providers.manifest_sha256
            || raw.build_command_identity_sha256
                != pre_execution
                    .launch
                    .current_lane_command_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "raw build reservation does not exactly bind build pre-execution",
            ));
        }
        let decision = self
            .verifier
            .verify_build_reservation_claim(pre_execution, &raw)?;
        if !(decision.signed_cas_claim
            && decision.exact_source_config_provider_and_command
            && decision.current_trust
            && decision.not_revoked
            && decision.fresh_before_deadline
            && decision.exact_one_use_fence
            && decision.exact_identity_and_generation
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected build reservation capability",
            ));
        }
        Ok(BuildReservation {
            fence: raw.fence,
            reservation_identity_sha256: raw.reservation_identity_sha256,
            generation: raw.generation,
            observed_source_sha256: raw.observed_source_sha256,
            config_sha256: raw.config_sha256,
            provider_manifest_sha256: raw.provider_manifest_sha256,
            build_command_identity_sha256: raw.build_command_identity_sha256,
            claim_evidence: raw.signed_cas_claim.clone(),
            claim_objects: vec![
                raw.signed_cas_claim,
                raw.current_trust_checkpoint,
                raw.current_revocation_checkpoint,
                raw.freshness_evidence,
                raw.one_use_fence_evidence,
            ],
            verification_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_build_candidate(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: RawBuildClosure,
    ) -> Result<VerifiedBuildCandidate> {
        if pre_execution.lane().operation != Operation::Build
            || raw.source_sha256
                != pre_execution.source.observed_source_sha256
            || raw.config_sha256 != pre_execution.request.config_sha256
            || raw.provider_manifest_sha256
                != pre_execution.providers.manifest_sha256
            || raw.build_command_identity_sha256
                != pre_execution
                    .launch
                    .current_lane_command_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "raw build closure does not bind the verified build command",
            ));
        }
        let decision = self.verifier.verify_build_closure(pre_execution, &raw)?;
        if !(decision.observed_source_binding
            && decision.config_binding
            && decision.provider_binding
            && decision.build_command_binding
            && decision.output_closure_complete
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected build closure",
            ));
        }
        Ok(VerifiedBuildCandidate {
            raw,
            verification_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_committed_build_success(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed: CommittedBuildSuccess,
    ) -> Result<VerifiedBuildClosure> {
        committed.validate_shape()?;
        if committed.observed_source_sha256
                != pre_execution.source.observed_source_sha256
            || committed.raw_closure.config_sha256
                != pre_execution.request.config_sha256
            || committed.raw_closure.provider_manifest_sha256
                != pre_execution.providers.manifest_sha256
            || (pre_execution.lane().operation == Operation::Build
                && committed.build_command_identity_sha256
                    != pre_execution
                        .launch
                        .current_lane_command_identity_sha256)
        {
            return Err(ControllerError::Rejected(
                "committed build success does not bind verified pre-execution",
            ));
        }
        let decision = self
            .verifier
            .verify_committed_build_success(pre_execution, &committed)?;
        if !(decision.raw_closure
            && decision.success_terminal
            && decision.fence_and_cas_inclusion
            && decision.exact_reservation_identity_and_generation
            && decision.committed_build_command_and_artifact_closure
            && decision.current_lane_command_binding
            && decision.output_manifest
            && decision.immutable_store
            && decision.global_retrieval
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected committed build success",
            ));
        }
        Ok(VerifiedBuildClosure {
            committed,
            verification_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_committed_build_success_for_reservation(
        &self,
        pre_execution: &VerifiedPreExecution,
        reservation: &BuildReservation,
        committed: CommittedBuildSuccess,
    ) -> Result<VerifiedBuildClosure> {
        if committed.build_fence != reservation.fence
            || committed.reservation_identity_sha256
                != reservation.reservation_identity_sha256
            || committed.reservation_generation != reservation.generation
            || committed.observed_source_sha256
                != reservation.observed_source_sha256
            || committed.raw_closure.config_sha256 != reservation.config_sha256
            || committed.raw_closure.provider_manifest_sha256
                != reservation.provider_manifest_sha256
            || committed.build_command_identity_sha256
                != reservation.build_command_identity_sha256
            || committed.raw_closure.build_command_identity_sha256
                != reservation.build_command_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "committed build success does not exact-bind current reservation",
            ));
        }
        self.verify_committed_build_success(pre_execution, committed)
    }

    fn verify_build_terminal(
        &self,
        reservation: &BuildReservation,
        terminal: &CommittedBuildTerminal,
    ) -> Result<()> {
        terminal.validate_shape()?;
        if terminal.build_fence != reservation.fence
            || terminal.reservation_identity_sha256
                != reservation.reservation_identity_sha256
            || terminal.reservation_generation != reservation.generation
            || terminal.observed_source_sha256
                != reservation.observed_source_sha256
            || terminal.build_command_identity_sha256
                != reservation.build_command_identity_sha256
        {
            return Err(ControllerError::Rejected(
                "committed build terminal does not match its reservation",
            ));
        }
        let decision = self
            .verifier
            .verify_build_terminal(reservation, terminal)?;
        if !(decision.reservation_and_fence
            && decision.exact_terminal
            && decision.cas_inclusion
            && decision.immutable_store
            && decision.global_retrieval
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected committed build terminal",
            ));
        }
        Ok(())
    }

    fn validate_build_readback(
        &self,
        pre_execution: &VerifiedPreExecution,
        reservation: &BuildReservation,
        readback: &CommittedBuildReadback,
    ) -> Result<()> {
        match readback {
            CommittedBuildReadback::Success(success) => self
                .verify_committed_build_success_for_reservation(
                    pre_execution,
                    reservation,
                    success.clone(),
                )
                .map(|_| ()),
            CommittedBuildReadback::Failure(terminal) => {
                if terminal.kind != BuildTerminalKind::Failure {
                    return Err(ControllerError::Rejected(
                        "build failure readback has the wrong terminal kind",
                    ));
                }
                self.verify_build_terminal(reservation, terminal)
            }
            CommittedBuildReadback::Unknown(terminal) => {
                if terminal.kind != BuildTerminalKind::Unknown {
                    return Err(ControllerError::Rejected(
                        "build unknown readback has the wrong terminal kind",
                    ));
                }
                self.verify_build_terminal(reservation, terminal)
            }
        }
    }

    fn validate_build_source_readback(
        &self,
        pre_execution: &VerifiedPreExecution,
        readback: &CommittedBuildReadback,
    ) -> Result<()> {
        match readback {
            CommittedBuildReadback::Success(success) => self
                .verify_committed_build_success(pre_execution, success.clone())
                .map(|_| ()),
            CommittedBuildReadback::Failure(terminal) => {
                if terminal.kind != BuildTerminalKind::Failure {
                    return Err(ControllerError::Rejected(
                        "build failure readback has the wrong terminal kind",
                    ));
                }
                if terminal.observed_source_sha256
                    != pre_execution.source.observed_source_sha256
                {
                    return Err(ControllerError::Rejected(
                        "build terminal does not bind observed source",
                    ));
                }
                let decision = self
                    .verifier
                    .verify_build_terminal_source(pre_execution, terminal)?;
                decision.require_source_readback()
            }
            CommittedBuildReadback::Unknown(terminal) => {
                if terminal.kind != BuildTerminalKind::Unknown {
                    return Err(ControllerError::Rejected(
                        "build unknown readback has the wrong terminal kind",
                    ));
                }
                if terminal.observed_source_sha256
                    != pre_execution.source.observed_source_sha256
                {
                    return Err(ControllerError::Rejected(
                        "build terminal does not bind observed source",
                    ));
                }
                let decision = self
                    .verifier
                    .verify_build_terminal_source(pre_execution, terminal)?;
                decision.require_source_readback()
            }
        }
    }

    fn verify_no_build_installation(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed_build: &VerifiedBuildClosure,
        raw: &RawNoBuildInstallation,
    ) -> Result<VerifiedNoBuildKernelCapability> {
        let decision = self
            .verifier
            .verify_no_build_installation(pre_execution, committed_build, raw)?;
        if pre_execution.lane().operation != Operation::RunNoBuild
            || committed_build
                .committed
                .build_command_identity_sha256
                == [0; 32]
            || pre_execution
                .launch
                .current_lane_command_identity_sha256
                == [0; 32]
            || !(decision.committed_build_command_and_artifact_closure
            && decision.current_no_build_command_identity
            && decision.pre_exec_allowlist_installed
            && decision.compilers_and_build_tools_denied
            && decision.import_escape_denied
            && decision.source_recursively_read_only
            && decision.writable_build_outputs_denied
            && decision.container_sockets_denied
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected no-build kernel enforcement",
            ));
        }
        Ok(VerifiedNoBuildKernelCapability {
            policy_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_replay(&self, replay: &CommittedReplay) -> Result<VerifiedReplayCapability> {
        validate_exact_replay_bounds(replay)?;
        let decision = self.verifier.verify_exact_replay(replay)?;
        if !(decision.exact_request_binding
            && decision.typed_terminal
            && decision.exact_signed_typed_receipt
            && decision.receipt_terminal_matches_cas_terminal
            && decision.receipt_provider_call_verified
            && decision.receipt_provider_worker_evidence_in_closure
            && decision.success_quorum_or_non_success_terminal
            && decision.final_evidence_closure
            && decision.terminal_and_reconciliation
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected exact replay",
            ));
        }
        Ok(VerifiedReplayCapability {
            replay_sha256: decision.decision_sha256,
            terminal: replay.terminal,
            _seal: capability_seal::Seal,
        })
    }
}

pub trait RootRequestAuthority: Send + Sync {
    fn construct_signed_request(
        &self,
        submission: &ClientSubmission,
        peer_binding_sha256: Digest,
        immutable_config_sha256: Digest,
        deadline_unix_ms: u64,
    ) -> Result<RawSignedRequest>;
}

pub trait ProviderEvidenceSource: Send + Sync {
    fn collect_raw_provider_set(&self) -> Result<RawProviderSet>;
}

pub trait ImmutableSourceObserver: Send + Sync {
    fn observe_immutable_snapshot(&self) -> Result<RawSourceSnapshot>;
}

pub trait RootFixedLaunchAuthority: Send + Sync {
    // The returned table owns the already-open executable descriptions. A
    // supervisor must execute the selected retained FD with execveat and the
    // verified token; resolving canonical_executable again is forbidden. It
    // must also carry the exact root-owned v11 trust manifest from the fixed
    // path, independently binding config and all five canonical identities.
    fn resolve_raw_fixed_launch(
        &self,
        lane: Lane,
        source: &RawSourceSnapshot,
    ) -> Result<RawFixedLaunch>;
}

#[derive(Clone, Debug)]
pub struct AtomicAcceptanceInput {
    pub lane: Lane,
    pub request_id: Digest,
    pub exact_signed_request_sha256: Digest,
    pub nonce_sha256: Digest,
    pub peer_binding_sha256: Digest,
    pub deadline_unix_ms: u64,
    pub config_sha256: Digest,
    pub observed_source_sha256: Digest,
    pub root_identity_sha256: Digest,
    pub source_root_sha256: Digest,
    pub current_lane_command_identity_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub fixed_plan_manifest_sha256: Digest,
    pub pre_execution_decision_sha256: Digest,
}

impl AtomicAcceptanceInput {
    pub fn canonical_sha256(&self) -> Digest {
        atomic_acceptance_input_sha256(self)
    }
}

#[derive(Clone, Debug)]
pub struct RawAcceptanceCasClaim {
    pub fence: u64,
    pub acceptance_identity_sha256: Digest,
    pub generation: u64,
    pub acceptance_sha256: Digest,
    pub exact_input_sha256: Digest,
    pub signed_cas_claim: EvidenceReference,
    pub current_trust_checkpoint: EvidenceReference,
    pub current_revocation_checkpoint: EvidenceReference,
    pub freshness_evidence: EvidenceReference,
    pub one_use_fence_evidence: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct NativeAcceptanceCasDecision {
    pub signed_cas_claim: bool,
    pub exact_acceptance_input: bool,
    pub current_trust: bool,
    pub not_revoked: bool,
    pub fresh_before_deadline: bool,
    pub exact_one_use_fence: bool,
    pub exact_identity_and_generation: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct AcceptanceLease {
    fence: u64,
    acceptance_identity_sha256: Digest,
    generation: u64,
    acceptance_sha256: Digest,
    claim_evidence: EvidenceReference,
    claim_objects: Vec<EvidenceReference>,
    verification_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl AcceptanceLease {
    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn identity_sha256(&self) -> Digest {
        self.acceptance_identity_sha256
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn acceptance_sha256(&self) -> Digest {
        self.acceptance_sha256
    }

    pub fn verification_sha256(&self) -> Digest {
        self.verification_sha256
    }

    pub fn claim_objects(&self) -> &[EvidenceReference] {
        &self.claim_objects
    }
}

#[derive(Clone, Debug)]
pub struct CommittedReplay {
    pub lane: Lane,
    pub request_id: Digest,
    pub exact_signed_request_sha256: Digest,
    pub nonce_sha256: Digest,
    pub peer_binding_sha256: Digest,
    pub deadline_unix_ms: u64,
    pub config_sha256: Digest,
    pub observed_source_sha256: Digest,
    pub root_identity_sha256: Digest,
    pub source_root_sha256: Digest,
    pub current_lane_command_identity_sha256: Digest,
    pub committed_build_command_identity_sha256: Digest,
    pub fixed_plan_manifest_sha256: Digest,
    pub acceptance_fence: u64,
    pub acceptance_identity_sha256: Digest,
    pub acceptance_generation: u64,
    pub build_fence: u64,
    pub build_reservation_identity_sha256: Digest,
    pub build_reservation_generation: u64,
    pub receipt_evidence_closure_sha256: Digest,
    pub receipt_terminal_evidence_sha256: Digest,
    pub attestation_scope_measurement_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub pre_execution_decision_sha256: Digest,
    pub exact_receipt: EvidenceReference,
    pub exact_receipt_bytes: Vec<u8>,
    pub receipt_provider_call: RawBoundedProviderCallEvidence,
    pub terminal: AcceptanceTerminalKind,
    pub terminal_evidence: EvidenceReference,
    pub replay_objects: Vec<EvidenceReference>,
    pub retrieval_ledger: RawGlobalRetrievalLedger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceTerminalKind {
    Success,
    Failure,
    Unknown,
}

pub enum AtomicAcceptance {
    New(RawAcceptanceCasClaim),
    Replay(CommittedReplay),
    InFlightReconciled(CommittedReplay),
    Conflict,
}

pub trait AtomicAcceptanceReplayCas: Send + Sync {
    fn accept_nonce_and_request_once(
        &self,
        input: &AtomicAcceptanceInput,
        verified: &VerifiedPreExecution,
    ) -> Result<AtomicAcceptance>;
    fn commit_failure(
        &self,
        lease: AcceptanceLease,
        failure: &EvidenceReference,
        receipt: VerifiedTypedReceiptCapability,
    ) -> Result<CommittedReplay>;
    fn commit_unknown(
        &self,
        lease: AcceptanceLease,
        unknown: &EvidenceReference,
        receipt: VerifiedTypedReceiptCapability,
    ) -> Result<CommittedReplay>;
    fn reconcile(
        &self,
        input: &AtomicAcceptanceInput,
    ) -> Result<CommittedReplay>;
    fn publish_verified_success(
        &self,
        lease: AcceptanceLease,
        publication: VerifiedPublicationCapability,
    ) -> Result<CommittedReplay>;
    fn hard_quarantine(
        &self,
        input: &AtomicAcceptanceInput,
        reason: &str,
    ) -> Result<CommittedReplay>;
}

#[derive(Clone, Debug)]
pub struct RawBuildReservationClaim {
    pub fence: u64,
    pub reservation_identity_sha256: Digest,
    pub generation: u64,
    pub observed_source_sha256: Digest,
    pub config_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub build_command_identity_sha256: Digest,
    pub signed_cas_claim: EvidenceReference,
    pub current_trust_checkpoint: EvidenceReference,
    pub current_revocation_checkpoint: EvidenceReference,
    pub freshness_evidence: EvidenceReference,
    pub one_use_fence_evidence: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct NativeBuildReservationDecision {
    pub signed_cas_claim: bool,
    pub exact_source_config_provider_and_command: bool,
    pub current_trust: bool,
    pub not_revoked: bool,
    pub fresh_before_deadline: bool,
    pub exact_one_use_fence: bool,
    pub exact_identity_and_generation: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct BuildReservation {
    fence: u64,
    reservation_identity_sha256: Digest,
    generation: u64,
    observed_source_sha256: Digest,
    config_sha256: Digest,
    provider_manifest_sha256: Digest,
    build_command_identity_sha256: Digest,
    claim_evidence: EvidenceReference,
    claim_objects: Vec<EvidenceReference>,
    verification_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl BuildReservation {
    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn identity_sha256(&self) -> Digest {
        self.reservation_identity_sha256
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn observed_source_sha256(&self) -> Digest {
        self.observed_source_sha256
    }

    pub fn build_command_identity_sha256(&self) -> Digest {
        self.build_command_identity_sha256
    }

    pub fn config_sha256(&self) -> Digest {
        self.config_sha256
    }

    pub fn provider_manifest_sha256(&self) -> Digest {
        self.provider_manifest_sha256
    }

    pub fn verification_sha256(&self) -> Digest {
        self.verification_sha256
    }

    pub fn claim_objects(&self) -> &[EvidenceReference] {
        &self.claim_objects
    }
}

#[derive(Clone, Debug)]
pub struct RawBuildClosure {
    pub source_sha256: Digest,
    pub config_sha256: Digest,
    pub provider_manifest_sha256: Digest,
    pub outputs_manifest: EvidenceReference,
    pub build_command_identity_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedBuildCandidate {
    raw: RawBuildClosure,
    verification_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedBuildCandidate {
    pub fn raw(&self) -> &RawBuildClosure {
        &self.raw
    }

    pub fn verification_sha256(&self) -> Digest {
        self.verification_sha256
    }
}

#[derive(Clone, Debug)]
pub struct CommittedBuildSuccess {
    pub build_fence: u64,
    pub reservation_identity_sha256: Digest,
    pub reservation_generation: u64,
    pub observed_source_sha256: Digest,
    pub build_command_identity_sha256: Digest,
    pub raw_closure: RawBuildClosure,
    pub success_terminal: EvidenceReference,
    pub fence_and_cas_inclusion: EvidenceReference,
    pub output_manifest: EvidenceReference,
    pub immutable_store_objects: Vec<EvidenceReference>,
    pub retrieval_ledger_evidence: EvidenceReference,
    pub retrieval_ledger: RawGlobalRetrievalLedger,
}

impl CommittedBuildSuccess {
    fn validate_shape(&self) -> Result<()> {
        self.success_terminal.validate()?;
        self.fence_and_cas_inclusion.validate()?;
        self.output_manifest.validate()?;
        self.retrieval_ledger_evidence.validate()?;
        self.retrieval_ledger.validate_structure()?;
        if self.build_fence == 0
            || self.reservation_identity_sha256 == [0; 32]
            || self.reservation_generation == 0
            || self.observed_source_sha256 == [0; 32]
            || self.build_command_identity_sha256 == [0; 32]
            || self.raw_closure.source_sha256 != self.observed_source_sha256
            || self.raw_closure.build_command_identity_sha256
                != self.build_command_identity_sha256
            || self.raw_closure.outputs_manifest.reference_sha256
                != self.output_manifest.reference_sha256
            || self.immutable_store_objects.is_empty()
        {
            return Err(ControllerError::Rejected(
                "committed build success shape is invalid",
            ));
        }
        for object in &self.immutable_store_objects {
            object.validate()?;
        }
        validate_objects_in_ledger(
            &self.retrieval_ledger,
            committed_build_success_objects(self),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildTerminalKind {
    Failure,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CommittedBuildTerminal {
    pub kind: BuildTerminalKind,
    pub build_fence: u64,
    pub reservation_identity_sha256: Digest,
    pub reservation_generation: u64,
    pub observed_source_sha256: Digest,
    pub build_command_identity_sha256: Digest,
    pub terminal: EvidenceReference,
    pub fence_and_cas_inclusion: EvidenceReference,
    pub immutable_store_objects: Vec<EvidenceReference>,
    pub retrieval_ledger_evidence: EvidenceReference,
    pub retrieval_ledger: RawGlobalRetrievalLedger,
}

#[derive(Clone, Debug)]
pub enum CommittedBuildReadback {
    Success(CommittedBuildSuccess),
    Failure(CommittedBuildTerminal),
    Unknown(CommittedBuildTerminal),
}

impl CommittedBuildTerminal {
    fn validate_shape(&self) -> Result<()> {
        self.terminal.validate()?;
        self.fence_and_cas_inclusion.validate()?;
        self.retrieval_ledger_evidence.validate()?;
        self.retrieval_ledger.validate_structure()?;
        if self.build_fence == 0
            || self.reservation_identity_sha256 == [0; 32]
            || self.reservation_generation == 0
            || self.observed_source_sha256 == [0; 32]
            || self.build_command_identity_sha256 == [0; 32]
            || self.immutable_store_objects.is_empty()
        {
            return Err(ControllerError::Rejected(
                "committed build terminal shape is invalid",
            ));
        }
        for object in &self.immutable_store_objects {
            object.validate()?;
        }
        let mut required = self.immutable_store_objects.clone();
        required.push(self.terminal.clone());
        required.push(self.fence_and_cas_inclusion.clone());
        required.push(self.retrieval_ledger_evidence.clone());
        validate_objects_in_ledger(&self.retrieval_ledger, required)
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedBuildClosure {
    committed: CommittedBuildSuccess,
    verification_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedBuildClosure {
    pub fn committed_build_command_identity_sha256(&self) -> Digest {
        self.committed.build_command_identity_sha256
    }

    pub fn build_fence(&self) -> u64 {
        self.committed.build_fence
    }

    pub fn reservation_identity_sha256(&self) -> Digest {
        self.committed.reservation_identity_sha256
    }

    pub fn reservation_generation(&self) -> u64 {
        self.committed.reservation_generation
    }

    pub fn outputs_manifest(&self) -> &EvidenceReference {
        &self.committed.output_manifest
    }

    pub fn verification_sha256(&self) -> Digest {
        self.verification_sha256
    }
}

#[derive(Clone, Copy, Debug)]
struct ReceiptBuildBinding {
    fence: u64,
    reservation_identity_sha256: Digest,
    reservation_generation: u64,
    build_command_identity_sha256: Digest,
}

impl ReceiptBuildBinding {
    fn from_reservation(reservation: &BuildReservation) -> Self {
        Self {
            fence: reservation.fence,
            reservation_identity_sha256:
                reservation.reservation_identity_sha256,
            reservation_generation: reservation.generation,
            build_command_identity_sha256:
                reservation.build_command_identity_sha256,
        }
    }

    fn from_success(success: &CommittedBuildSuccess) -> Self {
        Self {
            fence: success.build_fence,
            reservation_identity_sha256:
                success.reservation_identity_sha256,
            reservation_generation: success.reservation_generation,
            build_command_identity_sha256:
                success.build_command_identity_sha256,
        }
    }

    fn from_terminal(terminal: &CommittedBuildTerminal) -> Self {
        Self {
            fence: terminal.build_fence,
            reservation_identity_sha256:
                terminal.reservation_identity_sha256,
            reservation_generation: terminal.reservation_generation,
            build_command_identity_sha256:
                terminal.build_command_identity_sha256,
        }
    }

    fn from_readback(readback: &CommittedBuildReadback) -> Self {
        match readback {
            CommittedBuildReadback::Success(success) => {
                Self::from_success(success)
            }
            CommittedBuildReadback::Failure(terminal)
            | CommittedBuildReadback::Unknown(terminal) => {
                Self::from_terminal(terminal)
            }
        }
    }
}

pub enum BuildReserveResult {
    Reserved(RawBuildReservationClaim),
    ExistingSuccess(CommittedBuildSuccess),
    ExistingFailure(CommittedBuildTerminal),
    ExistingUnknown(CommittedBuildTerminal),
    InFlight,
}

pub trait FencedBuildCas: Send + Sync {
    fn reserve(
        &self,
        source: &VerifiedSourceCapability,
        request: &VerifiedRequestCapability,
    ) -> Result<BuildReserveResult>;
    fn commit_success(
        &self,
        reservation: BuildReservation,
        closure: VerifiedBuildCandidate,
    ) -> Result<CommittedBuildSuccess>;
    fn commit_failure(
        &self,
        reservation: BuildReservation,
        failure: &EvidenceReference,
    ) -> Result<CommittedBuildReadback>;
    fn commit_unknown(
        &self,
        reservation: BuildReservation,
        unknown: &EvidenceReference,
    ) -> Result<CommittedBuildReadback>;
    fn reconcile(&self, reservation: BuildReservation) -> Result<CommittedBuildReadback>;
    fn hard_quarantine(
        &self,
        reservation: BuildReservation,
        reason: &str,
    ) -> Result<CommittedBuildReadback>;
    fn reconcile_source(
        &self,
        source: &VerifiedSourceCapability,
    ) -> Result<CommittedBuildReadback>;
    fn hard_quarantine_source(
        &self,
        source: &VerifiedSourceCapability,
        reason: &str,
    ) -> Result<CommittedBuildReadback>;
    fn require_committed_success(
        &self,
        source: &VerifiedSourceCapability,
        config_sha256: Digest,
        providers: &VerifiedProviderCapability,
    ) -> Result<CommittedBuildSuccess>;
}

#[derive(Clone, Debug)]
pub struct RawNoBuildKernelPolicy {
    pub pre_exec_allowlist: EvidenceReference,
    pub compiler_and_build_tool_denials: EvidenceReference,
    pub import_escape_denials: EvidenceReference,
    pub recursive_source_read_only: EvidenceReference,
    pub writable_output_denials: EvidenceReference,
    pub docker_and_container_socket_denials: EvidenceReference,
    pub mount_namespace_policy: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct VerifiedNoBuildKernelCapability {
    policy_sha256: Digest,
    _seal: capability_seal::Seal,
}

pub trait NoBuildKernelEnforcer: Send + Sync {
    fn install_before_exec(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed_build: &VerifiedBuildClosure,
        raw_policy: &RawNoBuildKernelPolicy,
    ) -> Result<RawNoBuildInstallation>;
}

#[derive(Clone, Debug)]
pub struct RawNoBuildInstallation {
    pub policy: RawNoBuildKernelPolicy,
    pub kernel_pre_exec_hook: EvidenceReference,
    pub mount_enforcement: EvidenceReference,
    pub import_enforcement: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct NativeNoBuildDecision {
    pub committed_build_command_and_artifact_closure: bool,
    pub current_no_build_command_identity: bool,
    pub pre_exec_allowlist_installed: bool,
    pub compilers_and_build_tools_denied: bool,
    pub import_escape_denied: bool,
    pub source_recursively_read_only: bool,
    pub writable_build_outputs_denied: bool,
    pub container_sockets_denied: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct NativeBuildDecision {
    pub observed_source_binding: bool,
    pub config_binding: bool,
    pub provider_binding: bool,
    pub build_command_binding: bool,
    pub output_closure_complete: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct NativeCommittedBuildDecision {
    pub raw_closure: bool,
    pub success_terminal: bool,
    pub fence_and_cas_inclusion: bool,
    pub exact_reservation_identity_and_generation: bool,
    pub committed_build_command_and_artifact_closure: bool,
    pub current_lane_command_binding: bool,
    pub output_manifest: bool,
    pub immutable_store: bool,
    pub global_retrieval: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct NativeBuildTerminalDecision {
    pub reservation_and_fence: bool,
    pub exact_terminal: bool,
    pub cas_inclusion: bool,
    pub immutable_store: bool,
    pub global_retrieval: bool,
    pub decision_sha256: Digest,
}

impl NativeBuildTerminalDecision {
    fn require_source_readback(&self) -> Result<()> {
        if self.reservation_and_fence
            && self.exact_terminal
            && self.cas_inclusion
            && self.immutable_store
            && self.global_retrieval
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "native verifier rejected source build terminal readback",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignedTrustedTime {
    pub unix_ms: u64,
    pub signed_evidence: EvidenceReference,
}

pub trait TrustedTimeAuthority: Send + Sync {
    fn signed_now(&self) -> Result<SignedTrustedTime>;
    fn verify_order_and_deadline(
        &self,
        start: &SignedTrustedTime,
        end: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<EvidenceReference>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentTerminalKind {
    Clean,
    Failure,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct RawBoundedProviderCallEvidence {
    pub operation_sha256: Digest,
    pub request_sha256: Digest,
    pub fixed_plan_manifest_sha256: Digest,
    pub deadline_unix_ms: u64,
    pub worker_started_monotonic_ns: u64,
    pub worker_deadline_monotonic_ns: u64,
    pub worker_finished_monotonic_ns: u64,
    pub worker_process_identity: EvidenceReference,
    pub worker_pidfd_identity: EvidenceReference,
    pub monotonic_deadline_binding: EvidenceReference,
    pub result_or_terminal_binding: EvidenceReference,
    pub kill_and_bounded_reap: EvidenceReference,
    pub controller_reaper_boundary: EvidenceReference,
}

impl RawBoundedProviderCallEvidence {
    fn validate_shape(&self) -> Result<()> {
        let objects = bounded_provider_call_objects(self);
        if objects
            .iter()
            .map(|object| object.reference_sha256)
            .collect::<BTreeSet<_>>()
            .len()
            != objects.len()
        {
            return Err(ControllerError::Rejected(
                "provider call evidence objects are not distinct",
            ));
        }
        for object in objects {
            object.validate()?;
        }
        if self.operation_sha256 == [0; 32]
            || self.request_sha256 == [0; 32]
            || self.fixed_plan_manifest_sha256 == [0; 32]
            || self.deadline_unix_ms == 0
            || self.worker_started_monotonic_ns == 0
            || self.worker_deadline_monotonic_ns
                <= self.worker_started_monotonic_ns
            || self.worker_finished_monotonic_ns
                < self.worker_started_monotonic_ns
            || self.worker_finished_monotonic_ns
                > self.worker_deadline_monotonic_ns
        {
            return Err(ControllerError::Rejected(
                "provider call lacks an exact bounded-worker/deadline binding",
            ));
        }
        Ok(())
    }

    fn validate_against(&self, pre_execution: &VerifiedPreExecution) -> Result<()> {
        self.validate_shape()?;
        if self.request_sha256 != pre_execution.request.request_sha256
            || self.fixed_plan_manifest_sha256
                != pre_execution.launch.fixed_plan_manifest_sha256
            || self.deadline_unix_ms
                != pre_execution.request.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "provider call does not bind verified pre-execution",
            ));
        }
        Ok(())
    }

    fn validate_against_receipt_body(
        &self,
        body: &ControllerReceiptBody,
    ) -> Result<()> {
        self.validate_shape()?;
        if self.request_sha256 != body.exact_signed_request_sha256
            || self.fixed_plan_manifest_sha256
                != body.fixed_plan_manifest_sha256
            || self.deadline_unix_ms != body.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "receipt provider call does not bind the receipt body",
            ));
        }
        Ok(())
    }

    fn validate_against_direct_registration(
        &self,
        registration: &RawTrustedHostDirectSupervisorRegistration,
    ) -> Result<()> {
        self.validate_shape()?;
        if self.request_sha256 != registration.request_sha256
            || self.fixed_plan_manifest_sha256
                != registration.fixed_plan_manifest_sha256
            || self.deadline_unix_ms != registration.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "provider call does not bind the direct supervisor registration",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RawSupervisorCapabilityEvidence {
    pub preparation_provider_call: RawBoundedProviderCallEvidence,
    pub child_held_before_execution: EvidenceReference,
    pub retained_fd_launch_authority: EvidenceReference,
    pub supervision_authority: EvidenceReference,
    pub independent_watchdog_authority: EvidenceReference,
    pub durable_orphan_journal: EvidenceReference,
    pub controller_parent_reaper: EvidenceReference,
    pub runtime_no_launch_authority: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct TrustedHostSupervisorStateMachineMeasurements {
    pub shared_module_sha256: Digest,
    pub backend_executable_sha256: Digest,
    pub controller_process_identity_sha256: Digest,
    pub immutable_config_sha256: Digest,
    pub durable_orphan_journal_identity_sha256: Digest,
    pub exact_measurement: EvidenceReference,
}

pub fn trusted_host_supervisor_state_machine_sha256(
    measurements: &TrustedHostSupervisorStateMachineMeasurements,
) -> Digest {
    let mut bytes = Vec::with_capacity(224);
    bytes.extend_from_slice(
        b"serverware-controller-v11/shared-trusted-host-supervisor-state-machine\0",
    );
    bytes.extend_from_slice(&measurements.shared_module_sha256);
    bytes.extend_from_slice(&measurements.backend_executable_sha256);
    bytes.extend_from_slice(
        &measurements.controller_process_identity_sha256,
    );
    bytes.extend_from_slice(&measurements.immutable_config_sha256);
    bytes.extend_from_slice(
        &measurements.durable_orphan_journal_identity_sha256,
    );
    sha256(&bytes)
}

#[derive(Debug)]
pub struct RawSupervisorKernelPreparation {
    pub child: SupervisorChildHandle,
    pub capabilities: RawSupervisorCapabilityEvidence,
}

#[derive(Debug)]
pub struct RawSupervisorPreparedExecution {
    pub child: SupervisorChildHandle,
    pub capabilities: RawSupervisorCapabilityEvidence,
    pub shared_state_machine_identity_sha256: Digest,
    pub shared_state_machine_measurement: EvidenceReference,
    pub preparation_transition_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct NativeSupervisorExecutionGateDecision {
    pub exact_pre_execution_and_manifest_binding: bool,
    pub child_held_before_execution: bool,
    pub retained_fd_launch_capability: bool,
    pub supervision_capability: bool,
    pub independent_watchdog_non_parent_non_reaper: bool,
    pub durable_orphan_journal_armed: bool,
    pub controller_sole_parent_and_reaper: bool,
    pub runtime_cannot_nominate_or_launch_pid: bool,
    pub shared_trusted_host_state_machine: bool,
    pub exact_state_machine_preparation_transition: bool,
    pub provider_call_bounded_worker_and_deadline: bool,
    pub worker_pidfd_kill_and_bounded_reap: bool,
    pub decision_sha256: Digest,
}

impl NativeSupervisorExecutionGateDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_pre_execution_and_manifest_binding
            && self.child_held_before_execution
            && self.retained_fd_launch_capability
            && self.supervision_capability
            && self.independent_watchdog_non_parent_non_reaper
            && self.durable_orphan_journal_armed
            && self.controller_sole_parent_and_reaper
            && self.runtime_cannot_nominate_or_launch_pid
            && self.shared_trusted_host_state_machine
            && self.exact_state_machine_preparation_transition
            && self.provider_call_bounded_worker_and_deadline
            && self.worker_pidfd_kill_and_bounded_reap
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "native verifier rejected the supervisor execution gate",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSupervisorExecutionAuthorization {
    decision_sha256: Digest,
    registration_binding_sha256: Digest,
    shared_state_machine_identity_sha256: Digest,
    preparation_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

#[derive(Debug)]
pub struct VerifiedSupervisorExecutionGate {
    child: SupervisorChildHandle,
    capabilities: RawSupervisorCapabilityEvidence,
    authorization: VerifiedSupervisorExecutionAuthorization,
    shared_state_machine_measurement: EvidenceReference,
    authorization_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedSupervisorExecutionGate {
    fn from_state_machine_authorization(
        raw: RawSupervisorPreparedExecution,
        authorization: VerifiedSupervisorExecutionAuthorization,
        authorization_transition_sha256: Digest,
    ) -> Self {
        Self {
            child: raw.child,
            capabilities: raw.capabilities,
            authorization,
            shared_state_machine_measurement:
                raw.shared_state_machine_measurement,
            authorization_transition_sha256,
            _seal: capability_seal::Seal,
        }
    }

    pub fn pid(&self) -> i32 {
        self.child.pid()
    }

    pub fn authorization_sha256(&self) -> Digest {
        self.authorization.decision_sha256
    }

    pub fn registration_binding_sha256(&self) -> Digest {
        self.child.registration_binding_sha256()
    }

    pub fn fixed_plan_manifest_sha256(&self) -> Digest {
        self.child.fixed_plan_manifest_sha256
    }

    pub fn shared_state_machine_identity_sha256(&self) -> Digest {
        self.authorization.shared_state_machine_identity_sha256
    }

    pub fn preparation_transition_sha256(&self) -> Digest {
        self.authorization.preparation_transition_sha256
    }

    pub fn authorization_transition_sha256(&self) -> Digest {
        self.authorization_transition_sha256
    }

    pub fn shared_state_machine_measurement(&self) -> &EvidenceReference {
        &self.shared_state_machine_measurement
    }

    fn child(&self) -> &SupervisorChildHandle {
        &self.child
    }

    fn capabilities(&self) -> &RawSupervisorCapabilityEvidence {
        &self.capabilities
    }
}

#[derive(Clone, Debug)]
pub struct RawSupervisorReleaseEvidence {
    pub verified_gate_sha256: Digest,
    pub shared_state_machine_identity_sha256: Digest,
    pub predecessor_transition_sha256: Digest,
    pub state_machine_transition_sha256: Digest,
    pub retained_fd_execveat_release: EvidenceReference,
    pub provider_call: RawBoundedProviderCallEvidence,
}

impl RawSupervisorReleaseEvidence {
    fn validate_against(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: &VerifiedSupervisorExecutionGate,
    ) -> Result<()> {
        self.retained_fd_execveat_release.validate()?;
        self.provider_call.validate_against(pre_execution)?;
        if self.verified_gate_sha256 != gate.authorization_sha256()
            || self.shared_state_machine_identity_sha256
                != gate.shared_state_machine_identity_sha256()
            || self.predecessor_transition_sha256 == [0; 32]
            || self.state_machine_transition_sha256 == [0; 32]
            || self
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != self.retained_fd_execveat_release.object_sha256
        {
            return Err(ControllerError::Rejected(
                "supervisor release does not exact-bind the verified gate",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RawContainmentTerminal {
    pub kind: ContainmentTerminalKind,
    pub shared_state_machine_identity_sha256: Digest,
    pub predecessor_transition_sha256: Digest,
    pub state_machine_transition_sha256: Digest,
    pub preconditions: EvidenceReference,
    pub pidfd_signal: EvidenceReference,
    pub cgroup_kill: EvidenceReference,
    pub process_group_kill: EvidenceReference,
    pub bounded_reap: EvidenceReference,
    pub watchdog_deadline_enforcement: EvidenceReference,
    pub controller_parent_reaper: EvidenceReference,
    pub durable_orphan_journal: EvidenceReference,
    pub orphan_journal_reconciliation: EvidenceReference,
    pub cgroup_events_empty: EvidenceReference,
    pub cgroup_procs_empty: EvidenceReference,
    pub provider_call: RawBoundedProviderCallEvidence,
}

#[derive(Clone, Debug)]
pub struct NativeContainmentDecision {
    pub exact_preconditions_and_terminal: bool,
    pub exact_shared_state_machine_transition: bool,
    pub pidfd_cgroup_and_process_group_kill: bool,
    pub controller_sole_parent_and_bounded_reaper: bool,
    pub independent_watchdog_non_parent_non_reaper: bool,
    pub watchdog_deadline_enforced: bool,
    pub durable_orphan_journal_reconciled: bool,
    pub cgroup_proved_empty: bool,
    pub provider_call_bounded_worker_and_deadline: bool,
    pub provider_worker_pidfd_killed_and_reaped: bool,
    pub decision_sha256: Digest,
}

impl NativeContainmentDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_preconditions_and_terminal
            && self.exact_shared_state_machine_transition
            && self.pidfd_cgroup_and_process_group_kill
            && self.controller_sole_parent_and_bounded_reaper
            && self.independent_watchdog_non_parent_non_reaper
            && self.watchdog_deadline_enforced
            && self.durable_orphan_journal_reconciled
            && self.cgroup_proved_empty
            && self.provider_call_bounded_worker_and_deadline
            && self.provider_worker_pidfd_killed_and_reaped
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "native verifier rejected containment or orphan reconciliation",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedContainmentCleanup {
    terminal_sha256: Digest,
    _seal: capability_seal::Seal,
}

pub struct VerifiedSupervisorAbortCapability {
    registration_binding_sha256: Digest,
    shared_state_machine_identity_sha256: Digest,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedSupervisorAbortCapability {
    pub fn registration_binding_sha256(&self) -> Digest {
        self.registration_binding_sha256
    }

    pub fn shared_state_machine_identity_sha256(&self) -> Digest {
        self.shared_state_machine_identity_sha256
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub struct VerifiedSupervisorReleaseCapability<'a> {
    gate: &'a VerifiedSupervisorExecutionGate,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl<'a> VerifiedSupervisorReleaseCapability<'a> {
    pub fn gate(&self) -> &VerifiedSupervisorExecutionGate {
        self.gate
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub struct VerifiedSupervisorContainmentCapability {
    gate: VerifiedSupervisorExecutionGate,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedSupervisorContainmentCapability {
    pub fn gate(&self) -> &VerifiedSupervisorExecutionGate {
        &self.gate
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub trait TrustedHostSupervisorKernelBackend: Send + Sync {
    // This backend performs only measured kernel operations requested by the
    // shared state machine. Release and containment require nonconstructible
    // capabilities; no production provider accepts this backend directly.
    fn prepare_held_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        no_build: Option<&VerifiedNoBuildKernelCapability>,
        trusted_start: &SignedTrustedTime,
    ) -> Result<RawSupervisorKernelPreparation>;
    fn abort_held_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        prepared: RawSupervisorKernelPreparation,
        capability: VerifiedSupervisorAbortCapability,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
    fn release_held_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        capability: &VerifiedSupervisorReleaseCapability<'_>,
        trusted_start: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<RawSupervisorReleaseEvidence>;
    fn terminate_and_reap(
        &self,
        pre_execution: &VerifiedPreExecution,
        capability: VerifiedSupervisorContainmentCapability,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum SupervisorStatePhase {
    Prepared = 1,
    Authorized = 2,
    Releasing = 3,
    Running = 4,
    ReleaseUncertain = 5,
    Aborting = 6,
    Terminating = 7,
    Closed = 8,
    ContainmentUncertain = 9,
}

#[derive(Clone, Copy, Debug)]
struct SupervisorStateRecord {
    request_sha256: Digest,
    fixed_plan_manifest_sha256: Digest,
    authorization_sha256: Digest,
    phase: SupervisorStatePhase,
    last_transition_sha256: Digest,
}

fn supervisor_state_transition_sha256(
    state_machine_identity_sha256: Digest,
    registration_binding_sha256: Digest,
    request_sha256: Digest,
    fixed_plan_manifest_sha256: Digest,
    authorization_sha256: Digest,
    previous_transition_sha256: Digest,
    phase: SupervisorStatePhase,
) -> Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(
        b"serverware-controller-v11/shared-supervisor-transition\0",
    );
    bytes.extend_from_slice(&state_machine_identity_sha256);
    bytes.extend_from_slice(&registration_binding_sha256);
    bytes.extend_from_slice(&request_sha256);
    bytes.extend_from_slice(&fixed_plan_manifest_sha256);
    bytes.extend_from_slice(&authorization_sha256);
    bytes.extend_from_slice(&previous_transition_sha256);
    bytes.push(phase as u8);
    sha256(&bytes)
}

pub struct TrustedHostSupervisorStateMachine {
    backend: Arc<dyn TrustedHostSupervisorKernelBackend>,
    measurements: TrustedHostSupervisorStateMachineMeasurements,
    identity_sha256: Digest,
    states: Mutex<BTreeMap<Digest, SupervisorStateRecord>>,
}

impl TrustedHostSupervisorStateMachine {
    pub fn measured_trusted_host(
        backend: Arc<dyn TrustedHostSupervisorKernelBackend>,
        measurements: TrustedHostSupervisorStateMachineMeasurements,
    ) -> Result<Self> {
        measurements.exact_measurement.validate()?;
        let identity_sha256 =
            trusted_host_supervisor_state_machine_sha256(&measurements);
        if [
            measurements.shared_module_sha256,
            measurements.backend_executable_sha256,
            measurements.controller_process_identity_sha256,
            measurements.immutable_config_sha256,
            measurements.durable_orphan_journal_identity_sha256,
            identity_sha256,
        ]
        .iter()
        .any(|measurement| *measurement == [0; 32])
            || measurements.exact_measurement.object_sha256
                != identity_sha256
        {
            return Err(ControllerError::Unready(vec![
                "shared trusted-host supervisor measurements are incomplete or mismatched"
                    .to_owned(),
            ]));
        }
        Ok(Self {
            backend,
            measurements,
            identity_sha256,
            states: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn identity_sha256(&self) -> Digest {
        self.identity_sha256
    }

    fn lock_states(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<Digest, SupervisorStateRecord>>> {
        self.states.lock().map_err(|_| {
            ControllerError::Rejected(
                "shared supervisor state machine lock is poisoned",
            )
        })
    }

    fn transition(
        &self,
        registration_binding_sha256: Digest,
        record: &SupervisorStateRecord,
        phase: SupervisorStatePhase,
    ) -> Digest {
        supervisor_state_transition_sha256(
            self.identity_sha256,
            registration_binding_sha256,
            record.request_sha256,
            record.fixed_plan_manifest_sha256,
            record.authorization_sha256,
            record.last_transition_sha256,
            phase,
        )
    }

    pub fn prepare_registered_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        no_build: Option<&VerifiedNoBuildKernelCapability>,
        trusted_start: &SignedTrustedTime,
    ) -> Result<RawSupervisorPreparedExecution> {
        if self.measurements.immutable_config_sha256
            != pre_execution.request.config_sha256
        {
            return Err(ControllerError::Rejected(
                "shared supervisor state machine config measurement changed",
            ));
        }
        let raw = self.backend.prepare_held_child(
            pre_execution,
            no_build,
            trusted_start,
        )?;
        raw.child.validate_supervisor_binding(pre_execution)?;
        let registration_binding_sha256 =
            raw.child.registration_binding_sha256();
        let preparation_transition_sha256 =
            supervisor_state_transition_sha256(
                self.identity_sha256,
                registration_binding_sha256,
                pre_execution.request.request_sha256,
                pre_execution.launch.fixed_plan_manifest_sha256,
                [0; 32],
                [0; 32],
                SupervisorStatePhase::Prepared,
            );
        let record = SupervisorStateRecord {
            request_sha256: pre_execution.request.request_sha256,
            fixed_plan_manifest_sha256:
                pre_execution.launch.fixed_plan_manifest_sha256,
            authorization_sha256: [0; 32],
            phase: SupervisorStatePhase::Prepared,
            last_transition_sha256: preparation_transition_sha256,
        };
        let mut states = self.lock_states()?;
        if states.contains_key(&registration_binding_sha256) {
            drop(states);
            let mut duplicate_record = record;
            let abort_transition_sha256 = self.transition(
                registration_binding_sha256,
                &duplicate_record,
                SupervisorStatePhase::Aborting,
            );
            duplicate_record.phase = SupervisorStatePhase::Aborting;
            duplicate_record.last_transition_sha256 =
                abort_transition_sha256;
            let completion_transition_sha256 = self.transition(
                registration_binding_sha256,
                &duplicate_record,
                SupervisorStatePhase::Closed,
            );
            let capability = VerifiedSupervisorAbortCapability {
                registration_binding_sha256,
                shared_state_machine_identity_sha256: self.identity_sha256,
                transition_sha256: abort_transition_sha256,
                completion_transition_sha256,
                _seal: capability_seal::Seal,
            };
            let cleanup = self.backend.abort_held_child(
                pre_execution,
                raw,
                capability,
                pre_execution.request.deadline_unix_ms,
            );
            return match cleanup {
                Ok(terminal)
                    if terminal.shared_state_machine_identity_sha256
                        == self.identity_sha256
                        && terminal.predecessor_transition_sha256
                            == abort_transition_sha256
                        && terminal.state_machine_transition_sha256
                        == completion_transition_sha256 =>
                {
                    Err(ControllerError::Rejected(
                        "shared supervisor registration was already used",
                    ))
                }
                Ok(_) => Err(ControllerError::Unready(vec![
                    "duplicate supervisor registration cleanup returned an unbound transition"
                        .to_owned(),
                ])),
                Err(error) => Err(ControllerError::Unready(vec![format!(
                    "duplicate supervisor registration cleanup failed: {error}"
                )])),
            };
        }
        states.insert(registration_binding_sha256, record);
        drop(states);
        Ok(RawSupervisorPreparedExecution {
            child: raw.child,
            capabilities: raw.capabilities,
            shared_state_machine_identity_sha256: self.identity_sha256,
            shared_state_machine_measurement:
                self.measurements.exact_measurement.clone(),
            preparation_transition_sha256,
        })
    }

    pub fn authorize_verified_preparation(
        &self,
        pre_execution: &VerifiedPreExecution,
        raw: RawSupervisorPreparedExecution,
        authorization: VerifiedSupervisorExecutionAuthorization,
    ) -> Result<VerifiedSupervisorExecutionGate> {
        let registration_binding_sha256 =
            raw.child.registration_binding_sha256();
        let validation = (|| -> Result<Digest> {
            if raw.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || raw.shared_state_machine_measurement.reference_sha256
                    != self
                        .measurements
                        .exact_measurement
                        .reference_sha256
                || authorization.registration_binding_sha256
                    != registration_binding_sha256
                || authorization.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || authorization.preparation_transition_sha256
                    != raw.preparation_transition_sha256
            {
                return Err(ControllerError::Rejected(
                    "verified authorization does not bind the shared supervisor state machine",
                ));
            }
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "shared supervisor preparation is not registered",
                ))?;
            if record.phase != SupervisorStatePhase::Prepared
                || record.last_transition_sha256
                    != raw.preparation_transition_sha256
            {
                return Err(ControllerError::Rejected(
                    "shared supervisor preparation is not authorizable",
                ));
            }
            record.authorization_sha256 = authorization.decision_sha256;
            let transition = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Authorized,
            );
            record.phase = SupervisorStatePhase::Authorized;
            record.last_transition_sha256 = transition;
            Ok(transition)
        })();
        match validation {
            Ok(authorization_transition_sha256) => {
                Ok(VerifiedSupervisorExecutionGate::from_state_machine_authorization(
                    raw,
                    authorization,
                    authorization_transition_sha256,
                ))
            }
            Err(error) => {
                let cleanup = self.abort_unverified_preparation(
                    pre_execution,
                    raw,
                    pre_execution.request.deadline_unix_ms,
                );
                match cleanup {
                    Ok(_) => Err(error),
                    Err(cleanup_error) => Err(ControllerError::InvalidOwned(
                        format!(
                            "shared supervisor authorization failed: {error}; held-child cleanup failed: {cleanup_error}"
                        ),
                    )),
                }
            }
        }
    }

    pub fn abort_unverified_preparation(
        &self,
        pre_execution: &VerifiedPreExecution,
        prepared: RawSupervisorPreparedExecution,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal> {
        let registration_binding_sha256 =
            prepared.child.registration_binding_sha256();
        let (
            abort_transition_sha256,
            completion_transition_sha256,
        ) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "shared supervisor abort lacks a registered preparation",
                ))?;
            if record.phase != SupervisorStatePhase::Prepared {
                return Err(ControllerError::Rejected(
                    "shared supervisor abort is outside the prepared phase",
                ));
            }
            let transition = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Aborting,
            );
            record.phase = SupervisorStatePhase::Aborting;
            record.last_transition_sha256 = transition;
            let completion = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Closed,
            );
            (transition, completion)
        };
        let capability = VerifiedSupervisorAbortCapability {
            registration_binding_sha256,
            shared_state_machine_identity_sha256: self.identity_sha256,
            transition_sha256: abort_transition_sha256,
            completion_transition_sha256,
            _seal: capability_seal::Seal,
        };
        let kernel_preparation = RawSupervisorKernelPreparation {
            child: prepared.child,
            capabilities: prepared.capabilities,
        };
        match self.backend.abort_held_child(
            pre_execution,
            kernel_preparation,
            capability,
            deadline_unix_ms,
        ) {
            Ok(mut terminal) => {
                if terminal.shared_state_machine_identity_sha256
                        != self.identity_sha256
                    || terminal.predecessor_transition_sha256
                        != abort_transition_sha256
                    || terminal.state_machine_transition_sha256
                        != completion_transition_sha256
                {
                    if let Ok(mut states) = self.states.lock() {
                        if let Some(record) =
                            states.get_mut(&registration_binding_sha256)
                        {
                            let transition = self.transition(
                                registration_binding_sha256,
                                record,
                                SupervisorStatePhase::ContainmentUncertain,
                            );
                            record.phase =
                                SupervisorStatePhase::ContainmentUncertain;
                            record.last_transition_sha256 = transition;
                        }
                    }
                    return Err(ControllerError::Unready(vec![
                        "held-child abort did not bind the shared completion transition"
                            .to_owned(),
                    ]));
                }
                let mut states = self.lock_states()?;
                let record = states
                    .get_mut(&registration_binding_sha256)
                    .ok_or(ControllerError::Rejected(
                        "shared supervisor abort state disappeared",
                    ))?;
                record.phase = SupervisorStatePhase::Closed;
                record.last_transition_sha256 =
                    completion_transition_sha256;
                terminal.state_machine_transition_sha256 =
                    completion_transition_sha256;
                Ok(terminal)
            }
            Err(error) => {
                if let Ok(mut states) = self.states.lock() {
                    if let Some(record) =
                        states.get_mut(&registration_binding_sha256)
                    {
                        let transition = self.transition(
                            registration_binding_sha256,
                            record,
                            SupervisorStatePhase::ContainmentUncertain,
                        );
                        record.phase =
                            SupervisorStatePhase::ContainmentUncertain;
                        record.last_transition_sha256 = transition;
                    }
                }
                Err(error)
            }
        }
    }

    pub fn release_verified_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: &VerifiedSupervisorExecutionGate,
        trusted_start: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<RawSupervisorReleaseEvidence> {
        let registration_binding_sha256 =
            gate.registration_binding_sha256();
        let (
            release_transition_sha256,
            completion_transition_sha256,
        ) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "shared supervisor release lacks an authorized registration",
                ))?;
            if record.phase != SupervisorStatePhase::Authorized
                || record.authorization_sha256
                    != gate.authorization_sha256()
                || gate.shared_state_machine_identity_sha256()
                    != self.identity_sha256
            {
                return Err(ControllerError::Rejected(
                    "shared supervisor release is outside the authorized phase",
                ));
            }
            let transition = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Releasing,
            );
            record.phase = SupervisorStatePhase::Releasing;
            record.last_transition_sha256 = transition;
            let completion = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Running,
            );
            (transition, completion)
        };
        let capability = VerifiedSupervisorReleaseCapability {
            gate,
            transition_sha256: release_transition_sha256,
            completion_transition_sha256,
            _seal: capability_seal::Seal,
        };
        match self.backend.release_held_child(
            pre_execution,
            &capability,
            trusted_start,
            deadline_unix_ms,
        ) {
            Ok(mut release) => {
                if release.shared_state_machine_identity_sha256
                        != self.identity_sha256
                    || release.predecessor_transition_sha256
                        != release_transition_sha256
                    || release.state_machine_transition_sha256
                        != completion_transition_sha256
                {
                    if let Ok(mut states) = self.states.lock() {
                        if let Some(record) =
                            states.get_mut(&registration_binding_sha256)
                        {
                            let transition = self.transition(
                                registration_binding_sha256,
                                record,
                                SupervisorStatePhase::ReleaseUncertain,
                            );
                            record.phase =
                                SupervisorStatePhase::ReleaseUncertain;
                            record.last_transition_sha256 = transition;
                        }
                    }
                    return Err(ControllerError::Unready(vec![
                        "child release did not bind the shared completion transition"
                            .to_owned(),
                    ]));
                }
                let mut states = self.lock_states()?;
                let record = states
                    .get_mut(&registration_binding_sha256)
                    .ok_or(ControllerError::Rejected(
                        "shared supervisor release state disappeared",
                    ))?;
                record.phase = SupervisorStatePhase::Running;
                record.last_transition_sha256 =
                    completion_transition_sha256;
                release.state_machine_transition_sha256 =
                    completion_transition_sha256;
                Ok(release)
            }
            Err(error) => {
                if let Ok(mut states) = self.states.lock() {
                    if let Some(record) =
                        states.get_mut(&registration_binding_sha256)
                    {
                        let transition = self.transition(
                            registration_binding_sha256,
                            record,
                            SupervisorStatePhase::ReleaseUncertain,
                        );
                        record.phase = SupervisorStatePhase::ReleaseUncertain;
                        record.last_transition_sha256 = transition;
                    }
                }
                Err(error)
            }
        }
    }

    pub fn supervise_and_terminate(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: VerifiedSupervisorExecutionGate,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal> {
        let registration_binding_sha256 =
            gate.registration_binding_sha256();
        let (
            termination_transition_sha256,
            completion_transition_sha256,
        ) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "shared supervisor containment lacks a registration",
                ))?;
            if !matches!(
                record.phase,
                SupervisorStatePhase::Authorized
                    | SupervisorStatePhase::Releasing
                    | SupervisorStatePhase::Running
                    | SupervisorStatePhase::ReleaseUncertain
            ) || record.authorization_sha256
                != gate.authorization_sha256()
                || gate.shared_state_machine_identity_sha256()
                    != self.identity_sha256
            {
                return Err(ControllerError::Rejected(
                    "shared supervisor containment is outside a live phase",
                ));
            }
            let transition = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Terminating,
            );
            record.phase = SupervisorStatePhase::Terminating;
            record.last_transition_sha256 = transition;
            let completion = self.transition(
                registration_binding_sha256,
                record,
                SupervisorStatePhase::Closed,
            );
            (transition, completion)
        };
        let capability = VerifiedSupervisorContainmentCapability {
            gate,
            transition_sha256: termination_transition_sha256,
            completion_transition_sha256,
            _seal: capability_seal::Seal,
        };
        match self.backend.terminate_and_reap(
            pre_execution,
            capability,
            deadline_unix_ms,
        ) {
            Ok(mut terminal) => {
                if terminal.shared_state_machine_identity_sha256
                        != self.identity_sha256
                    || terminal.predecessor_transition_sha256
                        != termination_transition_sha256
                    || terminal.state_machine_transition_sha256
                        != completion_transition_sha256
                {
                    if let Ok(mut states) = self.states.lock() {
                        if let Some(record) =
                            states.get_mut(&registration_binding_sha256)
                        {
                            let transition = self.transition(
                                registration_binding_sha256,
                                record,
                                SupervisorStatePhase::ContainmentUncertain,
                            );
                            record.phase =
                                SupervisorStatePhase::ContainmentUncertain;
                            record.last_transition_sha256 = transition;
                        }
                    }
                    return Err(ControllerError::Unready(vec![
                        "child containment did not bind the shared completion transition"
                            .to_owned(),
                    ]));
                }
                let mut states = self.lock_states()?;
                let record = states
                    .get_mut(&registration_binding_sha256)
                    .ok_or(ControllerError::Rejected(
                        "shared supervisor containment state disappeared",
                    ))?;
                record.phase = SupervisorStatePhase::Closed;
                record.last_transition_sha256 =
                    completion_transition_sha256;
                terminal.state_machine_transition_sha256 =
                    completion_transition_sha256;
                Ok(terminal)
            }
            Err(error) => {
                if let Ok(mut states) = self.states.lock() {
                    if let Some(record) =
                        states.get_mut(&registration_binding_sha256)
                    {
                        let transition = self.transition(
                            registration_binding_sha256,
                            record,
                            SupervisorStatePhase::ContainmentUncertain,
                        );
                        record.phase =
                            SupervisorStatePhase::ContainmentUncertain;
                        record.last_transition_sha256 = transition;
                    }
                }
                Err(error)
            }
        }
    }
}

pub trait LinuxChildSupervisorBoundary: Send + Sync {
    fn prepare_registered_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        no_build: Option<&VerifiedNoBuildKernelCapability>,
        trusted_start: &SignedTrustedTime,
    ) -> Result<RawSupervisorPreparedExecution>;
    fn abort_unverified_preparation(
        &self,
        pre_execution: &VerifiedPreExecution,
        prepared: RawSupervisorPreparedExecution,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
    fn release_verified_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: &VerifiedSupervisorExecutionGate,
        trusted_start: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<RawSupervisorReleaseEvidence>;
    fn supervise_and_terminate(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: VerifiedSupervisorExecutionGate,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
}

impl LinuxChildSupervisorBoundary for TrustedHostSupervisorStateMachine {
    fn prepare_registered_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        no_build: Option<&VerifiedNoBuildKernelCapability>,
        trusted_start: &SignedTrustedTime,
    ) -> Result<RawSupervisorPreparedExecution> {
        TrustedHostSupervisorStateMachine::prepare_registered_child(
            self,
            pre_execution,
            no_build,
            trusted_start,
        )
    }

    fn abort_unverified_preparation(
        &self,
        pre_execution: &VerifiedPreExecution,
        prepared: RawSupervisorPreparedExecution,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal> {
        TrustedHostSupervisorStateMachine::abort_unverified_preparation(
            self,
            pre_execution,
            prepared,
            deadline_unix_ms,
        )
    }

    fn release_verified_child(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: &VerifiedSupervisorExecutionGate,
        trusted_start: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<RawSupervisorReleaseEvidence> {
        TrustedHostSupervisorStateMachine::release_verified_child(
            self,
            pre_execution,
            gate,
            trusted_start,
            deadline_unix_ms,
        )
    }

    fn supervise_and_terminate(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: VerifiedSupervisorExecutionGate,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal> {
        TrustedHostSupervisorStateMachine::supervise_and_terminate(
            self,
            pre_execution,
            gate,
            deadline_unix_ms,
        )
    }
}

#[derive(Clone, Debug)]
pub struct RawTrustedHostDirectSupervisorRegistration {
    pub registration_binding_sha256: Digest,
    pub request_sha256: Digest,
    pub config_sha256: Digest,
    pub fixed_plan_manifest_sha256: Digest,
    pub current_lane_command_identity_sha256: Digest,
    pub deadline_unix_ms: u64,
    pub exact_registration: EvidenceReference,
    pub registered_child_identity: EvidenceReference,
    pub child_held_before_execution: EvidenceReference,
    pub pidfd_identity: EvidenceReference,
    pub cgroup_identity: EvidenceReference,
    pub controller_parent_reaper: EvidenceReference,
    pub independent_watchdog_authority: EvidenceReference,
    pub durable_orphan_journal: EvidenceReference,
}

pub fn trusted_host_direct_supervisor_registration_sha256(
    raw: &RawTrustedHostDirectSupervisorRegistration,
) -> Digest {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(
        b"serverware-controller-v11/direct-supervisor-registration\0",
    );
    bytes.extend_from_slice(&raw.request_sha256);
    bytes.extend_from_slice(&raw.config_sha256);
    bytes.extend_from_slice(&raw.fixed_plan_manifest_sha256);
    bytes.extend_from_slice(&raw.current_lane_command_identity_sha256);
    bytes.extend_from_slice(&raw.deadline_unix_ms.to_be_bytes());
    for object in [
        &raw.registered_child_identity,
        &raw.child_held_before_execution,
        &raw.pidfd_identity,
        &raw.cgroup_identity,
        &raw.controller_parent_reaper,
        &raw.independent_watchdog_authority,
        &raw.durable_orphan_journal,
    ] {
        bytes.extend_from_slice(&object.reference_sha256);
    }
    sha256(&bytes)
}

pub fn trusted_host_direct_release_evidence_sha256(
    registration_binding_sha256: Digest,
    authorization_sha256: Digest,
    predecessor_transition_sha256: Digest,
    completion_transition_sha256: Digest,
) -> Digest {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(
        b"serverware-controller-v11/direct-supervisor-release-evidence\0",
    );
    bytes.extend_from_slice(&registration_binding_sha256);
    bytes.extend_from_slice(&authorization_sha256);
    bytes.extend_from_slice(&predecessor_transition_sha256);
    bytes.extend_from_slice(&completion_transition_sha256);
    sha256(&bytes)
}

pub fn trusted_host_direct_containment_evidence_sha256(
    registration_binding_sha256: Digest,
    authorization_sha256: Digest,
    predecessor_transition_sha256: Digest,
    completion_transition_sha256: Digest,
) -> Digest {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(
        b"serverware-controller-v11/direct-supervisor-containment-evidence\0",
    );
    bytes.extend_from_slice(&registration_binding_sha256);
    bytes.extend_from_slice(&authorization_sha256);
    bytes.extend_from_slice(&predecessor_transition_sha256);
    bytes.extend_from_slice(&completion_transition_sha256);
    sha256(&bytes)
}

impl RawTrustedHostDirectSupervisorRegistration {
    fn validate_shape(&self) -> Result<()> {
        let objects = [
            &self.exact_registration,
            &self.registered_child_identity,
            &self.child_held_before_execution,
            &self.pidfd_identity,
            &self.cgroup_identity,
            &self.controller_parent_reaper,
            &self.independent_watchdog_authority,
            &self.durable_orphan_journal,
        ];
        for object in objects {
            object.validate()?;
        }
        if [
            self.registration_binding_sha256,
            self.request_sha256,
            self.config_sha256,
            self.fixed_plan_manifest_sha256,
            self.current_lane_command_identity_sha256,
        ]
        .iter()
        .any(|digest| *digest == [0; 32])
            || self.deadline_unix_ms == 0
            || self.registration_binding_sha256
                != trusted_host_direct_supervisor_registration_sha256(self)
            || self.exact_registration.object_sha256
                != self.registration_binding_sha256
        {
            return Err(ControllerError::Rejected(
                "direct supervisor registration is empty or noncanonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NativeTrustedHostDirectSupervisorDecision {
    pub exact_opaque_registration: bool,
    pub measured_shared_state_machine: bool,
    pub exact_config_manifest_command_and_deadline: bool,
    pub child_held_before_execution: bool,
    pub registered_child_and_pidfd_identity: bool,
    pub controller_sole_parent_and_reaper: bool,
    pub independent_watchdog_non_parent_non_reaper: bool,
    pub durable_orphan_journal_armed: bool,
    pub no_release_before_authorization: bool,
    pub decision_sha256: Digest,
}

impl NativeTrustedHostDirectSupervisorDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_opaque_registration
            && self.measured_shared_state_machine
            && self.exact_config_manifest_command_and_deadline
            && self.child_held_before_execution
            && self.registered_child_and_pidfd_identity
            && self.controller_sole_parent_and_reaper
            && self.independent_watchdog_non_parent_non_reaper
            && self.durable_orphan_journal_armed
            && self.no_release_before_authorization
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "pinned verifier rejected direct supervisor registration",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeTrustedHostDirectReleaseDecision {
    pub exact_gate_and_registration: bool,
    pub exact_state_machine_transition: bool,
    pub retained_fd_execveat_release: bool,
    pub provider_call_bounded_worker_and_deadline: bool,
    pub provider_worker_pidfd_killed_and_reaped: bool,
    pub no_daemon_local_release_bypass: bool,
    pub decision_sha256: Digest,
}

impl NativeTrustedHostDirectReleaseDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_gate_and_registration
            && self.exact_state_machine_transition
            && self.retained_fd_execveat_release
            && self.provider_call_bounded_worker_and_deadline
            && self.provider_worker_pidfd_killed_and_reaped
            && self.no_daemon_local_release_bypass
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "pinned verifier rejected direct supervisor release",
            ))
        }
    }
}

pub trait PinnedTrustedHostDirectSupervisorVerifier: Send + Sync {
    fn verify_direct_registration(
        &self,
        registration: &RawTrustedHostDirectSupervisorRegistration,
        shared_state_machine_identity_sha256: Digest,
        shared_state_machine_measurement: &EvidenceReference,
    ) -> Result<NativeTrustedHostDirectSupervisorDecision>;
    fn verify_direct_release(
        &self,
        gate: &VerifiedTrustedHostDirectSupervisorGate,
        release: &RawSupervisorReleaseEvidence,
    ) -> Result<NativeTrustedHostDirectReleaseDecision>;
    fn verify_direct_containment(
        &self,
        registration: &RawTrustedHostDirectSupervisorRegistration,
        authorization_sha256: Digest,
        terminal: &RawContainmentTerminal,
    ) -> Result<NativeContainmentDecision>;
}

pub struct VerifiedTrustedHostDirectSupervisorGate {
    registration: RawTrustedHostDirectSupervisorRegistration,
    shared_state_machine_identity_sha256: Digest,
    shared_state_machine_measurement: EvidenceReference,
    authorization_sha256: Digest,
    preparation_transition_sha256: Digest,
    authorization_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedTrustedHostDirectSupervisorGate {
    pub fn registration(
        &self,
    ) -> &RawTrustedHostDirectSupervisorRegistration {
        &self.registration
    }

    pub fn registration_binding_sha256(&self) -> Digest {
        self.registration.registration_binding_sha256
    }

    pub fn shared_state_machine_identity_sha256(&self) -> Digest {
        self.shared_state_machine_identity_sha256
    }

    pub fn shared_state_machine_measurement(&self) -> &EvidenceReference {
        &self.shared_state_machine_measurement
    }

    pub fn authorization_sha256(&self) -> Digest {
        self.authorization_sha256
    }

    pub fn preparation_transition_sha256(&self) -> Digest {
        self.preparation_transition_sha256
    }

    pub fn authorization_transition_sha256(&self) -> Digest {
        self.authorization_transition_sha256
    }
}

pub struct VerifiedTrustedHostDirectAbortCapability {
    registration: RawTrustedHostDirectSupervisorRegistration,
    shared_state_machine_identity_sha256: Digest,
    authorization_sha256: Digest,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedTrustedHostDirectAbortCapability {
    pub fn registration(
        &self,
    ) -> &RawTrustedHostDirectSupervisorRegistration {
        &self.registration
    }

    pub fn shared_state_machine_identity_sha256(&self) -> Digest {
        self.shared_state_machine_identity_sha256
    }

    pub fn authorization_sha256(&self) -> Digest {
        self.authorization_sha256
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub struct VerifiedTrustedHostDirectReleaseCapability<'a> {
    gate: &'a VerifiedTrustedHostDirectSupervisorGate,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl<'a> VerifiedTrustedHostDirectReleaseCapability<'a> {
    pub fn gate(&self) -> &VerifiedTrustedHostDirectSupervisorGate {
        self.gate
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub struct VerifiedTrustedHostDirectContainmentCapability {
    gate: VerifiedTrustedHostDirectSupervisorGate,
    transition_sha256: Digest,
    completion_transition_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedTrustedHostDirectContainmentCapability {
    pub fn gate(&self) -> &VerifiedTrustedHostDirectSupervisorGate {
        &self.gate
    }

    pub fn transition_sha256(&self) -> Digest {
        self.transition_sha256
    }

    pub fn completion_transition_sha256(&self) -> Digest {
        self.completion_transition_sha256
    }
}

pub trait TrustedHostDirectSupervisorBackend: Send + Sync {
    // Implementations keep the daemon's RegisteredChild in a private registry
    // keyed by registration_binding_sha256. They cannot release or reap it
    // through this API without a sealed capability issued by shared code.
    fn abort_registered_child(
        &self,
        capability: VerifiedTrustedHostDirectAbortCapability,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
    fn release_registered_child(
        &self,
        capability: &VerifiedTrustedHostDirectReleaseCapability<'_>,
        deadline_unix_ms: u64,
    ) -> Result<RawSupervisorReleaseEvidence>;
    fn terminate_registered_child(
        &self,
        capability: VerifiedTrustedHostDirectContainmentCapability,
        deadline_unix_ms: u64,
    ) -> Result<RawContainmentTerminal>;
}

pub struct TrustedHostDirectSupervisorStateMachine {
    backend: Option<Arc<dyn TrustedHostDirectSupervisorBackend>>,
    verifier: Arc<dyn PinnedTrustedHostDirectSupervisorVerifier>,
    measurements: TrustedHostSupervisorStateMachineMeasurements,
    identity_sha256: Digest,
    states: Mutex<BTreeMap<Digest, SupervisorStateRecord>>,
}

impl TrustedHostDirectSupervisorStateMachine {
    pub fn measured_trusted_host(
        backend: Arc<dyn TrustedHostDirectSupervisorBackend>,
        verifier: Arc<dyn PinnedTrustedHostDirectSupervisorVerifier>,
        measurements: TrustedHostSupervisorStateMachineMeasurements,
    ) -> Result<Self> {
        measurements.exact_measurement.validate()?;
        let identity_sha256 =
            trusted_host_supervisor_state_machine_sha256(&measurements);
        if [
            measurements.shared_module_sha256,
            measurements.backend_executable_sha256,
            measurements.controller_process_identity_sha256,
            measurements.immutable_config_sha256,
            measurements.durable_orphan_journal_identity_sha256,
            identity_sha256,
        ]
        .iter()
        .any(|measurement| *measurement == [0; 32])
            || measurements.exact_measurement.object_sha256
                != identity_sha256
        {
            return Err(ControllerError::Unready(vec![
                "direct supervisor state-machine measurements are incomplete or mismatched"
                    .to_owned(),
            ]));
        }
        Ok(Self {
            backend: Some(backend),
            verifier,
            measurements,
            identity_sha256,
            states: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn measured_trusted_host_capability_route(
        verifier: Arc<dyn PinnedTrustedHostDirectSupervisorVerifier>,
        measurements: TrustedHostSupervisorStateMachineMeasurements,
    ) -> Result<Self> {
        measurements.exact_measurement.validate()?;
        let identity_sha256 =
            trusted_host_supervisor_state_machine_sha256(&measurements);
        if [
            measurements.shared_module_sha256,
            measurements.backend_executable_sha256,
            measurements.controller_process_identity_sha256,
            measurements.immutable_config_sha256,
            measurements.durable_orphan_journal_identity_sha256,
            identity_sha256,
        ]
        .iter()
        .any(|measurement| *measurement == [0; 32])
            || measurements.exact_measurement.object_sha256
                != identity_sha256
        {
            return Err(ControllerError::Unready(vec![
                "direct supervisor capability-route measurements are incomplete or mismatched"
                    .to_owned(),
            ]));
        }
        Ok(Self {
            backend: None,
            verifier,
            measurements,
            identity_sha256,
            states: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn identity_sha256(&self) -> Digest {
        self.identity_sha256
    }

    fn lock_states(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<Digest, SupervisorStateRecord>>> {
        self.states.lock().map_err(|_| {
            ControllerError::Rejected(
                "direct supervisor state machine lock is poisoned",
            )
        })
    }

    fn transition(
        &self,
        registration_binding_sha256: Digest,
        record: &SupervisorStateRecord,
        phase: SupervisorStatePhase,
    ) -> Digest {
        supervisor_state_transition_sha256(
            self.identity_sha256,
            registration_binding_sha256,
            record.request_sha256,
            record.fixed_plan_manifest_sha256,
            record.authorization_sha256,
            record.last_transition_sha256,
            phase,
        )
    }

    fn verify_direct_terminal(
        &self,
        registration: &RawTrustedHostDirectSupervisorRegistration,
        authorization_sha256: Digest,
        expected_predecessor: Digest,
        expected_completion: Digest,
        terminal: &RawContainmentTerminal,
    ) -> Result<()> {
        terminal
            .provider_call
            .validate_against_direct_registration(registration)?;
        for object in containment_objects(terminal) {
            object.validate()?;
        }
        if terminal.shared_state_machine_identity_sha256
                != self.identity_sha256
            || terminal.predecessor_transition_sha256
                != expected_predecessor
            || terminal.state_machine_transition_sha256
                != expected_completion
            || terminal
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != containment_terminal_result_sha256(terminal)
        {
            return Err(ControllerError::Rejected(
                "direct containment does not bind the exact shared transition",
            ));
        }
        let decision = self.verifier.verify_direct_containment(
            registration,
            authorization_sha256,
            terminal,
        )?;
        decision.require_all()
    }

    fn cleanup_rejected_registration(
        &self,
        registration: &RawTrustedHostDirectSupervisorRegistration,
        authorization_sha256: Digest,
    ) -> Result<()> {
        let prepared = supervisor_state_transition_sha256(
            self.identity_sha256,
            registration.registration_binding_sha256,
            registration.request_sha256,
            registration.fixed_plan_manifest_sha256,
            [0; 32],
            [0; 32],
            SupervisorStatePhase::Prepared,
        );
        let aborting = supervisor_state_transition_sha256(
            self.identity_sha256,
            registration.registration_binding_sha256,
            registration.request_sha256,
            registration.fixed_plan_manifest_sha256,
            authorization_sha256,
            prepared,
            SupervisorStatePhase::Aborting,
        );
        let closed = supervisor_state_transition_sha256(
            self.identity_sha256,
            registration.registration_binding_sha256,
            registration.request_sha256,
            registration.fixed_plan_manifest_sha256,
            authorization_sha256,
            aborting,
            SupervisorStatePhase::Closed,
        );
        let capability = VerifiedTrustedHostDirectAbortCapability {
            registration: registration.clone(),
            shared_state_machine_identity_sha256: self.identity_sha256,
            authorization_sha256,
            transition_sha256: aborting,
            completion_transition_sha256: closed,
            _seal: capability_seal::Seal,
        };
        let backend = self.backend.as_ref().ok_or_else(|| {
            ControllerError::Unready(vec![
                "caller-owned held child requires explicit capability-route abort"
                    .to_owned(),
            ])
        })?;
        let terminal = backend.abort_registered_child(
            capability,
            registration.deadline_unix_ms,
        )?;
        self.verify_direct_terminal(
            registration,
            authorization_sha256,
            aborting,
            closed,
            &terminal,
        )
    }

    pub fn verify_and_authorize_registered_child(
        &self,
        registration: RawTrustedHostDirectSupervisorRegistration,
    ) -> Result<VerifiedTrustedHostDirectSupervisorGate> {
        let verification = (|| -> Result<NativeTrustedHostDirectSupervisorDecision> {
            registration.validate_shape()?;
            if registration.config_sha256
                != self.measurements.immutable_config_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct registration config differs from measured config",
                ));
            }
            let decision = self.verifier.verify_direct_registration(
                &registration,
                self.identity_sha256,
                &self.measurements.exact_measurement,
            )?;
            decision.require_all()?;
            Ok(decision)
        })();
        let decision = match verification {
            Ok(decision) => decision,
            Err(error) => {
                return match self
                    .cleanup_rejected_registration(&registration, [0; 32])
                {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(ControllerError::Unready(vec![
                        format!(
                            "direct registration verification failed: {error}; mandatory held-child cleanup failed: {cleanup_error}"
                        ),
                    ])),
                }
            }
        };
        let prepared = supervisor_state_transition_sha256(
            self.identity_sha256,
            registration.registration_binding_sha256,
            registration.request_sha256,
            registration.fixed_plan_manifest_sha256,
            [0; 32],
            [0; 32],
            SupervisorStatePhase::Prepared,
        );
        let authorized = supervisor_state_transition_sha256(
            self.identity_sha256,
            registration.registration_binding_sha256,
            registration.request_sha256,
            registration.fixed_plan_manifest_sha256,
            decision.decision_sha256,
            prepared,
            SupervisorStatePhase::Authorized,
        );
        let record = SupervisorStateRecord {
            request_sha256: registration.request_sha256,
            fixed_plan_manifest_sha256:
                registration.fixed_plan_manifest_sha256,
            authorization_sha256: decision.decision_sha256,
            phase: SupervisorStatePhase::Authorized,
            last_transition_sha256: authorized,
        };
        let mut states = match self.lock_states() {
            Ok(states) => states,
            Err(lock_error) => {
                return match self.cleanup_rejected_registration(
                    &registration,
                    decision.decision_sha256,
                ) {
                    Ok(()) => Err(lock_error),
                    Err(cleanup_error) => {
                        Err(ControllerError::Unready(vec![format!(
                            "direct supervisor state registration failed: {lock_error}; mandatory held-child cleanup failed: {cleanup_error}"
                        )]))
                    }
                };
            }
        };
        if states.contains_key(&registration.registration_binding_sha256) {
            drop(states);
            return match self.cleanup_rejected_registration(
                &registration,
                decision.decision_sha256,
            ) {
                Ok(()) => Err(ControllerError::Rejected(
                    "direct supervisor registration was already used",
                )),
                Err(cleanup_error) => Err(ControllerError::Unready(vec![
                    format!(
                        "duplicate direct registration cleanup failed: {cleanup_error}"
                    ),
                ])),
            };
        }
        states.insert(registration.registration_binding_sha256, record);
        drop(states);
        Ok(VerifiedTrustedHostDirectSupervisorGate {
            registration,
            shared_state_machine_identity_sha256: self.identity_sha256,
            shared_state_machine_measurement:
                self.measurements.exact_measurement.clone(),
            authorization_sha256: decision.decision_sha256,
            preparation_transition_sha256: prepared,
            authorization_transition_sha256: authorized,
            _seal: capability_seal::Seal,
        })
    }

    pub fn begin_capability_release<'a>(
        &self,
        gate: &'a VerifiedTrustedHostDirectSupervisorGate,
    ) -> Result<VerifiedTrustedHostDirectReleaseCapability<'a>> {
        let registration = gate.registration();
        let (releasing, running) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration.registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "direct release lacks an authorized registration",
                ))?;
            if record.phase != SupervisorStatePhase::Authorized
                || record.authorization_sha256
                    != gate.authorization_sha256
                || gate.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || gate.shared_state_machine_measurement.reference_sha256
                    != self.measurements.exact_measurement.reference_sha256
                || record.request_sha256 != registration.request_sha256
                || record.fixed_plan_manifest_sha256
                    != registration.fixed_plan_manifest_sha256
                || record.last_transition_sha256
                    != gate.authorization_transition_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct release is outside the authorized phase",
                ));
            }
            let releasing = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Releasing,
            );
            record.phase = SupervisorStatePhase::Releasing;
            record.last_transition_sha256 = releasing;
            let running = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Running,
            );
            (releasing, running)
        };
        Ok(VerifiedTrustedHostDirectReleaseCapability {
            gate,
            transition_sha256: releasing,
            completion_transition_sha256: running,
            _seal: capability_seal::Seal,
        })
    }

    pub fn complete_capability_release(
        &self,
        capability: VerifiedTrustedHostDirectReleaseCapability<'_>,
        exact_release_evidence: &EvidenceReference,
    ) -> Result<()> {
        exact_release_evidence.validate()?;
        let gate = capability.gate();
        let registration = gate.registration();
        let expected = trusted_host_direct_release_evidence_sha256(
            registration.registration_binding_sha256,
            gate.authorization_sha256,
            capability.transition_sha256,
            capability.completion_transition_sha256,
        );
        if exact_release_evidence.object_sha256 != expected {
            self.mark_direct_uncertain(
                registration.registration_binding_sha256,
                SupervisorStatePhase::ReleaseUncertain,
            );
            return Err(ControllerError::Rejected(
                "direct release evidence does not bind the sealed capability",
            ));
        }
        let mut states = self.lock_states()?;
        let record = states
            .get_mut(&registration.registration_binding_sha256)
            .ok_or(ControllerError::Rejected(
                "direct release state disappeared",
            ))?;
        if record.phase != SupervisorStatePhase::Releasing
            || record.last_transition_sha256
                != capability.transition_sha256
        {
            return Err(ControllerError::Rejected(
                "direct release completion is outside the releasing phase",
            ));
        }
        record.phase = SupervisorStatePhase::Running;
        record.last_transition_sha256 =
            capability.completion_transition_sha256;
        Ok(())
    }

    pub fn begin_capability_containment(
        &self,
        gate: VerifiedTrustedHostDirectSupervisorGate,
    ) -> Result<VerifiedTrustedHostDirectContainmentCapability> {
        let registration = gate.registration();
        let (terminating, closed) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration.registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "direct containment lacks a registration",
                ))?;
            if !matches!(
                record.phase,
                SupervisorStatePhase::Authorized
                    | SupervisorStatePhase::Releasing
                    | SupervisorStatePhase::Running
                    | SupervisorStatePhase::ReleaseUncertain
            ) || record.authorization_sha256
                != gate.authorization_sha256
                || gate.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || gate.shared_state_machine_measurement.reference_sha256
                    != self.measurements.exact_measurement.reference_sha256
                || record.request_sha256 != registration.request_sha256
                || record.fixed_plan_manifest_sha256
                    != registration.fixed_plan_manifest_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct containment is outside a live phase",
                ));
            }
            let terminating = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Terminating,
            );
            record.phase = SupervisorStatePhase::Terminating;
            record.last_transition_sha256 = terminating;
            let closed = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Closed,
            );
            (terminating, closed)
        };
        Ok(VerifiedTrustedHostDirectContainmentCapability {
            gate,
            transition_sha256: terminating,
            completion_transition_sha256: closed,
            _seal: capability_seal::Seal,
        })
    }

    pub fn complete_capability_containment(
        &self,
        capability: VerifiedTrustedHostDirectContainmentCapability,
        exact_containment_evidence: &EvidenceReference,
    ) -> Result<()> {
        exact_containment_evidence.validate()?;
        let gate = capability.gate();
        let registration = gate.registration();
        let expected = trusted_host_direct_containment_evidence_sha256(
            registration.registration_binding_sha256,
            gate.authorization_sha256,
            capability.transition_sha256,
            capability.completion_transition_sha256,
        );
        if exact_containment_evidence.object_sha256 != expected {
            self.mark_direct_uncertain(
                registration.registration_binding_sha256,
                SupervisorStatePhase::ContainmentUncertain,
            );
            return Err(ControllerError::Rejected(
                "direct containment evidence does not bind the sealed capability",
            ));
        }
        let mut states = self.lock_states()?;
        let record = states
            .get_mut(&registration.registration_binding_sha256)
            .ok_or(ControllerError::Rejected(
                "direct containment state disappeared",
            ))?;
        if record.phase != SupervisorStatePhase::Terminating
            || record.last_transition_sha256
                != capability.transition_sha256
        {
            return Err(ControllerError::Rejected(
                "direct containment completion is outside the terminating phase",
            ));
        }
        record.phase = SupervisorStatePhase::Closed;
        record.last_transition_sha256 =
            capability.completion_transition_sha256;
        Ok(())
    }

    pub fn release_registered_child(
        &self,
        gate: &VerifiedTrustedHostDirectSupervisorGate,
    ) -> Result<RawSupervisorReleaseEvidence> {
        let registration = gate.registration();
        let (releasing, running) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration.registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "direct release lacks an authorized registration",
                ))?;
            if record.phase != SupervisorStatePhase::Authorized
                || record.authorization_sha256
                    != gate.authorization_sha256
                || gate.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || gate.shared_state_machine_measurement.reference_sha256
                    != self.measurements.exact_measurement.reference_sha256
                || record.request_sha256 != registration.request_sha256
                || record.fixed_plan_manifest_sha256
                    != registration.fixed_plan_manifest_sha256
                || record.last_transition_sha256
                    != gate.authorization_transition_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct release is outside the authorized phase",
                ));
            }
            let releasing = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Releasing,
            );
            record.phase = SupervisorStatePhase::Releasing;
            record.last_transition_sha256 = releasing;
            let running = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Running,
            );
            (releasing, running)
        };
        let capability = VerifiedTrustedHostDirectReleaseCapability {
            gate,
            transition_sha256: releasing,
            completion_transition_sha256: running,
            _seal: capability_seal::Seal,
        };
        let backend = self.backend.as_ref().ok_or_else(|| {
            ControllerError::Unready(vec![
                "direct supervisor backend is absent from capability-only route"
                    .to_owned(),
            ])
        })?;
        let release = backend.release_registered_child(
            &capability,
            registration.deadline_unix_ms,
        );
        let release = match release {
            Ok(release) => release,
            Err(error) => {
                self.mark_direct_uncertain(
                    registration.registration_binding_sha256,
                    SupervisorStatePhase::ReleaseUncertain,
                );
                return Err(error);
            }
        };
        let release_verification = (|| -> Result<()> {
            release
                .provider_call
                .validate_against_direct_registration(registration)?;
            release.retained_fd_execveat_release.validate()?;
            if release.verified_gate_sha256 != gate.authorization_sha256
                || release.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || release.predecessor_transition_sha256 != releasing
                || release.state_machine_transition_sha256 != running
                || release
                    .provider_call
                    .result_or_terminal_binding
                    .object_sha256
                    != release.retained_fd_execveat_release.object_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct release result does not bind the shared gate",
                ));
            }
            let decision =
                self.verifier.verify_direct_release(gate, &release)?;
            decision.require_all()
        })();
        if let Err(error) = release_verification {
            self.mark_direct_uncertain(
                registration.registration_binding_sha256,
                SupervisorStatePhase::ReleaseUncertain,
            );
            return Err(error);
        }
        let mut states = self.lock_states()?;
        let record = states
            .get_mut(&registration.registration_binding_sha256)
            .ok_or(ControllerError::Rejected(
                "direct release state disappeared",
            ))?;
        if record.phase != SupervisorStatePhase::Releasing
            || record.last_transition_sha256 != releasing
        {
            return Err(ControllerError::Unready(vec![
                "direct release completion raced another shared state transition"
                    .to_owned(),
            ]));
        }
        record.phase = SupervisorStatePhase::Running;
        record.last_transition_sha256 = running;
        Ok(release)
    }

    pub fn terminate_registered_child(
        &self,
        gate: VerifiedTrustedHostDirectSupervisorGate,
    ) -> Result<RawContainmentTerminal> {
        let registration = gate.registration.clone();
        let (terminating, closed) = {
            let mut states = self.lock_states()?;
            let record = states
                .get_mut(&registration.registration_binding_sha256)
                .ok_or(ControllerError::Rejected(
                    "direct containment lacks a registration",
                ))?;
            if !matches!(
                record.phase,
                SupervisorStatePhase::Authorized
                    | SupervisorStatePhase::Releasing
                    | SupervisorStatePhase::Running
                    | SupervisorStatePhase::ReleaseUncertain
            ) || record.authorization_sha256
                != gate.authorization_sha256
                || gate.shared_state_machine_identity_sha256
                    != self.identity_sha256
                || gate.shared_state_machine_measurement.reference_sha256
                    != self.measurements.exact_measurement.reference_sha256
                || record.request_sha256 != registration.request_sha256
                || record.fixed_plan_manifest_sha256
                    != registration.fixed_plan_manifest_sha256
            {
                return Err(ControllerError::Rejected(
                    "direct containment is outside a live phase",
                ));
            }
            let terminating = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Terminating,
            );
            record.phase = SupervisorStatePhase::Terminating;
            record.last_transition_sha256 = terminating;
            let closed = self.transition(
                registration.registration_binding_sha256,
                record,
                SupervisorStatePhase::Closed,
            );
            (terminating, closed)
        };
        let authorization_sha256 = gate.authorization_sha256;
        let capability = VerifiedTrustedHostDirectContainmentCapability {
            gate,
            transition_sha256: terminating,
            completion_transition_sha256: closed,
            _seal: capability_seal::Seal,
        };
        let backend = self.backend.as_ref().ok_or_else(|| {
            ControllerError::Unready(vec![
                "direct supervisor backend is absent from capability-only route"
                    .to_owned(),
            ])
        })?;
        let terminal = backend.terminate_registered_child(
            capability,
            registration.deadline_unix_ms,
        );
        let terminal = match terminal {
            Ok(terminal) => terminal,
            Err(error) => {
                self.mark_direct_uncertain(
                    registration.registration_binding_sha256,
                    SupervisorStatePhase::ContainmentUncertain,
                );
                return Err(error);
            }
        };
        if let Err(error) = self.verify_direct_terminal(
            &registration,
            authorization_sha256,
            terminating,
            closed,
            &terminal,
        ) {
            self.mark_direct_uncertain(
                registration.registration_binding_sha256,
                SupervisorStatePhase::ContainmentUncertain,
            );
            return Err(error);
        }
        let mut states = self.lock_states()?;
        let record = states
            .get_mut(&registration.registration_binding_sha256)
            .ok_or(ControllerError::Rejected(
                "direct containment state disappeared",
            ))?;
        if record.phase != SupervisorStatePhase::Terminating
            || record.last_transition_sha256 != terminating
        {
            return Err(ControllerError::Unready(vec![
                "direct containment completion raced another shared state transition"
                    .to_owned(),
            ]));
        }
        record.phase = SupervisorStatePhase::Closed;
        record.last_transition_sha256 = closed;
        Ok(terminal)
    }

    fn mark_direct_uncertain(
        &self,
        registration_binding_sha256: Digest,
        phase: SupervisorStatePhase,
    ) {
        if let Ok(mut states) = self.states.lock() {
            if let Some(record) =
                states.get_mut(&registration_binding_sha256)
            {
                let transition = self.transition(
                    registration_binding_sha256,
                    record,
                    phase,
                );
                record.phase = phase;
                record.last_transition_sha256 = transition;
            }
        }
    }
}

pub trait ContainmentEvidenceSink: Send + Sync {
    fn record_observation(
        &self,
        label: &'static str,
        canonical_bytes: &[u8],
    ) -> Result<EvidenceReference>;
}

#[derive(Clone, Debug)]
pub(crate) struct RawChildLaunchObservation {
    pub(crate) pid: i32,
    pub(crate) fixed_plan_launch_sha256: Digest,
    pub(crate) execveat_token_sha256: Digest,
    pub(crate) launch_observation: EvidenceReference,
}

#[derive(Debug)]
pub struct SupervisorChildHandle {
    request_sha256: Digest,
    observed_source_sha256: Digest,
    source_root: PathBuf,
    current_lane_command_identity_sha256: Digest,
    fixed_plan_launch_sha256: Digest,
    fixed_plan_manifest_sha256: Digest,
    execveat_token_sha256: Digest,
    cgroup_path: PathBuf,
    cgroup_directory: OwnedFd,
    pid: i32,
    pidfd: OwnedFd,
    member_pidfds: Vec<OwnedFd>,
    watchdog_pid: i32,
    watchdog_pidfd: OwnedFd,
    watchdog_deadline_unix_ms: u64,
    process_group: i32,
    namespace_identity_values: Vec<(String, String)>,
    mandatory_denied_socket_paths: Vec<PathBuf>,
    descendant_source_mounts_read_only: bool,
    launch_observation: EvidenceReference,
    pub pidfd_identity: EvidenceReference,
    pub watchdog_identity: EvidenceReference,
    pub cgroup_identity: EvidenceReference,
    pub namespace_identities: EvidenceReference,
    pub source_read_only: EvidenceReference,
    pub docker_masked: EvidenceReference,
    pub no_new_privileges: EvidenceReference,
    pub capability_drop: EvidenceReference,
    pub seccomp: EvidenceReference,
    pub lsm: EvidenceReference,
}

impl SupervisorChildHandle {
    // Crate-private because only the measured root clone3 launcher may issue
    // this capability. External runtime providers cannot launch, nominate a
    // PID, select containment authority, or arm the independent watchdog.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_supervisor_registration(
        pre_execution: &VerifiedPreExecution,
        observation: RawChildLaunchObservation,
        cgroup_directory: OwnedFd,
        pidfd: OwnedFd,
        member_pidfds: Vec<OwnedFd>,
        watchdog_pid: i32,
        watchdog_pidfd: OwnedFd,
        watchdog_deadline_unix_ms: u64,
        process_group: i32,
        namespace_identities: Vec<(String, String)>,
        pidfd_identity: EvidenceReference,
        watchdog_identity: EvidenceReference,
        cgroup_identity: EvidenceReference,
        namespace_identity_evidence: EvidenceReference,
        source_read_only: EvidenceReference,
        docker_masked: EvidenceReference,
        no_new_privileges: EvidenceReference,
        capability_drop: EvidenceReference,
        seccomp: EvidenceReference,
        lsm: EvidenceReference,
    ) -> Self {
        Self {
            request_sha256: pre_execution.request.request_sha256,
            observed_source_sha256: pre_execution.source.observed_source_sha256,
            source_root: pre_execution.source.source_root.clone(),
            current_lane_command_identity_sha256:
                pre_execution.launch.current_lane_command_identity_sha256,
            fixed_plan_launch_sha256:
                observation.fixed_plan_launch_sha256,
            fixed_plan_manifest_sha256:
                pre_execution.launch.fixed_plan_manifest_sha256,
            execveat_token_sha256:
                observation.execveat_token_sha256,
            cgroup_path: pre_execution.launch.cgroup_path.clone(),
            cgroup_directory,
            pid: observation.pid,
            pidfd,
            member_pidfds,
            watchdog_pid,
            watchdog_pidfd,
            watchdog_deadline_unix_ms,
            process_group,
            namespace_identity_values: namespace_identities,
            mandatory_denied_socket_paths: pre_execution
                .launch
                .mandatory_denied_socket_paths
                .clone(),
            descendant_source_mounts_read_only: pre_execution
                .launch
                .descendant_source_mounts_read_only,
            launch_observation: observation.launch_observation,
            pidfd_identity,
            watchdog_identity,
            cgroup_identity,
            namespace_identities: namespace_identity_evidence,
            source_read_only,
            docker_masked,
            no_new_privileges,
            capability_drop,
            seccomp,
            lsm,
        }
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn process_group(&self) -> i32 {
        self.process_group
    }

    pub(crate) fn pidfd(&self) -> &OwnedFd {
        &self.pidfd
    }

    pub(crate) fn member_pidfds(&self) -> &[OwnedFd] {
        &self.member_pidfds
    }

    pub(crate) fn watchdog_pid(&self) -> i32 {
        self.watchdog_pid
    }

    pub(crate) fn watchdog_pidfd(&self) -> &OwnedFd {
        &self.watchdog_pidfd
    }

    pub(crate) fn watchdog_deadline_unix_ms(&self) -> u64 {
        self.watchdog_deadline_unix_ms
    }

    pub(crate) fn cgroup_directory(&self) -> &OwnedFd {
        &self.cgroup_directory
    }

    pub(crate) fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    pub(crate) fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub(crate) fn denied_socket_paths(&self) -> &[PathBuf] {
        &self.mandatory_denied_socket_paths
    }

    pub(crate) fn namespace_identity_values(&self) -> &[(String, String)] {
        &self.namespace_identity_values
    }

    pub(crate) fn validate_supervisor_binding(
        &self,
        pre_execution: &VerifiedPreExecution,
    ) -> Result<()> {
        let evidence = [
            &self.launch_observation,
            &self.pidfd_identity,
            &self.watchdog_identity,
            &self.cgroup_identity,
            &self.namespace_identities,
            &self.source_read_only,
            &self.docker_masked,
            &self.no_new_privileges,
            &self.capability_drop,
            &self.seccomp,
            &self.lsm,
        ];
        for reference in evidence {
            reference.validate()?;
        }
        if self.pid <= 1
            || self.process_group != self.pid
            || self.watchdog_pid <= 1
            || self.watchdog_pid == self.pid
            || self.watchdog_deadline_unix_ms
                != pre_execution.request.deadline_unix_ms
            || self.request_sha256 != pre_execution.request.request_sha256
            || self.observed_source_sha256
                != pre_execution.source.observed_source_sha256
            || self.source_root != pre_execution.source.source_root
            || self.current_lane_command_identity_sha256
                != pre_execution.launch.current_lane_command_identity_sha256
            || self.fixed_plan_launch_sha256
                != pre_execution.launch.fixed_plan_launch_sha256
            || self.fixed_plan_manifest_sha256
                != pre_execution.launch.fixed_plan_manifest_sha256
            || self.execveat_token_sha256
                != pre_execution.launch.execveat_token.reference_sha256
            || self.cgroup_path != pre_execution.launch.cgroup_path
            || self.mandatory_denied_socket_paths
                != pre_execution.launch.mandatory_denied_socket_paths
            || !self.descendant_source_mounts_read_only
            || !pre_execution.launch.descendant_source_mounts_read_only
            || self.namespace_identity_values.is_empty()
        {
            return Err(ControllerError::Rejected(
                "supervisor child handle does not bind verified pre-execution",
            ));
        }
        Ok(())
    }

    pub fn registration_binding_sha256(&self) -> Digest {
        let mut bytes = Vec::with_capacity(224);
        bytes.extend_from_slice(b"serverware-controller-v11/supervisor-child\0");
        bytes.extend_from_slice(&self.request_sha256);
        bytes.extend_from_slice(&self.observed_source_sha256);
        bytes.extend_from_slice(&canonical_path_digest(&self.source_root));
        bytes.extend_from_slice(&self.current_lane_command_identity_sha256);
        bytes.extend_from_slice(&self.fixed_plan_launch_sha256);
        bytes.extend_from_slice(&self.fixed_plan_manifest_sha256);
        bytes.extend_from_slice(&self.execveat_token_sha256);
        bytes.extend_from_slice(&canonical_path_digest(&self.cgroup_path));
        bytes.extend_from_slice(&self.process_group.to_be_bytes());
        bytes.extend_from_slice(&self.watchdog_pid.to_be_bytes());
        bytes.extend_from_slice(&self.watchdog_deadline_unix_ms.to_be_bytes());
        bytes.extend_from_slice(&self.watchdog_identity.reference_sha256);
        for path in &self.mandatory_denied_socket_paths {
            bytes.extend_from_slice(&canonical_path_digest(path));
        }
        sha256(&bytes)
    }
}

#[derive(Clone, Debug)]
pub struct RawKernelMonitorSession {
    pub arm_evidence: EvidenceReference,
    pub session_sha256: Digest,
    pub provider_call: RawBoundedProviderCallEvidence,
}

#[derive(Clone, Debug)]
pub struct RawKernelExecutionEvidence {
    pub exec_start_exit: EvidenceReference,
    pub path_and_file_identity: EvidenceReference,
    pub interpreter_module_loader_jit: EvidenceReference,
    pub executable_vmas: EvidenceReference,
    pub provider_call: RawBoundedProviderCallEvidence,
}

#[derive(Clone, Debug)]
pub struct RawRuntimeCompletion {
    pub outputs: EvidenceReference,
    pub provider_call: RawBoundedProviderCallEvidence,
}

#[derive(Clone, Debug)]
pub struct RawExecutionClosure {
    pub monitor_arm: EvidenceReference,
    pub monitor_session_sha256: Digest,
    pub monitor_arm_provider_call: RawBoundedProviderCallEvidence,
    pub supervisor_capabilities: RawSupervisorCapabilityEvidence,
    pub supervisor_registration_binding_sha256: Digest,
    pub supervisor_state_machine_identity_sha256: Digest,
    pub supervisor_state_machine_measurement: EvidenceReference,
    pub supervisor_preparation_transition_sha256: Digest,
    pub supervisor_authorization_transition_sha256: Digest,
    pub supervisor_release: RawSupervisorReleaseEvidence,
    pub exec_start_exit: EvidenceReference,
    pub path_and_file_identity: EvidenceReference,
    pub interpreter_module_loader_jit: EvidenceReference,
    pub executable_vmas: EvidenceReference,
    pub monitor_collection_provider_call: RawBoundedProviderCallEvidence,
    pub runtime_provider_call: RawBoundedProviderCallEvidence,
    pub containment: RawContainmentTerminal,
    pub trusted_start: SignedTrustedTime,
    pub trusted_end: SignedTrustedTime,
    pub outputs: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct NativeExecutionDecision {
    pub exec_start_exit_complete: bool,
    pub path_and_file_identity_complete: bool,
    pub provenance_complete: bool,
    pub executable_vma_partition_complete: bool,
    pub no_writable_executable_mapping: bool,
    pub containment_clean: bool,
    pub verified_supervisor_state_machine: bool,
    pub exact_shared_supervisor_transition_chain: bool,
    pub exact_provider_result_bindings: bool,
    pub provider_calls_bounded_workers_and_deadlines: bool,
    pub provider_worker_pidfds_killed_and_bounded_reaped: bool,
    pub controller_sole_parent_and_reaper: bool,
    pub independent_watchdog_non_parent_non_reaper: bool,
    pub independent_watchdog_deadline_enforcement: bool,
    pub durable_orphan_journal_complete: bool,
    pub signed_time_ordered_and_fresh: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedExecutionCapability {
    execution_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedExecutionCapability {
    pub fn execution_sha256(&self) -> Digest {
        self.execution_sha256
    }
}

pub trait DisposableRuntime: Send + Sync {
    // Output collection receives only a native-verified supervisor gate and
    // has no launch, PID nomination, signal, wait, or reap authority.
    fn collect_completion(
        &self,
        pre_execution: &VerifiedPreExecution,
        gate: &VerifiedSupervisorExecutionGate,
        trusted_start: &SignedTrustedTime,
        deadline_unix_ms: u64,
    ) -> Result<RawRuntimeCompletion>;
}

pub trait KernelExecutionMonitor: Send + Sync {
    fn arm_before_launch(
        &self,
        pre_execution: &VerifiedPreExecution,
    ) -> Result<RawKernelMonitorSession>;
    fn collect_complete_evidence(
        &self,
        pre_execution: &VerifiedPreExecution,
        session: RawKernelMonitorSession,
        gate: &VerifiedSupervisorExecutionGate,
        deadline_unix_ms: u64,
    ) -> Result<RawKernelExecutionEvidence>;
}

#[derive(Clone, Debug)]
pub struct RetrievalLedgerEntry {
    pub global_ordinal: u64,
    pub predecessor_transcript_sha256: Digest,
    pub object: EvidenceReference,
    pub retrieved_length: u64,
    pub retrieved_sha256: Digest,
    pub retrieved_chunk_root_sha256: Digest,
    pub retrieved_chunk_lengths: Vec<u32>,
    pub retrieved_chunk_sha256: Vec<Digest>,
    pub cumulative_bytes_before: u64,
    pub cumulative_bytes_after: u64,
    pub transcript_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct RawGlobalRetrievalLedger {
    pub ledger_id: Digest,
    pub entries: Vec<RetrievalLedgerEntry>,
    pub final_transcript_sha256: Digest,
    pub total_bytes: u64,
}

impl RawGlobalRetrievalLedger {
    pub fn validate_structure(&self) -> Result<()> {
        if self.ledger_id == [0; 32] || self.entries.is_empty() {
            return Err(ControllerError::Invalid("global retrieval ledger is empty"));
        }
        let mut predecessor = [0u8; 32];
        let mut cumulative = 0u64;
        for (index, entry) in self.entries.iter().enumerate() {
            entry.object.validate()?;
            let chunk_length_sum = entry
                .retrieved_chunk_lengths
                .iter()
                .try_fold(0u64, |sum, length| {
                    sum.checked_add(*length as u64)
                        .ok_or(ControllerError::Invalid("chunk length sum overflow"))
                })?;
            if entry.retrieved_chunk_lengths.len()
                != entry.retrieved_chunk_sha256.len()
                || entry
                    .retrieved_chunk_lengths
                    .iter()
                    .any(|length| *length == 0 || *length > CHUNK_MAX_BYTES)
                || entry.retrieved_chunk_lengths.len() as u32
                    != chunks_for(entry.retrieved_length)
                || chunk_length_sum != entry.retrieved_length
                || ordered_chunk_root(
                    &entry.retrieved_chunk_lengths,
                    &entry.retrieved_chunk_sha256,
                ) != entry.retrieved_chunk_root_sha256
            {
                return Err(ControllerError::Rejected(
                    "retrieval chunk sequence or root is invalid",
                ));
            }
            if entry.global_ordinal != index as u64
                || entry.predecessor_transcript_sha256 != predecessor
                || entry.cumulative_bytes_before != cumulative
                || entry.cumulative_bytes_after
                    != cumulative.saturating_add(entry.retrieved_length)
                || entry.retrieved_length != entry.object.length
                || entry.retrieved_sha256 != entry.object.object_sha256
                || entry.retrieved_chunk_root_sha256 != entry.object.chunk_root_sha256
                || retrieval_transcript(self.ledger_id, entry)
                    != entry.transcript_sha256
            {
                return Err(ControllerError::Rejected(
                    "global retrieval ledger continuity or object binding failed",
                ));
            }
            cumulative = entry.cumulative_bytes_after;
            if cumulative > AGGREGATE_MAX_BYTES {
                return Err(ControllerError::Rejected(
                    "global retrieval ledger exceeds aggregate bound",
                ));
            }
            predecessor = entry.transcript_sha256;
        }
        if predecessor != self.final_transcript_sha256 || cumulative != self.total_bytes {
            return Err(ControllerError::Rejected("global retrieval ledger root mismatch"));
        }
        Ok(())
    }
}

fn ordered_chunk_root(lengths: &[u32], digests: &[Digest]) -> Digest {
    if lengths.is_empty() {
        return sha256(b"serverware-controller-v11/chunks/empty");
    }
    let mut level = Vec::with_capacity(digests.len());
    for (index, (length, digest)) in lengths.iter().zip(digests).enumerate() {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(b"serverware-controller-v11/chunks/leaf\0");
        bytes.extend_from_slice(&(index as u64).to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(digest);
        level.push(sha256(&bytes));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut bytes = Vec::with_capacity(96);
            bytes.extend_from_slice(b"serverware-controller-v11/chunks/node\0");
            bytes.extend_from_slice(&pair[0]);
            bytes.extend_from_slice(right);
            next.push(sha256(&bytes));
        }
        level = next;
    }
    level[0]
}

fn retrieval_transcript(ledger_id: Digest, entry: &RetrievalLedgerEntry) -> Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(b"serverware-controller-v11/retrieval/transcript\0");
    bytes.extend_from_slice(&ledger_id);
    bytes.extend_from_slice(&entry.global_ordinal.to_be_bytes());
    bytes.extend_from_slice(&entry.predecessor_transcript_sha256);
    bytes.extend_from_slice(&entry.object.reference_sha256);
    bytes.extend_from_slice(&entry.retrieved_length.to_be_bytes());
    bytes.extend_from_slice(&entry.retrieved_sha256);
    bytes.extend_from_slice(&entry.retrieved_chunk_root_sha256);
    bytes.extend_from_slice(&entry.cumulative_bytes_before.to_be_bytes());
    bytes.extend_from_slice(&entry.cumulative_bytes_after.to_be_bytes());
    sha256(&bytes)
}

pub trait ControllerEvidencePipeline: Send + Sync {
    fn begin_global_ledger(
        &self,
        request: &VerifiedRequestCapability,
    ) -> Result<RawGlobalRetrievalLedger>;
    fn stream_store_retrieve_and_recompute(
        &self,
        ledger: &mut RawGlobalRetrievalLedger,
        raw_objects: &[EvidenceReference],
    ) -> Result<Vec<EvidenceReference>>;
    fn seal_final_closure(
        &self,
        ledger: &RawGlobalRetrievalLedger,
        every_object: &[EvidenceReference],
    ) -> Result<EvidenceReference>;
    fn stream_retrieve_replay(
        &self,
        replay: &CommittedReplay,
    ) -> Result<RawGlobalRetrievalLedger>;
}

#[derive(Clone, Debug)]
pub struct RawMembershipQuorumEvidence {
    pub signed_checkpoint: EvidenceReference,
    pub immediate_predecessor: EvidenceReference,
    pub append_only_lineage: EvidenceReference,
    pub monotonic_epoch_floor: EvidenceReference,
    pub physical_key_uniqueness: EvidenceReference,
    pub weighted_intersection: EvidenceReference,
    pub actual_receipt_certificate: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct RawFinalCandidate {
    pub membership: RawMembershipQuorumEvidence,
    pub availability: Vec<EvidenceReference>,
    pub attestation: Vec<EvidenceReference>,
    pub quorum: Vec<EvidenceReference>,
    pub evidence_closure: EvidenceReference,
    pub retrieval_ledger: RawGlobalRetrievalLedger,
    pub exact_receipt_candidate: EvidenceReference,
}

#[derive(Clone, Debug)]
pub struct NativeFinalDecision {
    pub membership_lineage: bool,
    pub epoch_floor: bool,
    pub physical_key_uniqueness: bool,
    pub weighted_quorum_intersection: bool,
    pub actual_receipt_certificate: bool,
    pub availability: bool,
    pub attestation_exact_replay: bool,
    pub complete_global_retrieval: bool,
    pub exact_receipt_candidate: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedFinalCandidate {
    final_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedFinalCandidate {
    pub fn final_sha256(&self) -> Digest {
        self.final_sha256
    }
}

#[derive(Clone, Debug)]
pub struct NativePublicationDecision {
    pub exact_receipt_and_quorum: bool,
    pub final_evidence_closure: bool,
    pub atomic_acceptance_binding: bool,
    pub signed_start_end_time: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct NativeReplayDecision {
    pub exact_request_binding: bool,
    pub typed_terminal: bool,
    pub exact_signed_typed_receipt: bool,
    pub receipt_terminal_matches_cas_terminal: bool,
    pub receipt_provider_call_verified: bool,
    pub receipt_provider_worker_evidence_in_closure: bool,
    pub success_quorum_or_non_success_terminal: bool,
    pub final_evidence_closure: bool,
    pub terminal_and_reconciliation: bool,
    pub decision_sha256: Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedPublicationCapability {
    publication_sha256: Digest,
    exact_receipt: EvidenceReference,
    typed_receipt: VerifiedTypedReceiptCapability,
    _seal: capability_seal::Seal,
}

impl VerifiedPublicationCapability {
    pub fn publication_sha256(&self) -> Digest {
        self.publication_sha256
    }

    pub fn exact_receipt(&self) -> &EvidenceReference {
        &self.exact_receipt
    }

    pub fn typed_receipt(&self) -> &VerifiedTypedReceiptCapability {
        &self.typed_receipt
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedReplayCapability {
    replay_sha256: Digest,
    terminal: AcceptanceTerminalKind,
    _seal: capability_seal::Seal,
}

pub trait MembershipQuorumAuthority: Send + Sync {
    fn collect_raw_final_candidate(
        &self,
        execution: &VerifiedExecutionCapability,
        receipt_candidate: EvidenceReference,
        evidence_closure: EvidenceReference,
        retrieval_ledger: RawGlobalRetrievalLedger,
    ) -> Result<RawFinalCandidate>;
}

pub trait ReceiptAuthority: Send + Sync {
    fn construct_candidate(
        &self,
        pre_execution: &VerifiedPreExecution,
        execution: &VerifiedExecutionCapability,
        signed_time_order: &EvidenceReference,
    ) -> Result<EvidenceReference>;
    fn sign_typed_after_final_verification(
        &self,
        final_candidate: &VerifiedFinalCandidate,
        body: ControllerReceiptBody,
    ) -> Result<SignedReceiptArtifact>;
    fn sign_typed_terminal_after_verification(
        &self,
        terminal_evidence: &EvidenceReference,
        body: ControllerReceiptBody,
    ) -> Result<SignedReceiptArtifact>;
}

#[derive(Clone, Debug)]
pub struct SignedReceiptArtifact {
    pub signed_receipt: SignedControllerReceipt,
    pub exact_receipt: EvidenceReference,
    pub provider_call: RawBoundedProviderCallEvidence,
}

#[derive(Clone, Debug)]
pub struct NativeReceiptProviderCallDecision {
    pub exact_receipt_body_and_result: bool,
    pub bounded_worker_and_monotonic_deadline: bool,
    pub measured_worker_process_and_pidfd: bool,
    pub worker_killed_and_bounded_reaped: bool,
    pub controller_reaper_boundary: bool,
    pub decision_sha256: Digest,
}

impl NativeReceiptProviderCallDecision {
    fn require_all(&self) -> Result<()> {
        if self.exact_receipt_body_and_result
            && self.bounded_worker_and_monotonic_deadline
            && self.measured_worker_process_and_pidfd
            && self.worker_killed_and_bounded_reaped
            && self.controller_reaper_boundary
            && self.decision_sha256 != [0; 32]
        {
            Ok(())
        } else {
            Err(ControllerError::Rejected(
                "native verifier rejected receipt signer worker evidence",
            ))
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedTypedReceiptCapability {
    terminal: ReceiptTerminal,
    body: ControllerReceiptBody,
    exact_receipt: EvidenceReference,
    exact_receipt_bytes: Vec<u8>,
    wire_sha256: Digest,
    provider_call: RawBoundedProviderCallEvidence,
    provider_call_verification_sha256: Digest,
    _seal: capability_seal::Seal,
}

impl VerifiedTypedReceiptCapability {
    pub fn terminal(&self) -> ReceiptTerminal {
        self.terminal
    }

    pub fn body(&self) -> &ControllerReceiptBody {
        &self.body
    }

    pub fn exact_receipt(&self) -> &EvidenceReference {
        &self.exact_receipt
    }

    pub fn exact_receipt_bytes(&self) -> &[u8] {
        &self.exact_receipt_bytes
    }

    pub fn wire_sha256(&self) -> Digest {
        self.wire_sha256
    }

    pub fn provider_call_objects(&self) -> Vec<EvidenceReference> {
        bounded_provider_call_objects(&self.provider_call)
    }

    pub fn provider_call(&self) -> &RawBoundedProviderCallEvidence {
        &self.provider_call
    }

    pub fn provider_call_verification_sha256(&self) -> Digest {
        self.provider_call_verification_sha256
    }
}

pub trait NoBuildPolicyAuthority: Send + Sync {
    fn raw_kernel_policy(
        &self,
        pre_execution: &VerifiedPreExecution,
        committed_build: &VerifiedBuildClosure,
    ) -> Result<RawNoBuildKernelPolicy>;
}

pub trait BuildClosureAuthority: Send + Sync {
    fn construct_raw_build_closure(
        &self,
        pre_execution: &VerifiedPreExecution,
        execution: &VerifiedExecutionCapability,
        outputs: &EvidenceReference,
    ) -> Result<RawBuildClosure>;
}

pub trait TerminalEvidenceAuthority: Send + Sync {
    fn record_failure(&self, stage: &'static str, error: &str) -> Result<EvidenceReference>;
    fn record_unknown(&self, stage: &'static str, error: &str) -> Result<EvidenceReference>;
}

pub struct ProductionProviders<'a> {
    pub request_authority: &'a dyn RootRequestAuthority,
    pub provider_evidence: &'a dyn ProviderEvidenceSource,
    pub source_observer: &'a dyn ImmutableSourceObserver,
    pub launch_authority: &'a dyn RootFixedLaunchAuthority,
    pub acceptance: &'a dyn AtomicAcceptanceReplayCas,
    pub builds: &'a dyn FencedBuildCas,
    pub build_closure: &'a dyn BuildClosureAuthority,
    pub no_build_policy: &'a dyn NoBuildPolicyAuthority,
    pub no_build: &'a dyn NoBuildKernelEnforcer,
    pub trusted_time: &'a dyn TrustedTimeAuthority,
    pub runtime: &'a dyn DisposableRuntime,
    pub kernel_monitor: &'a dyn KernelExecutionMonitor,
    pub supervisor: &'a TrustedHostSupervisorStateMachine,
    pub evidence: &'a dyn ControllerEvidencePipeline,
    pub membership_quorum: &'a dyn MembershipQuorumAuthority,
    pub receipts: &'a dyn ReceiptAuthority,
    pub terminals: &'a dyn TerminalEvidenceAuthority,
}

pub struct ProductionController<'a> {
    bootstrap: BootstrapVerifierHandle,
    providers: ProductionProviders<'a>,
}

impl<'a> ProductionController<'a> {
    pub(crate) fn measured_trusted_host(
        verifier: Box<dyn PinnedNativeVerifier>,
        receipt_verifying_key: VerifyingKey,
        measurements: TrustedHostBootstrapMeasurements,
        providers: ProductionProviders<'a>,
    ) -> Result<Self> {
        let bootstrap = BootstrapVerifierHandle::measured_trusted_host(
            verifier,
            receipt_verifying_key,
            measurements,
        )?;
        Ok(Self {
            bootstrap,
            providers,
        })
    }

    pub fn hard_unready_reason() -> &'static str {
        "trusted-host production requires measured verifier/process/key/config/provider bindings, the root-owned fixed-plan manifest, bounded provider workers, external kernel monitor/evidence store/signers/trusted time/attestation, and the verified controller-only supervisor route; scope explicitly excludes TEE attestation"
    }

    pub fn execute(
        &self,
        submission: &ClientSubmission,
        peer_binding_sha256: Digest,
        immutable_config: EvidenceReference,
        deadline_unix_ms: u64,
    ) -> Result<ProductionOutcome> {
        immutable_config.validate()?;
        let raw_request = self.providers.request_authority.construct_signed_request(
            submission,
            peer_binding_sha256,
            immutable_config.object_sha256,
            deadline_unix_ms,
        )?;
        if raw_request.lane != submission.lane
            || raw_request.request_id != submission.request_id
            || raw_request.nonce_sha256 != sha256(&submission.raw_nonce)
            || raw_request.peer_binding_sha256 != peer_binding_sha256
            || raw_request.deadline_unix_ms != deadline_unix_ms
            || raw_request.config_sha256 != immutable_config.object_sha256
            || submission.peer_binding_sha256 != peer_binding_sha256
            || submission.deadline_unix_ms != deadline_unix_ms
            || submission.config_sha256 != immutable_config.object_sha256
            || raw_request.request_sha256
                != submission.exact_signed_request_sha256()
        {
            return Err(ControllerError::Rejected(
                "root request authority output does not bind client labels and transport",
            ));
        }
        let providers = self.providers.provider_evidence.collect_raw_provider_set()?;
        let source = self.providers.source_observer.observe_immutable_snapshot()?;
        let launch = self
            .providers
            .launch_authority
            .resolve_raw_fixed_launch(submission.lane, &source)?;
        let raw_pre = RawPreExecutionEvidence {
            config: immutable_config,
            request: raw_request,
            providers,
            source,
            launch,
        };

        // No replay/nonce/build state is mutated until the measured native
        // bootstrap has verified the signed request and every provider, source,
        // launch, config, and sandbox binding.
        let pre = self.bootstrap.verify_pre_execution(&raw_pre)?;
        let acceptance_input = AtomicAcceptanceInput {
            lane: pre.request.lane,
            request_id: pre.request.request_id,
            exact_signed_request_sha256: pre.request.request_sha256,
            nonce_sha256: pre.request.nonce_sha256,
            peer_binding_sha256,
            deadline_unix_ms,
            config_sha256: pre.request.config_sha256,
            observed_source_sha256: pre.source.observed_source_sha256,
            root_identity_sha256: pre.source.root_identity_sha256,
            source_root_sha256: pre.source.source_root_sha256,
            current_lane_command_identity_sha256:
                pre.launch.current_lane_command_identity_sha256,
            provider_manifest_sha256: pre.providers.manifest_sha256,
            fixed_plan_manifest_sha256:
                pre.launch.fixed_plan_manifest_sha256,
            pre_execution_decision_sha256: pre.decision_sha256,
        };
        match self
            .providers
            .acceptance
            .accept_nonce_and_request_once(&acceptance_input, &pre)?
        {
            AtomicAcceptance::Replay(replay)
            | AtomicAcceptance::InFlightReconciled(replay) => {
                self.verify_replay_outcome(replay, &acceptance_input)
            }
            AtomicAcceptance::Conflict => Err(ControllerError::Rejected(
                "atomic request/nonce acceptance conflict",
            )),
            AtomicAcceptance::New(raw_claim) => {
                let lease = match self.bootstrap.verify_acceptance_cas_claim(
                    &acceptance_input,
                    &pre,
                    raw_claim,
                ) {
                    Ok(lease) => lease,
                    Err(error) => {
                        return self.resolve_acceptance_readback(
                            &acceptance_input,
                            Err(error),
                            None,
                            None,
                            "unverified acceptance CAS claim",
                        )
                    }
                };
                let retained_lease = lease.clone();
                let mut effects_possible = false;
                let mut terminal_build_binding = None;
                match self.execute_new(
                    &raw_pre,
                    &pre,
                    acceptance_input.clone(),
                    lease,
                    &mut effects_possible,
                    &mut terminal_build_binding,
                ) {
                    Ok(outcome) => Ok(outcome),
                    Err(error) => self.close_acceptance_terminal(
                        &acceptance_input,
                        retained_lease,
                        if effects_possible {
                            AcceptanceTerminalKind::Unknown
                        } else {
                            AcceptanceTerminalKind::Failure
                        },
                        "production-session",
                        &error,
                        terminal_build_binding.as_ref(),
                    ),
                }
            }
        }
    }

    fn execute_new(
        &self,
        raw_pre: &RawPreExecutionEvidence,
        pre: &VerifiedPreExecution,
        acceptance_input: AtomicAcceptanceInput,
        lease: AcceptanceLease,
        effects_possible: &mut bool,
        terminal_build_binding: &mut Option<ReceiptBuildBinding>,
    ) -> Result<ProductionOutcome> {
        let mut build_reservation = None;
        let mut committed_build = None;
        let mut no_build_capability = None;
        let mut gate_objects = Vec::new();
        if pre.lane().operation == Operation::Build {
            *effects_possible = true;
            let reserve_result =
                match self.providers.builds.reserve(&pre.source, &pre.request) {
                    Ok(result) => result,
                    Err(error) => {
                        let readback = self.resolve_build_source_readback(
                            pre,
                            "build reservation reconciliation failed",
                        )?;
                        *terminal_build_binding =
                            Some(ReceiptBuildBinding::from_readback(&readback));
                        *effects_possible = false;
                        return Err(error);
                    }
                };
            match reserve_result {
                BuildReserveResult::Reserved(raw_claim) => {
                    let reservation = match self
                        .bootstrap
                        .verify_build_reservation_claim(pre, raw_claim)
                    {
                        Ok(reservation) => reservation,
                        Err(error) => {
                            let readback = self.resolve_build_source_readback(
                                pre,
                                "build reservation claim failed native verification",
                            )?;
                            *terminal_build_binding = Some(
                                ReceiptBuildBinding::from_readback(&readback),
                            );
                            *effects_possible = false;
                            return Err(error);
                        }
                    };
                    gate_objects.extend(
                        reservation.claim_objects().iter().cloned(),
                    );
                    *terminal_build_binding =
                        Some(ReceiptBuildBinding::from_reservation(&reservation));
                    build_reservation = Some(reservation);
                    *effects_possible = false;
                }
                BuildReserveResult::ExistingSuccess(success) => {
                    let verified = self
                        .bootstrap
                        .verify_committed_build_success(pre, success)?;
                    *terminal_build_binding = Some(
                        ReceiptBuildBinding::from_success(&verified.committed),
                    );
                    *effects_possible = false;
                    return Err(ControllerError::Rejected(
                        "build source digest already has committed success",
                    ));
                }
                BuildReserveResult::ExistingFailure(terminal) => {
                    if terminal.kind != BuildTerminalKind::Failure {
                        return Err(ControllerError::Rejected(
                            "build failure readback has the wrong terminal kind",
                        ));
                    }
                    self.bootstrap.validate_build_source_readback(
                        pre,
                        &CommittedBuildReadback::Failure(terminal.clone()),
                    )?;
                    *terminal_build_binding =
                        Some(ReceiptBuildBinding::from_terminal(&terminal));
                    *effects_possible = false;
                    return Err(ControllerError::Rejected(
                        "build source digest already has a committed failure",
                    ));
                }
                BuildReserveResult::ExistingUnknown(terminal) => {
                    if terminal.kind != BuildTerminalKind::Unknown {
                        return Err(ControllerError::Rejected(
                            "build unknown readback has the wrong terminal kind",
                        ));
                    }
                    self.bootstrap.validate_build_source_readback(
                        pre,
                        &CommittedBuildReadback::Unknown(terminal.clone()),
                    )?;
                    *terminal_build_binding =
                        Some(ReceiptBuildBinding::from_terminal(&terminal));
                    *effects_possible = false;
                    return Err(ControllerError::Rejected(
                        "build source digest already has a committed unknown",
                    ));
                }
                BuildReserveResult::InFlight => {
                    let readback = self.resolve_build_source_readback(
                        pre,
                        "in-flight build reservation could not be reconciled",
                    )?;
                    *terminal_build_binding =
                        Some(ReceiptBuildBinding::from_readback(&readback));
                    *effects_possible = false;
                    return Err(ControllerError::Rejected(
                        "build source digest has a reconciled reservation",
                    ));
                }
            }
        } else {
            let committed = self.providers.builds.require_committed_success(
                &pre.source,
                pre.request.config_sha256,
                &pre.providers,
            )?;
            let verified_build = self
                .bootstrap
                .verify_committed_build_success(pre, committed)?;
            *terminal_build_binding = Some(
                ReceiptBuildBinding::from_success(&verified_build.committed),
            );
            let raw_policy = self
                .providers
                .no_build_policy
                .raw_kernel_policy(pre, &verified_build)?;
            *effects_possible = true;
            let installation = self
                .providers
                .no_build
                .install_before_exec(pre, &verified_build, &raw_policy)?;
            gate_objects.extend(no_build_policy_objects(&installation));
            gate_objects.extend(committed_build_success_objects(
                &verified_build.committed,
            ));
            no_build_capability = Some(
                self.bootstrap
                    .verify_no_build_installation(pre, &verified_build, &installation)?,
            );
            committed_build = Some(verified_build);
        }

        let execution_result = self.execute_runtime_and_close(
            pre,
            no_build_capability.as_ref(),
            raw_pre,
            &lease,
            &gate_objects,
            effects_possible,
        );
        let (execution, raw_execution, _execution_time_order, mut ledger, mut every_object) =
            match execution_result {
                Ok(value) => value,
                Err(error) => {
                    if let Some(reservation) = build_reservation.take() {
                        self.close_build_terminal(
                            pre,
                            reservation,
                            if *effects_possible {
                                BuildTerminalKind::Unknown
                            } else {
                                BuildTerminalKind::Failure
                            },
                            "runtime-or-verification",
                            &error,
                        )?;
                    }
                    return Err(error);
                }
            };

        if let Some(reservation) = build_reservation.take() {
            let build_result = (|| -> Result<VerifiedBuildClosure> {
                let raw_build = self.providers.build_closure.construct_raw_build_closure(
                    pre,
                    &execution,
                    &raw_execution.outputs,
                )?;
                let candidate = self
                    .bootstrap
                    .verify_build_candidate(pre, raw_build)?;
                self.commit_build_success(pre, reservation.clone(), candidate)
            })();
            match build_result {
                Ok(verified_build) => {
                    *terminal_build_binding = Some(
                        ReceiptBuildBinding::from_success(
                            &verified_build.committed,
                        ),
                    );
                    let committed_objects =
                        committed_build_success_objects(&verified_build.committed);
                    let stored_build = self
                        .providers
                        .evidence
                        .stream_store_retrieve_and_recompute(
                            &mut ledger,
                            &committed_objects,
                        )?;
                    every_object.extend(stored_build);
                    committed_build = Some(verified_build);
                }
                Err(error) => {
                    self.close_build_terminal(
                        pre,
                        reservation,
                        BuildTerminalKind::Unknown,
                        "build-closure-or-terminal",
                        &error,
                    )?;
                    return Err(error);
                }
            }
        }
        let committed_build = committed_build.ok_or(ControllerError::Rejected(
            "execution lacks a verified build closure",
        ))?;

        let pre_sign_end = self.providers.trusted_time.signed_now()?;
        pre_sign_end.signed_evidence.validate()?;
        let signed_time_order = self.providers.trusted_time.verify_order_and_deadline(
            &raw_execution.trusted_start,
            &pre_sign_end,
            pre.request.deadline_unix_ms,
        )?;
        signed_time_order.validate()?;
        let stored_pre_sign_time = self
            .providers
            .evidence
            .stream_store_retrieve_and_recompute(
                &mut ledger,
                &[
                    pre_sign_end.signed_evidence.clone(),
                    signed_time_order.clone(),
                ],
            )?;
        every_object.extend(stored_pre_sign_time);

        let provisional_closure = self
            .providers
            .evidence
            .seal_final_closure(&ledger, &every_object)?;
        let receipt_candidate = self.providers.receipts.construct_candidate(
            pre,
            &execution,
            &signed_time_order,
        )?;
        let mut raw_final = self.providers.membership_quorum.collect_raw_final_candidate(
            &execution,
            receipt_candidate.clone(),
            provisional_closure,
            ledger.clone(),
        )?;
        if raw_final.exact_receipt_candidate.reference_sha256
            != receipt_candidate.reference_sha256
        {
            return Err(ControllerError::Rejected(
                "membership/quorum authority changed the receipt candidate",
            ));
        }
        let final_objects = final_candidate_objects(&raw_final);
        let stored_final = self
            .providers
            .evidence
            .stream_store_retrieve_and_recompute(&mut ledger, &final_objects)?;
        every_object.extend(stored_final);
        raw_final.evidence_closure = self
            .providers
            .evidence
            .seal_final_closure(&ledger, &every_object)?;
        raw_final.retrieval_ledger = ledger.clone();
        let verified_final = self.verify_final(&execution, &raw_final)?;

        // Controller receipt signing occurs only after membership lineage, epoch,
        // physical-key uniqueness, weighted intersection, and the actual quorum
        // certificate over the receipt candidate have passed native verification.
        let receipt_body = ControllerReceiptBody {
            terminal: ReceiptTerminal::Success,
            lane: pre.request.lane,
            attestation_scope: self.bootstrap.attestation_scope,
            deadline_unix_ms: pre.request.deadline_unix_ms,
            acceptance_fence: lease.fence,
            acceptance_generation: lease.generation,
            build_fence: committed_build.committed.build_fence,
            build_reservation_generation:
                committed_build.committed.reservation_generation,
            request_id: pre.request.request_id,
            exact_signed_request_sha256: pre.request.request_sha256,
            nonce_sha256: pre.request.nonce_sha256,
            observed_source_sha256:
                pre.source.observed_source_sha256,
            current_lane_command_sha256:
                pre.launch.current_lane_command_identity_sha256,
            committed_build_command_sha256:
                committed_build.committed.build_command_identity_sha256,
            acceptance_identity_sha256:
                lease.acceptance_identity_sha256,
            build_reservation_identity_sha256:
                committed_build.committed.reservation_identity_sha256,
            config_sha256: pre.request.config_sha256,
            provider_manifest_sha256:
                pre.providers.manifest_sha256,
            fixed_plan_manifest_sha256:
                pre.launch.fixed_plan_manifest_sha256,
            evidence_closure_sha256:
                raw_final.evidence_closure.reference_sha256,
            terminal_evidence_sha256: verified_final.final_sha256,
            attestation_scope_measurement_sha256:
                self.bootstrap.attestation_sha256,
        };
        let signed_artifact = self
            .providers
            .receipts
            .sign_typed_after_final_verification(
                &verified_final,
                receipt_body.clone(),
            )?;
        let verified_receipt = self
            .bootstrap
            .verify_signed_receipt_artifact(
                &receipt_body,
                signed_artifact,
            )?;
        let mut receipt_objects =
            vec![verified_receipt.exact_receipt.clone()];
        receipt_objects.extend(verified_receipt.provider_call_objects());
        let stored_receipt = self
            .providers
            .evidence
            .stream_store_retrieve_and_recompute(
                &mut ledger,
                &receipt_objects,
            )?;
        if stored_receipt.len() != receipt_objects.len() {
            return Err(ControllerError::Rejected(
                "immutable store did not return the receipt and signer worker evidence",
            ));
        }
        let exact_receipt = stored_receipt[0].clone();
        if exact_receipt.reference_sha256
            != verified_receipt.exact_receipt.reference_sha256
        {
            return Err(ControllerError::Rejected(
                "immutable store changed the verified typed receipt reference",
            ));
        }
        every_object.extend(stored_receipt);
        let pre_publish_end = self.providers.trusted_time.signed_now()?;
        pre_publish_end.signed_evidence.validate()?;
        let publication_time_order = self.providers.trusted_time.verify_order_and_deadline(
            &raw_execution.trusted_start,
            &pre_publish_end,
            pre.request.deadline_unix_ms,
        )?;
        publication_time_order.validate()?;
        let stored_pre_publish_time = self
            .providers
            .evidence
            .stream_store_retrieve_and_recompute(
                &mut ledger,
                &[
                    pre_publish_end.signed_evidence.clone(),
                    publication_time_order.clone(),
                ],
            )?;
        every_object.extend(stored_pre_publish_time);
        let final_evidence_closure = self
            .providers
            .evidence
            .seal_final_closure(&ledger, &every_object)?;
        let publication = self.verify_publication(
            &verified_final,
            verified_receipt,
            &final_evidence_closure,
            &lease.claim_evidence,
            &publication_time_order,
        )?;

        // Publication is the first mutation that can expose PASS. All evidence,
        // receipt, quorum, time, and replay bindings have already been verified.
        let publication_lease = lease.clone();
        let publication_build_binding =
            ReceiptBuildBinding::from_success(&committed_build.committed);
        match self
            .providers
            .acceptance
            .publish_verified_success(lease, publication)
        {
            result => self.resolve_acceptance_readback(
                &acceptance_input,
                result,
                Some(&publication_lease),
                Some(&publication_build_binding),
                "success publication did not return a verifiable committed readback",
            ),
        }
    }

    fn verify_replay_outcome(
        &self,
        mut replay: CommittedReplay,
        acceptance_input: &AtomicAcceptanceInput,
    ) -> Result<ProductionOutcome> {
        validate_replay_matches_input(&replay, acceptance_input)?;
        replay.retrieval_ledger.validate_structure()?;
        let ledger = self.providers.evidence.stream_retrieve_replay(&replay)?;
        ledger.validate_structure()?;
        if ledger.final_transcript_sha256
                != replay.retrieval_ledger.final_transcript_sha256
            || ledger.total_bytes != replay.retrieval_ledger.total_bytes
            || ledger.ledger_id != replay.retrieval_ledger.ledger_id
        {
            return Err(ControllerError::Rejected(
                "replayed global retrieval ledger does not match committed ledger",
            ));
        }
        replay.retrieval_ledger = ledger;
        validate_replay_object_closure(&replay)?;
        let capability = self.bootstrap.verify_replay(&replay)?;
        let verified_receipt = self
            .bootstrap
            .verify_signed_controller_receipt(
                &replay.exact_receipt_bytes,
            )?;
        validate_signed_receipt_matches_replay(
            verified_receipt.body(),
            &replay,
        )?;
        match replay.terminal {
            AcceptanceTerminalKind::Success => Ok(ProductionOutcome::Success {
                capability,
                exact_receipt_bytes: replay.exact_receipt_bytes,
            }),
            AcceptanceTerminalKind::Failure => Ok(ProductionOutcome::Failure {
                capability,
                terminal: replay.terminal_evidence,
                exact_receipt_bytes: replay.exact_receipt_bytes,
            }),
            AcceptanceTerminalKind::Unknown => Ok(ProductionOutcome::Unknown {
                capability,
                terminal: replay.terminal_evidence,
                exact_receipt_bytes: replay.exact_receipt_bytes,
            }),
        }
    }

    fn execute_runtime_and_close(
        &self,
        pre: &VerifiedPreExecution,
        no_build: Option<&VerifiedNoBuildKernelCapability>,
        raw_pre: &RawPreExecutionEvidence,
        lease: &AcceptanceLease,
        gate_objects: &[EvidenceReference],
        effects_possible: &mut bool,
    ) -> Result<(
        VerifiedExecutionCapability,
        RawExecutionClosure,
        EvidenceReference,
        RawGlobalRetrievalLedger,
        Vec<EvidenceReference>,
    )> {
        let trusted_start = self.providers.trusted_time.signed_now()?;
        trusted_start.signed_evidence.validate()?;
        if trusted_start.unix_ms == 0
            || trusted_start.unix_ms > pre.request.deadline_unix_ms
        {
            return Err(ControllerError::Rejected(
                "trusted start time is invalid or after the request deadline",
            ));
        }
        let monitor_session =
            self.providers.kernel_monitor.arm_before_launch(pre)?;
        monitor_session.arm_evidence.validate()?;
        monitor_session.provider_call.validate_against(pre)?;
        if monitor_session.session_sha256 == [0; 32]
            || monitor_session
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != monitor_session.session_sha256
        {
            return Err(ControllerError::Rejected(
                "kernel monitor returned an unbound session",
            ));
        }
        let monitor_arm = monitor_session.arm_evidence.clone();
        let monitor_session_sha256 = monitor_session.session_sha256;
        let monitor_arm_provider_call =
            monitor_session.provider_call.clone();
        // Preparation may create only a held pre-exec process. It is still
        // conservatively effectful because controller cleanup is now required.
        *effects_possible = true;
        let prepared = self
            .providers
            .supervisor
            .prepare_registered_child(pre, no_build, &trusted_start)?;
        let authorization = match self
            .bootstrap
            .verify_supervisor_execution_gate(pre, &prepared)
        {
            Ok(authorization) => authorization,
            Err(verification_error) => {
                let cleanup = self
                    .providers
                    .supervisor
                    .abort_unverified_preparation(
                        pre,
                        prepared,
                        pre.request.deadline_unix_ms,
                    );
                return match cleanup {
                    Ok(terminal) => match self
                        .bootstrap
                        .verify_containment_terminal(pre, &terminal)
                    {
                        Ok(_) => Err(verification_error),
                        Err(cleanup_verification_error) => {
                            Err(ControllerError::InvalidOwned(format!(
                                "supervisor gate verification failed: {verification_error}; cleanup evidence failed native verification: {cleanup_verification_error}"
                            )))
                        }
                    },
                    Err(cleanup_error) => Err(ControllerError::InvalidOwned(
                        format!(
                            "supervisor gate verification failed: {verification_error}; unverified preparation cleanup failed: {cleanup_error}"
                        ),
                    )),
                };
            }
        };
        let gate = self
            .providers
            .supervisor
            .authorize_verified_preparation(pre, prepared, authorization)?;
        let supervisor_capabilities = gate.capabilities().clone();
        let supervisor_registration_binding_sha256 =
            gate.registration_binding_sha256();
        let supervisor_state_machine_identity_sha256 =
            gate.shared_state_machine_identity_sha256();
        let supervisor_state_machine_measurement =
            gate.shared_state_machine_measurement().clone();
        let supervisor_preparation_transition_sha256 =
            gate.preparation_transition_sha256();
        let supervisor_authorization_transition_sha256 =
            gate.authorization_transition_sha256();
        let supervisor_release = match self
            .providers
            .supervisor
            .release_verified_child(
                pre,
                &gate,
                &trusted_start,
                pre.request.deadline_unix_ms,
            )
        {
            Ok(release) => {
                if let Err(error) = release.validate_against(pre, &gate) {
                    let cleanup = self.providers.supervisor.supervise_and_terminate(
                        pre,
                        gate,
                        pre.request.deadline_unix_ms,
                    );
                    return match cleanup {
                        Ok(terminal) => match self
                            .bootstrap
                            .verify_containment_terminal(pre, &terminal)
                        {
                            Ok(_) => Err(error),
                            Err(cleanup_verification_error) => {
                                Err(ControllerError::InvalidOwned(format!(
                                    "supervisor release verification failed: {error}; cleanup evidence failed native verification: {cleanup_verification_error}"
                                )))
                            }
                        },
                        Err(cleanup_error) => Err(ControllerError::InvalidOwned(
                            format!(
                                "supervisor release verification failed: {error}; cleanup failed: {cleanup_error}"
                            ),
                        )),
                    };
                }
                release
            }
            Err(release_error) => {
                let cleanup = self.providers.supervisor.supervise_and_terminate(
                    pre,
                    gate,
                    pre.request.deadline_unix_ms,
                );
                return match cleanup {
                    Ok(terminal) => match self
                        .bootstrap
                        .verify_containment_terminal(pre, &terminal)
                    {
                        Ok(_) => Err(release_error),
                        Err(cleanup_verification_error) => {
                            Err(ControllerError::InvalidOwned(format!(
                                "supervisor release failed: {release_error}; cleanup evidence failed native verification: {cleanup_verification_error}"
                            )))
                        }
                    },
                    Err(cleanup_error) => Err(ControllerError::InvalidOwned(
                        format!(
                            "supervisor release failed: {release_error}; cleanup failed: {cleanup_error}"
                        ),
                    )),
                };
            }
        };
        let runtime_completion = self
            .providers
            .runtime
            .collect_completion(
                pre,
                &gate,
                &trusted_start,
                pre.request.deadline_unix_ms,
            );
        let kernel_execution = self.providers.kernel_monitor.collect_complete_evidence(
            pre,
            monitor_session,
            &gate,
            pre.request.deadline_unix_ms,
        );
        let containment = self.providers.supervisor.supervise_and_terminate(
            pre,
            gate,
            pre.request.deadline_unix_ms,
        );
        let containment = containment?;
        self.bootstrap
            .verify_containment_terminal(pre, &containment)?;
        let runtime_completion = runtime_completion?;
        let kernel_execution = kernel_execution?;
        runtime_completion.provider_call.validate_against(pre)?;
        kernel_execution.provider_call.validate_against(pre)?;
        containment.provider_call.validate_against(pre)?;
        if runtime_completion
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != runtime_completion.outputs.object_sha256
            || kernel_execution
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != kernel_execution_result_sha256(&kernel_execution)
            || containment
                .provider_call
                .result_or_terminal_binding
                .object_sha256
                != containment_terminal_result_sha256(&containment)
        {
            return Err(ControllerError::Rejected(
                "execution provider result binding is not canonical",
            ));
        }
        let trusted_end = self.providers.trusted_time.signed_now()?;
        trusted_end.signed_evidence.validate()?;
        let raw_execution = RawExecutionClosure {
            monitor_arm,
            monitor_session_sha256,
            monitor_arm_provider_call,
            supervisor_capabilities,
            supervisor_registration_binding_sha256,
            supervisor_state_machine_identity_sha256,
            supervisor_state_machine_measurement,
            supervisor_preparation_transition_sha256,
            supervisor_authorization_transition_sha256,
            supervisor_release,
            exec_start_exit: kernel_execution.exec_start_exit,
            path_and_file_identity: kernel_execution.path_and_file_identity,
            interpreter_module_loader_jit:
                kernel_execution.interpreter_module_loader_jit,
            executable_vmas: kernel_execution.executable_vmas,
            monitor_collection_provider_call:
                kernel_execution.provider_call,
            runtime_provider_call: runtime_completion.provider_call,
            containment,
            trusted_start: trusted_start.clone(),
            trusted_end: trusted_end.clone(),
            outputs: runtime_completion.outputs,
        };
        let signed_time_order = self.providers.trusted_time.verify_order_and_deadline(
            &trusted_start,
            &trusted_end,
            pre.request.deadline_unix_ms,
        )?;
        signed_time_order.validate()?;
        if raw_execution.trusted_start.signed_evidence.reference_sha256
                != trusted_start.signed_evidence.reference_sha256
            || raw_execution.trusted_end.signed_evidence.reference_sha256
                != trusted_end.signed_evidence.reference_sha256
        {
            return Err(ControllerError::Rejected(
                "runtime trusted-time evidence does not match controller observations",
            ));
        }
        let execution = self.verify_execution(pre, &raw_execution)?;
        let mut ledger = self.providers.evidence.begin_global_ledger(&pre.request)?;
        let mut raw_objects = pre_execution_objects(raw_pre);
        raw_objects.extend(execution_objects(&raw_execution));
        raw_objects.push(signed_time_order.clone());
        raw_objects.extend(lease.claim_objects.iter().cloned());
        raw_objects.extend(gate_objects.iter().cloned());
        let every_object = self
            .providers
            .evidence
            .stream_store_retrieve_and_recompute(&mut ledger, &raw_objects)?;
        ledger.validate_structure()?;
        Ok((
            execution,
            raw_execution,
            signed_time_order,
            ledger,
            every_object,
        ))
    }

    fn close_acceptance_terminal(
        &self,
        input: &AtomicAcceptanceInput,
        lease: AcceptanceLease,
        kind: AcceptanceTerminalKind,
        stage: &'static str,
        error: &ControllerError,
        build_binding: Option<&ReceiptBuildBinding>,
    ) -> Result<ProductionOutcome> {
        let evidence = match kind {
            AcceptanceTerminalKind::Failure => self
                .providers
                .terminals
                .record_failure(stage, &error.to_string()),
            AcceptanceTerminalKind::Unknown => self
                .providers
                .terminals
                .record_unknown(stage, &error.to_string()),
            AcceptanceTerminalKind::Success => {
                return Err(ControllerError::Invalid(
                    "success cannot be emitted by terminal error closure",
                ))
            }
        };
        let expected_lease = lease.clone();
        let initial = match evidence {
            Ok(terminal) => (|| -> Result<CommittedReplay> {
                terminal.validate()?;
                let body = self.terminal_receipt_body(
                    input,
                    &lease,
                    kind,
                    &terminal,
                    build_binding,
                );
                let artifact = self
                    .providers
                    .receipts
                    .sign_typed_terminal_after_verification(
                        &terminal,
                        body.clone(),
                    )
                    .and_then(|artifact| {
                        self.bootstrap
                            .verify_signed_receipt_artifact(&body, artifact)
                    });
                match (kind, artifact) {
                    (AcceptanceTerminalKind::Failure, Ok(receipt)) => self
                        .providers
                        .acceptance
                        .commit_failure(lease, &terminal, receipt),
                    (AcceptanceTerminalKind::Unknown, Ok(receipt)) => self
                        .providers
                        .acceptance
                        .commit_unknown(lease, &terminal, receipt),
                    (AcceptanceTerminalKind::Success, _) => unreachable!(),
                    (_, Err(error)) => Err(error),
                }
            })(),
            Err(terminal_error) => Err(terminal_error),
        };
        self.resolve_acceptance_readback(
            input,
            initial,
            Some(&expected_lease),
            build_binding,
            "acceptance terminal close or reconciliation failed",
        )
    }

    fn terminal_receipt_body(
        &self,
        input: &AtomicAcceptanceInput,
        lease: &AcceptanceLease,
        kind: AcceptanceTerminalKind,
        terminal: &EvidenceReference,
        build_binding: Option<&ReceiptBuildBinding>,
    ) -> ControllerReceiptBody {
        let receipt_terminal = match kind {
            AcceptanceTerminalKind::Success => ReceiptTerminal::Success,
            AcceptanceTerminalKind::Failure => ReceiptTerminal::Failure,
            AcceptanceTerminalKind::Unknown => ReceiptTerminal::Unknown,
        };
        ControllerReceiptBody {
            terminal: receipt_terminal,
            lane: input.lane,
            attestation_scope: self.bootstrap.attestation_scope,
            deadline_unix_ms: input.deadline_unix_ms,
            acceptance_fence: lease.fence,
            acceptance_generation: lease.generation,
            build_fence: build_binding.map_or(0, |binding| binding.fence),
            build_reservation_generation: build_binding
                .map_or(0, |binding| binding.reservation_generation),
            request_id: input.request_id,
            exact_signed_request_sha256:
                input.exact_signed_request_sha256,
            nonce_sha256: input.nonce_sha256,
            observed_source_sha256: input.observed_source_sha256,
            current_lane_command_sha256:
                input.current_lane_command_identity_sha256,
            committed_build_command_sha256: build_binding.map_or(
                [0; 32],
                |binding| binding.build_command_identity_sha256,
            ),
            acceptance_identity_sha256:
                lease.acceptance_identity_sha256,
            build_reservation_identity_sha256: build_binding.map_or(
                [0; 32],
                |binding| binding.reservation_identity_sha256,
            ),
            config_sha256: input.config_sha256,
            provider_manifest_sha256: input.provider_manifest_sha256,
            fixed_plan_manifest_sha256:
                input.fixed_plan_manifest_sha256,
            evidence_closure_sha256: terminal_receipt_closure_sha256(
                input,
                lease,
                terminal,
                receipt_terminal,
                build_binding,
            ),
            terminal_evidence_sha256: terminal.reference_sha256,
            attestation_scope_measurement_sha256:
                self.bootstrap.attestation_sha256,
        }
    }

    fn resolve_acceptance_readback(
        &self,
        input: &AtomicAcceptanceInput,
        initial: Result<CommittedReplay>,
        expected_lease: Option<&AcceptanceLease>,
        expected_build_binding: Option<&ReceiptBuildBinding>,
        quarantine_reason: &str,
    ) -> Result<ProductionOutcome> {
        let (candidate, prior_error) = match initial {
            Ok(readback) => (Some(readback), None),
            Err(commit_error) => match self.providers.acceptance.reconcile(input) {
                Ok(readback) => (Some(readback), Some(commit_error.to_string())),
                Err(reconcile_error) => (
                    None,
                    Some(format!(
                        "commit error: {commit_error}; reconciliation error: {reconcile_error}"
                    )),
                ),
            },
        };
        let verification_error = match candidate {
            Some(readback) => match expected_lease
                .map(|lease| validate_replay_matches_lease(&readback, lease))
                .transpose()
                .and_then(|_| {
                    expected_build_binding
                        .map(|binding| {
                            validate_replay_matches_build_binding(
                                &readback,
                                binding,
                            )
                        })
                        .transpose()
                })
                .and_then(|_| self.verify_replay_outcome(readback, input))
            {
                Ok(outcome) => return Ok(outcome),
                Err(error) => Some(error.to_string()),
            },
            None => None,
        };
        let detail = verification_error
            .or(prior_error)
            .unwrap_or_else(|| "no committed acceptance readback".to_owned());
        let reason = format!("{quarantine_reason}: {detail}");
        let quarantined = self
            .providers
            .acceptance
            .hard_quarantine(input, &reason)?;
        if let Some(lease) = expected_lease {
            validate_replay_matches_lease(&quarantined, lease)?;
        }
        if let Some(binding) = expected_build_binding {
            validate_replay_matches_build_binding(&quarantined, binding)?;
        }
        self.verify_replay_outcome(quarantined, input)
    }

    fn commit_build_success(
        &self,
        pre: &VerifiedPreExecution,
        reservation: BuildReservation,
        candidate: VerifiedBuildCandidate,
    ) -> Result<VerifiedBuildClosure> {
        match self
            .providers
            .builds
            .commit_success(reservation.clone(), candidate)
        {
            Ok(committed) => {
                match self
                    .bootstrap
                    .verify_committed_build_success_for_reservation(
                        pre,
                        &reservation,
                        committed,
                    )
                {
                    Ok(verified) => Ok(verified),
                    Err(error) => {
                        let readback = self.resolve_build_readback(
                            pre,
                            &reservation,
                            Err(error),
                            "committed build success verification failed",
                        )?;
                        self.verified_build_from_readback(pre, &reservation, readback)
                    }
                }
            }
            Err(error) => {
                let readback = self.resolve_build_readback(
                    pre,
                    &reservation,
                    Err(error),
                    "build success commit reconciliation failed",
                )?;
                self.verified_build_from_readback(pre, &reservation, readback)
            }
        }
    }

    fn verified_build_from_readback(
        &self,
        pre: &VerifiedPreExecution,
        reservation: &BuildReservation,
        readback: CommittedBuildReadback,
    ) -> Result<VerifiedBuildClosure> {
        match readback {
            CommittedBuildReadback::Success(success) => {
                self.bootstrap.verify_committed_build_success_for_reservation(
                    pre,
                    reservation,
                    success,
                )
            }
            CommittedBuildReadback::Failure(terminal)
            | CommittedBuildReadback::Unknown(terminal) => {
                self.bootstrap
                    .verify_build_terminal(reservation, &terminal)?;
                Err(ControllerError::Rejected(
                    "build success was not committed",
                ))
            }
        }
    }

    fn close_build_terminal(
        &self,
        pre: &VerifiedPreExecution,
        reservation: BuildReservation,
        kind: BuildTerminalKind,
        stage: &'static str,
        error: &ControllerError,
    ) -> Result<()> {
        let evidence = match kind {
            BuildTerminalKind::Failure => self
                .providers
                .terminals
                .record_failure(stage, &error.to_string()),
            BuildTerminalKind::Unknown => self
                .providers
                .terminals
                .record_unknown(stage, &error.to_string()),
        };
        let initial = match evidence {
            Ok(terminal) => match kind {
                BuildTerminalKind::Failure => self
                    .providers
                    .builds
                    .commit_failure(reservation.clone(), &terminal),
                BuildTerminalKind::Unknown => self
                    .providers
                    .builds
                    .commit_unknown(reservation.clone(), &terminal),
            },
            Err(terminal_error) => Err(terminal_error),
        };
        let readback = self.resolve_build_readback(
            pre,
            &reservation,
            initial,
            "build terminal close or reconciliation failed",
        )?;
        match readback {
            CommittedBuildReadback::Success(success) => {
                self.bootstrap
                    .verify_committed_build_success_for_reservation(
                        pre,
                        &reservation,
                        success,
                    )
                    .map(|_| ())
            }
            CommittedBuildReadback::Failure(terminal)
            | CommittedBuildReadback::Unknown(terminal) => {
                self.bootstrap
                    .verify_build_terminal(&reservation, &terminal)
            }
        }
    }

    fn resolve_build_readback(
        &self,
        pre: &VerifiedPreExecution,
        reservation: &BuildReservation,
        initial: Result<CommittedBuildReadback>,
        quarantine_reason: &str,
    ) -> Result<CommittedBuildReadback> {
        let (readback, prior_error) = match initial {
            Ok(readback) => (Some(readback), None),
            Err(commit_error) => {
                match self.providers.builds.reconcile(reservation.clone()) {
                    Ok(readback) => {
                        (Some(readback), Some(commit_error.to_string()))
                    }
                    Err(reconcile_error) => (
                        None,
                        Some(format!(
                            "commit error: {commit_error}; reconciliation error: {reconcile_error}"
                        )),
                    ),
                }
            }
        };
        let verification_error = match readback {
            Some(readback) => match self
                .bootstrap
                .validate_build_readback(pre, reservation, &readback)
            {
                Ok(()) => return Ok(readback),
                Err(error) => Some(error.to_string()),
            },
            None => None,
        };
        let detail = verification_error
            .or(prior_error)
            .unwrap_or_else(|| "no committed build readback".to_owned());
        let reason = format!("{quarantine_reason}: {detail}");
        let quarantined = self
            .providers
            .builds
            .hard_quarantine(reservation.clone(), &reason)?;
        self.bootstrap
            .validate_build_readback(pre, reservation, &quarantined)?;
        Ok(quarantined)
    }

    fn resolve_build_source_readback(
        &self,
        pre: &VerifiedPreExecution,
        quarantine_reason: &str,
    ) -> Result<CommittedBuildReadback> {
        let reconciliation = self.providers.builds.reconcile_source(&pre.source);
        let detail = match reconciliation {
            Ok(readback) => match self
                .bootstrap
                .validate_build_source_readback(pre, &readback)
            {
                Ok(()) => return Ok(readback),
                Err(error) => format!("invalid reconciled source readback: {error}"),
            },
            Err(error) => format!("source reconciliation error: {error}"),
        };
        let reason = format!("{quarantine_reason}: {detail}");
        let quarantined = self
            .providers
            .builds
            .hard_quarantine_source(&pre.source, &reason)?;
        self.bootstrap
            .validate_build_source_readback(pre, &quarantined)?;
        Ok(quarantined)
    }

    fn verify_execution(
        &self,
        pre: &VerifiedPreExecution,
        raw: &RawExecutionClosure,
    ) -> Result<VerifiedExecutionCapability> {
        for object in execution_objects(raw) {
            object.validate()?;
        }
        raw.monitor_arm_provider_call.validate_against(pre)?;
        raw.supervisor_capabilities
            .preparation_provider_call
            .validate_against(pre)?;
        raw.supervisor_release.provider_call.validate_against(pre)?;
        raw.monitor_collection_provider_call.validate_against(pre)?;
        raw.runtime_provider_call.validate_against(pre)?;
        raw.containment.provider_call.validate_against(pre)?;
        raw.supervisor_state_machine_measurement.validate()?;
        if raw.supervisor_state_machine_identity_sha256 == [0; 32]
            || raw.supervisor_state_machine_measurement.object_sha256
                != raw.supervisor_state_machine_identity_sha256
            || raw.supervisor_preparation_transition_sha256 == [0; 32]
            || raw.supervisor_authorization_transition_sha256 == [0; 32]
            || raw.supervisor_release.verified_gate_sha256 == [0; 32]
            || raw
                .supervisor_release
                .shared_state_machine_identity_sha256
                != raw.supervisor_state_machine_identity_sha256
            || raw.containment.shared_state_machine_identity_sha256
                != raw.supervisor_state_machine_identity_sha256
            || raw.supervisor_release.state_machine_transition_sha256
                == [0; 32]
            || raw.containment.state_machine_transition_sha256 == [0; 32]
            || raw.monitor_session_sha256 == [0; 32]
            || raw
                .monitor_arm_provider_call
                .result_or_terminal_binding
                .object_sha256
                != raw.monitor_session_sha256
        {
            return Err(ControllerError::Rejected(
                "execution closure lacks a verified supervisor gate binding",
            ));
        }
        validate_full_supervisor_transition_chain(pre, raw)?;
        let decision = self.bootstrap.verifier.verify_execution_closure(pre, raw)?;
        if !(decision.exec_start_exit_complete
            && decision.path_and_file_identity_complete
            && decision.provenance_complete
            && decision.executable_vma_partition_complete
            && decision.no_writable_executable_mapping
            && decision.containment_clean
            && decision.verified_supervisor_state_machine
            && decision.exact_shared_supervisor_transition_chain
            && decision.exact_provider_result_bindings
            && decision.provider_calls_bounded_workers_and_deadlines
            && decision.provider_worker_pidfds_killed_and_bounded_reaped
            && decision.controller_sole_parent_and_reaper
            && decision.independent_watchdog_non_parent_non_reaper
            && decision.independent_watchdog_deadline_enforcement
            && decision.durable_orphan_journal_complete
            && decision.signed_time_ordered_and_fresh
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected execution or containment closure",
            ));
        }
        Ok(VerifiedExecutionCapability {
            execution_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_final(
        &self,
        execution: &VerifiedExecutionCapability,
        raw: &RawFinalCandidate,
    ) -> Result<VerifiedFinalCandidate> {
        raw.retrieval_ledger.validate_structure()?;
        let decision = self
            .bootstrap
            .verifier
            .verify_membership_and_receipt(execution, raw)?;
        if !(decision.membership_lineage
            && decision.epoch_floor
            && decision.physical_key_uniqueness
            && decision.weighted_quorum_intersection
            && decision.actual_receipt_certificate
            && decision.availability
            && decision.attestation_exact_replay
            && decision.complete_global_retrieval
            && decision.exact_receipt_candidate
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected final evidence candidate",
            ));
        }
        Ok(VerifiedFinalCandidate {
            final_sha256: decision.decision_sha256,
            _seal: capability_seal::Seal,
        })
    }

    fn verify_publication(
        &self,
        final_candidate: &VerifiedFinalCandidate,
        typed_receipt: VerifiedTypedReceiptCapability,
        final_evidence_closure: &EvidenceReference,
        acceptance_claim: &EvidenceReference,
        signed_time_order: &EvidenceReference,
    ) -> Result<VerifiedPublicationCapability> {
        typed_receipt.exact_receipt.validate()?;
        if typed_receipt.terminal != ReceiptTerminal::Success {
            return Err(ControllerError::Rejected(
                "success publication received a non-success typed receipt",
            ));
        }
        final_evidence_closure.validate()?;
        acceptance_claim.validate()?;
        signed_time_order.validate()?;
        let decision = self.bootstrap.verifier.verify_publication_candidate(
            final_candidate,
            &typed_receipt.exact_receipt,
            final_evidence_closure,
            acceptance_claim,
            signed_time_order,
        )?;
        if !(decision.exact_receipt_and_quorum
            && decision.final_evidence_closure
            && decision.atomic_acceptance_binding
            && decision.signed_start_end_time
            && decision.decision_sha256 != [0; 32])
        {
            return Err(ControllerError::Rejected(
                "native verifier rejected publication candidate",
            ));
        }
        Ok(VerifiedPublicationCapability {
            publication_sha256: decision.decision_sha256,
            exact_receipt: typed_receipt.exact_receipt.clone(),
            typed_receipt,
            _seal: capability_seal::Seal,
        })
    }
}

pub enum ProductionOutcome {
    Success {
        capability: VerifiedReplayCapability,
        exact_receipt_bytes: Vec<u8>,
    },
    Failure {
        capability: VerifiedReplayCapability,
        terminal: EvidenceReference,
        exact_receipt_bytes: Vec<u8>,
    },
    Unknown {
        capability: VerifiedReplayCapability,
        terminal: EvidenceReference,
        exact_receipt_bytes: Vec<u8>,
    },
}

fn validate_replay_matches_input(
    replay: &CommittedReplay,
    input: &AtomicAcceptanceInput,
) -> Result<()> {
    validate_exact_replay_bounds(replay)?;
    if replay.lane != input.lane
        || replay.request_id != input.request_id
        || replay.exact_signed_request_sha256
            != input.exact_signed_request_sha256
        || replay.nonce_sha256 != input.nonce_sha256
        || replay.peer_binding_sha256 != input.peer_binding_sha256
        || replay.deadline_unix_ms != input.deadline_unix_ms
        || replay.config_sha256 != input.config_sha256
        || replay.observed_source_sha256 != input.observed_source_sha256
        || replay.root_identity_sha256 != input.root_identity_sha256
        || replay.source_root_sha256 != input.source_root_sha256
        || replay.current_lane_command_identity_sha256
            != input.current_lane_command_identity_sha256
        || replay.provider_manifest_sha256 != input.provider_manifest_sha256
        || replay.fixed_plan_manifest_sha256
            != input.fixed_plan_manifest_sha256
        || replay.pre_execution_decision_sha256
            != input.pre_execution_decision_sha256
    {
        return Err(ControllerError::Rejected(
            "committed replay does not bind the atomic acceptance input",
        ));
    }
    Ok(())
}

fn atomic_acceptance_input_sha256(input: &AtomicAcceptanceInput) -> Digest {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(b"serverware-controller-v11/atomic-acceptance\0");
    bytes.push(input.lane.operation.code());
    bytes.push(input.lane.plan.code());
    bytes.extend_from_slice(&input.request_id);
    bytes.extend_from_slice(&input.exact_signed_request_sha256);
    bytes.extend_from_slice(&input.nonce_sha256);
    bytes.extend_from_slice(&input.peer_binding_sha256);
    bytes.extend_from_slice(&input.deadline_unix_ms.to_be_bytes());
    bytes.extend_from_slice(&input.config_sha256);
    bytes.extend_from_slice(&input.observed_source_sha256);
    bytes.extend_from_slice(&input.root_identity_sha256);
    bytes.extend_from_slice(&input.source_root_sha256);
    bytes.extend_from_slice(&input.current_lane_command_identity_sha256);
    bytes.extend_from_slice(&input.provider_manifest_sha256);
    bytes.extend_from_slice(&input.fixed_plan_manifest_sha256);
    bytes.extend_from_slice(&input.pre_execution_decision_sha256);
    sha256(&bytes)
}

fn terminal_receipt_closure_sha256(
    input: &AtomicAcceptanceInput,
    lease: &AcceptanceLease,
    terminal: &EvidenceReference,
    kind: ReceiptTerminal,
    build_binding: Option<&ReceiptBuildBinding>,
) -> Digest {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(
        b"serverware-controller-v11/typed-terminal-receipt-closure\0",
    );
    bytes.push(kind as u8);
    bytes.extend_from_slice(&atomic_acceptance_input_sha256(input));
    bytes.extend_from_slice(&lease.fence.to_be_bytes());
    bytes.extend_from_slice(&lease.acceptance_identity_sha256);
    bytes.extend_from_slice(&lease.generation.to_be_bytes());
    bytes.extend_from_slice(&lease.verification_sha256);
    if let Some(binding) = build_binding {
        bytes.push(1);
        bytes.extend_from_slice(&binding.fence.to_be_bytes());
        bytes.extend_from_slice(&binding.reservation_identity_sha256);
        bytes.extend_from_slice(&binding.reservation_generation.to_be_bytes());
        bytes.extend_from_slice(&binding.build_command_identity_sha256);
    } else {
        bytes.push(0);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&[0; 32]);
    }
    bytes.extend_from_slice(&terminal.reference_sha256);
    sha256(&bytes)
}

fn validate_signed_receipt_matches_replay(
    body: &ControllerReceiptBody,
    replay: &CommittedReplay,
) -> Result<()> {
    let expected_terminal = match replay.terminal {
        AcceptanceTerminalKind::Success => ReceiptTerminal::Success,
        AcceptanceTerminalKind::Failure => ReceiptTerminal::Failure,
        AcceptanceTerminalKind::Unknown => ReceiptTerminal::Unknown,
    };
    if body.terminal != expected_terminal
        || body.lane != replay.lane
        || body.request_id != replay.request_id
        || body.deadline_unix_ms != replay.deadline_unix_ms
        || body.acceptance_fence != replay.acceptance_fence
        || body.acceptance_generation != replay.acceptance_generation
        || body.build_fence != replay.build_fence
        || body.build_reservation_generation
            != replay.build_reservation_generation
        || body.exact_signed_request_sha256
            != replay.exact_signed_request_sha256
        || body.nonce_sha256 != replay.nonce_sha256
        || body.observed_source_sha256
            != replay.observed_source_sha256
        || body.current_lane_command_sha256
            != replay.current_lane_command_identity_sha256
        || body.committed_build_command_sha256
            != replay.committed_build_command_identity_sha256
        || body.acceptance_identity_sha256
            != replay.acceptance_identity_sha256
        || body.build_reservation_identity_sha256
            != replay.build_reservation_identity_sha256
        || body.config_sha256 != replay.config_sha256
        || body.provider_manifest_sha256
            != replay.provider_manifest_sha256
        || body.fixed_plan_manifest_sha256
            != replay.fixed_plan_manifest_sha256
        || body.terminal_evidence_sha256
            != replay.receipt_terminal_evidence_sha256
        || body.evidence_closure_sha256
            != replay.receipt_evidence_closure_sha256
        || body.attestation_scope_measurement_sha256
            != replay.attestation_scope_measurement_sha256
        || (replay.terminal != AcceptanceTerminalKind::Success
            && replay.receipt_terminal_evidence_sha256
                != replay.terminal_evidence.reference_sha256)
    {
        return Err(ControllerError::Rejected(
            "signed receipt does not exact-bind committed replay",
        ));
    }
    Ok(())
}

fn validate_replay_matches_lease(
    replay: &CommittedReplay,
    lease: &AcceptanceLease,
) -> Result<()> {
    if replay.acceptance_fence != lease.fence
        || replay.acceptance_identity_sha256
            != lease.acceptance_identity_sha256
        || replay.acceptance_generation != lease.generation
    {
        return Err(ControllerError::Rejected(
            "committed replay does not exact-bind verified acceptance lease",
        ));
    }
    Ok(())
}

fn validate_replay_matches_build_binding(
    replay: &CommittedReplay,
    binding: &ReceiptBuildBinding,
) -> Result<()> {
    if replay.build_fence != binding.fence
        || replay.build_reservation_identity_sha256
            != binding.reservation_identity_sha256
        || replay.build_reservation_generation
            != binding.reservation_generation
        || replay.committed_build_command_identity_sha256
            != binding.build_command_identity_sha256
    {
        return Err(ControllerError::Rejected(
            "committed replay does not exact-bind the verified build tuple",
        ));
    }
    Ok(())
}

fn validate_replay_object_closure(replay: &CommittedReplay) -> Result<()> {
    let mut required = replay.replay_objects.clone();
    required.push(replay.exact_receipt.clone());
    required.push(replay.terminal_evidence.clone());
    required.extend(bounded_provider_call_objects(
        &replay.receipt_provider_call,
    ));
    validate_objects_in_ledger(&replay.retrieval_ledger, required)
}

fn validate_objects_in_ledger(
    ledger: &RawGlobalRetrievalLedger,
    required: Vec<EvidenceReference>,
) -> Result<()> {
    let ledger_objects: BTreeSet<Digest> = ledger
        .entries
        .iter()
        .map(|entry| entry.object.reference_sha256)
        .collect();
    for object in required {
        object.validate()?;
        if !ledger_objects.contains(&object.reference_sha256) {
            return Err(ControllerError::Rejected(
                "required object is not fully bound in the global retrieval ledger",
            ));
        }
    }
    Ok(())
}

fn pre_execution_objects(raw: &RawPreExecutionEvidence) -> Vec<EvidenceReference> {
    let mut objects = vec![
        raw.config.clone(),
        raw.request.exact_canonical_bytes.clone(),
        raw.request.signed_envelope.clone(),
        raw.request.signature_evidence.clone(),
        raw.providers.manifest.clone(),
        raw.providers.freshness.clone(),
        raw.source.root_identity.clone(),
        raw.source.recursive_manifest.clone(),
        raw.source.immutable_snapshot.clone(),
        raw.launch.current_lane_command_identity.clone(),
        raw.launch.executable_identity.clone(),
        raw.launch.import_closure.clone(),
        raw.launch.sandbox_policy.clone(),
        raw.launch.no_build_policy.clone(),
        raw.launch.fixed_plan_table.table_evidence.clone(),
        raw.launch.trusted_plan_manifest.exact_bytes.clone(),
        raw.launch.trusted_plan_manifest.file_identity.clone(),
        raw.launch.trusted_plan_manifest.root_owned_immutable.clone(),
    ];
    for entry in &raw.launch.fixed_plan_table.entries {
        objects.push(entry.openat2_resolution.clone());
        objects.push(entry.file_identity.clone());
        objects.push(entry.cwd_identity.clone());
        objects.push(entry.retained_fd_evidence.clone());
        objects.push(entry.execveat_token.clone());
    }
    objects.extend(raw.providers.executable_bytes.iter().cloned());
    objects.extend(raw.providers.measurements.iter().cloned());
    objects.extend(raw.providers.process_identities.iter().cloned());
    objects.extend(raw.providers.trust_and_revocation.iter().cloned());
    objects
}

fn bounded_provider_call_objects(
    raw: &RawBoundedProviderCallEvidence,
) -> Vec<EvidenceReference> {
    vec![
        raw.worker_process_identity.clone(),
        raw.worker_pidfd_identity.clone(),
        raw.monotonic_deadline_binding.clone(),
        raw.result_or_terminal_binding.clone(),
        raw.kill_and_bounded_reap.clone(),
        raw.controller_reaper_boundary.clone(),
    ]
}

fn supervisor_capability_objects(
    raw: &RawSupervisorCapabilityEvidence,
) -> Vec<EvidenceReference> {
    let mut objects = vec![
        raw.child_held_before_execution.clone(),
        raw.retained_fd_launch_authority.clone(),
        raw.supervision_authority.clone(),
        raw.independent_watchdog_authority.clone(),
        raw.durable_orphan_journal.clone(),
        raw.controller_parent_reaper.clone(),
        raw.runtime_no_launch_authority.clone(),
    ];
    objects.extend(bounded_provider_call_objects(
        &raw.preparation_provider_call,
    ));
    objects
}

fn kernel_execution_result_sha256(
    raw: &RawKernelExecutionEvidence,
) -> Digest {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(
        b"serverware-controller-v11/kernel-monitor-result\0",
    );
    bytes.extend_from_slice(&raw.exec_start_exit.reference_sha256);
    bytes.extend_from_slice(&raw.path_and_file_identity.reference_sha256);
    bytes.extend_from_slice(
        &raw.interpreter_module_loader_jit.reference_sha256,
    );
    bytes.extend_from_slice(&raw.executable_vmas.reference_sha256);
    sha256(&bytes)
}

fn containment_terminal_result_sha256(
    raw: &RawContainmentTerminal,
) -> Digest {
    let kind = match raw.kind {
        ContainmentTerminalKind::Clean => 1,
        ContainmentTerminalKind::Failure => 2,
        ContainmentTerminalKind::Unknown => 3,
    };
    let mut bytes = Vec::with_capacity(416);
    bytes.extend_from_slice(
        b"serverware-controller-v11/containment-terminal\0",
    );
    bytes.push(kind);
    bytes.extend_from_slice(
        &raw.shared_state_machine_identity_sha256,
    );
    bytes.extend_from_slice(&raw.predecessor_transition_sha256);
    bytes.extend_from_slice(&raw.state_machine_transition_sha256);
    for object in [
        &raw.preconditions,
        &raw.pidfd_signal,
        &raw.cgroup_kill,
        &raw.process_group_kill,
        &raw.bounded_reap,
        &raw.watchdog_deadline_enforcement,
        &raw.controller_parent_reaper,
        &raw.durable_orphan_journal,
        &raw.orphan_journal_reconciliation,
        &raw.cgroup_events_empty,
        &raw.cgroup_procs_empty,
    ] {
        bytes.extend_from_slice(&object.reference_sha256);
    }
    sha256(&bytes)
}

fn validate_full_supervisor_transition_chain(
    pre_execution: &VerifiedPreExecution,
    raw: &RawExecutionClosure,
) -> Result<()> {
    let identity = raw.supervisor_state_machine_identity_sha256;
    let registration = raw.supervisor_registration_binding_sha256;
    let request = pre_execution.request.request_sha256;
    let manifest = pre_execution.launch.fixed_plan_manifest_sha256;
    let authorization = raw.supervisor_release.verified_gate_sha256;
    let prepared = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        [0; 32],
        [0; 32],
        SupervisorStatePhase::Prepared,
    );
    let authorized = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        authorization,
        prepared,
        SupervisorStatePhase::Authorized,
    );
    let releasing = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        authorization,
        authorized,
        SupervisorStatePhase::Releasing,
    );
    let running = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        authorization,
        releasing,
        SupervisorStatePhase::Running,
    );
    let terminating = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        authorization,
        running,
        SupervisorStatePhase::Terminating,
    );
    let closed = supervisor_state_transition_sha256(
        identity,
        registration,
        request,
        manifest,
        authorization,
        terminating,
        SupervisorStatePhase::Closed,
    );
    if raw.supervisor_preparation_transition_sha256 != prepared
        || raw.supervisor_authorization_transition_sha256 != authorized
        || raw.supervisor_release.predecessor_transition_sha256
            != releasing
        || raw.supervisor_release.state_machine_transition_sha256
            != running
        || raw.containment.predecessor_transition_sha256 != terminating
        || raw.containment.state_machine_transition_sha256 != closed
    {
        return Err(ControllerError::Rejected(
            "execution closure does not carry the exact shared supervisor transition chain",
        ));
    }
    Ok(())
}

fn containment_objects(
    raw: &RawContainmentTerminal,
) -> Vec<EvidenceReference> {
    let mut objects = vec![
        raw.preconditions.clone(),
        raw.pidfd_signal.clone(),
        raw.cgroup_kill.clone(),
        raw.process_group_kill.clone(),
        raw.bounded_reap.clone(),
        raw.watchdog_deadline_enforcement.clone(),
        raw.controller_parent_reaper.clone(),
        raw.durable_orphan_journal.clone(),
        raw.orphan_journal_reconciliation.clone(),
        raw.cgroup_events_empty.clone(),
        raw.cgroup_procs_empty.clone(),
    ];
    objects.extend(bounded_provider_call_objects(&raw.provider_call));
    objects
}

fn execution_objects(raw: &RawExecutionClosure) -> Vec<EvidenceReference> {
    let mut objects = vec![
        raw.monitor_arm.clone(),
        raw.supervisor_state_machine_measurement.clone(),
        raw.supervisor_release.retained_fd_execveat_release.clone(),
        raw.exec_start_exit.clone(),
        raw.path_and_file_identity.clone(),
        raw.interpreter_module_loader_jit.clone(),
        raw.executable_vmas.clone(),
        raw.trusted_start.signed_evidence.clone(),
        raw.trusted_end.signed_evidence.clone(),
        raw.outputs.clone(),
    ];
    objects.extend(bounded_provider_call_objects(
        &raw.monitor_arm_provider_call,
    ));
    objects.extend(supervisor_capability_objects(
        &raw.supervisor_capabilities,
    ));
    objects.extend(bounded_provider_call_objects(
        &raw.supervisor_release.provider_call,
    ));
    objects.extend(bounded_provider_call_objects(
        &raw.monitor_collection_provider_call,
    ));
    objects.extend(bounded_provider_call_objects(
        &raw.runtime_provider_call,
    ));
    objects.extend(containment_objects(&raw.containment));
    objects
}

fn no_build_policy_objects(raw: &RawNoBuildInstallation) -> Vec<EvidenceReference> {
    vec![
        raw.policy.pre_exec_allowlist.clone(),
        raw.policy.compiler_and_build_tool_denials.clone(),
        raw.policy.import_escape_denials.clone(),
        raw.policy.recursive_source_read_only.clone(),
        raw.policy.writable_output_denials.clone(),
        raw.policy.docker_and_container_socket_denials.clone(),
        raw.policy.mount_namespace_policy.clone(),
        raw.kernel_pre_exec_hook.clone(),
        raw.mount_enforcement.clone(),
        raw.import_enforcement.clone(),
    ]
}

fn committed_build_success_objects(
    committed: &CommittedBuildSuccess,
) -> Vec<EvidenceReference> {
    let mut objects = vec![
        committed.raw_closure.outputs_manifest.clone(),
        committed.success_terminal.clone(),
        committed.fence_and_cas_inclusion.clone(),
        committed.output_manifest.clone(),
        committed.retrieval_ledger_evidence.clone(),
    ];
    objects.extend(committed.immutable_store_objects.iter().cloned());
    objects.extend(
        committed
            .retrieval_ledger
            .entries
            .iter()
            .map(|entry| entry.object.clone()),
    );
    let mut seen = BTreeSet::new();
    objects.retain(|object| seen.insert(object.reference_sha256));
    objects
}

fn final_candidate_objects(raw: &RawFinalCandidate) -> Vec<EvidenceReference> {
    let mut objects = vec![
        raw.membership.signed_checkpoint.clone(),
        raw.membership.immediate_predecessor.clone(),
        raw.membership.append_only_lineage.clone(),
        raw.membership.monotonic_epoch_floor.clone(),
        raw.membership.physical_key_uniqueness.clone(),
        raw.membership.weighted_intersection.clone(),
        raw.membership.actual_receipt_certificate.clone(),
        raw.evidence_closure.clone(),
        raw.exact_receipt_candidate.clone(),
    ];
    objects.extend(raw.availability.iter().cloned());
    objects.extend(raw.attestation.iter().cloned());
    objects.extend(raw.quorum.iter().cloned());
    objects
}

pub fn validate_exact_replay_bounds(replay: &CommittedReplay) -> Result<()> {
    replay.terminal_evidence.validate()?;
    for object in &replay.replay_objects {
        object.validate()?;
    }
    let receipt = &replay.exact_receipt;
    receipt.validate()?;
    if receipt.length != SIGNED_CONTROLLER_RECEIPT_BYTES as u64
        || replay.exact_receipt_bytes.len() as u64 != receipt.length
        || sha256(&replay.exact_receipt_bytes) != receipt.object_sha256
    {
        return Err(ControllerError::Rejected(
            "typed replay receipt is invalid or not fixed v11 size",
        ));
    }
    let decoded_receipt =
        SignedControllerReceipt::decode(&replay.exact_receipt_bytes)?;
    replay
        .receipt_provider_call
        .validate_against_receipt_body(&decoded_receipt.body)?;
    if replay
        .receipt_provider_call
        .result_or_terminal_binding
        .object_sha256
        != receipt.object_sha256
    {
        return Err(ControllerError::Rejected(
            "typed replay receipt signer call does not bind exact wire bytes",
        ));
    }
    let build_binding_absent = replay.committed_build_command_identity_sha256
            == [0; 32]
        && replay.build_fence == 0
        && replay.build_reservation_identity_sha256 == [0; 32]
        && replay.build_reservation_generation == 0;
    let build_binding_complete = replay
        .committed_build_command_identity_sha256
        != [0; 32]
        && replay.build_fence != 0
        && replay.build_reservation_identity_sha256 != [0; 32]
        && replay.build_reservation_generation != 0;
    if replay.request_id == [0; 32]
        || replay.exact_signed_request_sha256 == [0; 32]
        || replay.nonce_sha256 == [0; 32]
        || replay.peer_binding_sha256 == [0; 32]
        || replay.config_sha256 == [0; 32]
        || replay.observed_source_sha256 == [0; 32]
        || replay.root_identity_sha256 == [0; 32]
        || replay.source_root_sha256 == [0; 32]
        || replay.current_lane_command_identity_sha256 == [0; 32]
        || replay.acceptance_fence == 0
        || replay.acceptance_identity_sha256 == [0; 32]
        || replay.acceptance_generation == 0
        || (!build_binding_absent && !build_binding_complete)
        || (replay.terminal == AcceptanceTerminalKind::Success
            && !build_binding_complete)
        || replay.receipt_evidence_closure_sha256 == [0; 32]
        || replay.receipt_terminal_evidence_sha256 == [0; 32]
        || replay.attestation_scope_measurement_sha256 == [0; 32]
        || replay.provider_manifest_sha256 == [0; 32]
        || replay.fixed_plan_manifest_sha256 == [0; 32]
        || replay.pre_execution_decision_sha256 == [0; 32]
    {
        return Err(ControllerError::Rejected("exact replay binding or size is invalid"));
    }
    Ok(())
}

pub fn path_is_absolute(path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ControllerError::Invalid("path must be absolute"))
    }
}

fn validate_absolute_normalized_path(path: &Path) -> Result<()> {
    use std::path::Component;

    if !path.is_absolute() || path == Path::new("/") {
        return Err(ControllerError::Rejected(
            "verified policy path must be absolute and non-root",
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(ControllerError::Rejected(
            "verified policy path is not lexically canonical",
        ));
    }
    Ok(())
}
