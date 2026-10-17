//! Closed native holder statements. These bytes are evidence, not admission.
//! The gate's sealed local owner supplies them only after registration or drain;
//! independent receiving authority verifies the original role-4 quotation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "catchplate.nativeCredentialCurrentnessStatement/v1";
pub const PROFILE: &str = "measured-holder-barrier-v1";
pub const SIGN_OPERATION: &str = "nativeCredentialCurrentness.sign/v1";
pub const ATTESTATION_DOMAIN: &[u8] = b"catchplate/credential-currentness-attestation/v1\0";
pub const LEASE_DOMAIN: &[u8] = b"catchplate.nativeCurrentCredentialLeaseBinding/v1\0";

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub profile: String,
    pub deployment_id: String,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), String> {
        if self.profile != PROFILE || !deployment(&self.deployment_id) {
            return Err("native currentness cold configuration is invalid".to_owned());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Statement {
    pub api_version: String,
    pub phase: String,
    pub holder_id: String,
    pub boot_id: String,
    pub key_id: String,
    pub control_plane_response_signing_key_id: String,
    pub deployment_id: String,
    pub credential_id: String,
    pub credential_version: u64,
    pub epoch: u64,
    pub challenge_id: String,
    pub challenge: String,
    pub barrier_id: Option<String>,
    pub barrier_sha256: Option<String>,
    pub policy_hash: String,
    pub data_plane_binary_sha256: String,
    pub issued_at_epoch_ns: u64,
    pub expires_at_epoch_ns: u64,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn deployment(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

pub fn digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value[7..].bytes().any(|byte| byte != b'0')
}

pub fn uuid(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) { byte == b'-' }
        else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
    })
}

pub fn bytes32(value: &str) -> Result<[u8; 32], String> {
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| "currentness base64url is invalid")?;
    if raw.len() != 32 || URL_SAFE_NO_PAD.encode(&raw) != value || raw.iter().all(|byte| *byte == 0) {
        return Err("currentness value is not canonical nonzero 32-byte material".to_owned());
    }
    raw.try_into().map_err(|_| "currentness byte length differs".to_owned())
}

pub fn holder_id(boot_id: &str, key_id: &str) -> Result<String, String> {
    if !digest(key_id) { return Err("currentness key ID is invalid".to_owned()); }
    let mut hash = Sha256::new();
    hash.update(b"catchplate/credential-currentness-holder/v1\0");
    hash.update(bytes32(boot_id)?);
    hash.update(hex::decode(&key_id[7..]).map_err(|_| "currentness key digest is invalid")?);
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

impl Statement {
    pub fn validate(&self, now_ns: u64) -> Result<(), String> {
        if self.api_version != SCHEMA || !matches!(self.phase.as_str(), "register" | "ack")
            || !deployment(&self.deployment_id) || !uuid(&self.credential_id)
            || self.credential_version == 0 || self.credential_version > i64::MAX as u64
            || self.epoch != self.credential_version || !uuid(&self.challenge_id)
            || !digest(&self.control_plane_response_signing_key_id)
            || !digest(&self.policy_hash) || !digest(&self.data_plane_binary_sha256)
            || self.holder_id != holder_id(&self.boot_id, &self.key_id)?
            || self.issued_at_epoch_ns == 0 || self.issued_at_epoch_ns > now_ns
            || self.expires_at_epoch_ns > i64::MAX as u64
            || now_ns >= self.expires_at_epoch_ns
            || self.expires_at_epoch_ns - self.issued_at_epoch_ns > 30_000_000_000
            || (self.phase == "register" && (self.barrier_id.is_some() || self.barrier_sha256.is_some()))
            || (self.phase == "ack" && (!self.barrier_id.as_deref().is_some_and(uuid)
                || !self.barrier_sha256.as_deref().is_some_and(digest))) {
            return Err("native currentness statement violates its closed profile".to_owned());
        }
        bytes32(&self.challenge)?;
        Ok(())
    }

    pub fn canonical(&self) -> Result<Vec<u8>, String> {
        crate::native_response_profile_v1::canonical_ascii_bytes(self)
    }

    pub fn preimage(&self) -> Result<Vec<u8>, String> {
        let mut bytes = SCHEMA.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(self.canonical()?);
        Ok(bytes)
    }
}

/// This binding is distinct from admission statements and existing lease AAD.
/// It commits the complete actual inner request, including its recipient quote.
pub fn lease_preimage(holder: &str, epoch: u64, registration: &str, request: &Value)
    -> Result<Vec<u8>, String> {
    lease_preimage_profile(holder, epoch, registration, request, false)
}

/// Additive broker-only family. The existing preimage function still refuses
/// these labels; actual cold broker ownership selects this entrypoint.
pub fn broker_lease_preimage(holder: &str, epoch: u64, registration: &str, request: &Value)
    -> Result<Vec<u8>, String> {
    lease_preimage_profile(holder, epoch, registration, request, true)
}

fn lease_preimage_profile(holder: &str, epoch: u64, registration: &str, request: &Value, broker: bool)
    -> Result<Vec<u8>, String> {
    let version = request.get("apiVersion").and_then(Value::as_str);
    let selected = if broker { matches!(version, Some("catchplate.nativeBrokerCredentialLeaseRequest/v1" | "catchplate.nativeBrokerCredentialLeaseRequest/v2")) }
        else { matches!(version, Some("catchplate.nativeCredentialLeaseRequest/v1" | "catchplate.nativeCredentialLeaseRequest/v2")) };
    if !digest(holder) || !digest(registration) || epoch == 0 || epoch > i64::MAX as u64
        || request.get("purpose").and_then(Value::as_str) != Some("dispatchSecret")
        || request.get("expectedCredentialVersion").and_then(Value::as_u64) != Some(epoch)
        || !selected {
        return Err("currentness lease binding is not an exact native secret request".to_owned());
    }
    let mut bytes = LEASE_DOMAIN.to_vec();
    bytes.extend(crate::native_response_profile_v1::canonical_ascii_bytes(&serde_json::json!({
        "holderId":holder, "epoch":epoch, "registrationSha256":registration, "leaseRequest":request,
    }))?);
    if bytes.len() > 64 * 1024 { return Err("currentness lease binding exceeds 64 KiB".to_owned()); }
    Ok(bytes)
}
