//! Closed consistency frames; none is an attestation or authorization.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub(super) const MAX_FRAME: usize = 4096;
pub(super) const MAX_BOOTSTRAP: usize = 16 * 1024;
pub(super) fn require(ok: bool, message: &'static str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(io::Error::new(io::ErrorKind::PermissionDenied, message)) }
}
pub(super) fn digest(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
fn hash(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value[7..].bytes().any(|b| b != b'0')
}
pub(super) fn ns(value: &str) -> io::Result<u64> {
    let number = value.parse::<u64>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid original deadline"))?;
    require(number > 0 && number.to_string() == value, "noncanonical original deadline")?;
    Ok(number)
}
fn nonce(value: &str) -> bool {
    URL_SAFE_NO_PAD.decode(value).is_ok_and(|bytes| bytes.len() == 32
        && bytes.iter().any(|v| *v != 0) && URL_SAFE_NO_PAD.encode(bytes) == value)
}
fn path(value: &str) -> bool {
    value.len() <= 4096 && value.starts_with('/') && !value.contains('\0')
        && value.split('/').skip(1).all(|v| !v.is_empty() && v != "." && v != "..")
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D)
    -> Result<Option<T>, D::Error> { Option::<T>::deserialize(d) }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub api_version: String,
    pub configuration_path: String,
    pub configuration_sha256: String,
    pub delivery_path: String,
    pub delivery_sha256: String,
    pub gate_lifetime_deadline_boottime_ns: String,
    pub channel_nonce: String,
}
impl Bootstrap {
    pub fn validate(&self) -> io::Result<()> {
        require(self.api_version == "serverware.responseV2.guestInspectorBootstrap/v1"
            && path(&self.configuration_path) && path(&self.delivery_path)
            && self.configuration_path != self.delivery_path
            && hash(&self.configuration_sha256) && hash(&self.delivery_sha256)
            && nonce(&self.channel_nonce), "invalid closed inspector bootstrap")?;
        ns(&self.gate_lifetime_deadline_boottime_ns).map(|_| ())
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Phase { Connection, Packet }
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Operation { Connection, BeforeDispatch, BeforeResponse }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    pub api_version: String,
    pub channel_nonce: String,
    pub request_sequence: u64,
    pub phase: Phase,
    #[serde(deserialize_with = "required_option")]
    pub frame_sha256: Option<String>,
    pub operation: Operation,
    #[serde(deserialize_with = "required_option")]
    pub session_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub sequence: Option<u16>,
    pub deadline_boottime_ns: String,
}
impl Request {
    pub fn validate(&self, nonce: &str, next: u64, lifetime: u64, now: u64) -> io::Result<u64> {
        let deadline = ns(&self.deadline_boottime_ns)?;
        require(self.api_version == "serverware.responseV2.guestInspectorRequest/v1"
            && self.channel_nonce == nonce && next > 0 && self.request_sequence == next
            && now < deadline && deadline <= lifetime, "inspection context/deadline mismatch")?;
        match self.phase {
            Phase::Connection => require(self.operation == Operation::Connection
                && self.frame_sha256.is_none() && self.session_id.is_none() && self.sequence.is_none(),
                "connection measurement must not manufacture frame context")?,
            Phase::Packet => require(self.operation != Operation::Connection
                && self.frame_sha256.as_deref().is_some_and(hash)
                && self.session_id.as_deref().is_none_or(hash)
                && self.sequence.is_some_and(|v| v <= 255), "invalid packet measurement context")?,
        }
        Ok(deadline)
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Measurement {
    pub process_binding_sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_sha256: String,
    pub security_label_sha256: String,
    pub executable_sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResultFrame<'a> {
    pub api_version: &'static str,
    pub request: &'a Request,
    pub measurement: Measurement,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Initialized<'a> {
    pub api_version: &'static str,
    pub channel_nonce: &'a str,
    pub bootstrap_sha256: &'a str,
}
