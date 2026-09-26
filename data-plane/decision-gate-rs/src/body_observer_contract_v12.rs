//! Shared closed originals for the fixed two-phase observer exchange.
//!
//! These are typed canonical scope/data records, not process observations,
//! observer signatures, or permission to inspect an arbitrary target. In
//! particular, a ready echo never replaces independent runtime admission.

use super::{ArtifactCasReference, Digest, LogicalLane, PlanProtocolError,
    PlanResult, SourceCasReference};
use super::body_launch_contract_v12::{BodyLaunchContextV12, MAX_CONTEXT_BYTES_V12};
use super::body_output_contract_v12::stream_byte_limit;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub const SOCKET_PATH: &str = "/run/serverware/coder/v12/runtime-observer/control.sock";
pub const LAUNCH_VERSION: &str = "serverware.controllerBodyObserverLaunch/v12";
pub const READY_VERSION: &str = "serverware.controllerBodyObserverReady/v12";
pub const TERMINAL_VERSION: &str = "serverware.controllerBodyObserverTerminal/v12";
pub const MAX_LAUNCH_BYTES: usize = MAX_CONTEXT_BYTES_V12;
pub const MAX_CONTROL_BYTES: usize = 4096;
pub const FD_ROLES: [&str; 9] = ["pidfd", "proc", "exe", "userns", "mntns",
    "pidns", "netns", "cgroupns", "cgroupdir"];
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 1_000_000;

// Declaration order is the original typed wire order, not sorted-key JSON.
// None artifacts remain explicit null; only the terminal native option is
// omitted. Changing either spelling changes the original protocol bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyObserverLaunchV12 {
    pub version: String,
    pub context: BodyLaunchContextV12,
    pub source: SourceCasReference,
    pub artifacts: Option<ArtifactCasReference>,
    pub expected_proxy: Digest,
    pub target_pid: u32,
    pub target_start: u64,
    pub target_pidfd_inode: u64,
    pub target_custody: Digest,
    pub deadline_boottime_ns: u64,
    pub fd_roles: [String; 9],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyObserverReadyV12 {
    pub version: String,
    pub context_sha256: Digest,
    pub target_pid: u32,
    pub target_start: u64,
    pub target_pidfd_inode: u64,
    pub target_custody: Digest,
    pub deadline_boottime_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyObserverTerminalRequestV12 {
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub body_sha256: Digest,
    pub command_sha256: Digest,
    pub exit_status: i32,
    pub stdout_sha256: Digest,
    pub stdout_bytes: u64,
    pub stderr_sha256: Digest,
    pub stderr_bytes: u64,
    pub output_manifest_sha256: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_postgres_output_sha256: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyObserverTerminalV12 {
    pub version: String,
    pub context_sha256: Digest,
    pub target_custody: Digest,
    pub deadline_boottime_ns: u64,
    pub claims: BodyObserverTerminalRequestV12,
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

struct BoundedBytes { bytes: Vec<u8>, maximum: usize }
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.bytes.len().checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData,
                "observer original exceeds its fixed frame bound"))?;
        if length > self.bytes.capacity() {
            let target = length.max(self.bytes.capacity().max(4096)
                .saturating_mul(2).min(self.maximum));
            self.bytes.try_reserve_exact(target - self.bytes.len())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other,
                    "observer original bounded allocation failed"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn preflight(bytes: &[u8], maximum: usize) -> PlanResult<()> {
    if !(2..=maximum).contains(&bytes.len()) { return Err(invalid("observer original exceeds its fixed frame bound")); }
    let (mut quoted, mut escaped, mut primitive) = (false, false, false);
    let (mut depth, mut nodes) = (0usize, 0usize);
    for &byte in bytes {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
            continue;
        }
        match byte {
            b'"' => { quoted = true; primitive = false; nodes += 1; }
            b'{' | b'[' => { depth += 1; nodes += 1; primitive = false; }
            b'}' | b']' => { depth = depth.checked_sub(1)
                .ok_or_else(|| invalid("observer original has unbalanced JSON"))?; primitive = false; }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => primitive = false,
            _ => { if !primitive { primitive = true; nodes += 1; } }
        }
        if depth > MAX_DEPTH || nodes > MAX_NODES { return Err(invalid("observer original structure exceeds source bounds")); }
    }
    if quoted || depth != 0 { return Err(invalid("observer original JSON is incomplete")); }
    Ok(())
}

fn encoded<T: Serialize>(value: &T, maximum: usize) -> PlanResult<Vec<u8>> {
    let mut output = BoundedBytes { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut output, value)?;
    preflight(&output.bytes, maximum)?;
    Ok(output.bytes)
}

fn decoded<T: serde::de::DeserializeOwned>(bytes: &[u8], maximum: usize) -> PlanResult<T> {
    preflight(bytes, maximum)?;
    // Every nested source type is closed. Typed serde rejects unknown and
    // duplicate fields; exact re-encoding below rejects alternate spellings.
    Ok(serde_json::from_slice(bytes)?)
}

impl BodyObserverLaunchV12 {
    fn validate_fields(&self) -> PlanResult<()> {
        if self.version != LAUNCH_VERSION || self.expected_proxy == [0; 32]
            || !(2..=i32::MAX as u32).contains(&self.target_pid) || self.target_start == 0
            || self.target_pidfd_inode == 0 || self.target_custody == [0; 32]
            || self.deadline_boottime_ns == 0 || self.deadline_boottime_ns > self.context.deadline_boottime_ns
            || self.fd_roles.iter().zip(FD_ROLES).any(|(actual, expected)| actual != expected) {
            return Err(invalid("observer launch has invalid fixed target/deadline/descriptor scope"));
        }
        self.context.validate()?;
        self.source.validate()?;
        if let Some(artifacts) = &self.artifacts {
            artifacts.validate()?;
            if artifacts.source_manifest_sha256 != self.source.manifest_sha256 {
                return Err(invalid("observer launch artifact/source scope differs"));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> PlanResult<()> { self.original_bytes().map(|_| ()) }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        // Stop before growing past the cap, before nested validators may clone
        // their complete graphs. No caller Value or proof carrier is accepted.
        let bytes = encoded(self, MAX_LAUNCH_BYTES)?;
        self.validate_fields()?;
        Ok(bytes)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decoded(bytes, MAX_LAUNCH_BYTES)?;
        if value.original_bytes()? != bytes { return Err(invalid("observer launch original is not exact typed canonical JSON")); }
        Ok(value)
    }
}

impl BodyObserverReadyV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if self.version != READY_VERSION || self.context_sha256 == [0; 32]
            || !(2..=i32::MAX as u32).contains(&self.target_pid) || self.target_start == 0
            || self.target_pidfd_inode == 0 || self.target_custody == [0; 32] || self.deadline_boottime_ns == 0 {
            return Err(invalid("observer ready has invalid fixed target/deadline scope"));
        }
        Ok(())
    }

    pub fn validate_for(&self, launch: &BodyObserverLaunchV12) -> PlanResult<()> {
        launch.validate()?;
        self.validate()?;
        if self.context_sha256 != launch.context.context_sha256 || self.target_pid != launch.target_pid
            || self.target_start != launch.target_start || self.target_pidfd_inode != launch.target_pidfd_inode
            || self.target_custody != launch.target_custody || self.deadline_boottime_ns != launch.deadline_boottime_ns {
            return Err(invalid("observer ready does not echo the exact original launch"));
        }
        Ok(())
    }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encoded(self, MAX_CONTROL_BYTES)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decoded(bytes, MAX_CONTROL_BYTES)?;
        if value.original_bytes()? != bytes { return Err(invalid("observer ready original is not exact typed canonical JSON")); }
        Ok(value)
    }
}

impl BodyObserverTerminalRequestV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if self.plan_id == [0; 32] || self.body_sha256 == [0; 32] || self.command_sha256 == [0; 32]
            || self.stdout_sha256 == [0; 32] || self.stderr_sha256 == [0; 32]
            || self.output_manifest_sha256 == [0; 32] || self.native_postgres_output_sha256 == Some([0; 32]) {
            return Err(invalid("observer terminal request lacks its original commitments"));
        }
        Ok(())
    }

    pub fn validate_for(&self, launch: &BodyObserverLaunchV12) -> PlanResult<()> {
        launch.validate()?;
        self.validate()?;
        let context = &launch.context;
        let limit = stream_byte_limit(context.runner.execution_bounds.output_bytes)?;
        if self.plan_id != context.plan_id || self.lane != context.lane
            || self.body_sha256 != context.body.body_sha256 || self.command_sha256 != context.body.command.command_sha256
            || self.stdout_bytes > limit || self.stderr_bytes > limit
            || self.native_postgres_output_sha256.is_some() != context.body.native_postgres.is_some() {
            return Err(invalid("observer terminal request differs from original body/output scope"));
        }
        Ok(())
    }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encoded(self, MAX_CONTROL_BYTES)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decoded(bytes, MAX_CONTROL_BYTES)?;
        if value.original_bytes()? != bytes { return Err(invalid("observer terminal claims original is not exact typed canonical JSON")); }
        Ok(value)
    }
}

impl BodyObserverTerminalV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if self.version != TERMINAL_VERSION || self.context_sha256 == [0; 32]
            || self.target_custody == [0; 32] || self.deadline_boottime_ns == 0 {
            return Err(invalid("observer terminal wrapper lacks its original launch scope"));
        }
        self.claims.validate()
    }

    pub fn validate_for(&self, launch: &BodyObserverLaunchV12) -> PlanResult<()> {
        self.validate()?;
        self.claims.validate_for(launch)?;
        if self.context_sha256 != launch.context.context_sha256 || self.target_custody != launch.target_custody
            || self.deadline_boottime_ns != launch.deadline_boottime_ns {
            return Err(invalid("observer terminal wrapper differs from the original launch"));
        }
        Ok(())
    }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encoded(self, MAX_CONTROL_BYTES)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decoded(bytes, MAX_CONTROL_BYTES)?;
        if value.original_bytes()? != bytes { return Err(invalid("observer terminal original is not exact typed canonical JSON")); }
        Ok(value)
    }
}
