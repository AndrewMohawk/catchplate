//! Original controller launch context, separate from the signed child command.
//!
//! The independently admitted controller owns publication and the read-only
//! bind. A valid digest or parsed context is not execution/observer authority.
//! The typed identity recipe zeros only contextSha256; it never inserts the
//! resulting plan ID or launch metadata into the child's signed argv/env.

use super::{sha256_bytes, BodyContract, ContainerCommand, Digest, LogicalLane,
    PlanProtocolError, PlanResult, RunnerIdentity, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

pub const SUPERVISOR_EXECUTABLE: &str = "/usr/libexec/serverware-coder-body-supervisor-v12";
pub const CONTEXT_DIRECTORY: &str = "/serverware-controller-launch-v12";
pub const CONTEXT_NAME: &str = "launch.json";
pub const CONTEXT_PATH: &str = "/serverware-controller-launch-v12/launch.json";
pub const RELEASE_NAME: &str = "release.json";
pub const RELEASE_PATH: &str = "/serverware-controller-launch-v12/release.json";
pub const BODY_LAUNCH_CONTEXT_VERSION_V12: &str = "serverware.controllerBodyLaunch/v12";
pub const BODY_LAUNCH_RELEASE_VERSION_V12: &str = "serverware.controllerBodyRelease/v12";
pub const MAX_CONTEXT_BYTES_V12: usize = MAX_FRAME_BYTES;
pub const MAX_RELEASE_BYTES_V12: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyLaunchContextV12 {
    pub version: String,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub runner: RunnerIdentity,
    pub body: BodyContract,
    pub deadline_boottime_ns: u64,
    pub context_sha256: Digest,
}

struct BoundedBytes(Vec<u8>);

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().checked_add(bytes.len())
            .filter(|length| *length <= MAX_CONTEXT_BYTES_V12).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "launch context frame bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn encoded<T: Serialize>(value: &T) -> PlanResult<Vec<u8>> {
    let mut output = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut output, value)?;
    Ok(output.0)
}

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

impl BodyLaunchContextV12 {
    pub fn new(plan_id: Digest, lane: LogicalLane, runner: RunnerIdentity,
        body: BodyContract, deadline_boottime_ns: u64) -> PlanResult<Self> {
        let mut context = Self { version: BODY_LAUNCH_CONTEXT_VERSION_V12.to_owned(),
            plan_id, lane, runner, body, deadline_boottime_ns, context_sha256: [0; 32] };
        context.validate_scope()?;
        context.context_sha256 = sha256_bytes(&encoded(&context)?);
        context.validate()?;
        Ok(context)
    }

    fn validate_scope(&self) -> PlanResult<()> {
        self.runner.validate()?;
        self.body.validate()?;
        if self.version != BODY_LAUNCH_CONTEXT_VERSION_V12 || self.plan_id == [0; 32]
            || self.body.lane != self.lane || self.deadline_boottime_ns == 0
            || self.body.command.executable == SUPERVISOR_EXECUTABLE {
            return Err(invalid("body launch context has invalid scope, deadline or recursive command"));
        }
        if self.runner.executable_closure_sha256
            .binary_search(&self.body.command.executable_sha256).is_err() {
            return Err(invalid("body launch child executable is outside the admitted runner closure"));
        }
        Ok(())
    }

    pub fn validate(&self) -> PlanResult<()> {
        self.validate_scope()?;
        let mut identity = self.clone();
        identity.context_sha256 = [0; 32];
        if self.context_sha256 == [0; 32]
            || sha256_bytes(&encoded(&identity)?) != self.context_sha256 {
            return Err(invalid("body launch context identity is not its exact typed commitment"));
        }
        Ok(())
    }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encoded(self)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CONTEXT_BYTES_V12 {
            return Err(invalid("body launch context original exceeds its frame bound"));
        }
        // Typed serde admission rejects unknown/duplicate fields and wrong
        // scalar types; its recursion limit remains enabled. Re-encoding also
        // denies alternate whitespace, key order and string/number spellings.
        let context: Self = serde_json::from_slice(bytes)?;
        if context.original_bytes()? != bytes {
            return Err(invalid("body launch context is not its exact canonical original"));
        }
        Ok(context)
    }
}

/// Ordinary root-controller launch permission, not signed observer approval.
/// The host PID is scope supplied by the actual host custody owner; a PID-1
/// supervisor independently joins only its own start ticks and namespace PID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyLaunchReleaseV12 {
    pub version: String,
    pub context_sha256: Digest,
    pub host_target_pid: u32,
    pub target_start_time_ticks: u64,
    pub namespace_target_pid: u32,
    pub deadline_boottime_ns: u64,
    pub release_sha256: Digest,
}

fn encoded_release(value: &BodyLaunchReleaseV12) -> PlanResult<Vec<u8>> {
    // Called only after the fixed version/scalar checks. This closed seven-
    // field type has no unbounded graph or caller-selected string inventory.
    let bytes = encoded(value)?;
    if bytes.len() > MAX_RELEASE_BYTES_V12 {
        return Err(invalid("body launch release exceeds its fixed frame bound"));
    }
    Ok(bytes)
}

impl BodyLaunchReleaseV12 {
    pub fn new(context_sha256: Digest, host_target_pid: u32,
        target_start_time_ticks: u64, deadline_boottime_ns: u64) -> PlanResult<Self> {
        let mut release = Self { version: BODY_LAUNCH_RELEASE_VERSION_V12.to_owned(),
            context_sha256, host_target_pid, target_start_time_ticks,
            namespace_target_pid: 1, deadline_boottime_ns, release_sha256: [0; 32] };
        release.validate_scope()?;
        release.release_sha256 = sha256_bytes(&encoded_release(&release)?);
        release.validate()?;
        Ok(release)
    }

    fn validate_scope(&self) -> PlanResult<()> {
        if self.version != BODY_LAUNCH_RELEASE_VERSION_V12 || self.context_sha256 == [0; 32]
            || !(2..=i32::MAX as u32).contains(&self.host_target_pid)
            || self.target_start_time_ticks == 0 || self.namespace_target_pid != 1
            || self.deadline_boottime_ns == 0 {
            return Err(invalid("body launch release has invalid fixed process scope"));
        }
        Ok(())
    }

    pub fn validate(&self) -> PlanResult<()> {
        self.validate_scope()?;
        let mut identity = self.clone();
        identity.release_sha256 = [0; 32];
        if self.release_sha256 == [0; 32]
            || sha256_bytes(&encoded_release(&identity)?) != self.release_sha256 {
            return Err(invalid("body launch release identity is not its exact typed commitment"));
        }
        Ok(())
    }

    pub fn validate_for(&self, context: &BodyLaunchContextV12) -> PlanResult<()> {
        context.validate()?;
        self.validate()?;
        if self.context_sha256 != context.context_sha256
            || self.deadline_boottime_ns > context.deadline_boottime_ns {
            return Err(invalid("body launch release changes its held context or extends its deadline"));
        }
        Ok(())
    }

    pub fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encoded_release(self)
    }

    pub fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RELEASE_BYTES_V12 {
            return Err(invalid("body launch release original exceeds its fixed frame bound"));
        }
        let release: Self = serde_json::from_slice(bytes)?;
        if release.original_bytes()? != bytes {
            return Err(invalid("body launch release is not its exact canonical original"));
        }
        Ok(release)
    }
}

/// Preserve the existing Docker Entrypoint/Cmd interpretation of signed argv.
/// Callers validate the actual ContainerCommand before using this projection.
pub fn effective_argv(command: &ContainerCommand) -> Vec<String> {
    let mut argv = Vec::with_capacity(command.argv.len() + 1);
    argv.push(command.executable.clone());
    if command.argv.first().map(String::as_str) == Some(command.executable.as_str()) {
        argv.extend(command.argv[1..].iter().cloned());
    } else {
        argv.extend(command.argv.iter().cloned());
    }
    argv
}
