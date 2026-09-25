//! Original-byte body evidence admission under independently retained trust.
//!
//! The policy and expected scope come from the release-admitted root owner,
//! never the received result. This verifies the existing observer signature;
//! it does not acquire observations, sign caller claims, or publish a terminal.
//! The returned parsed data does not replace the caller's actual exit, stream,
//! output, native-report, target PID/start-time and namespace custody joins.

use super::{ControllerError, Result};
use crate::plan_protocol::{
    ArtifactCasReference, BodyContract, Digest, LogicalLane, PlanProtocolError,
    RunnerIdentity, SourceCasReference,
};
use crate::runtime_evidence::{
    ExecutableRole, RuntimeObserverPolicy, StaticExecutableEvidenceV12,
};
use crate::runtime_evidence::body_result_v12::{
    BodyExecutionResultV12, BODY_RESULT_VERSION_V12,
};
use std::collections::BTreeSet;

fn evidence_error(error: PlanProtocolError) -> ControllerError {
    ControllerError::InvalidOwned(error.to_string())
}

fn static_role(
    evidence: &StaticExecutableEvidenceV12,
    role: ExecutableRole,
    expected: &Digest,
) -> Result<()> {
    if evidence.role != role
        || &evidence.content_sha256 != expected
        || evidence.size == 0
        || !evidence.filesystem_immutable
        || !evidence.root_owned
        || !evidence.no_interpreter
        || !evidence.no_needed_libraries
        || !evidence.no_writable_executable_segment
    {
        return Err(ControllerError::Rejected(
            "body static executable evidence differs from its admitted role",
        ));
    }
    Ok(())
}

/// Admit the original bounded wire once; no successful-result input or trust
/// policy supplied inside that wire can substitute for independent root pins.
pub(super) fn admit_original(
    bytes: &[u8],
    plan_id: Digest,
    lane: LogicalLane,
    body: &BodyContract,
    runner: &RunnerIdentity,
    source: &SourceCasReference,
    artifacts: Option<&ArtifactCasReference>,
    proxy: &Digest,
    policy: &RuntimeObserverPolicy,
) -> Result<BodyExecutionResultV12> {
    body.validate().map_err(evidence_error)?;
    runner.validate().map_err(evidence_error)?;
    source.validate().map_err(evidence_error)?;
    if let Some(artifacts) = artifacts {
        artifacts.validate().map_err(evidence_error)?;
    }
    if plan_id == [0; 32] || lane != body.lane
        || runner.executable_closure_sha256.binary_search(
            &body.command.executable_sha256,
        ).is_err()
    {
        return Err(ControllerError::Rejected(
            "body evidence admission lost its independent plan or executable scope",
        ));
    }
    let result = BodyExecutionResultV12::parse_original(bytes)
        .map_err(evidence_error)?;
    match (&body.native_postgres, &result.native_postgres_output_sha256) {
        (Some(_), Some(digest)) if *digest != [0; 32] => {}
        (None, None) => {}
        _ => return Err(ControllerError::Rejected(
            "body evidence lost its source-selected native PostgreSQL commitment",
        )),
    }
    if result.version != BODY_RESULT_VERSION_V12
        || result.plan_id != plan_id
        || result.lane != lane
        || result.body_sha256 != body.body_sha256
        || result.command_sha256 != body.command.command_sha256
        || result.stdout_sha256 == [0; 32]
        || result.stderr_sha256 == [0; 32]
        || result.output_manifest_sha256 == [0; 32]
        || result.terminal_sha256 == [0; 32]
    {
        return Err(ControllerError::Rejected(
            "body evidence differs from its independently admitted scope",
        ));
    }
    static_role(&result.runner_static_evidence,
        ExecutableRole::ControllerOwnedRunner, &runner.runtime_executable_sha256)?;
    static_role(&result.courier_static_evidence,
        ExecutableRole::StaticCourier,
        runner.static_courier_sha256.as_ref().ok_or(ControllerError::Rejected(
            "body runner lacks its admitted static courier pin",
        ))?)?;
    let allowed: BTreeSet<Digest> = runner.executable_closure_sha256
        .iter().copied().collect();
    result.runner_evidence.validate(source, artifacts, &runner.image, &allowed)
        .map_err(evidence_error)?;
    result.runner_evidence.validate_authoritative_join(
        runner, proxy, &body.command.command_sha256, policy,
    ).map_err(evidence_error)?;
    result.validate_terminal().map_err(evidence_error)?;
    Ok(result)
}
