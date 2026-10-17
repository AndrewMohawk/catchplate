//! One fully owned native execution attempt, including terminal cleanup.
//! This private composition does not turn an observation into release authority.

use super::{child::{ExitObservation, OutputObservation}, guarded::GuardedChild, start::PreparedStart};
use super::super::egress::{ExecutionParents, HostRetirement, HostVethAbsence};
use serde::Serialize;
use super::start_reservation::{StartPermit, outcome};
use std::sync::Arc;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in super::super) struct LifecycleObservation {
    schema: &'static str,
    result_scope: &'static str,
    execution: ExitObservation,
    output: OutputObservation,
    cleanup: CleanupObservation,
    workload_succeeded: bool,
    action_authorization: Option<()>,
    ok_for_action: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retirement: Option<RetirementObservation>,
    #[serde(skip)]
    _retired_owner: Option<GuardedChild>,
    #[serde(skip)]
    _host_originals: Option<HostRetirement>,
    #[serde(skip)]
    _terminal_originals: Option<TerminalOriginals>,
    #[serde(skip)]
    _outcome: Option<outcome::Committed>,
}

struct TerminalOriginals { guardian: Vec<u8>, events: Vec<u8>, leader: Vec<u8> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetirementObservation {
    schema: &'static str, result_scope: &'static str, operation_sha256: String,
    cleanup_before_boottime_ns: u64, host_veth_absence: HostVethAbsence,
    cgroup_removal: super::containment::CgroupRemoval,
    action_authorization: Option<()>, ok_for_action: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupObservation {
    leader_reaped: bool,
    leaf_empty_boottime_ns: u64,
    leaf_kill_acknowledged: bool,
    guardian_empty_boottime_ns: u64,
    guardian_kill_acknowledged: bool,
}

impl LifecycleObservation {
    pub(in super::super) fn workload_succeeded(&self) -> bool { self.workload_succeeded }
    pub(in super::super) fn outcome_receipt(&self) -> Option<&outcome::Receipt> {
        self._outcome.as_ref().map(outcome::Committed::receipt)
    }
    pub(super) fn publication_originals(&self, permit: &StartPermit)
        -> Result<(&[u8], &[u8], &[u8], &[u8]), String> {
        let owner = self._retired_owner.as_ref().ok_or("native outcome actual retired owner absent")?;
        if !std::ptr::eq(owner.outcome_permit()?, permit) || !owner.outcome_requested()
            || self.retirement.is_none() || self._outcome.is_some() {
            return Err("native outcome belongs to another actual owner or was already published".to_owned());
        }
        let host = self._host_originals.as_ref().ok_or("native outcome retained host original absent")?;
        let raw = self._terminal_originals.as_ref().ok_or("native outcome retained terminal originals absent")?;
        Ok((host.completed_original(owner.operation_sha256())?, &raw.guardian, &raw.events, &raw.leader))
    }
}

pub(in super::super) fn execute(prepared: PreparedStart, parents: Arc<ExecutionParents>, application:Option<super::application_proxy::Inputs>)
    -> Result<LifecycleObservation, String>
{
    let mut guarded = GuardedChild::create(prepared, parents)?;
    let retiring = guarded.retirement_requested();
    let publishing = guarded.outcome_requested();
    // Stack scopes retain the actual network installation and its original
    // locks through execution; no self-referential owner or Arc cycle exists.
    let prepared_result = (|| {
        let prepared = guarded.prepare_network()?;
        let mut ready = prepared.install()?;
        let host = if retiring { Some(ready.prepare_retirement()?) } else { None };
        Ok::<_, String>((guarded.run_and_finish(ready,application), host))
    })();
    // Always attempt direct-child, whole-leaf, independent guardian and output
    // cleanup before reporting either the run error or the cleanup error.
    let ((execution_result, cleanup_result), host) = match prepared_result {
        Ok(results) => results,
        Err(error) => {
            let _ = guarded.terminate();
            return Err(error);
        },
    };
    let cleanup = cleanup_result?;
    // The borrowing PreparedNetwork and all child backend copies have gone
    // out of scope. Retire even if execution failed, after genuine cleanup.
    let (retirement, host) = if let Some(host) = host {
        let (absent, removed, host) = guarded.retire(&cleanup, host)?;
        let operation = guarded.operation_sha256().iter().map(|b| format!("{b:02x}")).collect::<String>();
        (Some(RetirementObservation { schema: "catchplate.nativeExecutionRetirementObservation/v1",
            result_scope: "local-owned-network-and-cgroup-retirement-observation",
            operation_sha256: format!("sha256:{operation}"), cleanup_before_boottime_ns: guarded.cleanup_boottime_ns(),
            host_veth_absence: absent, cgroup_removal: removed, action_authorization: None, ok_for_action: false }), Some(host))
    } else { (None, None) };
    let execution = execution_result?;
    if execution.code() != cleanup.child().leader_code()
        || execution.status() != cleanup.child().leader_status()
        || !cleanup.child().leader_reaped()
    {
        return Err("native terminal observation differs from the actual leader reap".to_owned());
    }
    let observations = CleanupObservation {
        leader_reaped: true,
        leaf_empty_boottime_ns: cleanup.child().leaf_empty().observed_boottime_ns(),
        leaf_kill_acknowledged: cleanup.child().leaf_empty().kill_acknowledged(),
        guardian_empty_boottime_ns: cleanup.guardian().observed_boottime_ns(),
        guardian_kill_acknowledged: cleanup.guardian().kill_acknowledged(),
    };
    let workload_succeeded = execution.code() == libc::CLD_EXITED && execution.status() == 0;
    let originals = if publishing { Some(TerminalOriginals {
        guardian: cleanup.guardian().original().to_vec(), events: cleanup.child().leaf_empty().original().to_vec(),
        leader: cleanup.child().original().to_vec() }) } else { None };
    let mut observation = LifecycleObservation { schema: if retiring { "catchplate.nativeExecutionObservation/v2" }
            else { "catchplate.nativeExecutionObservation/v1" },
        result_scope: "local-single-attempt-execution-and-cleanup-observation",
        execution, output: cleanup.into_output(), cleanup: observations, workload_succeeded,
        action_authorization: None, ok_for_action: false, retirement,
        _retired_owner: if retiring { Some(guarded) } else { None }, _host_originals: host,
        _terminal_originals: originals, _outcome: None };
    if publishing {
        // Successful nonzero exits are still terminal outcomes. All actual
        // emergency cleanup and retirement precede this optional filesystem
        // effect; failure cannot suppress them and cannot replay execution.
        let owner = observation._retired_owner.as_ref().ok_or("native outcome actual owner absent")?;
        let committed = outcome::publish(owner.outcome_permit()?, &observation)?;
        observation._outcome = Some(committed);
    }
    Ok(observation)
}
