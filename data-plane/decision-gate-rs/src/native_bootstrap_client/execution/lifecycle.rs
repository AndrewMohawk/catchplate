//! One fully owned native execution attempt, including terminal cleanup.
//! This private composition does not turn an observation into release authority.

use super::{child::{ExitObservation, OutputObservation}, guarded::GuardedChild, start::PreparedStart};
use super::super::egress::{ExecutionParents, HostRetirement, HostVethAbsence};
use serde::Serialize;
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
}

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
}

pub(in super::super) fn execute(prepared: PreparedStart, parents: Arc<ExecutionParents>)
    -> Result<LifecycleObservation, String>
{
    let mut guarded = GuardedChild::create(prepared, parents)?;
    let retiring = guarded.retirement_requested();
    // Stack scopes retain the actual network installation and its original
    // locks through execution; no self-referential owner or Arc cycle exists.
    let prepared_result = (|| {
        let prepared = guarded.prepare_network()?;
        let mut ready = prepared.install()?;
        let host = if retiring { Some(ready.prepare_retirement()?) } else { None };
        Ok::<_, String>((guarded.run_and_finish(ready), host))
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
        (Some(RetirementObservation { schema: "serverware.nativeExecutionRetirementObservation/v1",
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
    Ok(LifecycleObservation { schema: if retiring { "serverware.nativeExecutionObservation/v2" }
            else { "serverware.nativeExecutionObservation/v1" },
        result_scope: "local-single-attempt-execution-and-cleanup-observation",
        execution, output: cleanup.into_output(), cleanup: observations, workload_succeeded,
        action_authorization: None, ok_for_action: false, retirement,
        _retired_owner: if retiring { Some(guarded) } else { None }, _host_originals: host })
}
