//! One fully owned native execution attempt, including terminal cleanup.
//! This private composition does not turn an observation into release authority.

use super::{child::{ExitObservation, OutputObservation}, guarded::GuardedChild, start::PreparedStart};
use super::super::egress::ExecutionParents;
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
    let guarded = GuardedChild::create(prepared, parents)?;
    // Stack scopes retain the actual network installation and its original
    // locks through execution; no self-referential owner or Arc cycle exists.
    let prepared_result = (|| {
        let prepared = guarded.prepare_network()?;
        let ready = prepared.install()?;
        Ok::<_, String>(guarded.run_and_finish(ready))
    })();
    // Always attempt direct-child, whole-leaf, independent guardian and output
    // cleanup before reporting either the run error or the cleanup error.
    let (execution_result, cleanup_result) = match prepared_result {
        Ok(results) => results,
        Err(error) => {
            let _ = guarded.terminate();
            return Err(error);
        },
    };
    let execution = execution_result?;
    let cleanup = cleanup_result?;
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
    Ok(LifecycleObservation { schema: "serverware.nativeExecutionObservation/v1",
        result_scope: "local-single-attempt-execution-and-cleanup-observation",
        execution, output: cleanup.into_output(), cleanup: observations, workload_succeeded,
        action_authorization: None, ok_for_action: false })
}
