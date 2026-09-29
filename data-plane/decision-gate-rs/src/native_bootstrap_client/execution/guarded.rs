//! Actual child, network admission and independent guardian composition.

use super::{child::{BlockedChild, ChildCleanup, Execution, ExitObservation, OutputObservation},
    guardian::{Guardian, GuardianObservation}, network::{PreparedNetwork, NetworkReady},
    start::{self, PreparedStart}};
use super::super::egress::ExecutionParents;
use std::sync::Arc;

pub(super) struct GuardedChild {
    // On abandonment the guardian is told to stop before the direct child's
    // emergency cleanup. Neither destructor claims a successful lifecycle.
    guardian: Guardian,
    child: BlockedChild,
}

pub(super) struct GuardedCleanup {
    child: ChildCleanup,
    guardian: GuardianObservation,
    output: OutputObservation,
}

impl GuardedCleanup {
    pub(super) fn child(&self) -> &ChildCleanup { &self.child }
    pub(super) fn guardian(&self) -> &GuardianObservation { &self.guardian }
    pub(super) fn into_output(self) -> OutputObservation { self.output }
}

impl GuardedChild {
    pub(super) fn create(prepared: PreparedStart, parents: Arc<ExecutionParents>)
        -> Result<Self, String>
    {
        let child = start::prepare_blocked_child(prepared, parents)?;
        let guardian = Guardian::arm(&child.guardian_borrow()?)?;
        guardian.require_child(&child)?;
        Ok(Self { guardian, child })
    }

    pub(super) fn check_blocked(&self) -> Result<(), String> {
        self.guardian.require_child(&self.child)
    }

    pub(super) fn prepare_network(&self) -> Result<PreparedNetwork<'_>, String> {
        self.check_blocked()?;
        PreparedNetwork::open(&self.child)
    }

    pub(super) fn run_and_finish(&self, mut network: NetworkReady<'_, '_>)
        -> (Result<ExitObservation, String>, Result<GuardedCleanup, String>)
    {
        let run = (|| Execution::begin(&self.child, &self.guardian, &mut network)?.wait())();
        // NetworkReady and its bridge/journal/backend owners remain held until
        // BOTH cleanup paths and bounded output completion have finished.
        let cleanup = self.finish_borrowed();
        (run, cleanup)
    }

    pub(super) fn terminate(self) -> Result<GuardedCleanup, String> {
        self.finish_borrowed()
    }

    fn finish_borrowed(&self) -> Result<GuardedCleanup, String> {
        self.guardian.request_stop();
        // Evaluate both cleanup operations before propagating either error.
        // An expired/damaged child journal cannot suppress guardian cleanup;
        // a failed guardian cannot suppress the exact direct-child reap.
        let child_result = self.child.terminate();
        let guardian_result = self.guardian.finish();
        let output_result = self.child.finish_output();
        let child = child_result?;
        let guardian = guardian_result?;
        let output = output_result?;
        if !child.leader_reaped() {
            return Err("native guarded cleanup lacks its actual leader reap".to_owned());
        }
        Ok(GuardedCleanup { child, guardian, output })
    }
}
