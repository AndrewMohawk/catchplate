//! Actual pre-exec child and independent guardian composition, not an exec API.

use super::{child::{BlockedChild, ChildCleanup}, guardian::{Guardian, GuardianObservation},
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
}

impl GuardedCleanup {
    pub(super) fn child(&self) -> &ChildCleanup { &self.child }
    pub(super) fn guardian(&self) -> &GuardianObservation { &self.guardian }
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

    pub(super) fn terminate(self) -> Result<GuardedCleanup, String> {
        let Self { guardian, mut child } = self;
        guardian.request_stop();
        // Evaluate both cleanup operations before propagating either error.
        // An expired/damaged child journal cannot suppress guardian cleanup;
        // a failed guardian cannot suppress the exact direct-child reap.
        let child_result = child.terminate();
        let guardian_result = guardian.finish();
        let child = child_result?;
        let guardian = guardian_result?;
        if !child.leader_reaped() {
            return Err("native guarded cleanup lacks its actual leader reap".to_owned());
        }
        Ok(GuardedCleanup { child, guardian })
    }
}
