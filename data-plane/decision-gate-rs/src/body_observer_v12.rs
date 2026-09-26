//! Observer-side receipt and actual pre-release custody, not an observer daemon.
//!
//! There is deliberately no ready, resume, sign or terminal-response operation:
//! a read-only gate snapshot does not establish continuous runtime observation.
//! A future independently admitted service must supply its owned accepted socket
//! and release-authenticated controller executable pin. No self-enrollment or
//! caller-selected endpoint/process operation is introduced here.

#[path = "body_observer_target_v12.rs"]
mod body_observer_target_v12;
#[path = "body_observer_gate_v12.rs"]
mod body_observer_gate_v12;
#[path = "body_observer_receive_v12.rs"]
mod body_observer_receive_v12;

use crate::plan_protocol::{Digest, PlanResult};
use crate::plan_protocol::body_observer_contract_v12::BodyObserverLaunchV12;
use body_observer_gate_v12::HeldBodyGateV12;
use body_observer_receive_v12::{ObserverLaunchChannelV12, ReceivedObserverLaunchV12};
use body_observer_target_v12::ReceivedBodyTargetV12;
use std::os::fd::OwnedFd;

/// Non-cloneable custody of a received, independently remeasured, still-gated
/// target. This is not serializable evidence or a transferable ready token.
pub(crate) struct AcquiredBodyObserverLaunchV12 {
    gate: HeldBodyGateV12,
    channel: ObserverLaunchChannelV12,
    launch: BodyObserverLaunchV12,
    deadline: u64,
}

impl AcquiredBodyObserverLaunchV12 {
    /// `deadline` is the independently owned maximum for this acquisition and
    /// its retained custody, not a relative timeout to renew after each phase.
    /// The original launch may shorten it but cannot extend it.
    pub(crate) fn acquire(
        accepted: OwnedFd,
        expected_controller_executable: Digest,
        deadline: u64,
    ) -> PlanResult<Self> {
        let ReceivedObserverLaunchV12 { channel, launch, target_fds, deadline } =
            ObserverLaunchChannelV12::receive(accepted, expected_controller_executable, deadline)?;
        let target = ReceivedBodyTargetV12::acquire(&launch, target_fds, deadline)?;
        channel.verify_pending(deadline)?;
        let gate = HeldBodyGateV12::acquire(target, deadline)?;
        let held = Self { gate, channel, launch, deadline };
        held.verify_pending(deadline)?;
        Ok(held)
    }

    pub(crate) fn verify_pending(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.deadline);
        self.channel.verify_pending(deadline)?;
        self.gate.verify_gated(deadline)?;
        self.channel.verify_pending(deadline)
    }

    pub(crate) fn launch(&self) -> &BodyObserverLaunchV12 { &self.launch }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }
}
