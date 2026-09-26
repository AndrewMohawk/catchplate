//! Observer-side receipt and actual pre-release custody, not an observer daemon.
//!
//! There is deliberately no ready, resume, sign or terminal-response operation:
//! neither a read-only gate snapshot nor an initial stopped target establishes
//! complete continuous runtime observation.
//! A future independently admitted service must supply its owned accepted socket
//! and release-authenticated controller executable pin. No self-enrollment or
//! caller-selected endpoint/process operation is introduced here.

#[path = "body_observer_target_v12.rs"]
mod body_observer_target_v12;
#[path = "body_observer_gate_v12.rs"]
mod body_observer_gate_v12;
#[path = "body_observer_receive_v12.rs"]
mod body_observer_receive_v12;
#[path = "body_observer_process_v12.rs"]
mod body_observer_process_v12;
#[path = "body_observer_worker_v12.rs"]
mod body_observer_worker_v12;
#[path = "body_observer_worker_contract_v12.rs"]
mod body_observer_worker_contract_v12;
#[path = "body_observer_maps_v12.rs"]
mod body_observer_maps_v12;
#[path = "body_observer_mapping_files_v12.rs"]
mod body_observer_mapping_files_v12;
#[path = "body_observer_snapshot_v12.rs"]
mod body_observer_snapshot_v12;
#[path = "body_observer_history_contract_v14.rs"]
mod body_observer_history_contract_v14;
#[path = "body_observer_history_state_v14.rs"]
mod body_observer_history_state_v14;
#[path = "body_observer_history_acquire_v14.rs"]
mod body_observer_history_acquire_v14;
#[path = "body_observer_wait_contract_v14.rs"]
mod body_observer_wait_contract_v14;
#[path = "body_observer_wait_acquire_v14.rs"]
mod body_observer_wait_acquire_v14;
#[path = "body_observer_syscall_info_v14.rs"]
mod body_observer_syscall_info_v14;
#[path = "body_observer_task_proc_v14.rs"]
mod body_observer_task_proc_v14;
#[path = "body_observer_task_acquire_v14.rs"]
mod body_observer_task_acquire_v14;
#[path = "body_observer_history_files_v14.rs"]
mod body_observer_history_files_v14;
#[path = "body_observer_history_store_v14.rs"]
mod body_observer_history_store_v14;
#[path = "body_observer_session_v14.rs"]
mod body_observer_session_v14;

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use crate::plan_protocol::body_observer_contract_v12::BodyObserverLaunchV12;
use body_observer_gate_v12::HeldBodyGateV12;
use body_observer_receive_v12::{ObserverLaunchChannelV12, ReceivedObserverLaunchV12};
use body_observer_target_v12::ReceivedBodyTargetV12;
use body_observer_process_v12::HeldNamespaceWorkerV12;
use body_observer_worker_contract_v12::{receive_stop, NamespaceWorkerStopV12};
pub(crate) use body_observer_snapshot_v12::StoppedBodyMappingSnapshotV12;
pub(crate) use body_observer_history_acquire_v14::HeldInitialBodyHistoryV14;
pub(crate) use body_observer_session_v14::BodyObservationSessionV14;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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

    /// Start only the fixed observer helper in the target's already-held PID
    /// namespace. The helper can address that namespace's init as PID 1; it
    /// cannot reinterpret a recycled host PID as the original target. This
    /// consumes pending custody and does not send readiness or release a body.
    pub(crate) fn stop_for_initial_acquisition(self) -> PlanResult<StoppedBodyObserverLaunchV12> {
        self.verify_pending(self.deadline)?;
        let Self { gate, channel, launch, deadline } = self;
        let target = gate.into_target();
        let worker = HeldNamespaceWorkerV12::start(&target, launch.context.context_sha256, deadline)?;
        let stop = receive_stop(worker.control_fd(), worker.worker_pidfd(), worker.worker_pid(), deadline)?;
        if stop.context_sha256 != launch.context.context_sha256
            || stop.host_target_pid != launch.target_pid
            || stop.target_start_ticks != launch.target_start
            || stop.target_pidfd_inode != launch.target_pidfd_inode
            || stop.target_pid_namespace_inode != target.pid_namespace_inode()
            || stop.host_worker_pid != worker.worker_pid()
            || stop.deadline_boottime_ns != deadline
            || stop.observed_at_boottime_ns < worker.started_at_boottime_ns() {
            return Err(PlanProtocolError::Invalid("namespace worker stop differs from actual held launch/birth"));
        }
        let held = StoppedBodyObserverLaunchV12 { worker, target, channel, launch, stop, deadline };
        held.verify_stopped(deadline)?;
        Ok(held)
    }
}

/// The fixed worker and target remain owned together. Worker failure/abandonment
/// is fail-closed through exact held pidfds; it is never a successful terminal
/// result or proof that the outer generation has been destroyed.
pub(crate) struct StoppedBodyObserverLaunchV12 {
    // Drop the worker's fail-closed guard before releasing the other custody.
    worker: HeldNamespaceWorkerV12,
    target: ReceivedBodyTargetV12,
    channel: ObserverLaunchChannelV12,
    launch: BodyObserverLaunchV12,
    stop: NamespaceWorkerStopV12,
    deadline: u64,
}

impl StoppedBodyObserverLaunchV12 {
    /// Consume the actual held stop into a complete initial maps snapshot with
    /// retained executable-file backing custody. This remains unsigned internal
    /// observation: it cannot authorize ready, resume or observer signing.
    pub(crate) fn acquire_initial_mappings(self) -> PlanResult<StoppedBodyMappingSnapshotV12> {
        StoppedBodyMappingSnapshotV12::acquire(self)
    }

    pub(crate) fn verify_stopped(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.deadline);
        self.channel.verify_pending(deadline)?;
        self.worker.verify_live(deadline)?;
        self.target.verify_gated(deadline)?;
        actual_tracer(&self.target, self.worker.worker_pid(), deadline)?;
        self.worker.verify_live(deadline)?;
        self.channel.verify_pending(deadline)
    }

    pub(crate) fn launch(&self) -> &BodyObserverLaunchV12 { &self.launch }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    /// Abort the held target/helper and reap only this helper under the remaining
    /// original interval. This is not the outer controller's cgroup cleanup or
    /// generation destruction proof.
    pub(crate) fn abort(mut self, deadline: u64) -> PlanResult<()> {
        self.worker.abort_and_reap(deadline.min(self.deadline))
    }
}

impl StoppedBodyMappingSnapshotV12 {
    /// Start an unsigned history from actual held snapshot custody. Journal-local
    /// task/address-space ordinals do not prove kernel identity or authorize
    /// continuous execution, and structural replay does not grant authority.
    pub(crate) fn begin_history(self) -> PlanResult<HeldInitialBodyHistoryV14> {
        HeldInitialBodyHistoryV14::acquire(self)
    }
}

impl HeldInitialBodyHistoryV14 {
    /// Retain actual gated custody while publishing the exact initial originals
    /// into a consumed, preprovisioned directory. This does not admit storage
    /// isolation or execution policy, acknowledge readiness, or resume a task.
    pub(crate) fn persist_initial(self, directory: OwnedFd) -> PlanResult<BodyObservationSessionV14> {
        BodyObservationSessionV14::persist_initial(self, directory)
    }
}

fn live(deadline: u64) -> PlanResult<()> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec)
        || time.tv_sec as u128 * 1_000_000_000 + time.tv_nsec as u128 >= deadline as u128 {
        return Err(PlanProtocolError::Invalid("observer initial-stop deadline expired"));
    }
    Ok(())
}

fn actual_tracer(target: &ReceivedBodyTargetV12, expected_tracer: u32, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let raw = unsafe { libc::openat(target.proc_fd(), c"status".as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut bytes = vec![0u8; 64 * 1024 + 1];
    let mut length = 0;
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(fd.as_raw_fd(), bytes[length..].as_mut_ptr().cast(),
            bytes.len() - length, length as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { break; }
        length += count as usize;
        if length == bytes.len() { return Err(PlanProtocolError::Invalid("observer target status exceeds source bound")); }
    }
    let status = std::str::from_utf8(&bytes[..length])
        .map_err(|_| PlanProtocolError::Invalid("observer target status is not UTF8"))?;
    for (field, expected) in [("Pid:", target.host_pid()), ("Tgid:", target.host_pid()),
        ("TracerPid:", expected_tracer), ("Threads:", 1)] {
        let mut values = status.lines().filter_map(|line| line.strip_prefix(field));
        if values.next().and_then(|value| value.trim().parse::<u32>().ok()) != Some(expected)
            || values.next().is_some() {
            return Err(PlanProtocolError::Invalid("actual observer target/tracer identity differs from held stop"));
        }
    }
    let mut states = status.lines().filter_map(|line| line.strip_prefix("State:"));
    if states.next().and_then(|value| value.split_ascii_whitespace().next()) != Some("t")
        || states.next().is_some() {
        return Err(PlanProtocolError::Invalid("actual observer target is not in a tracing stop"));
    }
    target.verify_gated(deadline)?;
    live(deadline)
}
