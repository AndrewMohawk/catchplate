//! Unsigned initial v14 records derived from actual retained stopped custody.
//!
//! The complete original maps and measured executable backing stay owned, not
//! replaced by a caller record or by structural replay. Task/address-space one
//! are local history identifiers; the latter is not a measured kernel pointer.
//! This owner emits no later event, end, signature, readiness or resume command.

use super::body_observer_history_contract_v14::{
    history_event_original_sha256, snapshot_original_sha256, FileMeasurementV14,
    HistoryEventKindV14, HistoryEventV14, HistoryMappingV14, HistoryScopeV14,
    MappingSnapshotV14, TaskIdentityV14, HISTORY_EVENT_VERSION, MAX_LIVE_TASKS,
    SNAPSHOT_VERSION,
};
use super::body_observer_history_state_v14::HistoryReplayV14;
use super::body_observer_maps_v12::{MAX_MAPS_BYTES, MAX_MAPPINGS};
use super::StoppedBodyMappingSnapshotV12;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;

const INITIAL_TASK: u64 = 1;
const INITIAL_ADDRESS_SPACE: u64 = 1;
type MappingKey = (u64, u64, u64, u32, u32, u64);

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn now(deadline: u64) -> PlanResult<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("initial history clock is invalid"));
    }
    let sampled = (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("initial history clock overflows"))?;
    if sampled >= deadline { return Err(invalid("initial history original deadline expired")); }
    Ok(sampled)
}

fn scope_from(snapshot: &StoppedBodyMappingSnapshotV12) -> PlanResult<HistoryScopeV14> {
    let maximum = snapshot.launch().context.runner.execution_bounds.pids;
    if maximum == 0 || maximum > MAX_LIVE_TASKS {
        return Err(invalid("initial history task capacity differs from admitted runner bounds"));
    }
    let scope = HistoryScopeV14 {
        context_sha256: snapshot.context_sha256(),
        target_pidfd_inode: snapshot.target_pidfd_inode(),
        target_pid_namespace_inode: snapshot.target_pid_namespace_inode(),
        deadline_boottime_ns: snapshot.deadline(),
        // Preserve the actual admitted bound. No clamp or new capacity exists.
        max_live_tasks: maximum,
    };
    scope.validate()?;
    Ok(scope)
}

fn initial_task(snapshot: &StoppedBodyMappingSnapshotV12) -> TaskIdentityV14 {
    // Initial stopped custody already admitted exactly one namespace-init task.
    TaskIdentityV14 {
        task_id: INITIAL_TASK,
        host_tid: snapshot.target_host_pid(),
        host_tgid: snapshot.target_host_pid(),
        namespace_tid: 1,
        namespace_tgid: 1,
        start_ticks: snapshot.target_start_ticks(),
        pid_namespace_inode: snapshot.target_pid_namespace_inode(),
    }
}

fn maps_digest(snapshot: &StoppedBodyMappingSnapshotV12, deadline: u64) -> PlanResult<Digest> {
    let original = snapshot.original_maps();
    if original.is_empty() || original.len() > MAX_MAPS_BYTES {
        return Err(invalid("initial history maps original is outside its source bound"));
    }
    let mut hash = Sha256::new();
    for chunk in original.chunks(64 * 1024) {
        now(deadline)?;
        hash.update(chunk);
    }
    now(deadline)?;
    // This is raw SHA256 of actual procfs bytes, unlike the versioned record IDs.
    Ok(hash.finalize().into())
}

fn mapping_snapshot(
    snapshot: &StoppedBodyMappingSnapshotV12,
    scope: &HistoryScopeV14,
    maps_original_sha256: Digest,
    deadline: u64,
) -> PlanResult<MappingSnapshotV14> {
    now(deadline)?;
    let rows = snapshot.mappings();
    let bindings = snapshot.executable_bindings()?;
    if rows.is_empty() || rows.len() > MAX_MAPPINGS || bindings.len() > rows.len() {
        return Err(invalid("initial history mapping or measurement inventory is not bounded complete data"));
    }
    let mut remaining = BTreeMap::<MappingKey, _>::new();
    for binding in bindings {
        now(deadline)?;
        let key = (binding.start, binding.end, binding.offset, binding.device_major,
            binding.device_minor, binding.inode);
        if remaining.insert(key, binding).is_some() {
            return Err(invalid("initial history has duplicate executable backing measurements"));
        }
    }
    let mut mappings = Vec::with_capacity(rows.len());
    for row in rows {
        now(deadline)?;
        let key = (row.start, row.end, row.offset, row.device_major, row.device_minor, row.inode);
        let file_measurement = if row.permissions.executable {
            let binding = remaining.remove(&key)
                .ok_or_else(|| invalid("initial history executable row has no exact retained backing binding"))?;
            match (row.inode, binding.backing_file_sha256, binding.backing_file_bytes) {
                (0, None, None) => None,
                (inode, Some(sha256), Some(bytes)) if inode != 0 && sha256 != [0u8; 32] && bytes != 0 => {
                    Some(FileMeasurementV14 { sha256, bytes })
                }
                _ => return Err(invalid("initial history backing measurement presence differs from actual row custody")),
            }
        } else {
            None
        };
        let permissions: String = [
            if row.permissions.readable { 'r' } else { '-' },
            if row.permissions.writable { 'w' } else { '-' },
            if row.permissions.executable { 'x' } else { '-' },
            if row.permissions.shared { 's' } else { 'p' },
        ].into_iter().collect();
        mappings.push(HistoryMappingV14 {
            start: row.start, end: row.end, offset: row.offset,
            device_major: row.device_major, device_minor: row.device_minor, inode: row.inode,
            permissions,
            // Preserve opaque display bytes, not a resolved path or provenance.
            pathname_base64: STANDARD.encode(&row.pathname),
            file_measurement,
        });
        now(deadline)?;
    }
    if !remaining.is_empty() {
        return Err(invalid("initial history has executable backing measurements outside complete maps"));
    }
    let (observed_start_boottime_ns, observed_end_boottime_ns) = snapshot.observation_interval();
    Ok(MappingSnapshotV14 {
        version: SNAPSHOT_VERSION.to_owned(), scope: scope.clone(), task: initial_task(snapshot),
        address_space_id: INITIAL_ADDRESS_SPACE,
        observed_start_boottime_ns, observed_end_boottime_ns, maps_original_sha256, mappings,
    })
}

fn initial_event(
    snapshot: &StoppedBodyMappingSnapshotV12,
    scope: &HistoryScopeV14,
    snapshot_sha256: Digest,
    observed_at_boottime_ns: u64,
) -> HistoryEventV14 {
    HistoryEventV14 {
        version: HISTORY_EVENT_VERSION.to_owned(), scope: scope.clone(), sequence: 1,
        previous_event_sha256: [0u8; 32], observed_at_boottime_ns,
        event: HistoryEventKindV14::Initial {
            task: initial_task(snapshot), address_space_id: INITIAL_ADDRESS_SPACE, snapshot_sha256,
        },
    }
}

pub(crate) struct HeldInitialBodyHistoryV14 {
    // Field order is deliberate: fail-closed stopped custody drops before any
    // retained originals or structural reducer. No Clone/serde conversion exists.
    snapshot: StoppedBodyMappingSnapshotV12,
    scope: HistoryScopeV14,
    replay: HistoryReplayV14,
    maps_original_sha256: Digest,
    snapshot_sha256: Digest,
    snapshot_original: Vec<u8>,
    event_sha256: Digest,
    event_original: Vec<u8>,
    event_observed_at: u64,
}

impl HeldInitialBodyHistoryV14 {
    pub(crate) fn acquire(snapshot: StoppedBodyMappingSnapshotV12) -> PlanResult<Self> {
        // Pure scalar scope admission precedes ownership construction; no new
        // process observation, descriptor or caller-authored record is involved.
        let scope = scope_from(&snapshot)?;
        let replay = HistoryReplayV14::new(scope.clone())?;
        let mut held = Self { snapshot, scope, replay, maps_original_sha256: [0u8; 32],
            snapshot_sha256: [0u8; 32], snapshot_original: Vec::new(), event_sha256: [0u8; 32],
            event_original: Vec::new(), event_observed_at: 0 };
        let deadline = held.snapshot.deadline();
        held.snapshot.verify(deadline)?;
        held.maps_original_sha256 = maps_digest(&held.snapshot, deadline)?;
        let mapping = mapping_snapshot(&held.snapshot, &held.scope, held.maps_original_sha256, deadline)?;
        held.snapshot_original = mapping.original_bytes()?;
        now(deadline)?;
        // Identity helpers hash these exact typed canonical originals once; they
        // are not an alternative admission path for external serialized records.
        held.snapshot_sha256 = snapshot_original_sha256(&held.snapshot_original)?;
        held.event_observed_at = now(deadline)?;
        if held.event_observed_at < held.snapshot.observation_interval().1 {
            return Err(invalid("initial history event predates actual mapping observation"));
        }
        let event = initial_event(&held.snapshot, &held.scope, held.snapshot_sha256, held.event_observed_at);
        held.event_original = event.original_bytes()?;
        now(deadline)?;
        held.event_sha256 = history_event_original_sha256(&held.event_original)?;
        held.replay.apply_original(&held.event_original, Some(&held.snapshot_original))?;
        held.verify_initial_state()?;
        held.snapshot.verify(deadline)?;
        if now(deadline)? < held.event_observed_at {
            return Err(invalid("initial history clock moved backwards after record construction"));
        }
        Ok(held)
    }

    fn verify_initial_state(&self) -> PlanResult<()> {
        if self.replay.scope() != &self.scope || self.replay.event_count() != 1
            || self.replay.head_sha256() != self.event_sha256 || self.replay.is_closed()
            || self.replay.is_poisoned() || self.replay.live_task_count() != 1
            || self.replay.live_address_space_count() != 1
            || self.replay.address_space_snapshot_sha256(INITIAL_ADDRESS_SPACE) != Some(self.snapshot_sha256)
            || self.replay.total_event_bytes() != self.event_original.len() as u64
            || self.replay.total_snapshot_bytes() != self.snapshot_original.len() as u64 {
            return Err(invalid("initial history reducer differs from its one retained original event"));
        }
        Ok(())
    }

    pub(crate) fn verify(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.snapshot.deadline());
        if now(deadline)? < self.event_observed_at {
            return Err(invalid("initial history verification predates its original event"));
        }
        self.snapshot.verify(deadline)?;
        if scope_from(&self.snapshot)? != self.scope
            || self.event_observed_at < self.snapshot.observation_interval().1
            || self.event_observed_at >= self.snapshot.deadline() {
            return Err(invalid("initial history scope or original observation interval changed"));
        }
        // The retained maps bytes are private and immutable; actual snapshot
        // verification rechecks them against procfs. Reuse their original hash,
        // regenerate the exact projection, and do not hash/replay history anew.
        let mapping = mapping_snapshot(&self.snapshot, &self.scope, self.maps_original_sha256, deadline)?;
        if mapping.original_bytes()? != self.snapshot_original {
            return Err(invalid("initial history snapshot original differs from retained actual mappings"));
        }
        now(deadline)?;
        let event = initial_event(&self.snapshot, &self.scope, self.snapshot_sha256, self.event_observed_at);
        if event.original_bytes()? != self.event_original {
            return Err(invalid("initial history event original differs from retained initial scope"));
        }
        self.verify_initial_state()?;
        self.snapshot.verify(deadline)?;
        if now(deadline)? < self.event_observed_at {
            return Err(invalid("initial history verification clock moved backwards"));
        }
        Ok(())
    }

    pub(crate) fn abort(self, deadline: u64) -> PlanResult<()> {
        // Abort the actual stopped owner before other fields drop; there is no
        // fresh cleanup window, detach, resume, or historical-end fabrication.
        self.snapshot.abort(deadline)
    }

    pub(crate) fn initial_snapshot_original(&self) -> &[u8] { &self.snapshot_original }
    pub(crate) fn initial_event_original(&self) -> &[u8] { &self.event_original }
    pub(crate) fn head_sha256(&self) -> Digest { self.replay.head_sha256() }
    pub(crate) fn event_count(&self) -> u64 { self.replay.event_count() }
    pub(crate) fn deadline(&self) -> u64 { self.snapshot.deadline() }
}
