//! Bounded streaming structural replay of reported mapping history.
//!
//! Exact original codecs and hash links establish data consistency only. This
//! reducer does not acquire kernel events, authenticate a producer, measure code
//! integrity, resume a task, authorize readiness, or prove cgroup destruction.
//! It retains live task/MM references, not an unbounded event or snapshot log.

use super::body_observer_history_contract_v14::{
    history_event_original_sha256, snapshot_original_sha256, HistoryEventKindV14,
    HistoryEventV14, HistoryScopeV14, MappingSnapshotV14, TaskIdentityV14,
};
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::collections::BTreeMap;

pub(super) const MAX_REPLAY_EVENTS: u64 = 1_000_000;
pub(super) const MAX_REPLAY_ORIGINAL_BYTES: u64 = 512 * 1024 * 1024;

struct LiveTask {
    identity: TaskIdentityV14,
    address_space_id: u64,
}

struct AddressSpace {
    members: usize,
    snapshot_sha256: Digest,
}

/// Not serializable, cloneable, or an acquisition-success carrier. Getters are
/// inspection of reported structural state, including after terminal poisoning.
pub(super) struct HistoryReplayV14 {
    scope: HistoryScopeV14,
    tasks: BTreeMap<u64, LiveTask>,
    address_spaces: BTreeMap<u64, AddressSpace>,
    last_task_id: u64,
    last_address_space_id: u64,
    head: Digest,
    event_count: u64,
    total_event_bytes: u64,
    total_snapshot_bytes: u64,
    last_observed_at: u64,
    closed: bool,
    poisoned: bool,
}

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

impl HistoryReplayV14 {
    pub(super) fn new(scope: HistoryScopeV14) -> PlanResult<Self> {
        scope.validate()?;
        Ok(Self {
            scope, tasks: BTreeMap::new(), address_spaces: BTreeMap::new(),
            last_task_id: 0, last_address_space_id: 0, head: [0; 32],
            event_count: 0, total_event_bytes: 0, total_snapshot_bytes: 0, last_observed_at: 0,
            closed: false, poisoned: false,
        })
    }

    pub(super) fn scope(&self) -> &HistoryScopeV14 { &self.scope }
    pub(super) fn head_sha256(&self) -> Digest { self.head }
    pub(super) fn event_count(&self) -> u64 { self.event_count }
    pub(super) fn total_event_bytes(&self) -> u64 { self.total_event_bytes }
    pub(super) fn total_snapshot_bytes(&self) -> u64 { self.total_snapshot_bytes }
    pub(super) fn total_original_bytes(&self) -> u64 { self.total_event_bytes + self.total_snapshot_bytes }
    pub(super) fn is_closed(&self) -> bool { self.closed }
    pub(super) fn is_poisoned(&self) -> bool { self.poisoned }
    pub(super) fn live_task_count(&self) -> usize { self.tasks.len() }
    pub(super) fn live_address_space_count(&self) -> usize { self.address_spaces.len() }
    pub(super) fn address_space_snapshot_sha256(&self, address_space_id: u64) -> Option<Digest> {
        self.address_spaces.get(&address_space_id).map(|space| space.snapshot_sha256)
    }

    /// Every failed application permanently poisons this instance, including an
    /// extra event after End. There is no replay retry, reset or recovery method.
    pub(super) fn apply_original(&mut self, event_original: &[u8],
        snapshot_original: Option<&[u8]>) -> PlanResult<()> {
        if self.poisoned {
            return Err(invalid("reported history replay is poisoned"));
        }
        let result = self.apply_inner(event_original, snapshot_original);
        if result.is_err() { self.poisoned = true; }
        result
    }

    fn snapshot(&self, original: Option<&[u8]>, task: &TaskIdentityV14,
        address_space_id: u64, expected: Digest, event_time: u64) -> PlanResult<Digest> {
        let original = original.ok_or_else(|| invalid("reported history requires a full snapshot original"))?;
        let snapshot = MappingSnapshotV14::parse_original(original)?;
        if snapshot.scope != self.scope || &snapshot.task != task
            || snapshot.address_space_id != address_space_id
            || snapshot.observed_end_boottime_ns > event_time
            || (self.event_count != 0 && snapshot.observed_start_boottime_ns < self.last_observed_at) {
            return Err(invalid("reported mapping snapshot differs from its task/MM/scope/time transition"));
        }
        // Only hash the original after the genuine closed canonical parser.
        let actual = snapshot_original_sha256(original)?;
        if actual != expected {
            return Err(invalid("reported mapping snapshot original digest does not join its event"));
        }
        Ok(actual)
    }

    fn no_snapshot(original: Option<&[u8]>) -> PlanResult<()> {
        if original.is_some() {
            return Err(invalid("reported history event has an unexpected snapshot original"));
        }
        Ok(())
    }

    fn fresh_task(&self, task: &TaskIdentityV14) -> PlanResult<()> {
        if self.last_task_id.checked_add(1) != Some(task.task_id)
            || self.tasks.len() >= self.scope.max_live_tasks as usize
            || self.tasks.values().any(|live| {
                live.identity.host_tid == task.host_tid || live.identity.host_tgid == task.host_tid
                    || (live.identity.pid_namespace_inode == task.pid_namespace_inode
                        && (live.identity.namespace_tid == task.namespace_tid
                            || live.identity.namespace_tgid == task.namespace_tid))
            }) {
            return Err(invalid("reported task birth reuses an identity or exceeds its live bound"));
        }
        Ok(())
    }

    fn fresh_address_space(&self, address_space_id: u64) -> PlanResult<()> {
        if self.last_address_space_id.checked_add(1) != Some(address_space_id) {
            return Err(invalid("reported address-space ordinal is not the next allocation"));
        }
        Ok(())
    }

    fn remove_task(&mut self, task_id: u64) -> PlanResult<()> {
        let task = self.tasks.remove(&task_id)
            .ok_or_else(|| invalid("reported task is not live"))?;
        let space = self.address_spaces.get_mut(&task.address_space_id)
            .ok_or_else(|| invalid("reported live task lacks its address-space reference"))?;
        space.members = space.members.checked_sub(1)
            .ok_or_else(|| invalid("reported address-space membership underflows"))?;
        if space.members == 0 { self.address_spaces.remove(&task.address_space_id); }
        Ok(())
    }

    fn apply_inner(&mut self, event_original: &[u8], snapshot_original: Option<&[u8]>) -> PlanResult<()> {
        if self.closed || self.event_count >= MAX_REPLAY_EVENTS {
            return Err(invalid("reported history is closed or exceeds its event bound"));
        }
        let total_event_bytes = self.total_event_bytes.checked_add(event_original.len() as u64)
            .ok_or_else(|| invalid("reported history event-original bytes overflow"))?;
        let total_snapshot_bytes = self.total_snapshot_bytes
            .checked_add(snapshot_original.map_or(0, |original| original.len() as u64))
            .ok_or_else(|| invalid("reported history snapshot-original bytes overflow"))?;
        if total_event_bytes.checked_add(total_snapshot_bytes)
            .filter(|total| *total <= MAX_REPLAY_ORIGINAL_BYTES).is_none() {
            return Err(invalid("reported history exceeds its combined original-byte bound"));
        }
        let event = HistoryEventV14::parse_original(event_original)?;
        if event.scope != self.scope || event.sequence != self.event_count + 1
            || event.previous_event_sha256 != self.head
            || event.observed_at_boottime_ns >= self.scope.deadline_boottime_ns
            || (self.event_count != 0 && event.observed_at_boottime_ns < self.last_observed_at)
            || (self.event_count == 0 && !matches!(&event.event, HistoryEventKindV14::Initial { .. })) {
            return Err(invalid("reported history scope/sequence/hash/time or initial transition is invalid"));
        }
        let next_head = history_event_original_sha256(event_original)?;
        let event_time = event.observed_at_boottime_ns;
        match &event.event {
            HistoryEventKindV14::Initial { task, address_space_id, snapshot_sha256 } => {
                if self.event_count != 0 || task.task_id != 1 || *address_space_id != 1
                    || task.host_tid != task.host_tgid
                    || task.namespace_tid != 1 || task.namespace_tgid != 1
                    || task.pid_namespace_inode != self.scope.target_pid_namespace_inode {
                    return Err(invalid("reported initial task/MM does not identify the scoped namespace init"));
                }
                let digest = self.snapshot(snapshot_original, task, *address_space_id, *snapshot_sha256, event_time)?;
                self.tasks.insert(1, LiveTask { identity: task.clone(), address_space_id: 1 });
                self.address_spaces.insert(1, AddressSpace { members: 1, snapshot_sha256: digest });
                self.last_task_id = 1;
                self.last_address_space_id = 1;
            }
            HistoryEventKindV14::TaskBorn { parent_task_id, task, address_space_id,
                shares_address_space, snapshot_sha256 } => {
                self.fresh_task(task)?;
                let parent = self.tasks.get(parent_task_id)
                    .ok_or_else(|| invalid("reported birth parent is not live"))?;
                if task.host_tgid == parent.identity.host_tgid {
                    if !*shares_address_space || task.pid_namespace_inode != parent.identity.pid_namespace_inode
                        || task.namespace_tgid != parent.identity.namespace_tgid
                        || task.host_tid == task.host_tgid || task.namespace_tid == task.namespace_tgid {
                        return Err(invalid("reported same-group birth changes namespace/group or does not share its MM"));
                    }
                } else if task.host_tid != task.host_tgid || task.namespace_tid != task.namespace_tgid
                    || self.tasks.values().any(|live| {
                        live.identity.host_tgid == task.host_tgid
                            || (live.identity.pid_namespace_inode == task.pid_namespace_inode
                                && live.identity.namespace_tgid == task.namespace_tgid)
                    }) {
                    return Err(invalid("reported new thread group is not a new group leader"));
                }
                if *shares_address_space {
                    Self::no_snapshot(snapshot_original)?;
                    if snapshot_sha256.is_some() || *address_space_id != parent.address_space_id {
                        return Err(invalid("reported shared birth does not reference exactly its parent's MM"));
                    }
                    let space = self.address_spaces.get_mut(address_space_id)
                        .ok_or_else(|| invalid("reported shared birth references an absent MM"))?;
                    space.members = space.members.checked_add(1)
                        .ok_or_else(|| invalid("reported MM member count overflows"))?;
                } else {
                    self.fresh_address_space(*address_space_id)?;
                    let expected = (*snapshot_sha256).ok_or_else(|| invalid("reported new MM lacks its snapshot digest"))?;
                    let digest = self.snapshot(snapshot_original, task, *address_space_id, expected, event_time)?;
                    self.address_spaces.insert(*address_space_id, AddressSpace { members: 1, snapshot_sha256: digest });
                    self.last_address_space_id = *address_space_id;
                }
                self.tasks.insert(task.task_id, LiveTask { identity: task.clone(), address_space_id: *address_space_id });
                self.last_task_id = task.task_id;
            }
            HistoryEventKindV14::Executed { task_id, replacement, address_space_id,
                snapshot_sha256, retired_task_ids } => {
                let old = self.tasks.get(task_id)
                    .ok_or_else(|| invalid("reported exec task is not live"))?;
                if replacement.task_id != *task_id
                    || replacement.host_tid != old.identity.host_tgid
                    || replacement.host_tgid != old.identity.host_tgid
                    || replacement.namespace_tid != old.identity.namespace_tgid
                    || replacement.namespace_tgid != old.identity.namespace_tgid
                    || replacement.pid_namespace_inode != old.identity.pid_namespace_inode {
                    return Err(invalid("reported exec replacement does not preserve the old group and namespace"));
                }
                let peers: Vec<u64> = self.tasks.iter().filter_map(|(id, live)| {
                    (*id != *task_id && live.identity.host_tgid == old.identity.host_tgid).then_some(*id)
                }).collect();
                if &peers != retired_task_ids || self.tasks.values().any(|live| {
                    live.identity.host_tgid != old.identity.host_tgid
                        && (live.identity.host_tid == replacement.host_tid
                            || (live.identity.pid_namespace_inode == replacement.pid_namespace_inode
                                && live.identity.namespace_tid == replacement.namespace_tid))
                }) {
                    return Err(invalid("reported exec supersession does not exactly retire its remaining group peers"));
                }
                self.fresh_address_space(*address_space_id)?;
                let digest = self.snapshot(snapshot_original, replacement, *address_space_id, *snapshot_sha256, event_time)?;
                // This is explicit exec supersession, never a manufactured final
                // exit. Removing references preserves unrelated CLONE_VM sharers.
                for peer in peers { self.remove_task(peer)?; }
                self.remove_task(*task_id)?;
                self.address_spaces.insert(*address_space_id, AddressSpace { members: 1, snapshot_sha256: digest });
                self.tasks.insert(*task_id, LiveTask { identity: replacement.clone(), address_space_id: *address_space_id });
                self.last_address_space_id = *address_space_id;
            }
            HistoryEventKindV14::MappingsObserved { task_id, snapshot_sha256 } => {
                let task = self.tasks.get(task_id)
                    .ok_or_else(|| invalid("reported mapping observer task is not live"))?;
                let address_space_id = task.address_space_id;
                let digest = self.snapshot(snapshot_original, &task.identity, address_space_id, *snapshot_sha256, event_time)?;
                // Every sharing task refers to this one MM record; no global
                // cross-task address ordering or disjointness is imposed.
                self.address_spaces.get_mut(&address_space_id)
                    .ok_or_else(|| invalid("reported mapping update lacks its live MM"))?
                    .snapshot_sha256 = digest;
            }
            HistoryEventKindV14::TaskExited { task_id, .. } => {
                Self::no_snapshot(snapshot_original)?;
                // The record asserts final termination, not a pre-exit stop.
                // Structural replay does not authenticate that kernel outcome.
                self.remove_task(*task_id)?;
            }
            HistoryEventKindV14::End => {
                Self::no_snapshot(snapshot_original)?;
                if self.event_count == 0 || !self.tasks.is_empty() || !self.address_spaces.is_empty() {
                    return Err(invalid("reported history ends before all tasks and MMs are retired"));
                }
                self.closed = true;
            }
        }
        if self.tasks.len() > self.scope.max_live_tasks as usize
            || self.address_spaces.len() > self.tasks.len() {
            return Err(invalid("reported history live task/MM bounds are inconsistent"));
        }
        self.head = next_head;
        self.event_count += 1;
        self.total_event_bytes = total_event_bytes;
        self.total_snapshot_bytes = total_snapshot_bytes;
        self.last_observed_at = event_time;
        Ok(())
    }
}
