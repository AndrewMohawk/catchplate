//! Local publication of the genuine, still-gated initial history originals.
//!
//! The commit is a local publication marker, not an event, authenticated
//! acquisition-original transport, independent storage/policy admission,
//! readiness, resume permission, or terminal evidence. Only the actual held
//! initial owner is accepted. There is no append, import, recovery or reset API.
//! Errors can leave partial files, or even a published commit followed by a
//! failed custody check; neither case returns a successful store.

use super::body_observer_history_acquire_v14::HeldInitialBodyHistoryV14;
use super::body_observer_history_contract_v14::{
    HistoryScopeV14, MAX_HISTORY_EVENT_BYTES, MAX_SNAPSHOT_BYTES,
};
use super::body_observer_history_files_v14::{
    HistoryStoreDirectoryV14, StoredOriginalV14, MAX_ORIGINAL_BYTES,
};
use super::body_observer_maps_v12::MAX_MAPS_BYTES;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::cell::Cell;
use std::os::fd::OwnedFd;

const COMMIT_PREFIX: &[u8] = b"serverware.controllerBodyInitialHistoryCommit/v14\0";
const COMMIT_PAYLOAD_BYTES: usize = 188;
pub(super) const MAX_INITIAL_COMMIT_BYTES: usize = 256;
const MAX_STORED_BYTES: u64 = MAX_MAPS_BYTES as u64 + MAX_SNAPSHOT_BYTES as u64
    + MAX_HISTORY_EVENT_BYTES as u64 + MAX_INITIAL_COMMIT_BYTES as u64;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

#[derive(Eq, PartialEq)]
struct InitialIdentity {
    scope: HistoryScopeV14,
    maps_bytes: u64,
    maps_sha256: Digest,
    snapshot_bytes: u64,
    snapshot_sha256: Digest,
    event_bytes: u64,
    event_sha256: Digest,
}

impl InitialIdentity {
    fn capture(initial: &HeldInitialBodyHistoryV14) -> PlanResult<Self> {
        let scope = initial.history_scope().clone();
        scope.validate()?;
        let maps_bytes = initial.original_maps().len();
        let snapshot_bytes = initial.initial_snapshot_original().len();
        let event_bytes = initial.initial_event_original().len();
        if initial.event_count() != 1 || initial.deadline() != scope.deadline_boottime_ns
            || maps_bytes == 0 || maps_bytes > MAX_MAPS_BYTES || maps_bytes > MAX_ORIGINAL_BYTES
            || snapshot_bytes == 0 || snapshot_bytes > MAX_SNAPSHOT_BYTES || snapshot_bytes > MAX_ORIGINAL_BYTES
            || event_bytes == 0 || event_bytes > MAX_HISTORY_EVENT_BYTES || event_bytes > MAX_ORIGINAL_BYTES {
            return Err(invalid("initial history store originals differ from the fixed initial scope or bounds"));
        }
        let maps_sha256 = initial.maps_original_sha256();
        let snapshot_sha256 = initial.initial_snapshot_sha256();
        let event_sha256 = initial.head_sha256();
        if maps_sha256 == [0u8; 32] || snapshot_sha256 == [0u8; 32] || event_sha256 == [0u8; 32] {
            return Err(invalid("initial history store has an empty retained original identity"));
        }
        // These identities come from this genuine owner's original acquisition;
        // they are not caller DTOs or a replacement structural replay result.
        Ok(Self { scope, maps_bytes: maps_bytes as u64, maps_sha256,
            snapshot_bytes: snapshot_bytes as u64, snapshot_sha256,
            event_bytes: event_bytes as u64, event_sha256 })
    }

    fn commit_original(&self) -> PlanResult<Vec<u8>> {
        let length = COMMIT_PREFIX.len().checked_add(COMMIT_PAYLOAD_BYTES)
            .ok_or_else(|| invalid("initial history commit length overflows"))?;
        if length > MAX_INITIAL_COMMIT_BYTES || length > MAX_ORIGINAL_BYTES {
            return Err(invalid("initial history commit exceeds its fixed source bound"));
        }
        // Closed, unambiguous binary encoding. After the literal NUL-terminated
        // prefix: context digest[32], pidfd inode u64BE, PID-namespace inode
        // u64BE, original scope deadline u64BE, task bound u32BE, count u64BE
        // (=1), then maps/snapshot/event {length u64BE, digest[32]} in that order.
        // The maps digest is raw SHA256; the other two preserve their existing
        // distinct v14 original-record hash domains. No self-hash is included.
        let mut original = Vec::with_capacity(length);
        original.extend_from_slice(COMMIT_PREFIX);
        original.extend_from_slice(&self.scope.context_sha256);
        original.extend_from_slice(&self.scope.target_pidfd_inode.to_be_bytes());
        original.extend_from_slice(&self.scope.target_pid_namespace_inode.to_be_bytes());
        original.extend_from_slice(&self.scope.deadline_boottime_ns.to_be_bytes());
        original.extend_from_slice(&self.scope.max_live_tasks.to_be_bytes());
        original.extend_from_slice(&1u64.to_be_bytes());
        original.extend_from_slice(&self.maps_bytes.to_be_bytes());
        original.extend_from_slice(&self.maps_sha256);
        original.extend_from_slice(&self.snapshot_bytes.to_be_bytes());
        original.extend_from_slice(&self.snapshot_sha256);
        original.extend_from_slice(&self.event_bytes.to_be_bytes());
        original.extend_from_slice(&self.event_sha256);
        if original.len() != length {
            return Err(invalid("initial history commit field layout differs from its fixed length"));
        }
        Ok(original)
    }

    fn stored_bytes(&self, commit_bytes: u64) -> PlanResult<u64> {
        self.maps_bytes.checked_add(self.snapshot_bytes)
            .and_then(|bytes| bytes.checked_add(self.event_bytes))
            .and_then(|bytes| bytes.checked_add(commit_bytes))
            .filter(|bytes| *bytes <= MAX_STORED_BYTES)
            .ok_or_else(|| invalid("initial history store aggregate byte count exceeds its source bounds"))
    }
}

pub(super) struct HistoryOriginalStoreV14 {
    // Retain all read descriptors until this private store is dropped. Keep the
    // directory/independent-OFD lock alive until after those descriptors close.
    maps: StoredOriginalV14,
    snapshot: StoredOriginalV14,
    event: StoredOriginalV14,
    commit: StoredOriginalV14,
    directory: HistoryStoreDirectoryV14,
    identity: InitialIdentity,
    commit_original: Vec<u8>,
    stored_bytes: u64,
    deadline: u64,
    poisoned: Cell<bool>,
}

impl HistoryOriginalStoreV14 {
    pub(super) fn persist_initial(
        directory: OwnedFd,
        initial: &HeldInitialBodyHistoryV14,
        deadline: u64,
    ) -> PlanResult<Self> {
        // This is the caller's original window, shortened by actual initial
        // custody, never a newly opened storage-operation allowance.
        let deadline = deadline.min(initial.deadline());
        initial.verify(deadline)?;
        let identity = InitialIdentity::capture(initial)?;
        let commit_original = identity.commit_original()?;
        let stored_bytes = identity.stored_bytes(commit_original.len() as u64)?;
        let mut directory = HistoryStoreDirectoryV14::adopt(directory, deadline)?;

        // Each fixed publication performs exact original write/readback, file
        // fsync and directory fsync before returning its retained file owner.
        let maps = directory.publish(c"maps.bin", initial.original_maps(), deadline)?;
        let snapshot = directory.publish(c"snapshot.json", initial.initial_snapshot_original(), deadline)?;
        let event = directory.publish(c"event.json", initial.initial_event_original(), deadline)?;
        maps.verify(&directory, deadline)?;
        snapshot.verify(&directory, deadline)?;
        event.verify(&directory, deadline)?;
        // Only after all three originals have been published and remain held
        // may the final marker be published through the same fsync boundary.
        let commit = directory.publish(c"initial.commit", &commit_original, deadline)?;
        let held = Self { maps, snapshot, event, commit, directory, identity,
            commit_original, stored_bytes, deadline, poisoned: Cell::new(true) };
        held.verify_stored(initial, deadline)?;
        // A late failure leaves the files in place, including any commit, but
        // provides no successful store or policy/readiness conclusion.
        initial.verify(deadline)?;
        held.poisoned.set(false);
        Ok(held)
    }

    fn verify_stored(&self, initial: &HeldInitialBodyHistoryV14, deadline: u64) -> PlanResult<()> {
        if InitialIdentity::capture(initial)? != self.identity
            || self.identity.commit_original()? != self.commit_original
            || self.maps.bytes() != self.identity.maps_bytes
            || self.snapshot.bytes() != self.identity.snapshot_bytes
            || self.event.bytes() != self.identity.event_bytes
            || self.commit.bytes() != self.commit_original.len() as u64
            || self.identity.stored_bytes(self.commit.bytes())? != self.stored_bytes {
            return Err(invalid("initial history store differs from its held originals or commit identity"));
        }
        self.directory.verify(deadline)?;
        self.maps.verify(&self.directory, deadline)?;
        self.snapshot.verify(&self.directory, deadline)?;
        self.event.verify(&self.directory, deadline)?;
        self.commit.verify(&self.directory, deadline)?;
        self.directory.verify(deadline)
    }

    pub(super) fn verify(&self, initial: &HeldInitialBodyHistoryV14, deadline: u64) -> PlanResult<()> {
        if self.poisoned.replace(true) {
            return Err(invalid("initial history store is poisoned or already being verified"));
        }
        let deadline = deadline.min(self.deadline).min(initial.deadline());
        initial.verify(deadline)?;
        // Original hashes are immutable private acquisition results. File
        // verification rechecks retained and fresh-name metadata; it does not
        // repeatedly hash large raw/volatile procfs originals or replay history.
        self.verify_stored(initial, deadline)?;
        initial.verify(deadline)?;
        self.poisoned.set(false);
        Ok(())
    }

    /// Originally published initial count, not fresh acquisition authority.
    pub(super) fn event_count(&self) -> u64 { 1 }
    pub(super) fn head_sha256(&self) -> Digest { self.identity.event_sha256 }
    /// Logical bytes of maps, snapshot, event and commit originals together.
    pub(super) fn stored_bytes(&self) -> u64 { self.stored_bytes }
}
