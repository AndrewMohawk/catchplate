//! Ordinary bounded task-original collection, not acquired task authority.
//!
//! The fixed eight raw originals are parsed and joined to an unsigned stop
//! record. This proves consistency of supplied bytes only, not procfs/nsfs
//! provenance, live descriptor custody, a tracer, namespace ancestry, MM
//! sharing or authentic kernel events. Acquisition and authenticated channel
//! owners must establish those separate properties. No clock is sampled and
//! the stop's original observation time/deadline are never renewed.

use super::body_observer_task_proc_v14::{
    parse_task_originals, ProcTaskIdentityV14, MAX_STAT_BYTES, MAX_STATUS_BYTES,
};
use super::body_observer_worker_contract_v12::{NamespaceWorkerStopV12, MAX_WORKER_CONTROL_BYTES};
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use sha2::{Digest as ShaDigest, Sha256};
use std::ffi::CStr;

pub(super) const TASK_ORIGINAL_COUNT: usize = 8;
pub(super) const MAX_TASK_ORIGINAL_BYTES: u64 = 4 * (MAX_STATUS_BYTES as u64 + MAX_STAT_BYTES as u64);
const BINDING_DOMAIN: &[u8] = b"catchplate/controller-body-task-originals/v14\0";

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

pub(super) fn task_original_name(index: usize) -> PlanResult<&'static CStr> {
    match index {
        0 => Ok(c"target-before-status.bin"),
        1 => Ok(c"target-before-stat.bin"),
        2 => Ok(c"target-after-status.bin"),
        3 => Ok(c"target-after-stat.bin"),
        4 => Ok(c"worker-before-status.bin"),
        5 => Ok(c"worker-before-stat.bin"),
        6 => Ok(c"worker-after-status.bin"),
        7 => Ok(c"worker-after-stat.bin"),
        _ => Err(invalid("task original index is outside its fixed inventory")),
    }
}

pub(super) fn task_original_limit(index: usize) -> PlanResult<usize> {
    if index >= TASK_ORIGINAL_COUNT {
        return Err(invalid("task original index is outside its fixed inventory"));
    }
    Ok(if index % 2 == 0 { MAX_STATUS_BYTES } else { MAX_STAT_BYTES })
}

fn join_pair(target: &ProcTaskIdentityV14, worker: &ProcTaskIdentityV14,
    stop: &NamespaceWorkerStopV12) -> PlanResult<()> {
    if target.host_tid() != stop.host_target_pid || target.host_tgid() != stop.host_target_pid
        || target.start_ticks() != stop.target_start_ticks || target.state() != b't' || target.threads() != 1
        || target.tracer_pid() != stop.host_worker_pid
        || target.namespace_tids().len() < 2 || target.namespace_tids().last() != Some(&1)
        || target.namespace_tgids().last() != Some(&1)
        || worker.host_tid() != stop.host_worker_pid || worker.host_tgid() != stop.host_worker_pid
        || worker.start_ticks() != stop.worker_start_ticks || worker.tracer_pid() != 0 || worker.threads() != 1
        || !matches!(worker.state(), b'R' | b'S' | b'D' | b'I')
        || worker.namespace_tids().len() != target.namespace_tids().len()
        || worker.namespace_tgids().len() != target.namespace_tgids().len()
        || worker.namespace_tids().last() != Some(&stop.namespace_worker_pid)
        || worker.namespace_tgids().last() != Some(&stop.namespace_worker_pid) {
        return Err(invalid("task originals differ from the reported target, tracer or worker namespace scope"));
    }
    // The joined parser already checks both vector depths, host-first values,
    // per-level leader shape, and status/stat PID, PPid, Threads and state.
    // Neither raw file contains a trustworthy PID-namespace inode or pidfd
    // identity: those stop fields are bound below, not inferred here.
    Ok(())
}

pub(super) struct TaskOriginalsV14 {
    originals: [Vec<u8>; TASK_ORIGINAL_COUNT],
    original_hashes: [Digest; TASK_ORIGINAL_COUNT],
    stop_original: Vec<u8>,
    stop_original_sha256: Digest,
    binding_sha256: Digest,
    total_bytes: u64,
}

impl TaskOriginalsV14 {
    pub(super) fn from_originals(originals: [Vec<u8>; TASK_ORIGINAL_COUNT],
        stop: &NamespaceWorkerStopV12) -> PlanResult<Self> {
        stop.validate()?;
        let mut total_bytes = 0u64;
        for (index, original) in originals.iter().enumerate() {
            if original.is_empty() || original.len() > task_original_limit(index)? {
                return Err(invalid("task original exceeds its fixed per-object bound"));
            }
            total_bytes = total_bytes.checked_add(original.len() as u64)
                .filter(|bytes| *bytes <= MAX_TASK_ORIGINAL_BYTES)
                .ok_or_else(|| invalid("task originals exceed their fixed aggregate bound"))?;
        }
        let target_before = parse_task_originals(&originals[0], &originals[1])?;
        let target_after = parse_task_originals(&originals[2], &originals[3])?;
        let worker_before = parse_task_originals(&originals[4], &originals[5])?;
        let worker_after = parse_task_originals(&originals[6], &originals[7])?;
        // Equality covers the parser's identity/state/comm projection only.
        // Volatile counters and other raw proc fields need not be byte-equal.
        if target_before != target_after || worker_before != worker_after {
            return Err(invalid("task original before/after identity projections differ"));
        }
        join_pair(&target_before, &worker_before, stop)?;
        join_pair(&target_after, &worker_after, stop)?;

        let stop_original = stop.original_bytes()?;
        if stop_original.is_empty() || stop_original.len() > MAX_WORKER_CONTROL_BYTES {
            return Err(invalid("task originals stop preimage exceeds its fixed bound"));
        }
        let stop_original_sha256: Digest = Sha256::digest(&stop_original).into();
        let mut original_hashes = [[0u8; 32]; TASK_ORIGINAL_COUNT];
        let mut binding = Sha256::new();
        // Exact binding preimage: fixed NUL-terminated domain, u64BE stop byte
        // count, canonical stop original, then for each fixed index 0..7:
        // u32BE index, u64BE raw byte count, exact raw original. No JSON
        // reencoding of the task files or concatenation-sized allocation occurs.
        binding.update(BINDING_DOMAIN);
        binding.update((stop_original.len() as u64).to_be_bytes());
        binding.update(&stop_original);
        for (index, original) in originals.iter().enumerate() {
            original_hashes[index] = Sha256::digest(original).into();
            binding.update((index as u32).to_be_bytes());
            binding.update((original.len() as u64).to_be_bytes());
            binding.update(original);
        }
        Ok(Self { originals, original_hashes, stop_original, stop_original_sha256,
            binding_sha256: binding.finalize().into(), total_bytes })
    }

    pub(super) fn original(&self, index: usize) -> PlanResult<&[u8]> {
        self.originals.get(index).map(Vec::as_slice)
            .ok_or_else(|| invalid("task original index is outside its fixed inventory"))
    }

    pub(super) fn original_sha256(&self, index: usize) -> PlanResult<Digest> {
        self.original_hashes.get(index).copied()
            .ok_or_else(|| invalid("task original index is outside its fixed inventory"))
    }

    pub(super) fn stop_original(&self) -> &[u8] { &self.stop_original }
    pub(super) fn stop_original_sha256(&self) -> Digest { self.stop_original_sha256 }
    pub(super) fn binding_sha256(&self) -> Digest { self.binding_sha256 }
    /// Eight task originals only; the separately bounded stop is not included.
    pub(super) fn total_bytes(&self) -> u64 { self.total_bytes }
}
