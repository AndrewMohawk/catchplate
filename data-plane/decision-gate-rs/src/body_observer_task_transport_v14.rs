//! Fixed authenticated transfer of the eight initial task proc originals.
//!
//! The preceding v14 stop is already credential-checked by receive_stop. Every
//! data/end packet independently requires the exact child's kernel credentials.
//! This transport carries no ready, resume, acknowledgment or generic command;
//! its returned owner is not execution evidence or an independently signed proof.

use super::body_observer_task_acquire_v14::AcquiredInitialTaskV14;
use super::body_observer_task_originals_v14::{
    TaskOriginalsV14, MAX_TASK_ORIGINAL_BYTES, TASK_ORIGINAL_COUNT, task_original_limit,
};
use super::body_observer_wait_acquire_v14::InitialNamespaceStopV14;
use super::body_observer_worker_contract_v12::{
    NamespaceWorkerStopV12, MAX_INITIAL_TASK_PACKET_BYTES, receive_initial_task_packet,
    require_initial_task_transfer_quiet, send_initial_task_packet,
};
use super::super::boottime_ns;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::cell::Cell;
use std::marker::PhantomData;
use std::os::fd::RawFd;
use std::rc::Rc;

const MAGIC: &[u8; 8] = b"SWTOT014";
const HEADER_BYTES: usize = 56;
const CHUNK_BYTES: usize = 16 * 1024;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn live(deadline: u64) -> PlanResult<u64> {
    let now = boottime_ns()?;
    if now >= deadline { return Err(invalid("initial task transfer original deadline expired")); }
    Ok(now)
}

fn scope(record: &NamespaceWorkerStopV12, worker_host_pid: u32, deadline: u64) -> PlanResult<()> {
    record.validate()?;
    if !(2..=i32::MAX as u32).contains(&worker_host_pid) || record.host_worker_pid != worker_host_pid
        || record.deadline_boottime_ns != deadline || record.observed_at_boottime_ns > live(deadline)? {
        return Err(invalid("initial task transfer differs from its original stop scope"));
    }
    if TASK_ORIGINAL_COUNT != 8 || MAX_INITIAL_TASK_PACKET_BYTES != HEADER_BYTES + CHUNK_BYTES {
        return Err(invalid("initial task transfer source framing differs"));
    }
    Ok(())
}

fn send_frame(fd: RawFd, parent_pidfd: RawFd, binding: Digest, index: usize, total: usize,
    offset: usize, payload: &[u8], deadline: u64) -> PlanResult<()> {
    let limit = if index == TASK_ORIGINAL_COUNT { 0 } else { task_original_limit(index)? };
    if payload.len() > CHUNK_BYTES || total > limit || offset > total || payload.len() > total - offset {
        return Err(invalid("initial task sender frame exceeds its fixed bounds"));
    }
    let mut bytes = [0u8; MAX_INITIAL_TASK_PACKET_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&binding);
    bytes[40] = index as u8;
    // Bytes41..44 are reserved zero. All integers have a fixed network order.
    bytes[44..48].copy_from_slice(&(total as u32).to_be_bytes());
    bytes[48..52].copy_from_slice(&(offset as u32).to_be_bytes());
    bytes[52..56].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
    send_initial_task_packet(fd, parent_pidfd, &bytes[..HEADER_BYTES + payload.len()], deadline)
}

struct Frame<'a> {
    binding: Digest,
    index: usize,
    total: usize,
    offset: usize,
    payload: &'a [u8],
}

fn frame(original: &[u8]) -> PlanResult<Frame<'_>> {
    if !(HEADER_BYTES..=MAX_INITIAL_TASK_PACKET_BYTES).contains(&original.len())
        || &original[..8] != MAGIC || original[41..44] != [0, 0, 0] {
        return Err(invalid("initial task frame lacks its exact versioned header"));
    }
    let binding = original[8..40].try_into().map_err(|_| invalid("initial task frame digest is truncated"))?;
    let total = u32::from_be_bytes(original[44..48].try_into()
        .map_err(|_| invalid("initial task frame length is truncated"))?) as usize;
    let offset = u32::from_be_bytes(original[48..52].try_into()
        .map_err(|_| invalid("initial task frame offset is truncated"))?) as usize;
    let length = u32::from_be_bytes(original[52..56].try_into()
        .map_err(|_| invalid("initial task frame payload length is truncated"))?) as usize;
    if length > CHUNK_BYTES || length != original.len() - HEADER_BYTES {
        return Err(invalid("initial task frame does not contain its exact bounded payload"));
    }
    Ok(Frame { binding, index: original[40] as usize, total, offset, payload: &original[HEADER_BYTES..] })
}

pub(super) fn send_task_originals(fd: RawFd, parent_pidfd: RawFd, record: &NamespaceWorkerStopV12,
    task: &AcquiredInitialTaskV14, stop: &InitialNamespaceStopV14, deadline: u64) -> PlanResult<()> {
    scope(record, task.tracer_host_tid(), deadline)?;
    if task.deadline() != deadline || stop.deadline() != deadline
        || task.host_tid() != record.host_target_pid || task.host_tgid() != record.host_target_pid
        || task.start_ticks() != record.target_start_ticks || task.pid_namespace_inode() != record.target_pid_namespace_inode {
        return Err(invalid("initial task transfer differs from its actual acquired task"));
    }
    task.verify(stop, deadline)?;
    let originals = task.originals();
    let mut total = 0u64;
    for (index, original) in originals.iter().enumerate() {
        if original.is_empty() || original.len() > task_original_limit(index)? {
            return Err(invalid("initial task sender original exceeds its fixed object bound"));
        }
        total = total.checked_add(original.len() as u64).filter(|value| *value <= MAX_TASK_ORIGINAL_BYTES)
            .ok_or_else(|| invalid("initial task sender originals exceed their aggregate bound"))?;
    }
    let originals = std::array::from_fn(|index| originals[index].to_vec());
    let records = TaskOriginalsV14::from_originals(originals, record)?;
    let binding = records.binding_sha256();
    live(deadline)?;
    for index in 0..TASK_ORIGINAL_COUNT {
        let original = records.original(index)?;
        let mut offset = 0usize;
        while offset < original.len() {
            let end = original.len().min(offset + CHUNK_BYTES);
            send_frame(fd, parent_pidfd, binding, index, original.len(), offset, &original[offset..end], deadline)?;
            offset = end;
        }
    }
    // The end marker is withheld if actual custody changed during transfer.
    task.verify(stop, deadline)?;
    send_frame(fd, parent_pidfd, binding, TASK_ORIGINAL_COUNT, 0, 0, &[], deadline)
}

pub(super) struct ReceivedInitialTaskOriginalsV14 {
    records: TaskOriginalsV14,
    binding: Digest,
    control_fd: RawFd,
    worker_pidfd: RawFd,
    worker_host_pid: u32,
    deadline: u64,
    poisoned: Cell<bool>,
    _same_thread: PhantomData<Rc<()>>,
}

impl ReceivedInitialTaskOriginalsV14 {
    pub(super) fn records(&self) -> &TaskOriginalsV14 { &self.records }

    pub(super) fn verify_quiet(&self, fd: RawFd, worker_pidfd: RawFd, expected_worker_host_pid: u32,
        deadline: u64) -> PlanResult<()> {
        if self.poisoned.replace(true) { return Err(invalid("initial task transfer is permanently poisoned")); }
        // A rejected packet may already have been consumed. Never permit a
        // second quiet check to turn that denial (or an unwind) into success.
        let result = (|| {
            if fd != self.control_fd || worker_pidfd != self.worker_pidfd || expected_worker_host_pid != self.worker_host_pid
                || self.records.binding_sha256() != self.binding {
                return Err(invalid("initial task transfer retained channel or binding differs"));
            }
            require_initial_task_transfer_quiet(fd, worker_pidfd, deadline.min(self.deadline))
        })();
        if result.is_ok() { self.poisoned.set(false); }
        result
    }
}

pub(super) fn receive_task_originals(fd: RawFd, worker_pidfd: RawFd, expected_worker_host_pid: u32,
    record: &NamespaceWorkerStopV12, deadline: u64) -> PlanResult<ReceivedInitialTaskOriginalsV14> {
    scope(record, expected_worker_host_pid, deadline)?;
    let mut originals: [Vec<u8>; TASK_ORIGINAL_COUNT] = std::array::from_fn(|_| Vec::new());
    let mut buffer = [0u8; MAX_INITIAL_TASK_PACKET_BYTES];
    let mut binding = None;
    let mut aggregate = 0u64;
    for (index, original) in originals.iter_mut().enumerate() {
        let mut expected_total = None;
        loop {
            let count = receive_initial_task_packet(fd, worker_pidfd, expected_worker_host_pid, &mut buffer, deadline)?;
            let packet = frame(&buffer[..count])?;
            if packet.index != index || packet.total == 0 || packet.total > task_original_limit(index)?
                || packet.offset != original.len() || packet.offset >= packet.total
                || packet.payload.len() != CHUNK_BYTES.min(packet.total - packet.offset) {
                return Err(invalid("initial task transfer object order, length or chunk offset differs"));
            }
            if binding.is_some_and(|expected| expected != packet.binding)
                || expected_total.is_some_and(|expected| expected != packet.total) {
                return Err(invalid("initial task transfer binding or full object length changed"));
            }
            binding = Some(packet.binding);
            if expected_total.is_none() {
                aggregate = aggregate.checked_add(packet.total as u64).filter(|value| *value <= MAX_TASK_ORIGINAL_BYTES)
                    .ok_or_else(|| invalid("initial task transfer aggregate exceeds its source bound"))?;
                original.reserve_exact(packet.total);
                expected_total = Some(packet.total);
            }
            original.extend_from_slice(packet.payload);
            if original.len() == packet.total { break; }
        }
    }
    let records = TaskOriginalsV14::from_originals(originals, record)?;
    let actual_binding = records.binding_sha256();
    if binding != Some(actual_binding) { return Err(invalid("initial task originals do not reproduce the frame binding")); }
    live(deadline)?;
    let count = receive_initial_task_packet(fd, worker_pidfd, expected_worker_host_pid, &mut buffer, deadline)?;
    let end = frame(&buffer[..count])?;
    if end.index != TASK_ORIGINAL_COUNT || end.binding != actual_binding || end.total != 0 || end.offset != 0
        || !end.payload.is_empty() {
        return Err(invalid("initial task transfer lacks its exact terminal frame"));
    }
    let received = ReceivedInitialTaskOriginalsV14 { records, binding: actual_binding, control_fd: fd,
        worker_pidfd, worker_host_pid: expected_worker_host_pid, deadline, poisoned: Cell::new(false),
        _same_thread: PhantomData };
    received.verify_quiet(fd, worker_pidfd, expected_worker_host_pid, deadline)?;
    Ok(received)
}
