//! Closed, bounded, UNSIGNED v14 history and mapping-snapshot originals.
//!
//! These records describe observations; their shape/hash is not provenance,
//! executable-closure admission, a memory measurement or signed runtime proof.
//! They coexist with, and are not accepted as, the existing flat v13 evidence.
//! Cross-record task/MM lifetime and chain reduction belong to the separate
//! history reducer. No clock, process operation, ready or resume exists here.

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde::de::{DeserializeOwned, Error as _, SeqAccess, Visitor};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::marker::PhantomData;

pub(super) const SNAPSHOT_VERSION: &str = "catchplate.controllerBodyMappingSnapshot/v14";
pub(super) const HISTORY_EVENT_VERSION: &str = "catchplate.controllerBodyHistoryEvent/v14";
pub(super) const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_HISTORY_EVENT_BYTES: usize = 256 * 1024;
pub(super) const MAX_LIVE_TASKS: u32 = 8192;
pub(super) const MAX_MAPPINGS: usize = 4096;
pub(super) const MAX_PATHNAME_BYTES: usize = 4096;
pub(super) const MAX_MEASURED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATHNAME_BASE64_BYTES: usize = ((MAX_PATHNAME_BYTES + 2) / 3) * 4;
const MAX_DEPTH: usize = 16;
const MAX_SNAPSHOT_NODES: usize = 400_000;
const MAX_EVENT_NODES: usize = 20_000;
const SNAPSHOT_DOMAIN: &[u8] = b"catchplate/controller-body-mapping-snapshot/v14\0";
const EVENT_DOMAIN: &[u8] = b"catchplate/controller-body-history-event/v14\0";

// Declaration order is the typed canonical wire order. Digests use the same
// fixed 32-byte JSON array representation as existing typed scope records.
// Optional fields are present explicitly as null, never silently omitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct HistoryScopeV14 {
    pub(super) context_sha256: Digest,
    pub(super) target_pidfd_inode: u64,
    pub(super) target_pid_namespace_inode: u64,
    pub(super) deadline_boottime_ns: u64,
    pub(super) max_live_tasks: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct TaskIdentityV14 {
    pub(super) task_id: u64,
    pub(super) host_tid: u32,
    pub(super) host_tgid: u32,
    pub(super) namespace_tid: u32,
    pub(super) namespace_tgid: u32,
    pub(super) start_ticks: u64,
    pub(super) pid_namespace_inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct FileMeasurementV14 {
    pub(super) sha256: Digest,
    pub(super) bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct HistoryMappingV14 {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) offset: u64,
    pub(super) device_major: u32,
    pub(super) device_minor: u32,
    pub(super) inode: u64,
    pub(super) permissions: String,
    pub(super) pathname_base64: String,
    pub(super) file_measurement: Option<FileMeasurementV14>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct MappingSnapshotV14 {
    pub(super) version: String,
    pub(super) scope: HistoryScopeV14,
    pub(super) task: TaskIdentityV14,
    pub(super) address_space_id: u64,
    pub(super) observed_start_boottime_ns: u64,
    pub(super) observed_end_boottime_ns: u64,
    pub(super) maps_original_sha256: Digest,
    #[serde(deserialize_with = "mapping_rows")]
    pub(super) mappings: Vec<HistoryMappingV14>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", content = "data", rename_all = "camelCase",
    rename_all_fields = "camelCase")]
pub(super) enum HistoryEventKindV14 {
    Initial {
        task: TaskIdentityV14,
        address_space_id: u64,
        snapshot_sha256: Digest,
    },
    TaskBorn {
        parent_task_id: u64,
        task: TaskIdentityV14,
        address_space_id: u64,
        shares_address_space: bool,
        snapshot_sha256: Option<Digest>,
    },
    Executed {
        task_id: u64,
        replacement: TaskIdentityV14,
        address_space_id: u64,
        snapshot_sha256: Digest,
        // Exec supersession is not a fabricated final wait/exit observation.
        #[serde(deserialize_with = "retired_ids")]
        retired_task_ids: Vec<u64>,
    },
    MappingsObserved {
        task_id: u64,
        snapshot_sha256: Digest,
    },
    TaskExited {
        task_id: u64,
        exit_code: Option<i32>,
        term_signal: Option<u32>,
    },
    End,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct HistoryEventV14 {
    pub(super) version: String,
    pub(super) scope: HistoryScopeV14,
    pub(super) sequence: u64,
    pub(super) previous_event_sha256: Digest,
    pub(super) observed_at_boottime_ns: u64,
    pub(super) event: HistoryEventKindV14,
}

impl HistoryScopeV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        if self.context_sha256 == [0; 32] || self.target_pidfd_inode == 0
            || self.target_pid_namespace_inode == 0 || self.deadline_boottime_ns == 0
            || !(1..=MAX_LIVE_TASKS).contains(&self.max_live_tasks) {
            return Err(invalid("history scope lacks its bounded nonzero original fields"));
        }
        Ok(())
    }
}

impl TaskIdentityV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        if self.task_id == 0 || self.start_ticks == 0 || self.pid_namespace_inode == 0
            || [self.host_tid, self.host_tgid, self.namespace_tid, self.namespace_tgid]
                .iter().any(|pid| !(1..=i32::MAX as u32).contains(pid))
            || (self.host_tid == self.host_tgid) != (self.namespace_tid == self.namespace_tgid) {
            return Err(invalid("history task identity has invalid PID, namespace or leader shape"));
        }
        Ok(())
    }
}

impl FileMeasurementV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        if self.sha256 == [0; 32] || !(1..=MAX_MEASURED_BYTES).contains(&self.bytes) {
            return Err(invalid("history full-file measurement lacks a bounded nonzero identity"));
        }
        Ok(())
    }
}

impl HistoryMappingV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        let permissions = self.permissions.as_bytes();
        if self.start >= self.end || self.offset.checked_add(self.end - self.start).is_none()
            || permissions.len() != 4 || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-') || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's') {
            return Err(invalid("history mapping has invalid range, offset or canonical permissions"));
        }
        if self.pathname_base64.len() > MAX_PATHNAME_BASE64_BYTES {
            return Err(invalid("history pathname encoding exceeds its fixed bound"));
        }
        let pathname = STANDARD.decode(self.pathname_base64.as_bytes())
            .map_err(|_| invalid("history pathname is not standard padded base64"))?;
        if pathname.len() > MAX_PATHNAME_BYTES || STANDARD.encode(&pathname) != self.pathname_base64 {
            return Err(invalid("history pathname is not bounded canonical padded base64"));
        }
        // Display path and label spelling convey no backing/provenance facts.
        let measured = permissions[2] == b'x' && self.inode > 0;
        if measured != self.file_measurement.is_some() {
            return Err(invalid("history mapping measurement must match executable nonzero-inode shape"));
        }
        if let Some(file) = &self.file_measurement { file.validate()?; }
        Ok(())
    }
}

impl MappingSnapshotV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        self.scope.validate()?;
        self.task.validate()?;
        if self.version != SNAPSHOT_VERSION || self.address_space_id == 0
            || self.maps_original_sha256 == [0; 32] || self.observed_start_boottime_ns == 0
            || self.observed_start_boottime_ns > self.observed_end_boottime_ns
            || self.observed_end_boottime_ns > self.scope.deadline_boottime_ns
            || self.mappings.is_empty() || self.mappings.len() > MAX_MAPPINGS {
            return Err(invalid("mapping snapshot lacks its fixed scope, complete rows or bounded interval"));
        }
        // A later task can occupy a new PID namespace. The reducer, not a
        // universal equality here, joins each task/group to prior lifecycle.
        let mut previous_end = 0u64;
        let mut measured = BTreeMap::<(u32, u32, u64), &FileMeasurementV14>::new();
        let mut unique_bytes = 0u64;
        for row in &self.mappings {
            row.validate()?;
            if row.start < previous_end {
                return Err(invalid("mapping snapshot rows are not complete sorted nonoverlapping ranges"));
            }
            previous_end = row.end;
            if let Some(file) = &row.file_measurement {
                let key = (row.device_major, row.device_minor, row.inode);
                if let Some(previous) = measured.get(&key) {
                    if *previous != file {
                        return Err(invalid("mapping snapshot assigns inconsistent measurements to one backing"));
                    }
                } else {
                    unique_bytes = unique_bytes.checked_add(file.bytes)
                        .filter(|bytes| *bytes <= MAX_MEASURED_BYTES)
                        .ok_or_else(|| invalid("mapping snapshot exceeds unique measured backing byte limit"))?;
                    measured.insert(key, file);
                }
            }
        }
        Ok(())
    }

    pub(super) fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_NODES)
    }

    pub(super) fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decode(bytes, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_NODES)?;
        if value.original_bytes()? != bytes {
            return Err(invalid("mapping snapshot is not its exact typed canonical original"));
        }
        Ok(value)
    }

    pub(super) fn sha256(&self) -> PlanResult<Digest> {
        snapshot_original_sha256(&self.original_bytes()?)
    }
}

impl HistoryEventKindV14 {
    fn validate(&self) -> PlanResult<()> {
        match self {
            Self::Initial { task, address_space_id, snapshot_sha256 } => {
                task.validate()?;
                snapshot_reference(*address_space_id, snapshot_sha256)?;
            }
            Self::TaskBorn { parent_task_id, task, address_space_id,
                shares_address_space: _, snapshot_sha256 } => {
                task.validate()?;
                if *parent_task_id == 0 || *address_space_id == 0
                    || snapshot_sha256.as_ref().is_some_and(|digest| *digest == [0; 32]) {
                    return Err(invalid("history birth has invalid task/MM/snapshot scalar shape"));
                }
                // Actual parent membership and shared/new-MM snapshot rules
                // require the retained prior history, not this record alone.
            }
            Self::Executed { task_id, replacement, address_space_id,
                snapshot_sha256, retired_task_ids } => {
                replacement.validate()?;
                snapshot_reference(*address_space_id, snapshot_sha256)?;
                if *task_id == 0 || retired_task_ids.len() > MAX_LIVE_TASKS as usize
                    || retired_task_ids.iter().any(|id| *id == 0 || id == task_id)
                    || retired_task_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(invalid("history exec supersession list is not bounded sorted unique task IDs"));
                }
                // The reducer checks this is exactly the remaining old group,
                // and keeps supersession distinct from final exit reports.
            }
            Self::MappingsObserved { task_id, snapshot_sha256 } => {
                if *task_id == 0 || *snapshot_sha256 == [0; 32] {
                    return Err(invalid("history mapping event lacks task and snapshot identity"));
                }
            }
            Self::TaskExited { task_id, exit_code, term_signal } => {
                let outcome = match (exit_code, term_signal) {
                    (Some(code), None) => (0..=255).contains(code),
                    (None, Some(signal)) => (1..=64).contains(signal),
                    _ => false,
                };
                if *task_id == 0 || !outcome {
                    return Err(invalid("history exit requires one bounded final exit or signal outcome"));
                }
            }
            Self::End => {}
        }
        Ok(())
    }
}

impl HistoryEventV14 {
    pub(super) fn validate(&self) -> PlanResult<()> {
        self.scope.validate()?;
        if self.version != HISTORY_EVENT_VERSION || self.sequence == 0
            || (self.sequence == 1) != (self.previous_event_sha256 == [0; 32])
            || self.observed_at_boottime_ns == 0
            || self.observed_at_boottime_ns > self.scope.deadline_boottime_ns {
            return Err(invalid("history event lacks bounded original scope, sequence or previous identity"));
        }
        self.event.validate()
    }

    pub(super) fn original_bytes(&self) -> PlanResult<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_HISTORY_EVENT_BYTES, MAX_EVENT_NODES)
    }

    pub(super) fn parse_original(bytes: &[u8]) -> PlanResult<Self> {
        let value: Self = decode(bytes, MAX_HISTORY_EVENT_BYTES, MAX_EVENT_NODES)?;
        if value.original_bytes()? != bytes {
            return Err(invalid("history event is not its exact typed canonical original"));
        }
        Ok(value)
    }

    pub(super) fn sha256(&self) -> PlanResult<Digest> {
        history_event_original_sha256(&self.original_bytes()?)
    }
}

/// Hashes size-bounded original bytes only. This helper does not parse, validate
/// or authenticate them; callers use actual same-call encoding or parsing first.
pub(super) fn snapshot_original_sha256(bytes: &[u8]) -> PlanResult<Digest> {
    original_digest(bytes, SNAPSHOT_DOMAIN, MAX_SNAPSHOT_BYTES)
}

/// Same raw-original identity boundary as snapshot_original_sha256, with the
/// distinct event domain. No digest is embedded back into its own record.
pub(super) fn history_event_original_sha256(bytes: &[u8]) -> PlanResult<Digest> {
    original_digest(bytes, EVENT_DOMAIN, MAX_HISTORY_EVENT_BYTES)
}

fn original_digest(bytes: &[u8], domain: &[u8], maximum: usize) -> PlanResult<Digest> {
    if !(2..=maximum).contains(&bytes.len()) {
        return Err(invalid("history original identity exceeds its fixed byte bound"));
    }
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn snapshot_reference(address_space_id: u64, digest: &Digest) -> PlanResult<()> {
    if address_space_id == 0 || *digest == [0; 32] {
        return Err(invalid("history event lacks nonzero MM and snapshot identity"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

struct BoundedBytes { bytes: Vec<u8>, maximum: usize }
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let total = self.bytes.len().checked_add(bytes.len())
            .filter(|total| *total <= self.maximum)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData,
                "history original exceeds its source byte bound"))?;
        if total > self.bytes.capacity() {
            let wanted = total.max(self.bytes.capacity().max(4096)
                .saturating_mul(2).min(self.maximum));
            self.bytes.try_reserve_exact(wanted - self.bytes.len())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other,
                    "history original bounded allocation failed"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn preflight(bytes: &[u8], maximum: usize, maximum_nodes: usize) -> PlanResult<()> {
    if !(2..=maximum).contains(&bytes.len()) {
        return Err(invalid("history original exceeds its fixed frame bound"));
    }
    let (mut quoted, mut escaped, mut primitive) = (false, false, false);
    let (mut depth, mut nodes) = (0usize, 0usize);
    for &byte in bytes {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
            continue;
        }
        match byte {
            b'"' => { quoted = true; primitive = false; nodes += 1; }
            b'{' | b'[' => { depth += 1; nodes += 1; primitive = false; }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(|| invalid("history original JSON is unbalanced"))?;
                primitive = false;
            }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => primitive = false,
            _ => { if !primitive { primitive = true; nodes += 1; } }
        }
        if depth > MAX_DEPTH || nodes > maximum_nodes {
            return Err(invalid("history original JSON exceeds fixed structural bounds"));
        }
    }
    if quoted || depth != 0 { return Err(invalid("history original JSON is incomplete")); }
    Ok(())
}

fn encode<T: Serialize>(value: &T, maximum: usize, maximum_nodes: usize) -> PlanResult<Vec<u8>> {
    let mut output = BoundedBytes { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut output, value)?;
    preflight(&output.bytes, maximum, maximum_nodes)?;
    Ok(output.bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], maximum: usize, maximum_nodes: usize) -> PlanResult<T> {
    preflight(bytes, maximum, maximum_nodes)?;
    // Typed serde retains its recursion limit, denies unknown/duplicate fields
    // at every closed nested type, and the original comparison rejects missing
    // optional fields, alternate numeric spelling, whitespace and key order.
    Ok(serde_json::from_slice(bytes)?)
}

fn bounded_sequence<'de, D, T>(deserializer: D, maximum: usize) -> Result<Vec<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    struct Bounded<T> { maximum: usize, marker: PhantomData<T> }
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a source-bounded sequence")
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
            if sequence.size_hint().is_some_and(|size| size > self.maximum) {
                return Err(S::Error::custom("history sequence exceeds its fixed count"));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(S::Error::custom("history sequence exceeds its fixed count"));
                }
                if values.len() == values.capacity() {
                    let wanted = values.capacity().max(16).saturating_mul(2).min(self.maximum);
                    values.try_reserve_exact(wanted - values.len())
                        .map_err(|_| S::Error::custom("history sequence bounded allocation failed"))?;
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded { maximum, marker: PhantomData })
}

fn mapping_rows<'de, D: serde::Deserializer<'de>>(deserializer: D)
    -> Result<Vec<HistoryMappingV14>, D::Error> {
    bounded_sequence(deserializer, MAX_MAPPINGS)
}

fn retired_ids<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    bounded_sequence(deserializer, MAX_LIVE_TASKS as usize)
}
