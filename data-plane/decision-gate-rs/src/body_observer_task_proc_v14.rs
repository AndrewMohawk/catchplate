//! Bounded ordinary parsing of complete Linux proc task originals.
//!
//! These values do not establish descriptor provenance, a host PID namespace,
//! liveness, or a stopped task. The acquisition owner must read through its held
//! proc descriptors to EOF and bracket the observations. In particular, a
//! newline is framing, not proof that a supplied status file was read to EOF.
//! No pathname, process operation, serialization, or authority is exposed here.

use crate::plan_protocol::{PlanProtocolError, PlanResult};

pub(super) const MAX_STATUS_BYTES: usize = 64 * 1024;
pub(super) const MAX_STAT_BYTES: usize = 16 * 1024;
pub(super) const MAX_PID_NAMESPACE_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TaskStatV14 {
    pid: u32,
    state: u8,
    ppid: u32,
    threads: u32,
    start_ticks: u64,
    comm: Vec<u8>,
}

impl TaskStatV14 {
    pub(super) fn pid(&self) -> u32 { self.pid }
    pub(super) fn state(&self) -> u8 { self.state }
    pub(super) fn ppid(&self) -> u32 { self.ppid }
    pub(super) fn threads(&self) -> u32 { self.threads }
    pub(super) fn start_ticks(&self) -> u64 { self.start_ticks }
    pub(super) fn comm(&self) -> &[u8] { &self.comm }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TaskStatusV14 {
    host_tid: u32,
    host_tgid: u32,
    host_ppid: u32,
    tracer_pid: u32,
    state: u8,
    threads: u32,
    namespace_tids: Vec<u32>,
    namespace_tgids: Vec<u32>,
}

impl TaskStatusV14 {
    pub(super) fn host_tid(&self) -> u32 { self.host_tid }
    pub(super) fn host_tgid(&self) -> u32 { self.host_tgid }
    pub(super) fn host_ppid(&self) -> u32 { self.host_ppid }
    pub(super) fn tracer_pid(&self) -> u32 { self.tracer_pid }
    pub(super) fn state(&self) -> u8 { self.state }
    pub(super) fn threads(&self) -> u32 { self.threads }
    pub(super) fn namespace_tids(&self) -> &[u32] { &self.namespace_tids }
    pub(super) fn namespace_tgids(&self) -> &[u32] { &self.namespace_tgids }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcTaskIdentityV14 {
    stat: TaskStatV14,
    host_tgid: u32,
    tracer_pid: u32,
    namespace_tids: Vec<u32>,
    namespace_tgids: Vec<u32>,
}

impl ProcTaskIdentityV14 {
    pub(super) fn host_tid(&self) -> u32 { self.stat.pid }
    pub(super) fn host_tgid(&self) -> u32 { self.host_tgid }
    pub(super) fn host_ppid(&self) -> u32 { self.stat.ppid }
    pub(super) fn tracer_pid(&self) -> u32 { self.tracer_pid }
    pub(super) fn state(&self) -> u8 { self.stat.state }
    pub(super) fn threads(&self) -> u32 { self.stat.threads }
    pub(super) fn namespace_tids(&self) -> &[u32] { &self.namespace_tids }
    pub(super) fn namespace_tgids(&self) -> &[u32] { &self.namespace_tgids }
    pub(super) fn start_ticks(&self) -> u64 { self.stat.start_ticks }
    pub(super) fn comm(&self) -> &[u8] { &self.stat.comm }
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn record(original: &[u8], maximum: usize) -> PlanResult<()> {
    if original.is_empty() || original.len() > maximum || original.last() != Some(&b'\n')
        || original.contains(&0) {
        return Err(invalid("proc task original is not a bounded complete record"));
    }
    Ok(())
}

fn decimal(value: &[u8]) -> PlanResult<u64> {
    if value.is_empty() || value.len() > 20 || (value.len() > 1 && value[0] == b'0') {
        return Err(invalid("proc task decimal is not canonical"));
    }
    let mut number = 0u64;
    for &byte in value {
        if !byte.is_ascii_digit() { return Err(invalid("proc task decimal is not canonical")); }
        number = number.checked_mul(10).and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| invalid("proc task decimal overflows its source bound"))?;
    }
    Ok(number)
}

fn pid(value: &[u8], allow_zero: bool) -> PlanResult<u32> {
    let number = decimal(value)?;
    if number > i32::MAX as u64 || (!allow_zero && number == 0) {
        return Err(invalid("proc task identity is outside the Linux PID range"));
    }
    Ok(number as u32)
}

fn state(value: u8) -> PlanResult<u8> {
    // Linux's task_state_array, including parked and idle. This is a state
    // observation only: terminal states are not silently converted to liveness.
    if !matches!(value, b'R' | b'S' | b'D' | b'T' | b't' | b'X' | b'Z' | b'P' | b'I') {
        return Err(invalid("proc task state is unsupported"));
    }
    Ok(value)
}

fn stat_number(value: &[u8], field: usize) -> PlanResult<()> {
    // Signed fields in the documented 52-field Linux layout. Nothing in an
    // unrelated counter is interpreted as lifecycle authority.
    let signed = matches!(field, 4..=8 | 16..=21 | 24 | 38 | 39 | 44 | 52);
    if let Some(magnitude) = value.strip_prefix(b"-") {
        let magnitude = decimal(magnitude)?;
        if !signed || magnitude == 0 || magnitude > (i64::MAX as u64) + 1 {
            return Err(invalid("proc task signed stat field is invalid"));
        }
    } else {
        let number = decimal(value)?;
        if signed && number > i64::MAX as u64 {
            return Err(invalid("proc task signed stat field overflows"));
        }
    }
    Ok(())
}

pub(super) fn parse_stat_original(original: &[u8]) -> PlanResult<TaskStatV14> {
    record(original, MAX_STAT_BYTES)?;
    let pid_end = original.iter().position(|byte| *byte == b' ')
        .ok_or_else(|| invalid("proc task stat lacks its PID boundary"))?;
    let task_pid = pid(&original[..pid_end], false)?;
    if original.get(pid_end + 1) != Some(&b'(') {
        return Err(invalid("proc task stat lacks its command opening"));
    }
    // The kernel emits comm without escaping. It may contain parentheses,
    // newlines, and non-UTF8 bytes. Only the final ')' delimits its numeric tail.
    let close = original.iter().rposition(|byte| *byte == b')')
        .ok_or_else(|| invalid("proc task stat lacks its command terminator"))?;
    if close < pid_end + 2 || original.get(close + 1) != Some(&b' ')
        || close + 2 >= original.len() - 1 {
        return Err(invalid("proc task stat command boundary is invalid"));
    }
    let mut fields: [&[u8]; 50] = [&[]; 50];
    let mut count = 0usize;
    for value in original[close + 2..original.len() - 1].split(|byte| *byte == b' ') {
        if count == fields.len() || value.is_empty() {
            return Err(invalid("proc task stat does not have its complete fixed field layout"));
        }
        fields[count] = value;
        count += 1;
    }
    if count != fields.len() || fields[0].len() != 1 {
        return Err(invalid("proc task stat does not have its complete fixed field layout"));
    }
    let task_state = state(fields[0][0])?;
    for (index, value) in fields.iter().enumerate().skip(1) { stat_number(value, index + 3)?; }
    let parent = pid(fields[1], true)?; // field 4
    let threads = pid(fields[17], false)?; // field 20
    let start_ticks = decimal(fields[19])?; // field 22
    if start_ticks == 0 { return Err(invalid("proc task start time is zero")); }
    Ok(TaskStatV14 { pid: task_pid, state: task_state, ppid: parent, threads, start_ticks,
        comm: original[pid_end + 2..close].to_vec() })
}

fn trim_horizontal(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) { value = &value[1..]; }
    while matches!(value.last(), Some(b' ' | b'\t')) { value = &value[..value.len() - 1]; }
    value
}

fn set_once<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> PlanResult<()> {
    if slot.replace(value).is_some() { return Err(invalid("proc task status identity field is repeated")); }
    Ok(())
}

fn required(value: Option<&[u8]>) -> PlanResult<&[u8]> {
    value.ok_or_else(|| invalid("proc task status identity field is missing"))
}

fn namespace_ids(value: &[u8]) -> PlanResult<Vec<u32>> {
    let mut ids = Vec::new();
    for field in value.split(|byte| matches!(*byte, b' ' | b'\t')).filter(|field| !field.is_empty()) {
        if ids.len() == MAX_PID_NAMESPACE_DEPTH { return Err(invalid("proc task namespace depth exceeds its bound")); }
        ids.push(pid(field, false)?);
    }
    if ids.is_empty() { return Err(invalid("proc task namespace identity list is empty")); }
    Ok(ids)
}

fn status_state(value: &[u8]) -> PlanResult<u8> {
    let code = match value {
        b"R (running)" => b'R', b"S (sleeping)" => b'S', b"D (disk sleep)" => b'D',
        b"T (stopped)" => b'T', b"t (tracing stop)" => b't', b"X (dead)" => b'X',
        b"Z (zombie)" => b'Z', b"P (parked)" => b'P', b"I (idle)" => b'I',
        _ => return Err(invalid("proc task status state record is invalid")),
    };
    Ok(code)
}

pub(super) fn parse_status_original(status_original: &[u8]) -> PlanResult<TaskStatusV14> {
    record(status_original, MAX_STATUS_BYTES)?;
    let (mut tid, mut tgid, mut ppid, mut tracer, mut threads, mut task_state, mut nspid, mut nstgid) =
        (None, None, None, None, None, None, None, None);
    for line in status_original[..status_original.len() - 1].split(|byte| *byte == b'\n') {
        let colon = line.iter().position(|byte| *byte == b':')
            .ok_or_else(|| invalid("proc task status line has no field boundary"))?;
        let key = &line[..colon];
        if key.is_empty() || !key.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')) {
            return Err(invalid("proc task status field name is invalid"));
        }
        let value = trim_horizontal(&line[colon + 1..]);
        match key {
            b"Pid" => set_once(&mut tid, value)?, b"Tgid" => set_once(&mut tgid, value)?,
            b"PPid" => set_once(&mut ppid, value)?, b"TracerPid" => set_once(&mut tracer, value)?,
            b"Threads" => set_once(&mut threads, value)?, b"State" => set_once(&mut task_state, value)?,
            b"NSpid" => set_once(&mut nspid, value)?, b"NStgid" => set_once(&mut nstgid, value)?,
            _ => {} // Legitimate unrelated/architecture-specific proc fields remain allowed.
        }
    }
    let host_tid = pid(required(tid)?, false)?;
    let host_tgid = pid(required(tgid)?, false)?;
    let host_ppid = pid(required(ppid)?, true)?;
    let tracer_pid = pid(required(tracer)?, true)?;
    let threads = pid(required(threads)?, false)?;
    let task_state = status_state(required(task_state)?)?;
    let namespace_tids = namespace_ids(required(nspid)?)?;
    let namespace_tgids = namespace_ids(required(nstgid)?)?;
    if namespace_tids.len() != namespace_tgids.len() || namespace_tids[0] != host_tid
        || namespace_tgids[0] != host_tgid
        || namespace_tids.iter().zip(&namespace_tgids).any(|(tid, tgid)| (*tid == *tgid) != (host_tid == host_tgid)) {
        return Err(invalid("proc task namespace vectors or thread-leader shape differ"));
    }
    Ok(TaskStatusV14 { host_tid, host_tgid, host_ppid, tracer_pid, state: task_state,
        threads, namespace_tids, namespace_tgids })
}

pub(super) fn parse_task_originals(status_original: &[u8], stat_original: &[u8]) -> PlanResult<ProcTaskIdentityV14> {
    let status = parse_status_original(status_original)?;
    let stat = parse_stat_original(stat_original)?;
    if stat.pid != status.host_tid || stat.ppid != status.host_ppid
        || stat.threads != status.threads || stat.state != status.state {
        return Err(invalid("proc task stat and status identities differ"));
    }
    Ok(ProcTaskIdentityV14 { stat, host_tgid: status.host_tgid, tracer_pid: status.tracer_pid,
        namespace_tids: status.namespace_tids, namespace_tgids: status.namespace_tgids })
}
