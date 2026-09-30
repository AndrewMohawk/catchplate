//! Read-only pre-release census of the received, still-gated supervisor.
//!
//! This is a repeated bounded snapshot, not stopped-task custody, continuous
//! observation, an armed event source or permission to acknowledge readiness.
//! No ptrace, signal, wait/reap, resume, detach or process-control destructor exists.
//! Numeric-TID ptrace attachment was deliberately withheld: checking a pidfd
//! around SEIZE cannot eliminate a PID-reuse attachment to an unrelated task.

use super::body_observer_target_v12::ReceivedBodyTargetV12;
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const PROC_MAGIC: libc::c_long = 0x9fa0;
const MAX_STATUS_BYTES: usize = 64 * 1024;
const MAX_CHILDREN_BYTES: usize = 4096;

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

fn live(deadline: u64) -> PlanResult<()> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("body gate clock is invalid"));
    }
    let sampled = (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("body gate clock overflows"))?;
    if sampled >= deadline { return Err(invalid("body gate original deadline expired")); }
    Ok(())
}

fn stat(fd: RawFd) -> PlanResult<libc::stat> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}

fn open_proc(parent: RawFd, name: &CStr, directory: bool, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let parent_stat = stat(parent)?;
    let opened = stat(fd.as_raw_fd())?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let kind = if directory { libc::S_IFDIR } else { libc::S_IFREG };
    if filesystem.f_type as u64 != PROC_MAGIC as u64 || opened.st_dev != parent_stat.st_dev
        || opened.st_mode & libc::S_IFMT != kind {
        return Err(invalid("body gate observation left the held procfs object"));
    }
    live(deadline)?;
    Ok(fd)
}

fn read_proc(parent: RawFd, name: &CStr, maximum: usize, deadline: u64) -> PlanResult<Vec<u8>> {
    let fd = open_proc(parent, name, false, deadline)?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        let wanted = (maximum - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), wanted,
            bytes.len() as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { return Ok(bytes); }
        if count as usize > maximum - bytes.len() {
            return Err(invalid("body gate proc observation exceeds its fixed bound"));
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
}

fn field<'a>(text: &'a str, name: &str) -> PlanResult<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(name));
    let value = values.next().ok_or_else(|| invalid("body gate status field is absent"))?;
    if values.next().is_some() { return Err(invalid("body gate status field is duplicated")); }
    Ok(value.trim())
}

fn number(text: &str) -> PlanResult<u32> {
    let value = text.parse::<u32>().map_err(|_| invalid("body gate status number is invalid"))?;
    if value > i32::MAX as u32 || value.to_string() != text {
        return Err(invalid("body gate status number is not canonical"));
    }
    Ok(value)
}

fn status(target: &ReceivedBodyTargetV12, deadline: u64) -> PlanResult<()> {
    let bytes = read_proc(target.proc_fd(), c"status", MAX_STATUS_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("body gate status is not UTF-8"))?;
    if number(field(text, "Pid:")?)? != target.host_pid()
        || number(field(text, "Tgid:")?)? != target.host_pid()
        || number(field(text, "Threads:")?)? != 1
        || number(field(text, "TracerPid:")?)? != 0 {
        return Err(invalid("body gate PID, single-thread or zero-tracer identity differs"));
    }
    let state = field(text, "State:")?.split_ascii_whitespace().next()
        .ok_or_else(|| invalid("body gate status state is absent"))?;
    if !matches!(state, "R" | "S" | "D" | "I") {
        return Err(invalid("body gate supervisor is not in a live untraced state"));
    }
    live(deadline)
}

// Owns only the newly opened census stream, never a caller's descriptor offset.
struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

fn single_task_without_children(target: &ReceivedBodyTargetV12, deadline: u64) -> PlanResult<()> {
    let task = open_proc(target.proc_fd(), c"task", true, deadline)?;
    let scan_fd = open_proc(task.as_raw_fd(), c".", true, deadline)?.into_raw_fd();
    let stream = unsafe { libc::fdopendir(scan_fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(scan_fd); }
        return Err(error.into());
    }
    let scan = DirectoryStream(stream);
    let name = target.host_pid().to_string();
    let mut seen = [false; 3];
    let mut count = 0usize;
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(scan.0) };
        let error = if entry.is_null() { unsafe { *libc::__errno_location() } } else { 0 };
        live(deadline)?;
        if entry.is_null() {
            if error != 0 { return Err(std::io::Error::from_raw_os_error(error).into()); }
            break;
        }
        count += 1;
        if count > 3 { return Err(invalid("body gate task inventory exceeds one thread")); }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        let index = if bytes == b"." { 0 } else if bytes == b".." { 1 }
            else if bytes == name.as_bytes() { 2 }
            else { return Err(invalid("body gate has an unexpected thread")); };
        if seen[index] { return Err(invalid("body gate task inventory repeats an entry")); }
        seen[index] = true;
    }
    if seen != [true; 3] { return Err(invalid("body gate task inventory is incomplete")); }
    let name = CString::new(name).map_err(|_| invalid("body gate TID name is invalid"))?;
    let thread = open_proc(task.as_raw_fd(), &name, true, deadline)?;
    let children = read_proc(thread.as_raw_fd(), c"children", MAX_CHILDREN_BYTES, deadline)?;
    if !children.iter().all(u8::is_ascii_whitespace) {
        return Err(invalid("body gate supervisor already has children"));
    }
    live(deadline)
}

pub(crate) struct HeldBodyGateV12 {
    target: ReceivedBodyTargetV12,
    deadline: u64,
}

impl HeldBodyGateV12 {
    pub(crate) fn acquire(target: ReceivedBodyTargetV12, deadline: u64) -> PlanResult<Self> {
        let deadline = deadline.min(target.deadline());
        let held = Self { target, deadline };
        held.verify_gated(deadline)?;
        Ok(held)
    }

    pub(crate) fn target(&self) -> &ReceivedBodyTargetV12 { &self.target }

    pub(crate) fn into_target(self) -> ReceivedBodyTargetV12 { self.target }

    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    pub(crate) fn verify_gated(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        self.target.verify_gated(deadline)?;
        status(&self.target, deadline)?;
        single_task_without_children(&self.target, deadline)?;
        self.target.verify_gated(deadline)?;
        status(&self.target, deadline)?;
        live(deadline)
    }
}
