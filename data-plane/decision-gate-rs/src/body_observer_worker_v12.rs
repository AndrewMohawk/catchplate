//! Fixed initial-stop worker born in the held target's PID namespace.
//!
//! PID-taking calls use this child's active namespace, and its only ptrace
//! target is that namespace's original PID1. Init death kills namespace members
//! and prevents new births; unrelated host PID reuse cannot replace this PID1.
//! These semantics require the actual namespace joins below, not a numeric PID
//! claim from the parent. See pid_namespaces(7), setns(2), and ptrace(2).
//! No resume, ready, mapping/event history or signature operation exists here.

use super::body_observer_process_v12::NamespaceWorkerScopeV12;
use super::body_observer_worker_contract_v12::{
    send_stop, wait_for_abort, NamespaceWorkerStopV12, WORKER_STOP_VERSION,
};
use super::body_observer_wait_acquire_v14::acquire_initial_interrupt_stop;
use super::body_observer_syscall_info_v14::{observe as observe_syscall_info, SyscallOperationV14};
use super::body_observer_task_proc_v14::{parse_stat_original, parse_status_original, TaskStatusV14};
use super::body_observer_task_acquire_v14::acquire_initial_task;
use super::body_observer_task_transport_v14::send_task_originals;
use crate::plan_protocol::body_launch_contract_v12::{BodyLaunchContextV12, MAX_CONTEXT_BYTES_V12};
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const PROC_MAGIC: libc::c_long = 0x9fa0;
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const MAX_STATUS: usize = 64 * 1024;
const MAX_STAT: usize = 16 * 1024;
const OPTIONS: libc::c_int = libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_EXITKILL;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn now() -> PlanResult<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("namespace worker clock is invalid"));
    }
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("namespace worker clock overflows"))
}

fn live(deadline: u64) -> PlanResult<u64> {
    let sampled = now()?;
    if sampled >= deadline { return Err(invalid("namespace worker original deadline expired")); }
    Ok(sampled)
}

fn stat(fd: RawFd) -> PlanResult<libc::stat> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(value)
}

fn filesystem(fd: RawFd, expected: libc::c_long) -> PlanResult<()> {
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    if value.f_type as u64 != expected as u64 { return Err(invalid("namespace worker descriptor filesystem differs")); }
    Ok(())
}

fn open_at(parent: RawFd, name: &CStr, directory: bool, magic: bool, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }
        | if magic { 0 } else { libc::O_NOFOLLOW };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let held = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(held)
}

fn read_fd(fd: RawFd, maximum: usize, deadline: u64) -> PlanResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        let wanted = (maximum - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), wanted, bytes.len() as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { return Ok(bytes); }
        if count as usize > maximum - bytes.len() { return Err(invalid("namespace worker read exceeds its source bound")); }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
}

fn read_proc_bytes(parent: RawFd, name: &CStr, maximum: usize, deadline: u64) -> PlanResult<Vec<u8>> {
    let fd = open_at(parent, name, false, false, deadline)?;
    filesystem(fd.as_raw_fd(), PROC_MAGIC)?;
    if stat(fd.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(invalid("namespace worker proc observation is not regular"));
    }
    read_fd(fd.as_raw_fd(), maximum, deadline)
}

fn read_proc(parent: RawFd, name: &CStr, maximum: usize, deadline: u64) -> PlanResult<String> {
    String::from_utf8(read_proc_bytes(parent, name, maximum, deadline)?)
        .map_err(|_| invalid("namespace worker proc observation is not UTF-8"))
}

fn read_task_status(parent: RawFd, deadline: u64) -> PlanResult<TaskStatusV14> {
    parse_status_original(&read_proc_bytes(parent, c"status", MAX_STATUS, deadline)?)
}

fn field<'a>(text: &'a str, name: &str) -> PlanResult<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(name));
    let value = values.next().ok_or_else(|| invalid("namespace worker proc field is missing"))?;
    if values.next().is_some() { return Err(invalid("namespace worker proc field is repeated")); }
    Ok(value.trim())
}

fn number(value: &str) -> PlanResult<u32> {
    let parsed = value.parse::<u32>().map_err(|_| invalid("namespace worker proc number is invalid"))?;
    if parsed > i32::MAX as u32 || parsed.to_string() != value {
        return Err(invalid("namespace worker proc number is not canonical"));
    }
    Ok(parsed)
}

fn namespace_pids(status: &TaskStatusV14, host_pid: u32, local_pid: u32) -> PlanResult<()> {
    let ids = status.namespace_tids();
    if ids.first() != Some(&host_pid) { return Err(invalid("namespace worker host PID view differs")); }
    if ids.len() < 2 || ids.last() != Some(&local_pid) {
        return Err(invalid("namespace worker active PID view differs"));
    }
    Ok(())
}

fn start_ticks(proc_fd: RawFd, host_pid: u32, deadline: u64) -> PlanResult<u64> {
    let original = read_proc_bytes(proc_fd, c"stat", MAX_STAT, deadline)?;
    let observed = parse_stat_original(&original)?;
    if observed.pid() != host_pid { return Err(invalid("namespace worker stat PID differs")); }
    if matches!(observed.state(), b'Z' | b'X' | b'x') {
        return Err(invalid("namespace worker process is terminal"));
    }
    Ok(observed.start_ticks())
}

fn live_pidfd(fd: RawFd, deadline: u64) -> PlanResult<()> {
    loop {
        live(deadline)?;
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        let error = (result < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if result != 0 || poll.revents != 0 { return Err(invalid("namespace worker held pidfd is not live")); }
        return Ok(());
    }
}

fn pidfd_scope(fdinfo: RawFd, fd: RawFd, host_pid: u32, deadline: u64) -> PlanResult<()> {
    let name = CString::new(fd.to_string()).map_err(|_| invalid("namespace worker FD name is invalid"))?;
    let text = read_proc(fdinfo, &name, 4096, deadline)?;
    if number(field(&text, "Pid:")?)? != host_pid { return Err(invalid("namespace worker pidfd names another process")); }
    live_pidfd(fd, deadline)
}

fn pending_control(fd: RawFd, deadline: u64) -> PlanResult<()> {
    for (option, expected) in [(libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_SEQPACKET), (libc::SO_ACCEPTCONN, 0), (libc::SO_PASSCRED, 0)] {
        let mut value: libc::c_int = -1;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option,
            (&mut value as *mut libc::c_int).cast(), &mut length) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if length as usize != std::mem::size_of_val(&value) || value != expected {
            return Err(invalid("namespace worker private control endpoint differs"));
        }
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_NONBLOCK == 0 {
        return Err(invalid("namespace worker private control is not nonblocking"));
    }
    loop {
        live(deadline)?;
        let mut descriptor = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        let error = (result < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if result != 0 || descriptor.revents != 0 {
            return Err(invalid("namespace worker was aborted before its initial stop"));
        }
        return Ok(());
    }
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }

fn inventory(directory: OwnedFd, expected: &[String], deadline: u64) -> PlanResult<()> {
    let raw = directory.into_raw_fd();
    let pointer = unsafe { libc::fdopendir(raw) };
    if pointer.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(raw); }
        return Err(error.into());
    }
    let stream = DirectoryStream(pointer);
    let mut seen = vec![false; expected.len()];
    let mut count = 0usize;
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(stream.0) };
        let error = if entry.is_null() { unsafe { *libc::__errno_location() } } else { 0 };
        live(deadline)?;
        if entry.is_null() {
            if error != 0 { return Err(std::io::Error::from_raw_os_error(error).into()); }
            break;
        }
        count += 1;
        if count > expected.len() + 2 { return Err(invalid("namespace worker descriptor/task inventory is oversized")); }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." { continue; }
        let index = expected.iter().position(|value| value.as_bytes() == name)
            .ok_or_else(|| invalid("namespace worker inherited an unexpected descriptor/task"))?;
        if seen[index] { return Err(invalid("namespace worker inventory repeats an entry")); }
        seen[index] = true;
    }
    if seen.iter().any(|value| !*value) { return Err(invalid("namespace worker inventory is incomplete")); }
    Ok(())
}

fn one_task_no_children(proc_fd: RawFd, host_pid: u32, deadline: u64) -> PlanResult<()> {
    let task = open_at(proc_fd, c"task", true, false, deadline)?;
    filesystem(task.as_raw_fd(), PROC_MAGIC)?;
    inventory(open_at(task.as_raw_fd(), c".", true, false, deadline)?, &[host_pid.to_string()], deadline)?;
    let name = CString::new(host_pid.to_string()).map_err(|_| invalid("namespace worker task name is invalid"))?;
    let thread = open_at(task.as_raw_fd(), &name, true, false, deadline)?;
    if !read_proc(thread.as_raw_fd(), c"children", 4096, deadline)?.trim().is_empty() {
        return Err(invalid("namespace worker gated process already has children"));
    }
    Ok(())
}

fn pid_namespace(fd: RawFd) -> PlanResult<(u64, u64)> {
    filesystem(fd, NSFS_MAGIC)?;
    if unsafe { libc::ioctl(fd, NS_GET_NSTYPE) } != libc::CLONE_NEWPID {
        return Err(invalid("namespace worker descriptor is not a PID namespace"));
    }
    let value = stat(fd)?;
    Ok((value.st_dev, value.st_ino))
}

fn actual_pid_namespace(proc_fd: RawFd, deadline: u64) -> PlanResult<(u64, u64)> {
    let ns = open_at(proc_fd, c"ns", true, false, deadline)?;
    let pid = open_at(ns.as_raw_fd(), c"pid", false, true, deadline)?;
    pid_namespace(pid.as_raw_fd())
}

fn absent_release(directory: RawFd) -> PlanResult<()> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(directory, c"release.json".as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Err(invalid("namespace worker target was already released"));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOENT) { return Err(error.into()); }
    Ok(())
}

fn context(scope: &NamespaceWorkerScopeV12) -> PlanResult<()> {
    let deadline = scope.deadline_boottime_ns;
    let root = open_at(scope.target_proc_fd, c"root", true, true, deadline)?;
    let launch = open_at(root.as_raw_fd(), c"catchplate-controller-launch-v12", true, false, deadline)?;
    let directory = stat(launch.as_raw_fd())?;
    let mut mount: libc::statvfs = unsafe { std::mem::zeroed() };
    if directory.st_uid != 0 || directory.st_gid != 0 || directory.st_mode & 0o7777 != 0o555
        || unsafe { libc::fstatvfs(launch.as_raw_fd(), &mut mount) } != 0
        || mount.f_flag & libc::ST_RDONLY == 0 {
        return Err(invalid("namespace worker target launch directory is not protected read-only custody"));
    }
    absent_release(launch.as_raw_fd())?;
    let original = open_at(launch.as_raw_fd(), c"launch.json", false, false, deadline)?;
    let before = stat(original.as_raw_fd())?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG || before.st_mode & 0o7777 != 0o444
        || before.st_uid != 0 || before.st_gid != 0 || before.st_nlink != 1
        || before.st_size < 2 || before.st_size as u64 > MAX_CONTEXT_BYTES_V12 as u64 {
        return Err(invalid("namespace worker target launch original is invalid"));
    }
    let bytes = read_fd(original.as_raw_fd(), MAX_CONTEXT_BYTES_V12, deadline)?;
    let after = stat(original.as_raw_fd())?;
    let named = open_at(launch.as_raw_fd(), c"launch.json", false, false, deadline)?;
    let named = stat(named.as_raw_fd())?;
    for value in [&after, &named] {
        if value.st_dev != before.st_dev || value.st_ino != before.st_ino || value.st_mode != before.st_mode
            || value.st_uid != before.st_uid || value.st_gid != before.st_gid || value.st_nlink != before.st_nlink
            || value.st_size != before.st_size || value.st_mtime != before.st_mtime
            || value.st_mtime_nsec != before.st_mtime_nsec || value.st_ctime != before.st_ctime
            || value.st_ctime_nsec != before.st_ctime_nsec {
            return Err(invalid("namespace worker target launch original changed"));
        }
    }
    if bytes.len() as i64 != before.st_size { return Err(invalid("namespace worker target launch length differs")); }
    let parsed = BodyLaunchContextV12::parse_original(&bytes)?;
    if parsed.context_sha256 != scope.context_sha256 || deadline > parsed.deadline_boottime_ns {
        return Err(invalid("namespace worker target launch scope differs"));
    }
    absent_release(launch.as_raw_fd())?;
    live(deadline)?;
    Ok(())
}

struct WorkerView {
    proc_root: OwnedFd,
    own_proc: OwnedFd,
    fdinfo: OwnedFd,
    parent_proc: OwnedFd,
    host_pid: u32,
    local_pid: u32,
    start_ticks: u64,
    namespace: (u64, u64),
}

impl WorkerView {
    fn acquire(scope: &NamespaceWorkerScopeV12) -> PlanResult<Self> {
        let deadline = scope.deadline_boottime_ns;
        live(deadline)?;
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err(invalid("namespace worker lacks its fixed root birth identity"));
        }
        let local_pid = unsafe { libc::getpid() };
        if local_pid <= 1 || unsafe { libc::syscall(libc::SYS_gettid) } != local_pid as libc::c_long {
            return Err(invalid("namespace worker must be its single non-init thread"));
        }
        let inherited = [scope.target_pidfd, scope.target_proc_fd, scope.target_pid_namespace_fd,
            scope.parent_pidfd, scope.control_fd];
        for (index, fd) in inherited.iter().enumerate() {
            let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
            if *fd < 3 || inherited[..index].contains(fd)
                || flags < 0 || flags & libc::FD_CLOEXEC == 0 {
                return Err(invalid("namespace worker inherited descriptor scope is invalid"));
            }
        }
        let proc_root = open_at(libc::AT_FDCWD, c"/proc", true, false, deadline)?;
        filesystem(proc_root.as_raw_fd(), PROC_MAGIC)?;
        let own_proc = open_at(proc_root.as_raw_fd(), c"self", true, true, deadline)?;
        let fd_directory = open_at(own_proc.as_raw_fd(), c"fd", true, false, deadline)?;
        let mut expected: Vec<String> = inherited.iter().map(ToString::to_string).collect();
        expected.extend([proc_root.as_raw_fd(), own_proc.as_raw_fd(), fd_directory.as_raw_fd()].map(|fd| fd.to_string()));
        inventory(fd_directory, &expected, deadline)?;
        let status = read_task_status(own_proc.as_raw_fd(), deadline)?;
        let host_pid = status.host_tid();
        let start_ticks = start_ticks(own_proc.as_raw_fd(), host_pid, deadline)?;
        let namespace = pid_namespace(scope.target_pid_namespace_fd)?;
        if namespace.1 == 0 || namespace.1 != scope.target_pid_namespace_inode
            || actual_pid_namespace(own_proc.as_raw_fd(), deadline)? != namespace {
            return Err(invalid("namespace worker was not born in the held target PID namespace"));
        }
        let fdinfo = open_at(own_proc.as_raw_fd(), c"fdinfo", true, false, deadline)?;
        let parent_name = CString::new(scope.parent_host_pid.to_string()).map_err(|_| invalid("namespace worker parent name is invalid"))?;
        let parent_proc = open_at(proc_root.as_raw_fd(), &parent_name, true, false, deadline)?;
        let held = Self { proc_root, own_proc, fdinfo, parent_proc, host_pid,
            local_pid: local_pid as u32, start_ticks, namespace };
        held.verify(scope, false)?;
        Ok(held)
    }

    fn verify(&self, scope: &NamespaceWorkerScopeV12, stopped: bool) -> PlanResult<()> {
        let deadline = scope.deadline_boottime_ns;
        live(deadline)?;
        if unsafe { libc::getpid() } != self.local_pid as libc::pid_t
            || unsafe { libc::syscall(libc::SYS_gettid) } != self.local_pid as libc::c_long
            || actual_pid_namespace(self.own_proc.as_raw_fd(), deadline)? != self.namespace
            || pid_namespace(scope.target_pid_namespace_fd)? != self.namespace {
            return Err(invalid("namespace worker actual process/namespace identity changed"));
        }
        let own = read_task_status(self.own_proc.as_raw_fd(), deadline)?;
        if own.host_tid() != self.host_pid || own.host_tgid() != self.host_pid
            || own.host_ppid() != scope.parent_host_pid || own.threads() != 1
            || own.tracer_pid() != 0
            || start_ticks(self.own_proc.as_raw_fd(), self.host_pid, deadline)? != self.start_ticks {
            return Err(invalid("namespace worker host process/parent identity changed"));
        }
        namespace_pids(&own, self.host_pid, self.local_pid)?;
        one_task_no_children(self.own_proc.as_raw_fd(), self.host_pid, deadline)?;
        pidfd_scope(self.fdinfo.as_raw_fd(), scope.parent_pidfd, scope.parent_host_pid, deadline)?;
        if start_ticks(self.parent_proc.as_raw_fd(), scope.parent_host_pid, deadline)? != scope.parent_start_ticks {
            return Err(invalid("namespace worker original parent start time differs"));
        }
        let target = read_task_status(scope.target_proc_fd, deadline)?;
        let expected_tracer = if stopped { self.host_pid } else { 0 };
        if target.host_tid() != scope.target_host_pid
            || target.host_tgid() != scope.target_host_pid
            || target.threads() != 1
            || target.tracer_pid() != expected_tracer
            || start_ticks(scope.target_proc_fd, scope.target_host_pid, deadline)? != scope.target_start_ticks
            || actual_pid_namespace(scope.target_proc_fd, deadline)? != self.namespace {
            return Err(invalid("namespace worker held init/tracer identity differs"));
        }
        namespace_pids(&target, scope.target_host_pid, 1)?;
        let state = target.state();
        if (stopped && state != b't') || (!stopped && !matches!(state, b'R' | b'S' | b'D' | b'I')) {
            return Err(invalid("namespace worker init is not in its required gate/stop state"));
        }
        pidfd_scope(self.fdinfo.as_raw_fd(), scope.target_pidfd, scope.target_host_pid, deadline)?;
        let name = CString::new(scope.target_host_pid.to_string()).map_err(|_| invalid("namespace worker target name is invalid"))?;
        let named = open_at(self.proc_root.as_raw_fd(), &name, true, false, deadline)?;
        let held = stat(scope.target_proc_fd)?;
        let named = stat(named.as_raw_fd())?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(invalid("namespace worker target proc descriptor was replaced"));
        }
        one_task_no_children(scope.target_proc_fd, scope.target_host_pid, deadline)?;
        context(scope)?;
        pending_control(scope.control_fd, deadline)?;
        live(deadline)?;
        Ok(())
    }
}

fn fixed_signal_policy() -> PlanResult<()> {
    // A enters with signals blocked. Keep every catchable signal blocked until
    // _exit; the private channel is the only graceful abort inlet. SIGKILL is
    // unmaskable. The Linux kernel signal-set ABI is 64 bits on this Linux path.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mask = u64::MAX;
    if unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK, &mask,
        std::ptr::null_mut::<u64>(), std::mem::size_of::<u64>()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    disposition.sa_sigaction = libc::SIG_DFL;
    unsafe { libc::sigemptyset(&mut disposition.sa_mask); }
    if unsafe { libc::sigaction(libc::SIGCHLD, &disposition, std::ptr::null_mut()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut observed: u64 = 0;
    let mut parent_death: libc::c_int = 0;
    if unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
        std::ptr::null::<u64>(), &mut observed, std::mem::size_of::<u64>()) } != 0
        || unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut parent_death, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let unblockable = (1u64 << (libc::SIGKILL - 1)) | (1u64 << (libc::SIGSTOP - 1));
    if observed != (u64::MAX & !unblockable) || parent_death != libc::SIGKILL {
        return Err(invalid("namespace worker fixed signal policy did not take effect"));
    }
    Ok(())
}

fn run(scope: &NamespaceWorkerScopeV12) -> PlanResult<()> {
    fixed_signal_policy()?;
    if scope.context_sha256 == [0; 32] || scope.target_host_pid <= 1 || scope.target_host_pid > i32::MAX as u32
        || scope.parent_host_pid <= 1 || scope.parent_host_pid > i32::MAX as u32
        || scope.parent_host_pid == scope.target_host_pid || scope.target_start_ticks == 0
        || scope.parent_start_ticks == 0 || scope.target_pid_namespace_inode == 0 {
        return Err(invalid("namespace worker lacks original parent/target scope"));
    }
    let worker = WorkerView::acquire(scope)?;
    // No caller PID enters a ptrace operation. This must remain the literal 1
    // in the already verified, held target namespace for every operation.
    if unsafe { libc::ptrace(libc::PTRACE_SEIZE, 1, std::ptr::null_mut::<libc::c_void>(),
        OPTIONS as usize as *mut libc::c_void) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(scope.deadline_boottime_ns)?;
    live_pidfd(scope.parent_pidfd, scope.deadline_boottime_ns)?;
    if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, 1, std::ptr::null_mut::<libc::c_void>(),
        std::ptr::null_mut::<libc::c_void>()) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    // Only actual literal-init wait custody can reach the metadata reader. A
    // replayed status or caller PID cannot substitute for this owned stop.
    let initial_stop = acquire_initial_interrupt_stop(scope)?;
    let syscall_info = observe_syscall_info(&initial_stop, scope.deadline_boottime_ns)?;
    if !matches!(syscall_info.operation, SyscallOperationV14::None) {
        return Err(invalid("namespace worker initial interrupt unexpectedly reports a syscall phase"));
    }
    let actual_task = acquire_initial_task(&initial_stop, scope)?;
    if actual_task.tracer_host_tid() != worker.host_pid {
        return Err(invalid("namespace worker actual task belongs to another tracer"));
    }
    worker.verify(scope, true)?;
    let record = NamespaceWorkerStopV12 {
        version: WORKER_STOP_VERSION.to_owned(), context_sha256: scope.context_sha256,
        host_target_pid: actual_task.host_tid(), target_start_ticks: actual_task.start_ticks(),
        target_pidfd_inode: stat(scope.target_pidfd)?.st_ino,
        target_pid_namespace_inode: actual_task.pid_namespace_inode(), host_worker_pid: worker.host_pid,
        namespace_worker_pid: worker.local_pid, worker_start_ticks: worker.start_ticks,
        observed_at_boottime_ns: actual_task.observed_at_boottime_ns(),
        deadline_boottime_ns: scope.deadline_boottime_ns,
    };
    actual_task.verify(&initial_stop, scope.deadline_boottime_ns)?;
    send_stop(scope.control_fd, scope.parent_pidfd, &record, scope.deadline_boottime_ns)?;
    send_task_originals(scope.control_fd, scope.parent_pidfd, &record, &actual_task,
        &initial_stop, scope.deadline_boottime_ns)?;
    // Keep the same-thread stop owner through the abort-only lifetime. No
    // continuation or journal event is inferred from the copied observations.
    let result = wait_for_abort(scope.control_fd, scope.parent_pidfd, scope.deadline_boottime_ns);
    drop(actual_task);
    drop(initial_stop);
    result
}

/// Only the source-owned clone3 child calls this fixed entry. Every path exits;
/// no error unwinds into the parent continuation and no trace is detached or
/// resumed. EXITKILL is scoped to this namespace's original init, but its effect
/// is not a destruction receipt: the host owner still kills/reaps via pidfds.
pub(super) fn run_namespace_worker(scope: NamespaceWorkerScopeV12) -> ! {
    let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&scope)));
    let code = if matches!(completed, Ok(Ok(()))) { 0 } else { 125 };
    unsafe { libc::_exit(code) }
}
