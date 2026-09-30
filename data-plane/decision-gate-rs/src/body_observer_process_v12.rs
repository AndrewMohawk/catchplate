//! Birth and sole-reaper custody of the fixed namespace-local observer worker.
//!
//! Only pid_for_children changes: the single host caller remains the real
//! parent. clone3 atomically supplies the child's pidfd; there is no fork,
//! numeric-target attachment, callback, exec, ready response or signer here.
//! The held namespace's init cannot be replaced after its death (Linux kills
//! its remaining members and refuses further births into that namespace).
//!
//! Restoring the parent's namespace and signal mask is mandatory, even after a
//! failed birth. If restoration cannot be proved, the service kills the exact
//! held child/target through pidfds and _exit(125), rather than returning an
//! owner with uncertain namespace state. Cleanup never claims generation-wide
//! destruction and cannot claim successful reaping after the original deadline.
//! Linux contracts: pid_namespaces(7), setns(2), clone(2), wait(2).

use super::body_observer_target_v12::ReceivedBodyTargetV12;
use super::body_observer_worker_v12::run_namespace_worker;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::rc::Rc;

const PROC_MAGIC: libc::c_long = 0x9fa0;
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const MAX_PROC_BYTES: usize = 64 * 1024;
const ALL_CATCHABLE_SIGNALS: u64 = u64::MAX
    & !(1u64 << (libc::SIGKILL - 1)) & !(1u64 << (libc::SIGSTOP - 1));

/// Exactly these five descriptors survive in the child. They are raw borrowed
/// descriptors only because the fixed entry never returns and ends in _exit.
pub(super) struct NamespaceWorkerScopeV12 {
    pub(super) target_pidfd: RawFd,
    pub(super) target_proc_fd: RawFd,
    pub(super) target_pid_namespace_fd: RawFd,
    pub(super) parent_pidfd: RawFd,
    pub(super) control_fd: RawFd,
    pub(super) context_sha256: Digest,
    pub(super) target_host_pid: u32,
    pub(super) target_start_ticks: u64,
    pub(super) target_pid_namespace_inode: u64,
    pub(super) parent_host_pid: u32,
    pub(super) parent_start_ticks: u64,
    pub(super) deadline_boottime_ns: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

#[repr(C)]
struct CloneArguments {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64,
    exit_signal: u64, stack: u64, stack_size: u64, tls: u64,
    set_tid: u64, set_tid_size: u64, cgroup: u64,
}

/// Not Send/Sync: PDEATHSIG and sole-reaping belong to this exact birth thread.
/// No caller may separately wait for, reap or change SIGCHLD policy for this
/// child. Descriptor getters are borrows, never ownership transfers.
pub(super) struct HeldNamespaceWorkerV12 {
    owner_pid: libc::pid_t,
    owner_tid: libc::pid_t,
    owner_start: u64,
    owner_proc: OwnedFd,
    owner_proc_node: Node,
    worker_pid: u32,
    worker_pidfd: OwnedFd,
    worker_node: Option<Node>,
    control: OwnedFd,
    control_node: Node,
    target_pidfd: OwnedFd,
    started_at: u64,
    deadline: u64,
    reaped: bool,
    finished: bool,
    _same_thread: PhantomData<Rc<()>>,
}

impl HeldNamespaceWorkerV12 {
    pub(super) fn start(target: &ReceivedBodyTargetV12, context_sha256: Digest,
        deadline: u64) -> PlanResult<Self> {
        live(deadline)?;
        if context_sha256 == [0; 32] || deadline > target.deadline() {
            return Err(invalid("namespace worker lacks original context/deadline scope"));
        }
        let owner_pid = unsafe { libc::getpid() };
        let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        let owner_proc = open_absolute(c"/proc/self", true)?;
        let owner_proc_node = node(owner_proc.as_raw_fd())?;
        let owner_start = caller(owner_proc.as_raw_fd(), owner_pid, owner_tid, None, deadline)?;
        target.verify_gated(deadline)?;
        let namespace_directory = open_proc(owner_proc.as_raw_fd(), c"ns", true)?;
        let original_namespace = open_namespace(namespace_directory.as_raw_fd(), c"pid_for_children")?;
        let current_namespace = open_namespace(namespace_directory.as_raw_fd(), c"pid")?;
        let original_node = namespace_node(original_namespace.as_raw_fd())?;
        let current_node = namespace_node(current_namespace.as_raw_fd())?;
        let target_node = namespace_node(target.pid_namespace_fd())?;
        if original_node != current_node || target_node == current_node
            || target_node.inode != target.pid_namespace_inode() {
            return Err(invalid("namespace worker requires original host and distinct held target namespaces"));
        }
        let target_pidfd = duplicate(target.pidfd())?;
        let target_proc = duplicate(target.proc_fd())?;
        let target_namespace = duplicate(target.pid_namespace_fd())?;
        let parent_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, owner_pid, 0u32) };
        if parent_raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let parent_pidfd = at_least_three(unsafe { OwnedFd::from_raw_fd(parent_raw as RawFd) })?;
        require_pidfd(parent_pidfd.as_raw_fd(), owner_proc.as_raw_fd(), owner_pid as u32, deadline)?;
        let (control, child_control) = control_pair()?;
        let control_node = node(control.as_raw_fd())?;
        let scope = NamespaceWorkerScopeV12 {
            target_pidfd: target_pidfd.as_raw_fd(), target_proc_fd: target_proc.as_raw_fd(),
            target_pid_namespace_fd: target_namespace.as_raw_fd(), parent_pidfd: parent_pidfd.as_raw_fd(),
            control_fd: child_control.as_raw_fd(), context_sha256,
            target_host_pid: target.host_pid(), target_start_ticks: target.start_ticks(),
            target_pid_namespace_inode: target.pid_namespace_inode(),
            parent_host_pid: owner_pid as u32, parent_start_ticks: owner_start,
            deadline_boottime_ns: deadline,
        };
        let mut keep = [scope.target_pidfd, scope.target_proc_fd, scope.target_pid_namespace_fd,
            scope.parent_pidfd, scope.control_fd];
        keep.sort_unstable();
        if keep[0] < 3 || keep.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("namespace worker inherited descriptor inventory is not exact"));
        }
        // Finish allocation/ownership and root/thread/SIGCHLD checks first.
        target.verify_gated(deadline)?;
        if caller(owner_proc.as_raw_fd(), owner_pid, owner_tid, None, deadline)? != owner_start {
            return Err(invalid("namespace worker parent identity changed before birth"));
        }
        let mut original_mask = 0u64;
        if !read_mask(&mut original_mask) {
            return Err(std::io::Error::last_os_error().into());
        }
        if !set_mask(ALL_CATCHABLE_SIGNALS) {
            restore_or_exit(original_namespace.as_raw_fd(), namespace_directory.as_raw_fd(),
                original_node, current_node, original_mask, -1, -1);
            return Err(invalid("namespace worker could not block birth signals"));
        }
        // Recheck under the actual blocked mask: an inherited signal handler
        // cannot introduce another thread between this census and clone3.
        let parent_still_owned = caller(owner_proc.as_raw_fd(), owner_pid, owner_tid, None, deadline);
        if !matches!(parent_still_owned, Ok(start) if start == owner_start) {
            restore_or_exit(original_namespace.as_raw_fd(), namespace_directory.as_raw_fd(),
                original_node, current_node, original_mask, -1, -1);
            return Err(invalid("namespace worker parent changed during signal blocking"));
        }
        // No fallible Rust early return between namespace change and restore.
        let entered = unsafe { libc::setns(target_namespace.as_raw_fd(), libc::CLONE_NEWPID) } == 0
            && named_namespace_is(namespace_directory.as_raw_fd(), c"pid_for_children", target_node)
            && named_namespace_is(namespace_directory.as_raw_fd(), c"pid", current_node);
        let mut child_pidfd = -1i32;
        let mut started_at = 0u64;
        let mut child_pid: libc::c_long = -1;
        let mut birth_errno = 0i32;
        if entered {
            // This actual sample bounds the child's later stop observation.
            if let Ok(sample) = now() {
                started_at = sample;
                if sample < deadline {
                    let arguments = CloneArguments {
                        flags: libc::CLONE_PIDFD as u64,
                        pidfd: (&mut child_pidfd as *mut i32) as u64,
                        child_tid: 0, parent_tid: 0, exit_signal: libc::SIGCHLD as u64,
                        stack: 0, stack_size: 0, tls: 0, set_tid: 0, set_tid_size: 0, cgroup: 0,
                    };
                    child_pid = unsafe { libc::syscall(libc::SYS_clone3, &arguments,
                        std::mem::size_of::<CloneArguments>()) };
                    if child_pid < 0 { birth_errno = unsafe { *libc::__errno_location() }; }
                    if child_pid == 0 {
                        // No inherited external socket, listener or stdio. The
                        // fixed worker installs PDEATHSIG while signals remain
                        // blocked, and independently checks its real parent.
                        if !close_except(&keep) {
                            signal_kill(scope.target_pidfd);
                            unsafe { libc::_exit(125) }
                        }
                        run_namespace_worker(scope)
                    }
                }
            }
        }
        restore_or_exit(original_namespace.as_raw_fd(), namespace_directory.as_raw_fd(),
            original_node, current_node, original_mask, child_pidfd,
            if child_pid > 0 { target_pidfd.as_raw_fd() } else { -1 });
        if child_pid < 0 {
            if birth_errno != 0 { return Err(std::io::Error::from_raw_os_error(birth_errno).into()); }
            return Err(invalid("namespace worker birth namespace or original deadline check failed"));
        }
        if child_pid <= 1 || child_pid > i32::MAX as libc::c_long || child_pidfd < 0 {
            fail_closed_exit(child_pidfd, target_pidfd.as_raw_fd());
        }
        // clone3 normally chooses >=3; preserve its actual open-file identity
        // even in a service whose standard descriptor slots were absent.
        let worker_pidfd = if child_pidfd >= 3 {
            unsafe { OwnedFd::from_raw_fd(child_pidfd) }
        } else {
            let fd = match duplicate(child_pidfd) {
                Ok(fd) => fd,
                Err(_) => fail_closed_exit(child_pidfd, target_pidfd.as_raw_fd()),
            };
            unsafe { libc::close(child_pidfd); }
            fd
        };
        let mut held = Self {
            owner_pid, owner_tid, owner_start, owner_proc, owner_proc_node,
            worker_pid: child_pid as u32, worker_pidfd, worker_node: None,
            control, control_node, target_pidfd, started_at, deadline,
            reaped: false, finished: false, _same_thread: PhantomData,
        };
        drop(child_control);
        held.worker_node = Some(node(held.worker_pidfd.as_raw_fd())?);
        held.verify_live(deadline)?;
        Ok(held)
    }

    pub(super) fn worker_pid(&self) -> u32 { self.worker_pid }
    pub(super) fn worker_pidfd(&self) -> RawFd { self.worker_pidfd.as_raw_fd() }
    pub(super) fn control_fd(&self) -> RawFd { self.control.as_raw_fd() }
    pub(super) fn deadline(&self) -> u64 { self.deadline }
    pub(super) fn started_at_boottime_ns(&self) -> u64 { self.started_at }

    pub(super) fn verify_live(&self, deadline: u64) -> PlanResult<()> {
        self.owner()?;
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if self.reaped || self.finished
            || node(self.owner_proc.as_raw_fd())? != self.owner_proc_node
            || Some(node(self.worker_pidfd.as_raw_fd())?) != self.worker_node
            || node(self.control.as_raw_fd())? != self.control_node
            || caller(self.owner_proc.as_raw_fd(), self.owner_pid, self.owner_tid,
                Some(self.worker_pid), deadline)? != self.owner_start {
            return Err(invalid("namespace worker birth/custody or sole-reaper identity changed"));
        }
        require_channel(self.control.as_raw_fd(), true)?;
        require_pidfd(self.worker_pidfd.as_raw_fd(), self.owner_proc.as_raw_fd(), self.worker_pid, deadline)?;
        live(deadline)
    }

    /// Abort only the retained init/worker and reap only this actual child.
    /// Failure/expiry never means successful cleanup, absence or safe reuse.
    pub(super) fn abort_and_reap(&mut self, deadline: u64) -> PlanResult<()> {
        self.owner()?;
        self.deadline = self.deadline.min(deadline);
        if self.finished { return Ok(()); }
        let deadline = self.deadline;
        // Fail-closed signals remain permitted after expiry; waits never gain
        // a new allowance. The first WNOHANG attempt is always nonblocking.
        let target_kill = signal_kill(self.target_pidfd.as_raw_fd());
        let worker_kill = signal_kill(self.worker_pidfd.as_raw_fd());
        unsafe { libc::shutdown(self.control.as_raw_fd(), libc::SHUT_RDWR); }
        loop {
            if !self.reaped {
                let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // P_PIDFD (Linux 5.4+): no numeric-PID reaping fallback.
                if unsafe { libc::waitid(3 as libc::idtype_t, self.worker_pidfd.as_raw_fd() as libc::id_t,
                    &mut information, libc::WEXITED | libc::WNOHANG) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let reaped_pid = unsafe { information.si_pid() };
                if reaped_pid != 0 {
                    if reaped_pid != self.worker_pid as libc::pid_t {
                        return Err(invalid("namespace worker reap returned a different child"));
                    }
                    self.reaped = true;
                }
            }
            let target_ended = pidfd_ended(self.target_pidfd.as_raw_fd())?;
            live(deadline)?;
            if self.reaped && target_ended {
                if !target_kill || !worker_kill {
                    return Err(invalid("namespace worker abort signal failed"));
                }
                self.finished = true;
                return Ok(());
            }
            let remaining = deadline.checked_sub(now()?)
                .ok_or_else(|| invalid("namespace worker cleanup deadline expired"))?;
            let pause = libc::timespec { tv_sec: 0, tv_nsec: remaining.min(10_000_000) as libc::c_long };
            if unsafe { libc::ppoll(std::ptr::null_mut(), 0, &pause, std::ptr::null()) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    fn owner(&self) -> PlanResult<()> {
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::syscall(libc::SYS_gettid) } != self.owner_tid as libc::c_long {
            return Err(invalid("namespace worker owner crossed its birth process/thread"));
        }
        Ok(())
    }
}

impl Drop for HeldNamespaceWorkerV12 {
    fn drop(&mut self) {
        // An inherited copy in an unrelated fork cannot control this owner.
        if self.owner().is_ok() && !self.finished {
            let _ = self.abort_and_reap(self.deadline);
        }
    }
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn now() -> PlanResult<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(invalid("namespace worker clock is invalid"));
    }
    (time.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| invalid("namespace worker clock overflows"))
}

fn live(deadline: u64) -> PlanResult<()> {
    if now()? >= deadline { return Err(invalid("namespace worker original deadline expired")); }
    Ok(())
}

fn node(fd: RawFd) -> PlanResult<Node> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid })
}

fn filesystem(fd: RawFd, expected: libc::c_long) -> PlanResult<()> {
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.f_type as u64 != expected as u64 { return Err(invalid("namespace worker kernel filesystem mismatch")); }
    Ok(())
}

fn duplicate(fd: RawFd) -> PlanResult<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn at_least_three(fd: OwnedFd) -> PlanResult<OwnedFd> {
    if fd.as_raw_fd() >= 3 { Ok(fd) } else { duplicate(fd.as_raw_fd()) }
}

fn open_absolute(name: &CStr, directory: bool) -> PlanResult<OwnedFd> {
    // Only source-fixed /proc/self; its kernel magic link is intentional.
    let raw = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    filesystem(fd.as_raw_fd(), PROC_MAGIC)?;
    Ok(fd)
}

fn open_proc(parent: RawFd, name: &CStr, directory: bool) -> PlanResult<OwnedFd> {
    let raw = unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC
        | libc::O_NONBLOCK | libc::O_NOFOLLOW | if directory { libc::O_DIRECTORY } else { 0 }) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    filesystem(fd.as_raw_fd(), PROC_MAGIC)?;
    let opened = node(fd.as_raw_fd())?;
    let expected_kind = if directory { libc::S_IFDIR } else { libc::S_IFREG };
    if opened.device != node(parent)?.device
        || opened.mode & libc::S_IFMT != expected_kind {
        return Err(invalid("namespace worker proc observation changed type/device"));
    }
    Ok(fd)
}

fn read_proc(parent: RawFd, name: &CStr, deadline: u64) -> PlanResult<Vec<u8>> {
    live(deadline)?;
    let fd = open_proc(parent, name, false)?;
    let mut bytes = Vec::with_capacity(4096);
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        let wanted = (MAX_PROC_BYTES - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), wanted,
            bytes.len() as libc::off_t) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        live(deadline)?;
        if count == 0 { return Ok(bytes); }
        if count as usize > MAX_PROC_BYTES - bytes.len() {
            return Err(invalid("namespace worker proc observation exceeds source bound"));
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
}

fn text(bytes: &[u8]) -> PlanResult<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("namespace worker proc text is invalid"))
}

fn decimal(value: &str) -> PlanResult<u64> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("namespace worker proc number is invalid"));
    }
    value.parse().map_err(|_| invalid("namespace worker proc number overflows"))
}

fn field<'a>(status: &'a str, name: &str) -> PlanResult<&'a str> {
    let mut found = status.lines().filter_map(|line| line.strip_prefix(name));
    let value = found.next().ok_or_else(|| invalid("namespace worker proc field is absent"))?;
    if found.next().is_some() { return Err(invalid("namespace worker proc field is duplicated")); }
    Ok(value.trim())
}

fn caller(proc: RawFd, pid: libc::pid_t, tid: libc::pid_t,
    child: Option<u32>, deadline: u64) -> PlanResult<u64> {
    live(deadline)?;
    if pid <= 1 || pid != tid || unsafe { libc::getpid() } != pid
        || unsafe { libc::syscall(libc::SYS_gettid) } != tid as libc::c_long
        || unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(invalid("namespace worker birth requires its actual single-thread root host owner"));
    }
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if disposition.sa_sigaction != libc::SIG_DFL || disposition.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(invalid("namespace worker requires default SIGCHLD and sole reaping"));
    }
    let original = read_proc(proc, c"status", deadline)?;
    let status = text(&original)?;
    if decimal(field(status, "Pid:")?)? != pid as u64
        || decimal(field(status, "Tgid:")?)? != pid as u64
        || field(status, "NSpid:")? != pid.to_string()
        || field(status, "Threads:")? != "1" || field(status, "TracerPid:")? != "0"
        || field(status, "Uid:")?.split_whitespace().collect::<Vec<_>>() != ["0"; 4]
        || field(status, "Gid:")?.split_whitespace().collect::<Vec<_>>() != ["0"; 4] {
        return Err(invalid("namespace worker parent proc status is not single-thread host root"));
    }
    let task = open_proc(proc, c"task", true)?;
    let task_name = CString::new(pid.to_string()).map_err(|_| invalid("namespace worker parent PID is invalid"))?;
    exact_task(task.as_raw_fd(), task_name.as_bytes(), deadline)?;
    let leader = open_proc(task.as_raw_fd(), &task_name, true)?;
    let children = read_proc(leader.as_raw_fd(), c"children", deadline)?;
    let children = text(&children)?.split_whitespace().collect::<Vec<_>>();
    if match child { None => !children.is_empty(), Some(pid) => children != [pid.to_string().as_str()] } {
        return Err(invalid("namespace worker parent is not the fixed sole-child owner"));
    }
    let original = read_proc(proc, c"stat", deadline)?;
    let stat = text(&original)?;
    let prefix = format!("{pid} (");
    let closing = stat.rfind(") ").ok_or_else(|| invalid("namespace worker parent stat is malformed"))?;
    if !stat.starts_with(&prefix) { return Err(invalid("namespace worker parent stat PID differs")); }
    let fields: Vec<_> = stat[closing + 2..].split_whitespace().collect();
    if fields.len() < 20 || matches!(fields[0], "Z" | "X" | "x") {
        return Err(invalid("namespace worker parent stat is incomplete or terminal"));
    }
    let start = decimal(fields[19])?;
    if start == 0 { return Err(invalid("namespace worker parent start time is absent")); }
    live(deadline)?;
    Ok(start)
}

struct Directory(*mut libc::DIR);
impl Drop for Directory { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }

fn exact_task(fd: RawFd, expected: &[u8], deadline: u64) -> PlanResult<()> {
    let duplicate = duplicate(fd)?.into_raw_fd();
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate); }
        return Err(error.into());
    }
    let directory = Directory(directory);
    let mut names = Vec::with_capacity(3);
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            if unsafe { *libc::__errno_location() } != 0 { return Err(std::io::Error::last_os_error().into()); }
            break;
        }
        if names.len() == 3 { return Err(invalid("namespace worker parent has additional tasks")); }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes().to_vec();
        if name != b"." && name != b".." && name != expected {
            return Err(invalid("namespace worker parent has another thread"));
        }
        if names.contains(&name) { return Err(invalid("namespace worker task inventory repeated")); }
        names.push(name);
    }
    if names.len() != 3 { return Err(invalid("namespace worker task inventory is incomplete")); }
    Ok(())
}

fn open_namespace(parent: RawFd, name: &CStr) -> PlanResult<OwnedFd> {
    // Intentional proc namespace magic links, checked by NSFS + NS_GET_NSTYPE.
    let raw = unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    namespace_node(fd.as_raw_fd())?;
    Ok(fd)
}

fn namespace_node(fd: RawFd) -> PlanResult<Node> {
    filesystem(fd, NSFS_MAGIC)?;
    if unsafe { libc::ioctl(fd, NS_GET_NSTYPE) } != libc::CLONE_NEWPID {
        return Err(invalid("namespace worker descriptor is not a PID namespace"));
    }
    node(fd)
}

fn named_namespace_is(parent: RawFd, name: &CStr, expected: Node) -> bool {
    match open_namespace(parent, name).and_then(|fd| namespace_node(fd.as_raw_fd())) {
        Ok(actual) => actual == expected,
        Err(_) => false,
    }
}

fn read_mask(mask: &mut u64) -> bool {
    // Linux's kernel signal set has exactly 64 signals; bypass libc's reserved
    // pthread-signal exclusions only after proving there is one thread.
    (unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
        std::ptr::null::<u64>(), mask as *mut u64, std::mem::size_of::<u64>()) }) == 0
}

fn set_mask(mask: u64) -> bool {
    let changed = unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
        &mask as *const u64, std::ptr::null_mut::<u64>(), std::mem::size_of::<u64>()) } == 0;
    let mut actual = 0u64;
    changed && read_mask(&mut actual) && actual == mask
}

fn restore_or_exit(original: RawFd, directory: RawFd, original_node: Node,
    current_node: Node, mask: u64, worker_pidfd: RawFd, target_pidfd: RawFd) {
    let restored = unsafe { libc::setns(original, libc::CLONE_NEWPID) } == 0
        && named_namespace_is(directory, c"pid_for_children", original_node)
        && named_namespace_is(directory, c"pid", current_node);
    // Never unblock an inherited handler while namespace state is uncertain.
    if !restored { fail_closed_exit(worker_pidfd, target_pidfd); }
    if !set_mask(mask) { fail_closed_exit(worker_pidfd, target_pidfd); }
}

fn signal_kill(fd: RawFd) -> bool {
    if fd < 0 { return false; }
    if unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGKILL,
        std::ptr::null::<libc::siginfo_t>(), 0u32) } == 0 { return true; }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn fail_closed_exit(worker_pidfd: RawFd, target_pidfd: RawFd) -> ! {
    signal_kill(target_pidfd);
    signal_kill(worker_pidfd);
    unsafe { libc::_exit(125) }
}

fn close_except(keep: &[RawFd; 5]) -> bool {
    let mut first = 0u32;
    for &fd in keep {
        let next = fd as u32;
        if first < next && unsafe { libc::syscall(libc::SYS_close_range, first, next - 1, 0u32) } != 0 {
            return false;
        }
        first = next + 1;
    }
    (unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0u32) }) == 0
}

fn socket_option(fd: RawFd, name: i32) -> PlanResult<i32> {
    let mut value = 0i32;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&mut value as *mut i32).cast(), &mut size) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if size as usize != std::mem::size_of_val(&value) { return Err(invalid("namespace worker socket option is truncated")); }
    Ok(value)
}

fn require_channel(fd: RawFd, credentials: bool) -> PlanResult<()> {
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if status < 0 || flags < 0 { return Err(std::io::Error::last_os_error().into()); }
    let expected_credentials = if credentials { 1 } else { 0 };
    if socket_option(fd, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
        || socket_option(fd, libc::SO_PASSCRED)? != expected_credentials
        || flags & libc::FD_CLOEXEC == 0 || status & libc::O_NONBLOCK == 0 {
        return Err(invalid("namespace worker control channel differs from fixed private contract"));
    }
    Ok(())
}

fn control_pair() -> PlanResult<(OwnedFd, OwnedFd)> {
    let mut pair = [-1i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX,
        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0, pair.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let parent = at_least_three(parent)?;
    let child = at_least_three(child)?;
    let enabled = 1i32;
    if unsafe { libc::setsockopt(parent.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PASSCRED,
        (&enabled as *const i32).cast(), std::mem::size_of_val(&enabled) as libc::socklen_t) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    require_channel(parent.as_raw_fd(), true)?;
    require_channel(child.as_raw_fd(), false)?;
    Ok((parent, child))
}

fn pidfd_ended(fd: RawFd) -> PlanResult<bool> {
    let mut watched = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let count = unsafe { libc::poll(&mut watched, 1, 0) };
    if count < 0 { return Err(std::io::Error::last_os_error().into()); }
    if watched.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(invalid("namespace worker pidfd poll failed"));
    }
    Ok(watched.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

fn require_pidfd(fd: RawFd, proc: RawFd, pid: u32, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    if pidfd_ended(fd)? { return Err(invalid("namespace worker or parent exited")); }
    let directory = open_proc(proc, c"fdinfo", true)?;
    let name = CString::new(fd.to_string()).map_err(|_| invalid("namespace worker pidfd is invalid"))?;
    let bytes = read_proc(directory.as_raw_fd(), &name, deadline)?;
    if decimal(field(text(&bytes)?, "Pid:")?)? != pid as u64 {
        return Err(invalid("namespace worker pidfd is not its actual birth identity"));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(invalid("namespace worker pidfd lost descriptor ownership"));
    }
    live(deadline)
}
