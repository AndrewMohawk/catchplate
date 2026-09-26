//! Actual descriptor-backed identity of the still-stopped namespace init.
//!
//! Acquisition uses only the source-owned target proc descriptor and the real
//! initial-stop token. No numeric target is opened. Raw proc originals remain
//! owned; only parsed identity fields are compared, never volatile stat bytes.
//! This owner establishes neither MM sharing nor continuous observation, and
//! provides no resume, readiness, signing or independently trusted receipt.

use super::body_observer_process_v12::NamespaceWorkerScopeV12;
use super::body_observer_task_proc_v14::{
    parse_task_originals, ProcTaskIdentityV14, MAX_STAT_BYTES, MAX_STATUS_BYTES,
};
use super::body_observer_wait_acquire_v14::InitialNamespaceStopV14;
use super::super::boottime_ns;
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;

const PROC_MAGIC: u64 = 0x9fa0;
const NSFS_MAGIC: u64 = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn live(deadline: u64) -> PlanResult<u64> {
    let sampled = boottime_ns()?;
    if sampled >= deadline { return Err(invalid("stopped task original deadline expired")); }
    Ok(sampled)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

fn node(fd: RawFd, deadline: u64) -> PlanResult<Node> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if value.st_ino == 0 { return Err(invalid("stopped task descriptor lacks node identity")); }
    Ok(Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid })
}

fn filesystem(fd: RawFd, expected: u64, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if value.f_type != expected as _ { return Err(invalid("stopped task descriptor filesystem differs")); }
    Ok(())
}

struct HeldFd {
    fd: OwnedFd,
    node: Node,
}

impl HeldFd {
    fn adopt(fd: OwnedFd, expected_filesystem: u64, expected_kind: libc::mode_t,
        deadline: u64) -> PlanResult<Self> {
        filesystem(fd.as_raw_fd(), expected_filesystem, deadline)?;
        let identity = node(fd.as_raw_fd(), deadline)?;
        if identity.mode & libc::S_IFMT != expected_kind {
            return Err(invalid("stopped task descriptor object type differs"));
        }
        Ok(Self { fd, node: identity })
    }

    fn duplicate(original: RawFd, expected_filesystem: u64, expected_kind: libc::mode_t,
        deadline: u64) -> PlanResult<Self> {
        if original < 3 { return Err(invalid("stopped task scope descriptor is not private")); }
        let before = node(original, deadline)?;
        let raw = unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 3) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let held = Self::adopt(fd, expected_filesystem, expected_kind, deadline)?;
        if held.node != before || node(original, deadline)? != before {
            return Err(invalid("stopped task source descriptor changed during duplication"));
        }
        Ok(held)
    }

    fn verify(&self, deadline: u64) -> PlanResult<()> {
        if node(self.fd.as_raw_fd(), deadline)? != self.node {
            return Err(invalid("stopped task held descriptor identity changed"));
        }
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 { return Err(std::io::Error::last_os_error().into()); }
        if flags & libc::FD_CLOEXEC == 0 { return Err(invalid("stopped task descriptor lost close-on-exec")); }
        live(deadline)?;
        Ok(())
    }
}

fn open_at(parent: RawFd, name: &CStr, directory: bool, follow: bool,
    deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }
        | if follow { 0 } else { libc::O_NOFOLLOW };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(fd)
}

fn named_proc(parent: RawFd, name: &CStr, directory: bool, deadline: u64) -> PlanResult<HeldFd> {
    HeldFd::adopt(open_at(parent, name, directory, false, deadline)?, PROC_MAGIC,
        if directory { libc::S_IFDIR } else { libc::S_IFREG }, deadline)
}

fn named_namespace(parent: RawFd, deadline: u64) -> PlanResult<HeldFd> {
    // Only this source-fixed procfs namespace link is followed.
    let held = HeldFd::adopt(open_at(parent, c"pid", false, true, deadline)?,
        NSFS_MAGIC, libc::S_IFREG, deadline)?;
    require_pid_namespace(&held, deadline)?;
    Ok(held)
}

fn require_pid_namespace(held: &HeldFd, deadline: u64) -> PlanResult<()> {
    held.verify(deadline)?;
    filesystem(held.fd.as_raw_fd(), NSFS_MAGIC, deadline)?;
    let kind = unsafe { libc::ioctl(held.fd.as_raw_fd(), NS_GET_NSTYPE) };
    if kind < 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if kind != libc::CLONE_NEWPID { return Err(invalid("stopped task descriptor is not a PID namespace")); }
    Ok(())
}

fn read_original(held: &HeldFd, maximum: usize, deadline: u64) -> PlanResult<Vec<u8>> {
    held.verify(deadline)?;
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        // At the exact cap, still perform a one-byte EOF probe.
        let wanted = (maximum - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(held.fd.as_raw_fd(), buffer.as_mut_ptr().cast(),
            wanted, bytes.len() as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { break; }
        if count as usize > maximum - bytes.len() {
            return Err(invalid("stopped task proc original exceeds its source bound"));
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
    held.verify(deadline)?;
    Ok(bytes)
}

struct TaskView {
    directory: HeldFd,
    status: HeldFd,
    stat: HeldFd,
    namespace_directory: HeldFd,
    pid_namespace: HeldFd,
}

impl TaskView {
    fn from_directory(directory: HeldFd, deadline: u64) -> PlanResult<Self> {
        let parent = directory.fd.as_raw_fd();
        let status = named_proc(parent, c"status", false, deadline)?;
        let stat = named_proc(parent, c"stat", false, deadline)?;
        let namespace_directory = named_proc(parent, c"ns", true, deadline)?;
        let pid_namespace = named_namespace(namespace_directory.fd.as_raw_fd(), deadline)?;
        let view = Self { directory, status, stat, namespace_directory, pid_namespace };
        view.verify(deadline)?;
        Ok(view)
    }

    fn verify(&self, deadline: u64) -> PlanResult<()> {
        for held in [&self.directory, &self.status, &self.stat, &self.namespace_directory, &self.pid_namespace] {
            held.verify(deadline)?;
        }
        let parent = self.directory.fd.as_raw_fd();
        for (name, directory, held) in [(c".", true, &self.directory),
            (c"status", false, &self.status), (c"stat", false, &self.stat),
            (c"ns", true, &self.namespace_directory)] {
            let fresh = named_proc(parent, name, directory, deadline)?;
            if fresh.node != held.node { return Err(invalid("stopped task named proc descriptor changed")); }
        }
        let fresh = named_namespace(self.namespace_directory.fd.as_raw_fd(), deadline)?;
        if fresh.node != self.pid_namespace.node { return Err(invalid("stopped task named PID namespace changed")); }
        require_pid_namespace(&self.pid_namespace, deadline)
    }

    fn observe(&self, deadline: u64) -> PlanResult<IdentityRead> {
        self.verify(deadline)?;
        let status = read_original(&self.status, MAX_STATUS_BYTES, deadline)?;
        let stat = read_original(&self.stat, MAX_STAT_BYTES, deadline)?;
        let identity = parse_task_originals(&status, &stat)?;
        self.verify(deadline)?;
        Ok(IdentityRead { _status_original: status, _stat_original: stat, identity })
    }
}

struct IdentityRead {
    _status_original: Vec<u8>,
    _stat_original: Vec<u8>,
    identity: ProcTaskIdentityV14,
}

struct ReadPair {
    target: IdentityRead,
    worker: IdentityRead,
}

struct Scope {
    host_target: u32,
    target_start: u64,
    namespace_inode: u64,
    host_parent: u32,
    deadline: u64,
    stop_observed_at: u64,
    stop_status: i32,
}

/// Non-cloneable, same-thread descriptor owner. Retained original observations
/// are not accepted back as a replacement for a fresh real verification.
pub(super) struct AcquiredInitialTaskV14 {
    scope: Scope,
    owner_pid: libc::pid_t,
    owner_tid: libc::c_long,
    target: TaskView,
    worker: TaskView,
    scoped_namespace: HeldFd,
    _before: ReadPair,
    after: ReadPair,
    observed_at: u64,
    _same_thread: PhantomData<Rc<()>>,
}

fn stop_scope(stop: &InitialNamespaceStopV14, scope: &Scope, deadline: u64) -> PlanResult<()> {
    if stop.deadline() != scope.deadline || stop.observed_at_boottime_ns() != scope.stop_observed_at
        || stop.wait_observation().namespace_tid() != 1
        || stop.wait_observation().original_status() != scope.stop_status {
        return Err(invalid("stopped task original stop scope changed"));
    }
    stop.verify_stopped(deadline)
}

fn identity_pair(scope: &Scope, pair: &ReadPair, owner_pid: libc::pid_t) -> PlanResult<()> {
    let target = &pair.target.identity;
    let worker = &pair.worker.identity;
    if target.host_tid() != scope.host_target || target.host_tgid() != scope.host_target
        || target.start_ticks() != scope.target_start || target.state() != b't' || target.threads() != 1
        || target.namespace_tids().len() < 2 || target.namespace_tids().last() != Some(&1)
        || target.namespace_tgids().last() != Some(&1)
        || target.tracer_pid() != worker.host_tid()
        || worker.host_tid() != worker.host_tgid() || worker.host_ppid() != scope.host_parent
        || worker.tracer_pid() != 0 || worker.threads() != 1
        || !matches!(worker.state(), b'R' | b'S' | b'D' | b'I')
        || worker.namespace_tids().len() != target.namespace_tids().len()
        || worker.namespace_tids().last().copied() != Some(owner_pid as u32)
        || worker.namespace_tgids().last().copied() != Some(owner_pid as u32) {
        return Err(invalid("stopped task/worker original identities, tracer or namespace views differ"));
    }
    Ok(())
}

impl AcquiredInitialTaskV14 {
    pub(super) fn host_tid(&self) -> u32 { self.after.target.identity.host_tid() }
    pub(super) fn host_tgid(&self) -> u32 { self.after.target.identity.host_tgid() }
    pub(super) fn start_ticks(&self) -> u64 { self.after.target.identity.start_ticks() }
    pub(super) fn pid_namespace_inode(&self) -> u64 { self.target.pid_namespace.node.inode }
    pub(super) fn tracer_host_tid(&self) -> u32 { self.after.worker.identity.host_tid() }
    pub(super) fn observed_at_boottime_ns(&self) -> u64 { self.observed_at }
    pub(super) fn deadline(&self) -> u64 { self.scope.deadline }

    /// Exact retained acquisition originals in fixed transport/storage order.
    /// Borrowing these bytes performs no fresh proc read or custody admission.
    pub(super) fn originals(&self) -> [&[u8]; 8] {
        [&self._before.target._status_original, &self._before.target._stat_original,
            &self.after.target._status_original, &self.after.target._stat_original,
            &self._before.worker._status_original, &self._before.worker._stat_original,
            &self.after.worker._status_original, &self.after.worker._stat_original]
    }

    fn custody(&self, stop: &InitialNamespaceStopV14, deadline: u64) -> PlanResult<()> {
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::syscall(libc::SYS_gettid) } != self.owner_tid {
            return Err(invalid("stopped task owner thread changed"));
        }
        stop_scope(stop, &self.scope, deadline)?;
        self.target.verify(deadline)?;
        self.worker.verify(deadline)?;
        require_pid_namespace(&self.scoped_namespace, deadline)?;
        if self.target.pid_namespace.node != self.scoped_namespace.node
            || self.worker.pid_namespace.node != self.scoped_namespace.node {
            return Err(invalid("stopped task actual target/worker PID namespace differs"));
        }
        Ok(())
    }

    pub(super) fn verify(&self, stop: &InitialNamespaceStopV14, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.scope.deadline);
        self.custody(stop, deadline)?;
        let before = ReadPair { worker: self.worker.observe(deadline)?, target: self.target.observe(deadline)? };
        identity_pair(&self.scope, &before, self.owner_pid)?;
        self.custody(stop, deadline)?;
        let after = ReadPair { worker: self.worker.observe(deadline)?, target: self.target.observe(deadline)? };
        identity_pair(&self.scope, &after, self.owner_pid)?;
        // The parser projection contains only identity/state/comm fields, not
        // volatile counters. Never require equality of entire proc originals.
        if before.target.identity != self.after.target.identity || after.target.identity != self.after.target.identity
            || before.worker.identity != self.after.worker.identity || after.worker.identity != self.after.worker.identity {
            return Err(invalid("stopped task identity changed across actual observations"));
        }
        self.custody(stop, deadline)
    }
}

pub(super) fn acquire_initial_task(stop: &InitialNamespaceStopV14, original: &NamespaceWorkerScopeV12)
    -> PlanResult<AcquiredInitialTaskV14> {
    let scope = Scope { host_target: original.target_host_pid, target_start: original.target_start_ticks,
        namespace_inode: original.target_pid_namespace_inode, host_parent: original.parent_host_pid,
        deadline: original.deadline_boottime_ns, stop_observed_at: stop.observed_at_boottime_ns(),
        stop_status: stop.wait_observation().original_status() };
    let target_fd = original.target_proc_fd;
    let namespace_fd = original.target_pid_namespace_fd;
    let owner_pid = unsafe { libc::getpid() };
    let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if owner_pid <= 1 || owner_tid != owner_pid as libc::c_long || scope.host_target <= 1
        || scope.host_parent <= 1 || scope.host_target == scope.host_parent
        || scope.target_start == 0 || scope.namespace_inode == 0 {
        return Err(invalid("stopped task lacks its source-owned initial identity scope"));
    }
    stop_scope(stop, &scope, scope.deadline)?;
    let target = TaskView::from_directory(HeldFd::duplicate(target_fd, PROC_MAGIC, libc::S_IFDIR, scope.deadline)?, scope.deadline)?;
    let scoped_namespace = HeldFd::duplicate(namespace_fd, NSFS_MAGIC, libc::S_IFREG, scope.deadline)?;
    require_pid_namespace(&scoped_namespace, scope.deadline)?;
    if scoped_namespace.node.inode != scope.namespace_inode || target.pid_namespace.node != scoped_namespace.node {
        return Err(invalid("stopped task actual namespace differs from its source-held namespace"));
    }
    let proc_root = named_proc(libc::AT_FDCWD, c"/proc", true, scope.deadline)?;
    // Fixed current-thread proc link, not a numeric target path.
    let worker_dir = HeldFd::adopt(open_at(proc_root.fd.as_raw_fd(), c"thread-self", true, true, scope.deadline)?,
        PROC_MAGIC, libc::S_IFDIR, scope.deadline)?;
    if worker_dir.node.device != proc_root.node.device {
        return Err(invalid("stopped task worker proc view left the actual proc filesystem"));
    }
    let worker = TaskView::from_directory(worker_dir, scope.deadline)?;
    if worker.pid_namespace.node != scoped_namespace.node {
        return Err(invalid("stopped task worker is not in the held target PID namespace"));
    }
    let before = ReadPair { worker: worker.observe(scope.deadline)?, target: target.observe(scope.deadline)? };
    identity_pair(&scope, &before, owner_pid)?;
    stop_scope(stop, &scope, scope.deadline)?;
    let after = ReadPair { worker: worker.observe(scope.deadline)?, target: target.observe(scope.deadline)? };
    identity_pair(&scope, &after, owner_pid)?;
    if before.target.identity != after.target.identity || before.worker.identity != after.worker.identity {
        return Err(invalid("stopped task acquisition identity observations are not coherent"));
    }
    let observed_at = live(scope.deadline)?;
    let acquired = AcquiredInitialTaskV14 { scope, owner_pid, owner_tid, target, worker, scoped_namespace,
        _before: before, after, observed_at, _same_thread: PhantomData };
    acquired.custody(stop, acquired.scope.deadline)?;
    Ok(acquired)
}
