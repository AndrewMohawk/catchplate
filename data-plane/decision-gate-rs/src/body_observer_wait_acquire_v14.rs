//! Actual initial interrupt-stop acquisition in the fixed namespace worker.
//!
//! Every wait/ptrace target is the literal namespace PID 1. This module has no
//! arbitrary-PID constructor, wait-any-child, attach, resume, detach or signal
//! operation. Its opaque token owns descriptor custody and is not transferable
//! between threads. It is not readiness, a history event, or signed evidence.
//! Other classifier branches have no continuous acquisition producer here;
//! GETEVENTMSG is not meaningful for this one initial EVENT_STOP and is not used.

use super::body_observer_process_v12::NamespaceWorkerScopeV12;
use super::body_observer_wait_contract_v14::{
    classify_wait_status, PtraceEventV14, WaitKindV14, WaitObservationV14,
};
use super::super::boottime_ns;
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;

const PROC_MAGIC: libc::c_long = 0x9fa0;
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const MAX_WAIT_SLICE_NS: u64 = 5_000_000;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn live(deadline: u64) -> PlanResult<u64> {
    let observed = boottime_ns()?;
    if observed >= deadline { return Err(invalid("initial wait original deadline expired")); }
    Ok(observed)
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
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if value.st_ino == 0 { return Err(invalid("initial wait descriptor has no node identity")); }
    Ok(Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid })
}

fn filesystem(fd: RawFd, expected: libc::c_long, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if value.f_type as u64 != expected as u64 { return Err(invalid("initial wait descriptor filesystem differs")); }
    Ok(())
}

struct HeldFd {
    fd: OwnedFd,
    node: Node,
}

impl HeldFd {
    fn duplicate(original: RawFd, deadline: u64) -> PlanResult<Self> {
        if original < 3 { return Err(invalid("initial wait scope descriptor is not private")); }
        let before = node(original, deadline)?;
        let raw = unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 3) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        // Adopt before any subsequent deadline/identity error.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let copied = node(fd.as_raw_fd(), deadline)?;
        if copied != before || node(original, deadline)? != before {
            return Err(invalid("initial wait scope descriptor changed during duplication"));
        }
        let held = Self { fd, node: copied };
        held.verify(deadline)?;
        Ok(held)
    }

    fn verify(&self, deadline: u64) -> PlanResult<()> {
        if node(self.fd.as_raw_fd(), deadline)? != self.node {
            return Err(invalid("initial wait held descriptor identity changed"));
        }
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 { return Err(std::io::Error::last_os_error().into()); }
        if flags & libc::FD_CLOEXEC == 0 {
            return Err(invalid("initial wait held descriptor lost close-on-exec"));
        }
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

fn pid_namespace(fd: RawFd, deadline: u64) -> PlanResult<Node> {
    filesystem(fd, NSFS_MAGIC, deadline)?;
    let kind = unsafe { libc::ioctl(fd, NS_GET_NSTYPE) };
    if kind < 0 { return Err(std::io::Error::last_os_error().into()); }
    if kind != libc::CLONE_NEWPID { return Err(invalid("initial wait namespace is not a PID namespace")); }
    node(fd, deadline)
}

fn actual_namespace(proc_fd: RawFd, deadline: u64) -> PlanResult<Node> {
    let ns = open_at(proc_fd, c"ns", true, false, deadline)?;
    filesystem(ns.as_raw_fd(), PROC_MAGIC, deadline)?;
    // This one source-fixed procfs namespace link is intentionally followed.
    let pid = open_at(ns.as_raw_fd(), c"pid", false, true, deadline)?;
    pid_namespace(pid.as_raw_fd(), deadline)
}

fn owner_proc(deadline: u64) -> PlanResult<HeldFd> {
    let root = open_at(libc::AT_FDCWD, c"/proc", true, false, deadline)?;
    filesystem(root.as_raw_fd(), PROC_MAGIC, deadline)?;
    let root_node = node(root.as_raw_fd(), deadline)?;
    // Resolve the current thread, never a caller's numeric PID or proc path.
    let fd = open_at(root.as_raw_fd(), c"thread-self", true, true, deadline)?;
    filesystem(fd.as_raw_fd(), PROC_MAGIC, deadline)?;
    let current = node(fd.as_raw_fd(), deadline)?;
    if current.device != root_node.device || current.mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(invalid("initial wait current-thread proc identity differs"));
    }
    Ok(HeldFd { fd, node: current })
}

fn live_pidfds(parent: RawFd, target: RawFd, deadline: u64) -> PlanResult<()> {
    loop {
        live(deadline)?;
        let mut fds = [libc::pollfd { fd: parent, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: target, events: libc::POLLIN, revents: 0 }];
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
        let error = (result < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if result != 0 || fds.iter().any(|fd| fd.revents != 0) {
            return Err(invalid("initial wait parent or namespace init is not live"));
        }
        return Ok(());
    }
}

struct WaitCustody {
    owner_pid: libc::pid_t,
    owner_tid: libc::c_long,
    parent: HeldFd,
    target: HeldFd,
    namespace: HeldFd,
    own_proc: HeldFd,
    deadline: u64,
}

impl WaitCustody {
    fn capture(scope: &NamespaceWorkerScopeV12) -> PlanResult<Self> {
        let deadline = scope.deadline_boottime_ns;
        let owner_pid = unsafe { libc::getpid() };
        let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if owner_pid <= 1 || owner_tid != owner_pid as libc::c_long {
            return Err(invalid("initial wait is not owned by the namespace worker main thread"));
        }
        let parent = HeldFd::duplicate(scope.parent_pidfd, deadline)?;
        let target = HeldFd::duplicate(scope.target_pidfd, deadline)?;
        let namespace = HeldFd::duplicate(scope.target_pid_namespace_fd, deadline)?;
        // The fixed WorkerView caller admits the original pidfds through actual
        // fdinfo PID joins before and after this acquisition. F_DUPFD retains
        // those same open descriptions. Distinct pidfds may share an anon-inode
        // fstat identity; Node equality is never a process-identity comparison.
        if pid_namespace(namespace.fd.as_raw_fd(), deadline)?.inode != scope.target_pid_namespace_inode {
            return Err(invalid("initial wait original namespace scope differs"));
        }
        let custody = Self { owner_pid, owner_tid, parent, target, namespace,
            own_proc: owner_proc(deadline)?, deadline };
        custody.verify_live(deadline)?;
        Ok(custody)
    }

    fn verify_live(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::syscall(libc::SYS_gettid) } != self.owner_tid
            || unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err(invalid("initial wait worker thread or root identity changed"));
        }
        for held in [&self.parent, &self.target, &self.namespace, &self.own_proc] {
            held.verify(deadline)?;
        }
        if pid_namespace(self.namespace.fd.as_raw_fd(), deadline)? != self.namespace.node
            || actual_namespace(self.own_proc.fd.as_raw_fd(), deadline)? != self.namespace.node {
            return Err(invalid("initial wait left its actual held target PID namespace"));
        }
        live_pidfds(self.parent.fd.as_raw_fd(), self.target.fd.as_raw_fd(), deadline)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InitialSignalInformation {
    signal: libc::c_int,
    error: libc::c_int,
    code: libc::c_int,
}

fn initial_signal_information(deadline: u64) -> PlanResult<InitialSignalInformation> {
    live(deadline)?;
    let mut raw: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, 1,
        std::ptr::null_mut::<libc::c_void>(), (&mut raw as *mut libc::siginfo_t).cast::<libc::c_void>()) };
    let error = (result != 0).then(std::io::Error::last_os_error);
    live(deadline)?;
    if let Some(error) = error { return Err(error.into()); }
    let information = InitialSignalInformation { signal: raw.si_signo, error: raw.si_errno, code: raw.si_code };
    if information.signal != libc::SIGTRAP || information.error != 0
        || information.code != ((libc::PTRACE_EVENT_STOP << 8) | libc::SIGTRAP) {
        return Err(invalid("initial wait exact interrupt-stop SIGINFO differs"));
    }
    Ok(information)
}

/// Constructed only after an actual same-thread literal-PID1 wait and SIGINFO.
/// The Rc marker makes this owned-custody token !Send/!Sync; it is not Clone.
/// Dropping it closes its duplicates, never resumes/detaches/kills a target.
pub(super) struct InitialNamespaceStopV14 {
    custody: WaitCustody,
    observation: WaitObservationV14,
    information: InitialSignalInformation,
    observed_at: u64,
    _same_thread: PhantomData<Rc<()>>,
}

impl InitialNamespaceStopV14 {
    pub(super) fn deadline(&self) -> u64 { self.custody.deadline }
    pub(super) fn observed_at_boottime_ns(&self) -> u64 { self.observed_at }
    pub(super) fn wait_observation(&self) -> &WaitObservationV14 { &self.observation }

    pub(super) fn verify_stopped(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.custody.deadline);
        self.custody.verify_live(deadline)?;
        if initial_signal_information(deadline)? != self.information {
            return Err(invalid("initial wait kernel stop metadata changed"));
        }
        self.custody.verify_live(deadline)
    }
}

/// Called only inside the fixed worker's genuine WorkerView admission: its
/// before/after fdinfo checks bind the original parent/target pidfds to scope.
pub(super) fn acquire_initial_interrupt_stop(scope: &NamespaceWorkerScopeV12)
    -> PlanResult<InitialNamespaceStopV14> {
    let custody = WaitCustody::capture(scope)?;
    let deadline = custody.deadline;
    let observation = loop {
        custody.verify_live(deadline)?;
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(1, &mut status,
            libc::__WALL | libc::__WNOTHREAD | libc::WNOHANG) };
        let error = (waited < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if waited != 0 {
            if waited != 1 { return Err(invalid("initial wait returned a different namespace task")); }
            let observation = classify_wait_status(1, status)?;
            match observation.kind() {
                WaitKindV14::PtraceEvent { event: PtraceEventV14::Stop, stop_signal }
                    if stop_signal == libc::SIGTRAP as u32 => break observation,
                WaitKindV14::PtraceEvent { event: PtraceEventV14::Exit, .. } =>
                    return Err(invalid("initial wait observed a pre-exit event, not the required interrupt stop")),
                WaitKindV14::Exited { .. } | WaitKindV14::Signaled { .. } =>
                    return Err(invalid("initial wait observed final termination before its required stop")),
                _ => return Err(invalid("initial wait did not observe its exact interrupt stop")),
            }
        }
        let remaining = deadline - live(deadline)?;
        let timeout = libc::timespec { tv_sec: 0,
            tv_nsec: remaining.min(MAX_WAIT_SLICE_NS) as libc::c_long };
        let mut fds = [libc::pollfd { fd: custody.parent.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: custody.target.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        let result = unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t,
            &timeout, std::ptr::null()) };
        let error = (result < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if result != 0 || fds.iter().any(|fd| fd.revents != 0) {
            return Err(invalid("initial wait parent or init terminated during polling"));
        }
    };
    custody.verify_live(deadline)?;
    let information = initial_signal_information(deadline)?;
    custody.verify_live(deadline)?;
    let observed_at = live(deadline)?;
    Ok(InitialNamespaceStopV14 { custody, observation, information, observed_at,
        _same_thread: PhantomData })
}
