//! One genuinely claimed executable child, retained in a ptrace stop before
//! exec. Only the consuming, same-child network and guardian composition may
//! release it. There is no raw PID, descriptor, or serialized-permit constructor.

#[path = "child_release.rs"]
mod release;
pub(super) use release::{Execution, ExitObservation, OutputObservation};

use super::{child_network, child_trampoline, containment::{ContainmentCleanupBorrow, ContainmentOwner, LeafEmpty},
    filesystem::ChildFilesystem};
use std::cell::{Cell, RefCell};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
const PIDFD_THREAD: libc::c_uint = libc::O_EXCL as libc::c_uint;
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const PTRACE_EVENT_STOP: i32 = 128;
const PTRACE_EVENT_EXEC: i32 = 4;
const OPTIONS: usize = 0x0010_0000 | 0x0000_0010; // EXITKILL | TRACEEXEC

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

fn boottime() -> Result<u64, String> {
    let mut now: libc::timespec = unsafe { zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut now) } == 0
        && now.tv_sec >= 0 && (0..1_000_000_000).contains(&now.tv_nsec),
        "native child boottime unavailable")?;
    (now.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(now.tv_nsec as u64))
        .ok_or_else(|| "native child boottime overflow".to_owned())
}

#[derive(PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32 }

fn identity(fd: BorrowedFd<'_>) -> Result<Identity, String> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    require(flags >= 0 && flags & libc::FD_CLOEXEC != 0
        && unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } == 0 && stat.st_ino != 0,
        "native child retained descriptor changed")?;
    Ok(Identity { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode })
}

fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, String> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    require(raw >= 64, "native child descriptor duplication failed")?;
    let result = unsafe { OwnedFd::from_raw_fd(raw) };
    require(identity(result.as_fd())? == identity(fd)?, "native child descriptor duplicate differs")?;
    Ok(result)
}

fn poll(fd: BorrowedFd<'_>, events: i16, deadline: u64) -> Result<i16, String> {
    let now = boottime()?;
    require(now < deadline, "native child original deadline ended")?;
    let remaining = (deadline - now).min(50_000_000);
    let timeout = libc::timespec { tv_sec: 0, tv_nsec: remaining as libc::c_long };
    let mut descriptor = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
    require(unsafe { libc::ppoll(&mut descriptor, 1, &timeout, std::ptr::null()) } >= 0
        && descriptor.revents & libc::POLLNVAL == 0,
        "native child bounded wait failed; no renewed allowance")?;
    require(boottime()? < deadline, "native child closing wait missed its deadline")?;
    Ok(descriptor.revents)
}

fn alive(fd: BorrowedFd<'_>) -> Result<(), String> {
    let mut descriptor = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    require(unsafe { libc::poll(&mut descriptor, 1, 0) } == 0 && descriptor.revents == 0,
        "native child or creator-thread pidfd is no longer live")
}

struct Leader {
    pidfd: OwnedFd,
    identity: Identity,
    pid: libc::pid_t,
    killed: Cell<bool>,
    reaped: Cell<bool>,
}

impl Leader {
    fn check(&self) -> Result<(), String> {
        require(!self.reaped.get() && identity(self.pidfd.as_fd())? == self.identity,
            "native child leader pidfd identity changed")?;
        alive(self.pidfd.as_fd())
    }

    fn emergency_kill(&self) {
        // Exact clone-returned pidfd only; never fall back to numeric kill.
        if self.reaped.get() || self.killed.replace(true) { return; }
        if identity(self.pidfd.as_fd()).is_ok_and(|value| value == self.identity) {
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd.as_raw_fd(),
                libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0u32); }
        }
    }

    fn event(&self, options: i32) -> Result<Option<(i32, i32)>, String> {
        require(!self.reaped.get() && identity(self.pidfd.as_fd())? == self.identity,
            "native child wait lost its exact leader")?;
        let mut info: libc::siginfo_t = unsafe { zeroed() };
        require(unsafe { libc::waitid(libc::P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t,
            &mut info, options | libc::WNOHANG | 0x2000_0000) } == 0,
            "native child pidfd wait failed; outcome remains uncertain")?; // __WNOTHREAD
        if unsafe { info.si_pid() } == 0 { return Ok(None); }
        require(unsafe { info.si_pid() } == self.pid && info.si_signo == libc::SIGCHLD
            && info.si_errno == 0, "native child wait returned another task")?;
        Ok(Some((info.si_code, unsafe { info.si_status() })))
    }

    fn reap(&self, deadline: u64) -> Result<(i32, i32), String> {
        loop {
            require(boottime()? < deadline, "native child leader reap missed cleanup deadline")?;
            if let Some((code, status)) = self.event(libc::WEXITED)? {
                if matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED) {
                    self.reaped.set(true);
                    require(boottime()? < deadline, "native child closing reap missed cleanup deadline")?;
                    return Ok((code, status));
                }
                // Linux ptrace waits can report a stop even with WEXITED.
                // Consume that old stop without resuming; pending SIGKILL
                // terminates it independently. Only the later exit is a reap.
                require(code == libc::CLD_TRAPPED,
                    "native child cleanup returned an unexpected wait condition")?;
            }
            let _ = poll(self.pidfd.as_fd(), libc::POLLIN, deadline)?;
        }
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        self.emergency_kill();
        // Best effort only, with no waiting and no success/cleanup receipt.
        if !self.reaped.get() {
            if let Ok(Some((code, _))) = self.event(libc::WEXITED) {
                if matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED) {
                    self.reaped.set(true);
                }
            }
        }
    }
}

struct Namespace { fd: OwnedFd, identity: Identity, kind: i32, command: libc::c_ulong }
impl Namespace {
    fn from_pidfd(pidfd: BorrowedFd<'_>, command: libc::c_ulong, kind: i32) -> Result<Self, String> {
        // Linux v6.12 PIDFD_GET_{IPC,MNT,NET,PID,UTS}_NAMESPACE ioctls. No
        // caller namespace path, numeric-PID reopen, setns or fallback exists.
        let raw = unsafe { libc::ioctl(pidfd.as_raw_fd(), command as _) };
        require(raw >= 0, "native child exact pidfd namespace ioctl unavailable")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let result = Self { identity: identity(fd.as_fd())?, fd, kind, command };
        result.check_descriptor()?;
        Ok(result)
    }
    fn check_descriptor(&self) -> Result<(), String> {
        let mut fs: libc::statfs = unsafe { zeroed() };
        require(identity(self.fd.as_fd())? == self.identity
            && unsafe { libc::fstatfs(self.fd.as_raw_fd(), &mut fs) } == 0 && fs.f_type as u64 == NSFS_MAGIC as u64
            && unsafe { libc::ioctl(self.fd.as_raw_fd(), NS_GET_NSTYPE as _) } == self.kind,
            "native child held namespace identity/type changed")
    }
    fn check(&self, leader: &Leader) -> Result<(), String> {
        leader.check()?;
        self.check_descriptor()?;
        let current = Self::from_pidfd(leader.pidfd.as_fd(), self.command, self.kind)?;
        require(current.identity == self.identity, "native child moved from its created namespace")?;
        leader.check()
    }
}

#[repr(C)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64, exit_signal: u64,
    stack: u64, stack_size: u64, tls: u64, set_tid: u64, set_tid_size: u64, cgroup: u64,
}

fn pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut raw = [-1; 2];
    require(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
        0, raw.as_mut_ptr()) } == 0, "native child private gate unavailable")?;
    Ok(unsafe { (OwnedFd::from_raw_fd(raw[0]), OwnedFd::from_raw_fd(raw[1])) })
}

fn output_pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut raw = [-1; 2];
    require(unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
        "native child output pipe unavailable")?;
    let read = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    require(unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == 0,
        "native child output reader cannot be bounded")?;
    Ok((read, write))
}

fn null_input() -> Result<OwnedFd, String> {
    let raw = unsafe { libc::open(b"/dev/null\0".as_ptr().cast(),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) };
    require(raw >= 0, "native child null input unavailable")?;
    let result = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(result.as_raw_fd(), &mut stat) } == 0
        && stat.st_mode & libc::S_IFMT == libc::S_IFCHR && stat.st_rdev == libc::makedev(1, 3),
        "native child null input is not the actual null device")?;
    Ok(result)
}

/// Non-Clone, no raw constructor. Release requires the actual network/guardian owners.
pub(in super::super) struct BlockedChild {
    // Drop must request whole-leaf termination while all real claims remain
    // held, then preserve exact leader pidfd cleanup before owner destruction.
    leader: Leader,
    containment: ContainmentOwner,
    filesystem: ChildFilesystem,
    launcher: OwnedFd,
    launcher_identity: Identity,
    gate: OwnedFd,
    namespaces: Vec<Namespace>,
    network: Option<child_network::Sockets>,
    application_listener: Option<child_network::Listener>,
    application_attempted: Cell<bool>,
    network_attempted: Cell<bool>,
    stdout: OwnedFd,
    stderr: OwnedFd,
    output_remaining: Cell<u64>,
    output: RefCell<release::OutputState>,
    guardian_attempted: Cell<bool>,
    release_attempted: Cell<bool>,
    executed: Cell<bool>,
    continuation_stopped: Cell<bool>,
    stopped: Cell<bool>,
    cleanup_attempted: Cell<bool>,
}

impl BlockedChild {
    pub(super) fn create(containment: ContainmentOwner) -> Result<Self, String> {
        require(cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
            "native child syscall ABI is unsupported")?;
        containment.check_admission()?;
        let owner = containment.owner();
        let isolation = &owner.constraints().isolation;
        require(isolation.profile == "non-root-empty-capabilities-v1"
            && isolation.uid != 0 && isolation.gid != 0 && isolation.supplementary_groups.is_empty()
            && isolation.no_new_privileges && isolation.umask == 0o077
            && isolation.stdio == "null-input-bounded-output-v1",
            "native child isolation is not the signed fixed profile")?;
        let uid = isolation.uid;
        let gid = isolation.gid;
        let output_remaining = owner.constraints().resources.output_max_bytes;
        let filesystem = owner.filesystem().prepare_child()?;
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        require(tid > 0 && tid <= i32::MAX as libc::c_long, "native creator thread unavailable")?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, tid as i32, PIDFD_THREAD) };
        require(raw >= 0, "native child requires creator-thread pidfd support")?;
        let launcher = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
        let launcher_identity = identity(launcher.as_fd())?;
        alive(launcher.as_fd())?;
        // A competing inherited handler/automatic SIGCHLD reap would destroy
        // exact leader outcome custody. Do not replace process-wide handlers.
        let mut action: libc::sigaction = unsafe { zeroed() };
        require(unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } == 0
            && action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0,
            "native child requires default retained SIGCHLD reap ownership")?;
        let (gate, child_gate) = pair()?;
        let (stdout, stdout_writer) = output_pipe()?;
        let (stderr, stderr_writer) = output_pipe()?;
        let stdin = null_input()?;
        let originals = [filesystem.root(), filesystem.cwd(), filesystem.entry(), child_gate.as_fd(),
            launcher.as_fd(), stdin.as_fd(), stdout_writer.as_fd(), stderr_writer.as_fd()];
        let copies = originals.into_iter().map(duplicate).collect::<Result<Vec<_>, _>>()?;
        let mut keep = [0; 8];
        for (slot, fd) in keep.iter_mut().zip(&copies) { *slot = fd.as_raw_fd(); }
        keep.sort_unstable();
        let spec = child_trampoline::Spec { root: copies[0].as_raw_fd(), cwd: copies[1].as_raw_fd(),
            entry: copies[2].as_raw_fd(), gate: copies[3].as_raw_fd(), parent: copies[4].as_raw_fd(),
            stdin: copies[5].as_raw_fd(), stdout: copies[6].as_raw_fd(), stderr: copies[7].as_raw_fd(),
            keep, uid, gid, argv: filesystem.argv(), envp: filesystem.envp(),
            application_port: owner.filesystem().application().map_or(0,|value|value.listener_port) };
        owner.check_admission()?;
        filesystem.check(owner.filesystem())?;
        let cgroup = containment.begin_child()?.as_raw_fd();
        let mut pidfd = -1i32;
        let args = CloneArgs { flags: CLONE_INTO_CGROUP | CLONE_PIDFD
            | (libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS | libc::CLONE_NEWNET) as u64,
            pidfd: (&mut pidfd as *mut i32) as u64, child_tid: 0, parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64, stack: 0, stack_size: 0, tls: 0,
            set_tid: 0, set_tid_size: 0, cgroup: cgroup as u64 };
        let all_signals = u64::MAX;
        let mut original_mask = 0u64;
        require(unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
            &all_signals as *const u64, &mut original_mask as *mut u64, 8usize) } == 0,
            "native child signal mask cannot be sealed before clone")?;
        // Sole creation attempt. No retry, migration, existing-PID adoption or
        // numeric-PID fallback; the irreversible claims are already retained.
        let cloned = unsafe { libc::syscall(libc::SYS_clone3, &args as *const CloneArgs,
            size_of::<CloneArgs>()) };
        if cloned == 0 { unsafe { child_trampoline::run(&spec) } }
        let restored = unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
            &original_mask as *const u64, std::ptr::null_mut::<u64>(), 8usize) } == 0;
        if cloned < 0 || cloned > i32::MAX as libc::c_long || pidfd < 0 {
            let _ = containment.attempt_emergency_kill();
            return Err("native clone failed or has uncertain pidfd custody; claims remain consumed".to_owned());
        }
        let held = unsafe { OwnedFd::from_raw_fd(pidfd) };
        // Arrange exact-pidfd Drop custody before any fallible post-clone
        // observation, including fstat. If fstat fails, leaf cleanup still runs.
        let observed = match identity(held.as_fd()) {
            Ok(value) => value,
            Err(error) => {
                unsafe { libc::syscall(libc::SYS_pidfd_send_signal, held.as_raw_fd(), libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(), 0u32); }
                let _ = containment.attempt_emergency_kill();
                return Err(error);
            }
        };
        let leader = Leader { pidfd: held, identity: observed, pid: cloned as i32,
            killed: Cell::new(false), reaped: Cell::new(false) };
        drop(copies);
        drop(child_gate);
        drop(stdout_writer);
        drop(stderr_writer);
        drop(stdin);
        let mut result = Self { leader, containment, filesystem, launcher, launcher_identity, gate,
            namespaces: Vec::with_capacity(5), network: None, application_listener:None,
            application_attempted:Cell::new(false), network_attempted: Cell::new(false), stdout, stderr,
            output_remaining: Cell::new(output_remaining), output: RefCell::new(release::OutputState::new()),
            guardian_attempted: Cell::new(false),
            release_attempted: Cell::new(false), executed: Cell::new(false),
            continuation_stopped: Cell::new(false),
            stopped: Cell::new(false), cleanup_attempted: Cell::new(false) };
        require(restored, "native launcher signal mask restore failed; child remains unreleased")?;
        result.await_ready()?;
        result.leader.check()?;
        require(unsafe { libc::ptrace(libc::PTRACE_SEIZE, result.leader.pid,
            std::ptr::null_mut::<libc::c_void>(), OPTIONS as *mut libc::c_void) } == 0,
            "native child ptrace custody unavailable")?;
        result.leader.check()?;
        require(unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, result.leader.pid,
            std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) } == 0,
            "native child cannot enter retained ptrace stop")?;
        result.await_blocked()?;
        for (command, kind) in [(0xff02, libc::CLONE_NEWIPC), (0xff03, libc::CLONE_NEWNS),
            (0xff04, libc::CLONE_NEWNET), (0xff05, libc::CLONE_NEWPID), (0xff0a, libc::CLONE_NEWUTS)] {
            let child = Namespace::from_pidfd(result.leader.pidfd.as_fd(), command, kind)?;
            let parent = Namespace::from_pidfd(result.launcher.as_fd(), command, kind)?;
            require(child.identity != parent.identity, "native child reused a launcher namespace")?;
            result.namespaces.push(child);
        }
        result.check()?;
        Ok(result)
    }

    fn admission(&self) -> Result<u64, String> {
        self.containment.check_child_admission(self.leader.pid)?;
        self.leader.check()?;
        require(identity(self.launcher.as_fd())? == self.launcher_identity,
            "native child creator-thread pidfd changed")?;
        alive(self.launcher.as_fd())?;
        self.containment.owner().clock().boottime_deadline()
    }

    fn await_ready(&mut self) -> Result<(), String> {
        loop {
            let deadline = self.admission()?;
            let events = poll(self.gate.as_fd(), libc::POLLIN, deadline)?;
            self.admission()?;
            require(events & (libc::POLLERR | libc::POLLHUP) == 0,
                "native executable child died before blocked readiness")?;
            if events & libc::POLLIN == 0 { continue; }
            match child_network::receive(self.gate.as_fd())? {
                child_network::Message::Originals(originals) => {
                    require(self.network.is_none(), "native child sent duplicate network originals")?;
                    self.network = Some(originals);
                }
                child_network::Message::Ready => {
                    require(self.network.is_some(), "native child readiness lacks its actual network sockets")?;
                    require(self.application_listener.is_some()==self.containment.owner().filesystem().application().is_some(),
                        "native child readiness listener differs from explicitly signed profile")?;
                    self.admission()?;
                    return Ok(());
                }
                child_network::Message::Listener(listener) => {
                    require(self.application_listener.is_none() && self.containment.owner().filesystem().application().is_some(),
                        "native child sent unexpected or repeated application listener")?;
                    self.application_listener=Some(listener);
                }
            }
        }
    }

    fn stop_event(&self) -> Result<Option<(i32, i32)>, String> {
        self.leader.event(libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT)
    }

    fn await_blocked(&self) -> Result<(), String> {
        loop {
            let deadline = self.admission()?;
            if let Some((code, status)) = self.stop_event()? {
                require(code == libc::CLD_TRAPPED
                    && status == (libc::SIGTRAP | (PTRACE_EVENT_STOP << 8)),
                    "native executable child did not reach its exact pre-exec ptrace stop")?;
                return self.admission().map(|_| ());
            }
            // A pidfd poll may wait until its 50ms slice even for a ptrace
            // stop; each iteration re-reads the exact kernel wait event.
            let _ = poll(self.leader.pidfd.as_fd(), libc::POLLIN, deadline)?;
        }
    }

    pub(super) fn check(&self) -> Result<(), String> {
        require(!self.stopped.replace(true) && !self.cleanup_attempted.get() && !self.release_attempted.get(),
            "native blocked child admission is stopped")?;
        self.admission()?;
        require(self.stop_event()? == Some((libc::CLD_TRAPPED,
            libc::SIGTRAP | (PTRACE_EVENT_STOP << 8))),
            "native child is no longer held at the original pre-exec stop")?;
        self.filesystem.check(self.containment.owner().filesystem())?;
        require(self.namespaces.len() == 5, "native child namespace originals are incomplete")?;
        for namespace in &self.namespaces { namespace.check(&self.leader)?; }
        self.network_originals()?.check(self.network_namespace()?.fd.as_fd())?;
        if let Some(settings)=self.containment.owner().filesystem().application() {
            self.application_listener.as_ref().ok_or("actual application listener disappeared")?
                .check(self.network_namespace()?.fd.as_fd(),settings.listener_port)?;
        } else {require(self.application_listener.is_none(),"unexpected application listener")?;}
        self.admission()?;
        require(self.stop_event()? == Some((libc::CLD_TRAPPED,
            libc::SIGTRAP | (PTRACE_EVENT_STOP << 8))), "native child closing stop changed")?;
        self.stopped.set(false);
        Ok(())
    }

    pub(super) fn guardian_borrow(&self) -> Result<GuardianBorrow<'_>, String> {
        self.check()?;
        self.containment.cleanup_borrow()?.check()?;
        Ok(GuardianBorrow { child: self })
    }
    pub(super) fn application_context(&self)->Result<(&super::application_proxy::Settings,
        &super::super::egress::ExecutionParents,&std::sync::Arc<super::super::OriginalClock>),String> {
        self.check()?;
        let owner=self.containment.owner();
        let settings=owner.filesystem().application().ok_or("child lacks explicit application profile")?;
        require(owner.constraints().application_proxy_sha256.as_deref()==Some(settings.sha256()?.as_str()),
            "child application permission differs")?;
        Ok((settings,owner.parents(),owner.clock_owner()))
    }
    pub(super) fn application_listener(&self)->Result<std::net::TcpListener,String> {
        self.check()?;
        require(!self.application_attempted.replace(true),"child application listener attempt consumed")?;
        let (settings,_,_)=self.application_context()?;
        self.application_listener.as_ref().ok_or("child actual listener unavailable")?
            .duplicate(self.network_namespace()?.fd.as_fd(),settings.listener_port)
    }
    pub(super) fn application_requested(&self)->bool { self.containment.owner().filesystem().application().is_some() }

    fn network_namespace(&self) -> Result<&Namespace, String> {
        self.namespaces.iter().find(|value| value.kind == libc::CLONE_NEWNET)
            .ok_or_else(|| "native child network namespace original absent".to_owned())
    }
    fn network_originals(&self) -> Result<&child_network::Sockets, String> {
        self.network.as_ref().ok_or_else(|| "native child network socket originals absent".to_owned())
    }
    pub(in super::super) fn network_borrow(&self) -> Result<ChildNetworkBorrow<'_>, String> {
        self.check()?;
        Ok(ChildNetworkBorrow { child: self })
    }

    // Actual positive EXEC observer after genuine same-child network release. EOF,
    // CLD_EXITED/127 and every other stop are NOT successful exec evidence.
    fn observe_exec(&self) -> Result<ExecAcknowledgement, String> {
        loop {
            let deadline = self.admission()?;
            if let Some((code, status)) = self.stop_event()? {
                require(code == libc::CLD_TRAPPED
                    && status == (libc::SIGTRAP | (PTRACE_EVENT_EXEC << 8)),
                    "native child exited or stopped without a positive EXEC event")?;
                let mut former_tid = 0usize;
                self.leader.check()?;
                require(unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, self.leader.pid,
                    std::ptr::null_mut::<libc::c_void>(), &mut former_tid as *mut usize) } == 0
                    && former_tid == self.leader.pid as usize,
                    "native child EXEC event changed leader identity")?;
                self.admission()?;
                require(self.stop_event()? == Some((code, status)), "native child EXEC event drifted")?;
                let observed_boottime_ns = boottime()?;
                require(observed_boottime_ns < deadline,
                    "native child EXEC acknowledgement missed original admission")?;
                self.admission()?;
                return Ok(ExecAcknowledgement { operation: self.containment.owner().operation_sha256(),
                    observed_boottime_ns });
            }
            self.drain_output()?;
            let _ = poll(self.leader.pidfd.as_fd(), libc::POLLIN, deadline)?;
        }
    }

    fn drain_output(&self) -> Result<bool, String> {
        self.output.try_borrow_mut().map_err(|_| "native child output owner already borrowed")?
            .drain([self.stdout.as_fd(), self.stderr.as_fd()], &self.output_remaining)
    }

    pub(super) fn terminate(&self) -> Result<ChildCleanup, String> {
        self.stopped.set(true);
        let first = !self.cleanup_attempted.replace(true);
        // None of these emergency attempts depend on renewed admission, the
        // guardian being alive or a timely wall/boot clock. Each actor has its
        // own one-shot latch; there is no global exactly-once-kill assertion.
        let leaf_kill = self.containment.attempt_emergency_kill();
        self.leader.emergency_kill();
        require(first, "native child cleanup has already been consumed")?;
        let leader = self.leader.reap(self.containment.owner().cleanup_boottime_ns());
        let empty = self.containment.kill_and_wait_empty();
        // Perform both observations before propagating errors. Empty cgroup
        // and exact leader reap are separate facts; neither substitutes for the other.
        leaf_kill?;
        let (code, status) = leader?;
        let empty = empty?;
        // Serialize selected initialized waitid results and actual retained
        // pidfd identity, never padding from a raw siginfo_t or caller status.
        let original = catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(
            &serde_json::json!({"apiVersion":"catchplate.nativeLeaderReapOriginal/v1",
                "operationSha256":format!("sha256:{}", self.operation_sha256().iter()
                    .map(|byte| format!("{byte:02x}")).collect::<String>()),
                "leaderPid":self.leader.pid, "pidfdDevice":self.leader.identity.device,
                "pidfdInode":self.leader.identity.inode, "code":code, "status":status}))?;
        Ok(ChildCleanup { code, status, empty, original })
    }

    pub(super) fn retirement_requested(&self) -> bool {
        self.containment.owner().constraints().containment.retirement_profile.as_deref()
            == Some("remove-empty-owned-leaf-v1")
    }

    pub(super) fn operation_sha256(&self) -> [u8; 32] { self.containment.owner().operation_sha256() }
    pub(super) fn cleanup_boottime_ns(&self) -> u64 { self.containment.owner().cleanup_boottime_ns() }
    pub(super) fn outcome_requested(&self) -> bool {
        self.containment.owner().constraints().journal.outcome_profile.as_deref()
            == Some(super::start_authority::OUTCOME_PROFILE)
    }
    pub(super) fn outcome_permit(&self) -> Result<&super::start_reservation::StartPermit, String> {
        require(self.leader.reaped.get() && self.network.is_none() && self.namespaces.is_empty(),
            "native outcome retains a live child or child network pins")?;
        self.containment.outcome_permit()
    }

    /// Requires exclusive access: no live PreparedNetwork/NetworkReady borrow
    /// can coexist. Guardian completion is checked by the owning composition.
    pub(super) fn release_network_pins(&mut self) -> Result<NetworkPinsReleased, String> {
        require(self.retirement_requested() && self.cleanup_attempted.get() && self.leader.reaped.get()
            && self.network.is_some() && self.namespaces.len() == 5,
            "native child pin retirement lacks its exact one-use cleanup")?;
        self.containment.check_retirement()?;
        for namespace in &self.namespaces { namespace.check_descriptor()?; }
        let namespace = self.network_namespace()?;
        self.network_originals()?.check(namespace.fd.as_fd())?;
        let result = NetworkPinsReleased { operation: self.operation_sha256(),
            namespace: (namespace.identity.device, namespace.identity.inode), deadline: self.cleanup_boottime_ns() };
        // All duplicate backend/socket pins must have dropped before this
        // exclusive method is reachable. Close sockets before namespace FDs.
        drop(self.network.take());
        drop(self.application_listener.take());
        self.namespaces.clear();
        self.containment.check_retirement()?;
        Ok(result)
    }

    pub(super) fn retire_containment(&self) -> Result<super::containment::CgroupRemoval, String> {
        require(self.network.is_none() && self.application_listener.is_none() && self.namespaces.is_empty() && self.leader.reaped.get(),
            "native child retirement still holds network namespace pins")?;
        self.containment.retire()
    }
}

impl Drop for BlockedChild {
    fn drop(&mut self) {
        let _ = self.containment.attempt_emergency_kill();
        self.leader.emergency_kill();
    }
}

/// Sealed borrow, checked again by Guardian::arm/require_child. No field or
/// generic FD constructor is exported. These are actual source-created owners.
pub(super) struct GuardianBorrow<'child> { child: &'child BlockedChild }
impl GuardianBorrow<'_> {
    pub(super) fn check(&self) -> Result<(), String> { self.child.check() }
    pub(super) fn begin_guardian(&self) -> Result<(), String> {
        self.check()?;
        require(!self.child.guardian_attempted.replace(true),
            "native child guardian creation was already attempted")
    }
    pub(super) fn leader_pidfd(&self) -> BorrowedFd<'_> { self.child.leader.pidfd.as_fd() }
    pub(super) fn launcher_pidfd(&self) -> BorrowedFd<'_> { self.child.launcher.as_fd() }
    pub(super) fn cleanup(&self) -> ContainmentCleanupBorrow<'_> {
        // Private construction remains in containment; this access is only
        // possible after guardian_borrow/check admitted the actual owner.
        self.child.containment.cleanup_view()
    }
    pub(super) fn operation_sha256(&self) -> [u8; 32] {
        self.child.containment.owner().operation_sha256()
    }
    pub(super) fn stop_boottime_ns(&self) -> u64 { self.child.containment.owner().stop_boottime_ns() }
    pub(super) fn cleanup_boottime_ns(&self) -> u64 { self.child.containment.owner().cleanup_boottime_ns() }
    pub(super) fn admission_deadline_boottime_ns(&self) -> Result<u64, String> {
        self.child.containment.owner().clock().boottime_deadline()
    }
}

/// Private, data-only positive observation. No serializable object grants start rights.
struct ExecAcknowledgement { operation: [u8; 32], observed_boottime_ns: u64 }

pub(super) struct ChildCleanup { code: i32, status: i32, empty: LeafEmpty, original: Vec<u8> }
impl ChildCleanup {
    pub(super) fn leader_reaped(&self) -> bool { true }
    pub(super) fn leader_status(&self) -> i32 { self.status }
    pub(super) fn leader_code(&self) -> i32 { self.code }
    pub(super) fn leaf_empty(&self) -> &LeafEmpty { &self.empty }
    pub(super) fn original(&self) -> &[u8] { &self.original }
}

/// Non-Clone sealed reference to this exact executable child. It never accepts
/// a supplied socket, namespace, PID, successful verdict or diagnostic owner.
pub(in super::super) struct ChildNetworkBorrow<'child> { child: &'child BlockedChild }
/// Sealed, one-use post-cleanup data. It is never accepted from capture JSON.
pub(in super::super) struct NetworkPinsReleased {
    operation: [u8; 32], namespace: (u64, u64), deadline: u64,
}
impl NetworkPinsReleased {
    pub(in super::super) fn require(&self, operation: [u8; 32], namespace: (u64, u64), deadline: u64)
        -> Result<(), String> {
        require(self.operation == operation && self.namespace == namespace && self.deadline == deadline,
            "cleanup observation belongs to a different released child")
    }
}
impl ChildNetworkBorrow<'_> {
    pub(in super::super) fn retirement_requested(&self) -> bool { self.child.retirement_requested() }
    pub(in super::super) fn cleanup_boottime_ns(&self) -> u64 { self.child.cleanup_boottime_ns() }
    pub(in super::super) fn check(&self) -> Result<(), String> { self.child.check() }
    pub(in super::super) fn check_running(&self) -> Result<(), String> {
        self.child.check_continuation()?;
        self.child.network_originals()?.check(self.child.network_namespace()?.fd.as_fd())?;
        self.host_namespace()?;
        self.child.check_continuation()
    }
    pub(in super::super) fn require_child(&self, child: &BlockedChild) -> Result<(), String> {
        require(std::ptr::eq(self.child, child), "network permission belongs to another executable child")?;
        self.check()
    }
    pub(in super::super) fn begin_network(&self) -> Result<(), String> {
        self.check()?;
        require(!self.child.network_attempted.replace(true), "native child network attempt already consumed")
    }
    pub(in super::super) fn kernel_identity(&self) -> [u64; 3] {
        [self.child.leader.identity.device, self.child.leader.identity.inode, self.child.leader.pid as u64]
    }
    pub(in super::super) fn operation_sha256(&self) -> [u8; 32] {
        self.child.containment.owner().operation_sha256()
    }
    pub(in super::super) fn parents(&self) -> &std::sync::Arc<super::super::egress::ExecutionParents> {
        self.child.containment.owner().parents()
    }
    pub(in super::super) fn deadline(&self) -> Result<std::time::Instant, String> {
        self.check()?;
        self.child.containment.owner().clock().instant_deadline()
    }
    pub(in super::super) fn stop_boottime_ns(&self) -> u64 { self.child.stop_boottime_ns() }
    pub(in super::super) fn filter(&self) -> Result<std::fs::File, String> {
        self.check()?;
        let result = self.child.network_originals()?.filter(self.child.network_namespace()?.fd.as_fd())?;
        self.check()?;
        Ok(result)
    }
    pub(in super::super) fn route(&self) -> Result<std::fs::File, String> {
        self.check()?;
        let result = self.child.network_originals()?.route(self.child.network_namespace()?.fd.as_fd())?;
        self.check()?;
        Ok(result)
    }
    pub(in super::super) fn child_namespace(&self) -> Result<std::fs::File, String> {
        child_network::duplicate(self.child.network_namespace()?.fd.as_fd())
    }
    pub(in super::super) fn host_namespace(&self) -> Result<std::fs::File, String> {
        let namespace = Namespace::from_pidfd(self.child.launcher.as_fd(), 0xff04, libc::CLONE_NEWNET)?;
        let signed = &self.child.containment.owner().constraints().network_owner;
        require((namespace.identity.device, namespace.identity.inode)
            == (signed.namespace_device, signed.namespace_inode),
            "native executable launcher network namespace changed")?;
        child_network::duplicate(namespace.fd.as_fd())
    }
    pub(in super::super) fn filter_identity(&self) -> Result<(u64, u64, u32, u64, u64), String> {
        let namespace = self.child.network_namespace()?;
        let (device, inode, port) = self.child.network_originals()?.filter_identity();
        Ok((namespace.identity.device, namespace.identity.inode, port, device, inode))
    }
    pub(in super::super) fn route_identity(&self) -> Result<(u64, u64, u32), String> {
        Ok(self.child.network_originals()?.route_identity())
    }
}
