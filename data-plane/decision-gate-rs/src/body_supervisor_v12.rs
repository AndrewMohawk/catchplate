//! Fixed PID1 payload supervisor, not a runtime observer or result publisher.
//!
//! The controller independently admits the private Docker PID mode and owns
//! the original context bind. Local PID/proc checks are not global host proof.
//! Only a retained, measured ELF descriptor is executed; scripts require their
//! explicit signed interpreter command. Stdout/stderr belong only to that
//! payload. Failure is communicated solely by a nonzero supervisor exit code.

use crate::plan_protocol::body_launch_contract_v12::{
    effective_argv, BodyLaunchContextV12, BodyLaunchReleaseV12, CONTEXT_DIRECTORY, CONTEXT_PATH,
    MAX_CONTEXT_BYTES_V12, MAX_RELEASE_BYTES_V12, RELEASE_PATH, SUPERVISOR_EXECUTABLE,
};
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use crate::runtime_evidence::{verify_static_executable_fd_bounded, ExecutableRole};
use sha2::{Digest as ShaDigest, Sha256};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_IN_ROOT: u64 = 0x10;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
const CLEANUP_NS: u64 = 2_000_000_000;
const TERM_GRACE_NS: u64 = 100_000_000;
const FORWARDED_SIGNALS: &[libc::c_int] = &[
    libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGQUIT, libc::SIGHUP,
    libc::SIGUSR1, libc::SIGUSR2, libc::SIGWINCH, libc::SIGCONT, libc::SIGTSTP,
    libc::SIGTTIN, libc::SIGTTOU, libc::SIGALRM, libc::SIGPIPE,
];
static STARTED: AtomicBool = AtomicBool::new(false);
static EARLY_SIGNAL: AtomicBool = AtomicBool::new(false);

fn invalid(message: &'static str) -> PlanProtocolError {
    PlanProtocolError::Invalid(message)
}

fn now() -> PlanResult<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("body supervisor clock is invalid"));
    }
    (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("body supervisor clock overflows"))
}

fn live(deadline: u64) -> PlanResult<()> {
    if now()? >= deadline { return Err(invalid("body original deadline expired")); }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64,
    size: i64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}

fn identity(fd: RawFd) -> PlanResult<Identity> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Identity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink,
        size: value.st_size, mtime: value.st_mtime, mtime_ns: value.st_mtime_nsec,
        ctime: value.st_ctime, ctime_ns: value.st_ctime_nsec })
}

fn readonly(fd: RawFd) -> PlanResult<()> {
    let mut value: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.f_flag & libc::ST_RDONLY == 0 {
        return Err(invalid("body protected input mount is writable"));
    }
    Ok(())
}

fn root_owned(value: &Identity) -> PlanResult<()> {
    if value.uid != 0 || value.mode & 0o022 != 0 || value.links == 0 {
        return Err(invalid("body protected input is not root-owned nonwritable custody"));
    }
    Ok(())
}

#[repr(C)]
struct OpenHow { flags: u64, mode: u64, resolve: u64 }

fn open_rooted(root: RawFd, path: &str, directory: bool, no_symlinks: bool)
    -> PlanResult<OwnedFd> {
    if !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(invalid("body input path is not absolute"));
    }
    let relative = if path == "/" { "." } else { &path[1..] };
    let name = CString::new(relative).map_err(|_| invalid("body path contains NUL"))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK
            | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
            | if no_symlinks { RESOLVE_NO_SYMLINKS } else { 0 },
    };
    let raw = unsafe { libc::syscall(libc::SYS_openat2, root, name.as_ptr(),
        &how, std::mem::size_of::<OpenHow>()) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

fn open_kernel(path: &std::ffi::CStr, directory: bool) -> PlanResult<OwnedFd> {
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC
        | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 }) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn protected_directory(root: RawFd, path: &str) -> PlanResult<OwnedFd> {
    let directory = open_rooted(root, path, true, true)?;
    root_owned(&identity(directory.as_raw_fd())?)?;
    readonly(directory.as_raw_fd())?;
    Ok(directory)
}

fn read_regular(fd: RawFd, maximum: usize, deadline: Option<u64>) -> PlanResult<Vec<u8>> {
    if let Some(deadline) = deadline { live(deadline)?; }
    let before = identity(fd)?;
    root_owned(&before)?;
    readonly(fd)?;
    if before.mode & libc::S_IFMT != libc::S_IFREG || before.links != 1
        || before.size <= 0 || before.size as u64 > maximum as u64 {
        return Err(invalid("body context is not a bounded original regular file"));
    }
    let mut bytes = vec![0u8; before.size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        if let Some(deadline) = deadline { live(deadline)?; }
        let count = unsafe { libc::pread(fd, bytes[offset..].as_mut_ptr().cast(),
            (bytes.len() - offset).min(CHUNK_BYTES), offset as libc::off_t) };
        if let Some(deadline) = deadline { live(deadline)?; }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { return Err(invalid("body context original was truncated")); }
        offset += count as usize;
    }
    let mut extra = 0u8;
    if let Some(deadline) = deadline { live(deadline)?; }
    if unsafe { libc::pread(fd, (&mut extra as *mut u8).cast(), 1, offset as libc::off_t) } != 0
        || identity(fd)? != before {
        return Err(invalid("body context original changed while read"));
    }
    if let Some(deadline) = deadline { live(deadline)?; }
    Ok(bytes)
}

fn require_no_pending_signal(signals: RawFd) -> PlanResult<()> {
    let mut pending: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let count = unsafe { libc::read(signals,
        (&mut pending as *mut libc::signalfd_siginfo).cast(),
        std::mem::size_of::<libc::signalfd_siginfo>()) };
    if count >= 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock
        || EARLY_SIGNAL.load(Ordering::Relaxed) {
        return Err(invalid("body launch received a signal before child creation"));
    }
    Ok(())
}

fn own_start_ticks(deadline: u64) -> PlanResult<u64> {
    live(deadline)?;
    if unsafe { libc::getpid() } != 1 {
        return Err(invalid("body release target is not namespace PID1"));
    }
    let stat = open_kernel(c"/proc/self/stat", false)?;
    let mut bytes = [0u8; 16 * 1024];
    let count = loop {
        live(deadline)?;
        let count = unsafe { libc::pread(stat.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        live(deadline)?;
        if count >= 0 { break count as usize; }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
    };
    if count == 0 || count == bytes.len() {
        return Err(invalid("body release target stat is absent or excessive"));
    }
    let text = std::str::from_utf8(&bytes[..count])
        .map_err(|_| invalid("body release target stat is not UTF8"))?;
    let opening = text.find('(').ok_or_else(|| invalid("body target stat lacks its command"))?;
    let closing = text.rfind(')').ok_or_else(|| invalid("body target stat command is unterminated"))?;
    if opening >= closing || text[..opening].trim() != "1" {
        return Err(invalid("body target stat does not name namespace PID1"));
    }
    // The suffix starts at field3 (state); field22 is therefore index19.
    // Parentheses and spaces inside comm cannot shift this original position.
    let field = text[closing + 1..].split_ascii_whitespace().nth(19)
        .ok_or_else(|| invalid("body target stat lacks original start ticks"))?;
    if field.is_empty() || field.len() > 20 || field.starts_with('0')
        || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("body target start ticks are not canonical and positive"));
    }
    let ticks = field.parse::<u64>().map_err(|_| invalid("body target start ticks overflow"))?;
    live(deadline)?;
    Ok(ticks)
}

fn mount_id(fd: RawFd, deadline: u64) -> PlanResult<u64> {
    live(deadline)?;
    let path = CString::new(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|_| invalid("body launch descriptor path is invalid"))?;
    let info = open_kernel(&path, false)?;
    let mut bytes = [0u8; 4096];
    let count = unsafe { libc::pread(info.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    live(deadline)?;
    if count <= 0 || count as usize == bytes.len() {
        return Err(invalid("body launch descriptor metadata is absent or excessive"));
    }
    let text = std::str::from_utf8(&bytes[..count as usize])
        .map_err(|_| invalid("body launch descriptor metadata is not UTF8"))?;
    let mut matches = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let value = matches.next().ok_or_else(|| invalid("body launch descriptor lacks mount identity"))?.trim();
    if matches.next().is_some() || value.is_empty() || value.len() > 20
        || value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("body launch mount identity is not canonical and positive"));
    }
    value.parse::<u64>().map_err(|_| invalid("body launch mount identity overflows"))
}

fn verify_launch_anchor(root: RawFd, launch: RawFd, expected: &Identity,
    expected_mount: u64, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let named = protected_directory(root, CONTEXT_DIRECTORY)?;
    for fd in [launch, named.as_raw_fd()] {
        let actual = identity(fd)?;
        if actual.device != expected.device || actual.inode != expected.inode
            || actual.uid != 0 || actual.gid != 0
            || actual.mode & libc::S_IFMT != libc::S_IFDIR
            || actual.mode & 0o7777 != 0o555 || actual.links == 0
            || mount_id(fd, deadline)? != expected_mount {
            return Err(invalid("body release launch-directory custody changed"));
        }
        readonly(fd)?;
    }
    // Publishing release.json legitimately changes directory timestamps and
    // entries. Those are not used as an immutable anchor for this gate.
    live(deadline)
}

/// Wait only for root's source-fixed launch permission after target custody.
/// This is neither independent observer approval nor continuous mapping proof.
fn wait_for_release(context: &BodyLaunchContextV12, root: RawFd, launch: RawFd, signals: RawFd,
    deadline: u64) -> PlanResult<u64> {
    let start_ticks = own_start_ticks(deadline)?;
    let directory_identity = identity(launch)?;
    let directory_mount = mount_id(launch, deadline)?;
    loop {
        live(deadline)?;
        require_no_pending_signal(signals)?;
        verify_launch_anchor(root, launch, &directory_identity, directory_mount, deadline)?;
        match open_rooted(root, RELEASE_PATH, false, true) {
            Ok(release_fd) => {
                live(deadline)?;
                let before = identity(release_fd.as_raw_fd())?;
                if before.uid != 0 || before.gid != 0 || before.mode & 0o7777 != 0o444 {
                    return Err(invalid("body release is not the fixed root-owned readonly original"));
                }
                let bytes = read_regular(release_fd.as_raw_fd(), MAX_RELEASE_BYTES_V12, Some(deadline))?;
                let release = BodyLaunchReleaseV12::parse_original(&bytes)?;
                release.validate_for(context)?;
                if release.namespace_target_pid != unsafe { libc::getpid() } as u32
                    || release.target_start_time_ticks != start_ticks
                    || own_start_ticks(deadline)? != start_ticks
                    || identity(release_fd.as_raw_fd())? != before {
                    return Err(invalid("body release differs from this actual retained supervisor"));
                }
                // host_target_pid belongs to root's acquired host view. This
                // process does not pretend to measure that PID from inside its
                // namespace. Only the actual local PID/start ticks are joined.
                let narrowed = deadline.min(release.deadline_boottime_ns);
                live(narrowed)?;
                verify_launch_anchor(root, launch, &directory_identity, directory_mount, narrowed)?;
                require_no_pending_signal(signals)?;
                return Ok(narrowed);
            }
            Err(PlanProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Root atomically publishes the complete final name. Never learn a
        // path from directory contents or treat an in-progress temporary file
        // as release authority; only absence of release.json is retryable.
        let sampled = now()?;
        if sampled >= deadline { return Err(invalid("body acquisition release deadline expired")); }
        let timeout = ((deadline - sampled) / 1_000_000).min(10) as i32;
        let mut descriptor = libc::pollfd { fd: signals, events: libc::POLLIN, revents: 0 };
        let waited = unsafe { libc::poll(&mut descriptor, 1, timeout.max(1)) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(invalid("body release signal channel is unavailable"));
        }
        live(deadline)?;
    }
}

fn measure_command(fd: RawFd, expected: &Digest, deadline: u64) -> PlanResult<Identity> {
    live(deadline)?;
    let before = identity(fd)?;
    root_owned(&before)?;
    readonly(fd)?;
    if before.mode & libc::S_IFMT != libc::S_IFREG || before.links != 1
        || before.mode & 0o111 == 0 || before.mode & 0o6000 != 0
        || before.size < 4 || before.size as u64 > MAX_EXECUTABLE_BYTES {
        return Err(invalid("body command is not a bounded readonly executable"));
    }
    let mut buffer = [0u8; CHUNK_BYTES];
    let mut offset = 0u64;
    let mut hasher = Sha256::new();
    while offset < before.size as u64 {
        live(deadline)?;
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(),
            (before.size as u64 - offset).min(CHUNK_BYTES as u64) as usize,
            offset as libc::off_t) };
        live(deadline)?;
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { return Err(invalid("body executable was truncated")); }
        if offset == 0 && (count < 4 || &buffer[..4] != b"\x7fELF") {
            return Err(invalid("body scripts require an explicit signed ELF interpreter"));
        }
        hasher.update(&buffer[..count as usize]);
        offset += count as u64;
    }
    let mut extra = 0u8;
    let eof = unsafe { libc::pread(fd, (&mut extra as *mut u8).cast(), 1, offset as libc::off_t) };
    let digest: Digest = hasher.finalize().into();
    if eof != 0 || &digest != expected || identity(fd)? != before {
        return Err(invalid("body executable differs from its original measured identity"));
    }
    live(deadline)?;
    Ok(before)
}

fn process_admission(context: &BodyLaunchContextV12) -> PlanResult<()> {
    let bounds = &context.runner.execution_bounds;
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    if unsafe { libc::getpid() } != 1 || unsafe { libc::getppid() } != 0
        || unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        || [real_uid, effective_uid, saved_uid].iter().any(|uid| *uid != bounds.user_uid)
        || [real_gid, effective_gid, saved_gid].iter().any(|gid| *gid != bounds.user_gid)
        || bounds.user_uid == 0 || bounds.user_gid == 0 {
        return Err(invalid("body supervisor is not the admitted nonroot namespace init"));
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut group = 0;
    if count < 0 || count > 1 || (count == 1
        && (unsafe { libc::getgroups(1, &mut group) } != 1 || group != bounds.user_gid)) {
        return Err(invalid("body supervisor inherited additional groups"));
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(invalid("body supervisor lacks no-new-privileges enforcement"));
    }
    let proc = open_kernel(c"/proc", true)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc.as_raw_fd(), &mut filesystem) } != 0
        || filesystem.f_type != PROC_SUPER_MAGIC {
        return Err(invalid("body supervisor process view is not procfs"));
    }
    let own_ns = open_kernel(c"/proc/self/ns/pid", false)?;
    let init_ns = open_kernel(c"/proc/1/ns/pid", false)?;
    let own = identity(own_ns.as_raw_fd())?;
    let init = identity(init_ns.as_raw_fd())?;
    if (own.device, own.inode) != (init.device, init.inode) || own.inode == 0 {
        return Err(invalid("body supervisor proc view differs from its PID namespace"));
    }
    let status = open_kernel(c"/proc/self/status", false)?;
    let mut buffer = [0u8; CHUNK_BYTES];
    let count = unsafe { libc::pread(status.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if count <= 0 || count as usize == buffer.len() {
        return Err(invalid("body supervisor status is absent or excessive"));
    }
    let status = std::str::from_utf8(&buffer[..count as usize])
        .map_err(|_| invalid("body supervisor status is not UTF8"))?;
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let mut values = status.lines().filter_map(|line| line.strip_prefix(key));
        let value = values.next().ok_or_else(|| invalid("body capability state is absent"))?;
        if values.next().is_some() || u64::from_str_radix(value.trim(), 16).ok() != Some(0) {
            return Err(invalid("body supervisor retains Linux capabilities"));
        }
    }
    live(context.deadline_boottime_ns)
}

extern "C" fn signal_handler(_: libc::c_int) {
    EARLY_SIGNAL.store(true, Ordering::Relaxed);
}

fn signal_channel() -> PlanResult<OwnedFd> {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut mask); }
    for &signal in FORWARDED_SIGNALS {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal_handler as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask); }
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
            || unsafe { libc::sigaddset(&mut mask, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    // Namespace PID1 needs real handlers before blocked signals can be queued
    // for signalfd. A signal delivered during installation aborts before fork.
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let raw = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn signal_target(target: libc::pid_t, signal: libc::c_int) -> PlanResult<()> {
    if unsafe { libc::kill(target, signal) } == 0 { return Ok(()); }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) { return Ok(()); }
    Err(error.into())
}

fn forward_signal(scope: &ChildScope, signal: libc::c_int) -> PlanResult<()> {
    if unsafe { libc::kill(-scope.leader, signal) } == 0 { return Ok(()); }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ESRCH) { return Err(error.into()); }
    // The child may not yet have established its process group. Deliver once
    // to the direct child in that case, never twice to an established leader.
    if scope.status.is_none() { signal_target(scope.leader, signal)?; }
    Ok(())
}

struct ChildScope { leader: libc::pid_t, status: Option<i32>, armed: bool }

impl Drop for ChildScope {
    fn drop(&mut self) {
        if self.armed {
            // Admission established this process as the namespace PID1. This
            // last-resort kill is local to that namespace, not host-wide.
            unsafe { libc::kill(-1, libc::SIGKILL); }
        }
    }
}

fn reap(scope: &mut ChildScope) -> PlanResult<bool> {
    for _ in 0..256 {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            if pid == scope.leader {
                scope.status = Some(if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) }
                    else if libc::WIFSIGNALED(status) { 128 + libc::WTERMSIG(status) }
                    else { return Err(invalid("body child has an unsupported terminal status")); });
            }
        } else if pid == 0 { return Ok(true); }
        else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            if error.raw_os_error() == Some(libc::ECHILD) { return Ok(false); }
            return Err(error.into());
        }
    }
    Ok(true)
}

fn pause_ms(milliseconds: i32) -> PlanResult<()> {
    if unsafe { libc::poll(std::ptr::null_mut(), 0, milliseconds) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
    }
    Ok(())
}

fn cleanup(scope: &mut ChildScope, original_deadline: u64) -> PlanResult<()> {
    let start = now()?;
    let end = start.checked_add(CLEANUP_NS).ok_or_else(|| invalid("body cleanup clock overflows"))?;
    let grace = start.saturating_add(TERM_GRACE_NS).min(original_deadline);
    signal_target(-1, if start < grace { libc::SIGTERM } else { libc::SIGKILL })?;
    loop {
        if !reap(scope)? { scope.armed = false; return Ok(()); }
        let sampled = now()?;
        if sampled >= end { return Err(invalid("body descendants did not reap within cleanup bound")); }
        if sampled >= grace { signal_target(-1, libc::SIGKILL)?; }
        pause_ms(10)?;
    }
}

fn supervise(scope: &mut ChildScope, signals: RawFd, errors: RawFd, deadline: u64)
    -> PlanResult<i32> {
    let mut exec_observed = false;
    loop {
        reap(scope)?;
        let sampled = now()?;
        if sampled >= deadline { return Ok(124); }
        let mut errno_bytes = [0u8; std::mem::size_of::<libc::c_int>()];
        if !exec_observed {
            let count = unsafe { libc::read(errors, errno_bytes.as_mut_ptr().cast(), errno_bytes.len()) };
            if count == 0 { exec_observed = true; }
            else if count > 0 { return Err(invalid("body descriptor-pinned exec failed")); }
            else {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::WouldBlock
                    && error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
            }
        }
        if exec_observed {
            if let Some(status) = scope.status { return Ok(status); }
        }
        for _ in 0..32 {
            let mut event: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let count = unsafe { libc::read(signals, (&mut event as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of::<libc::signalfd_siginfo>()) };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock { break; }
                if error.kind() == std::io::ErrorKind::Interrupted { continue; }
                return Err(error.into());
            }
            if count as usize != std::mem::size_of::<libc::signalfd_siginfo>() {
                return Err(invalid("body signal channel lost an exact event"));
            }
            let signal = event.ssi_signo as libc::c_int;
            if signal != libc::SIGCHLD && FORWARDED_SIGNALS.contains(&signal) {
                forward_signal(scope, signal)?;
            }
        }
        let mut descriptors = [
            libc::pollfd { fd: signals, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if exec_observed { -1 } else { errors }, events: libc::POLLIN, revents: 0 },
        ];
        let remaining = deadline.saturating_sub(now()?);
        let timeout = ((remaining / 1_000_000).min(25) as i32).max(1);
        if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, timeout) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
        }
    }
}

unsafe fn child_failure(error_fd: RawFd) -> ! {
    let error = *libc::__errno_location();
    libc::write(error_fd, (&error as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>());
    libc::_exit(127)
}

/// Fixed argv/context only. No signer, output publication or observer claims.
pub fn run_body_supervisor_v12_cli() -> PlanResult<i32> {
    if STARTED.swap(true, Ordering::SeqCst) {
        return Err(invalid("body supervisor cannot be initialized twice"));
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 2 || arguments[0] != SUPERVISOR_EXECUTABLE
        || arguments[1] != CONTEXT_PATH {
        return Err(invalid("body supervisor invocation is not source-fixed"));
    }
    // Engine-generated PATH/HOSTNAME are not authority and are never read or
    // inherited by the payload: exec receives only the context's exact envp.
    if unsafe { libc::getpid() } != 1 {
        return Err(invalid("body supervisor must be the container namespace init"));
    }
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let signals = signal_channel()?;
    let root = open_kernel(c"/", true)?;
    root_owned(&identity(root.as_raw_fd())?)?;
    readonly(root.as_raw_fd())?;
    let launch_directory = protected_directory(root.as_raw_fd(), CONTEXT_DIRECTORY)?;
    let context_fd = open_rooted(root.as_raw_fd(), CONTEXT_PATH, false, true)?;
    let original = read_regular(context_fd.as_raw_fd(), MAX_CONTEXT_BYTES_V12, None)?;
    let context = BodyLaunchContextV12::parse_original(&original)?;
    process_admission(&context)?;
    let opening = now()?;
    let deadline = opening.checked_add(context.body.command.timeout_ns)
        .ok_or_else(|| invalid("body child timeout overflows"))?
        .min(context.deadline_boottime_ns);
    live(deadline)?;
    let self_executable = open_kernel(c"/proc/self/exe", false)?;
    let measured = verify_static_executable_fd_bounded(self_executable.as_raw_fd(),
        ExecutableRole::ControllerOwnedRunner, MAX_EXECUTABLE_BYTES, deadline)?;
    if measured.content_sha256 != context.runner.runtime_executable_sha256 {
        return Err(invalid("body supervisor differs from the admitted static runner"));
    }
    let mounts = &context.runner.mount_policy;
    let _source = protected_directory(root.as_raw_fd(), &mounts.source_destination)?;
    let _artifacts = match protected_directory(root.as_raw_fd(), &mounts.artifact_destination) {
        Ok(directory) => Some(directory),
        Err(PlanProtocolError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let command = &context.body.command;
    let executable = open_rooted(root.as_raw_fd(), &command.executable, false, false)?;
    let executable_identity = measure_command(executable.as_raw_fd(), &command.executable_sha256, deadline)?;
    let cwd = open_rooted(root.as_raw_fd(), &command.cwd, true, false)?;
    let deadline = wait_for_release(&context, root.as_raw_fd(), launch_directory.as_raw_fd(),
        signals.as_raw_fd(), deadline)?;
    let arguments = effective_argv(command).into_iter().map(CString::new)
        .collect::<Result<Vec<_>, _>>().map_err(|_| invalid("body argv contains NUL"))?;
    let environment = command.environment.iter().map(|entry|
        CString::new(format!("{}={}", entry.name, entry.value)))
        .collect::<Result<Vec<_>, _>>().map_err(|_| invalid("body environment contains NUL"))?;
    let argv: Vec<_> = arguments.iter().map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null())).collect();
    let envp: Vec<_> = environment.iter().map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null())).collect();
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let error_read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let error_write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    live(deadline)?;
    require_no_pending_signal(signals.as_raw_fd())?;
    if identity(executable.as_raw_fd())? != executable_identity {
        return Err(invalid("body launch was interrupted or its executable changed"));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 { return Err(std::io::Error::last_os_error().into()); }
    if pid == 0 {
        // This source-fixed single-threaded owner preallocated argv/environment.
        // The child performs only libc calls until exec or _exit; it writes no
        // diagnostics into the payload streams.
        unsafe {
            libc::close(error_read.as_raw_fd());
            if libc::setpgid(0, 0) != 0 || libc::fchdir(cwd.as_raw_fd()) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                child_failure(error_write.as_raw_fd());
            }
            for signal in 1..=64 {
                if signal == libc::SIGKILL || signal == libc::SIGSTOP { continue; }
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                    // libc reserves internal real-time signals that cannot be
                    // changed through sigaction. Every application-catchable
                    // Linux signal must otherwise return to its default.
                    if *libc::__errno_location() != libc::EINVAL {
                        child_failure(error_write.as_raw_fd());
                    }
                }
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
                || libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                child_failure(error_write.as_raw_fd());
            }
            libc::umask(0o077);
            let mut sampled: libc::timespec = std::mem::zeroed();
            if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sampled) != 0 {
                child_failure(error_write.as_raw_fd());
            }
            if sampled.tv_sec < 0 || sampled.tv_nsec < 0 || sampled.tv_nsec >= 1_000_000_000
                || sampled.tv_sec as u128 * 1_000_000_000 + sampled.tv_nsec as u128 >= deadline as u128 {
                *libc::__errno_location() = libc::ETIMEDOUT;
                child_failure(error_write.as_raw_fd());
            }
            libc::syscall(libc::SYS_execveat, executable.as_raw_fd(), c"".as_ptr(),
                argv.as_ptr(), envp.as_ptr(), libc::AT_EMPTY_PATH);
            child_failure(error_write.as_raw_fd());
        }
    }
    drop(error_write);
    let mut scope = ChildScope { leader: pid, status: None, armed: true };
    let outcome = supervise(&mut scope, signals.as_raw_fd(), error_read.as_raw_fd(), deadline);
    let cleaned = cleanup(&mut scope, deadline);
    cleaned?;
    outcome
}
