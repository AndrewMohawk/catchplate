//! Source-owned, never-executed child in a newly created network namespace.
//!
//! Trusted-host-local only. No PID/path assertion, namespace membership scan,
//! arbitrary command, start/exec/SIGCONT, or existing-namespace attachment API.
//! The selected executable is retained but NEVER executed by this profile.
//! Linux ABI references: linux/{sched,nsfs,sockios,wait}.h and man-pages
//! clone(2), wait(2), PR_SET_PDEATHSIG(2const). Missing kernel support refuses.

use super::{authority::Authorization, creation_reservation::CreationPermit, PrecreationOwner};
use super::super::{json, originals::{ArtifactV1, HeldOriginal}, OriginalClock};
use catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROFILE: &str = "native-egress-create-new-workload-v1";
const MANIFEST_SCHEMA: &str = "catchplate.nativeEgressLaunchManifest/v1";
const EXECUTION_PROFILE: &str = "native-egress-new-execution-v1";
const EXECUTION_MANIFEST_SCHEMA: &str = "catchplate.nativeEgressLaunchManifest/v2";
const MAX_MANIFEST: usize = 4096;
const MAX_EXECUTABLE: usize = 16 * 1024 * 1024;
const DIRECTORY: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;
const ORIGINAL: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const SIOCGSKNS: libc::c_ulong = 0x894c;
const P_PIDFD: libc::idtype_t = 3;
const READY: u8 = 0x57;

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native egress workload ownership refused".to_owned()) }
}

fn checked<T>(clock: &OriginalClock, operation: impl FnOnce() -> io::Result<T>)
    -> Result<T, String>
{
    clock.check()?;
    let value = operation().map_err(|_| "native egress workload observation failed")?;
    clock.check()?;
    Ok(value)
}

fn descriptor(value: RawFd) -> io::Result<File> {
    if value < 0 { Err(io::Error::last_os_error()) }
    else { Ok(unsafe { File::from_raw_fd(value) }) }
}

fn open_at(parent: RawFd, name: &str, flags: i32, clock: &OriginalClock) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| "native workload fixed name invalid")?;
    checked(clock, || descriptor(unsafe { libc::openat(parent, name.as_ptr(), flags) }))
}

type Identity = (u64, u64, u32, u32, u32);
type Fingerprint = (Identity, u64, u64, i64, i64, i64, i64);
fn identity(meta: &Metadata) -> Identity { (meta.dev(), meta.ino(), meta.mode(), meta.uid(), meta.gid()) }
fn fingerprint(meta: &Metadata) -> Fingerprint {
    (identity(meta), meta.nlink(), meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec())
}
fn metadata(file: &File, clock: &OriginalClock) -> Result<Metadata, String> {
    checked(clock, || file.metadata())
}

fn path_text(path: &Path) -> Result<&str, String> {
    let text = path.to_str().ok_or("native workload path is not ASCII")?;
    require(text.len() > 1 && text.len() <= 4096 && text.starts_with('/')
        && !text.contains('\\') && text.bytes().all(|b| (0x21..=0x7e).contains(&b)))?;
    let mut count = 0;
    for component in text[1..].split('/') {
        count += 1;
        require(!matches!(component, "" | "." | "..") && component.len() <= 255 && count <= 64)?;
    }
    Ok(text)
}

fn digest_text(raw: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(raw)) }
fn digest_pin(pin: &str) -> Result<(), String> {
    require(pin.len() == 71 && pin.starts_with("sha256:")
        && pin[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && pin[7..].bytes().any(|b| b != b'0'))
}

fn protected_directory(file: &File, clock: &OriginalClock) -> Result<(), String> {
    let meta = metadata(file, clock)?;
    require(meta.is_dir() && meta.uid() == 0 && meta.gid() == 0 && meta.mode() & 0o022 == 0)
}

fn protected_open(path: &Path, clock: &OriginalClock) -> Result<File, String> {
    let text = path_text(path)?;
    let mut parts = text[1..].split('/').peekable();
    let mut parent = open_at(libc::AT_FDCWD, "/", DIRECTORY, clock)?;
    protected_directory(&parent, clock)?;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() { return open_at(parent.as_raw_fd(), part, ORIGINAL, clock); }
        parent = open_at(parent.as_raw_fd(), part, DIRECTORY, clock)?;
        protected_directory(&parent, clock)?;
    }
    Err("native workload path has no leaf".to_owned())
}

struct Executable {
    held: HeldOriginal,
    file: File,
    path: PathBuf,
    pin: String,
    fingerprint: Fingerprint,
}

impl Executable {
    fn open(pin: ArtifactV1, clock: &OriginalClock) -> Result<Self, String> {
        digest_pin(&pin.sha256)?;
        let file = protected_open(&pin.path, clock)?;
        let meta = metadata(&file, clock)?;
        require(meta.is_file() && meta.uid() == 0 && meta.gid() == 0 && meta.mode() & 0o6022 == 0
            && meta.mode() & 0o100 != 0 && meta.len() > 0 && meta.len() <= MAX_EXECUTABLE as u64)?;
        let path = pin.path.clone();
        let expected = pin.sha256.clone();
        clock.check()?;
        let (held, bytes) = HeldOriginal::read(pin, MAX_EXECUTABLE)?;
        clock.check()?;
        require(digest_text(&bytes) == expected)?;
        let mut value = Self { held, file, path, pin: expected, fingerprint: fingerprint(&meta) };
        value.check(clock)?;
        Ok(value)
    }

    fn check(&mut self, clock: &OriginalClock) -> Result<(), String> {
        clock.check()?;
        self.held.recheck()?;
        let named = protected_open(&self.path, clock)?;
        require(fingerprint(&metadata(&named, clock)?) == self.fingerprint
            && fingerprint(&metadata(&self.file, clock)?) == self.fingerprint)?;
        clock.check()
    }
}

fn file_hash(file: &mut File, maximum: usize, clock: &OriginalClock) -> Result<String, String> {
    checked(clock, || file.seek(SeekFrom::Start(0)))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0usize;
    loop {
        let length = checked(clock, || file.read(&mut buffer))?;
        if length == 0 { break; }
        total = total.checked_add(length).ok_or("native executable length overflow")?;
        require(total <= maximum)?;
        digest.update(&buffer[..length]);
    }
    require(total > 0)?;
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn filesystem(file: &File, expected: libc::c_long, clock: &OriginalClock) -> Result<(), String> {
    let kind = checked(clock, || {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0 { Ok(stat.f_type as libc::c_long) }
        else { Err(io::Error::last_os_error()) }
    })?;
    require(kind == expected)
}

fn namespace(file: &File, clock: &OriginalClock) -> Result<Identity, String> {
    filesystem(file, NSFS_MAGIC, clock)?;
    let kind = checked(clock, || {
        let kind = unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE as _) };
        if kind >= 0 { Ok(kind) } else { Err(io::Error::last_os_error()) }
    })?;
    let meta = metadata(file, clock)?;
    require(kind == libc::CLONE_NEWNET && meta.ino() > 0 && meta.uid() == 0 && meta.gid() == 0)?;
    Ok(identity(&meta))
}

fn source_process(clock: &OriginalClock) -> Result<(u32, libc::pid_t), String> {
    clock.check()?;
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    require(pid > 0 && tid > 0 && tid <= i32::MAX as libc::c_long
        && unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0 && unsafe { libc::getegid() } == 0)?;
    clock.check()?;
    Ok((pid as u32, tid as libc::pid_t))
}

struct ProcOwner { directories: Vec<File>, identities: Vec<Identity> }
impl ProcOwner {
    fn open(pid: u32, tid: libc::pid_t, clock: &OriginalClock) -> Result<Self, String> {
        let mut directories = vec![open_at(libc::AT_FDCWD, "/", DIRECTORY, clock)?];
        protected_directory(&directories[0], clock)?;
        for part in ["proc".to_owned(), pid.to_string(), "task".to_owned(), tid.to_string(), "ns".to_owned()] {
            let next = open_at(directories.last().ok_or("native proc root absent")?.as_raw_fd(), &part, DIRECTORY, clock)?;
            protected_directory(&next, clock)?;
            filesystem(&next, PROC_MAGIC, clock)?;
            directories.push(next);
        }
        let identities = directories.iter().map(|file| metadata(file, clock).map(|meta| identity(&meta)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { directories, identities })
    }
    fn check(&self, pid: u32, tid: libc::pid_t, clock: &OriginalClock) -> Result<(), String> {
        let current = Self::open(pid, tid, clock)?;
        require(current.identities == self.identities)?;
        for (file, expected) in self.directories.iter().zip(&self.identities) {
            require(identity(&metadata(file, clock)?) == *expected)?;
        }
        Ok(())
    }
    fn net(&self, clock: &OriginalClock) -> Result<File, String> {
        // The only followed link is the fixed kernel ns magic link below
        // actual held procfs/PID/TID directories. nsfs and type are checked.
        open_at(self.directories[5].as_raw_fd(), "net", libc::O_RDONLY | libc::O_CLOEXEC, clock)
    }
    fn executable(&self, clock: &OriginalClock) -> Result<(PathBuf, File), String> {
        let mut bytes = [0u8; 4097];
        let count = checked(clock, || {
            let count = unsafe { libc::readlinkat(self.directories[2].as_raw_fd(),
                b"exe\0".as_ptr().cast(), bytes.as_mut_ptr().cast(), bytes.len()) };
            if count < 0 { Err(io::Error::last_os_error()) } else { Ok(count as usize) }
        })?;
        require(count > 0 && count <= 4096)?;
        let path = PathBuf::from(std::str::from_utf8(&bytes[..count])
            .map_err(|_| "native launcher executable path is not UTF-8")?);
        path_text(&path)?;
        let file = open_at(self.directories[2].as_raw_fd(), "exe", libc::O_RDONLY | libc::O_CLOEXEC, clock)?;
        Ok((path, file))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestExecutable { path: PathBuf, sha256: String }

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchManifest {
    api_version: String,
    profile: String,
    executable: ManifestExecutable,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
}

/// Only genuine signed-authority admission plus actual held originals creates
/// this non-Clone private-field construction input. No caller success carrier.
pub(super) struct LaunchSpec {
    clock: usize,
    pid: u32,
    tid: libc::pid_t,
    proc: ProcOwner,
    manifest: HeldOriginal,
    manifest_path: PathBuf,
    manifest_fingerprint: Fingerprint,
    executable: Executable,
    launcher: Executable,
    actual_launcher: File,
    host_namespace: File,
    host_identity: Identity,
    manual_network_policy: bool,
}

pub(super) fn admit(authorization: &Authorization, manifest_pin: &ArtifactV1,
    clock: &OriginalClock) -> Result<LaunchSpec, String>
{
    clock.check()?;
    let workload = &authorization.workload;
    require(!authorization.execution_profile && workload.profile == PROFILE && workload.namespace_mode == "create-new"
        && workload.before_completion == "never-executed"
        && workload.failure_mode == "terminate-before-start"
        && manifest_pin.sha256 == workload.launch_manifest_sha256)?;
    digest_pin(&manifest_pin.sha256)?;
    digest_pin(&workload.launcher_binary_sha256)?;
    path_text(&manifest_pin.path)?;
    let manifest_file = protected_open(&manifest_pin.path, clock)?;
    let (mut manifest, raw) = HeldOriginal::read(ArtifactV1 {
        path: manifest_pin.path.clone(), sha256: manifest_pin.sha256.clone(),
    }, MAX_MANIFEST)?;
    manifest.require_private()?;
    let manifest_fingerprint = fingerprint(&metadata(&manifest_file, clock)?);
    require(manifest_fingerprint.0.3 == 0 && raw.is_ascii())?;
    let value = json::parse(&raw, MAX_MANIFEST)?;
    require(canonical_ascii_bytes(&value)? == raw)?;
    let parsed: LaunchManifest = serde_json::from_value(value).map_err(|_| "native launch manifest is not closed")?;
    let executable_path = path_text(&parsed.executable.path)?;
    require(parsed.api_version == MANIFEST_SCHEMA && parsed.profile == PROFILE
        && parsed.environment.is_empty() && parsed.argv.len() == 1
        && parsed.argv[0] == executable_path)?;
    let (pid, tid) = source_process(clock)?;
    let proc = ProcOwner::open(pid, tid, clock)?;
    let host_namespace = proc.net(clock)?;
    let host_identity = namespace(&host_namespace, clock)?;
    require(host_identity.0 == authorization.network_owner.namespace_device
        && host_identity.1 == authorization.network_owner.namespace_inode
        && authorization.network_owner.owner_uid == 0)?;
    let executable = Executable::open(ArtifactV1 {
        path: parsed.executable.path, sha256: parsed.executable.sha256,
    }, clock)?;
    let (launcher_path, mut actual_launcher) = proc.executable(clock)?;
    let launcher = Executable::open(ArtifactV1 { path: launcher_path,
        sha256: workload.launcher_binary_sha256.clone() }, clock)?;
    require(fingerprint(&metadata(&actual_launcher, clock)?) == launcher.fingerprint
        && file_hash(&mut actual_launcher, MAX_EXECUTABLE, clock)? == launcher.pin)?;
    manifest.recheck()?;
    let mut spec = LaunchSpec { clock: clock as *const OriginalClock as usize, pid, tid, proc,
        manifest, manifest_path: manifest_pin.path.clone(), manifest_fingerprint,
        executable, launcher, actual_launcher, host_namespace, host_identity,
        manual_network_policy: authorization.child_network_policy.is_some() };
    spec.check(clock)?;
    Ok(spec)
}

impl LaunchSpec {
    pub(super) fn check(&mut self, clock: &OriginalClock) -> Result<(), String> {
        require(self.clock == clock as *const OriginalClock as usize
            && source_process(clock)? == (self.pid, self.tid))?;
        self.proc.check(self.pid, self.tid, clock)?;
        self.manifest.require_private()?;
        self.manifest.recheck()?;
        self.manifest.require_private()?;
        let manifest_named = protected_open(&self.manifest_path, clock)?;
        require(fingerprint(&metadata(&manifest_named, clock)?) == self.manifest_fingerprint)?;
        self.executable.check(clock)?;
        self.launcher.check(clock)?;
        let (path, named) = self.proc.executable(clock)?;
        require(path == self.launcher.path
            && fingerprint(&metadata(&named, clock)?) == self.launcher.fingerprint
            && fingerprint(&metadata(&self.actual_launcher, clock)?) == self.launcher.fingerprint
            && file_hash(&mut self.actual_launcher, MAX_EXECUTABLE, clock)? == self.launcher.pin)?;
        require(fingerprint(&metadata(&self.actual_launcher, clock)?) == self.launcher.fingerprint)?;
        let current_namespace = self.proc.net(clock)?;
        require(namespace(&self.host_namespace, clock)? == self.host_identity
            && namespace(&current_namespace, clock)? == self.host_identity)?;
        self.proc.check(self.pid, self.tid, clock)?;
        require(source_process(clock)? == (self.pid, self.tid))?;
        clock.check()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionLaunchManifest {
    api_version: String,
    profile: String,
    execution_manifest_sha256: String,
    launcher_binary_sha256: String,
}

/// Distinct pre-start admission. No placeholder executable and no conversion
/// into the legacy never-executed LaunchSpec or WorkloadOwner are available.
pub(super) struct ExecutionLaunchSpec {
    clock: usize,
    pid: u32,
    tid: libc::pid_t,
    proc: ProcOwner,
    manifest: HeldOriginal,
    manifest_path: PathBuf,
    manifest_fingerprint: Fingerprint,
    manifest_sha256: String,
    execution_manifest_sha256: String,
    launcher: Executable,
    actual_launcher: File,
    host_namespace: File,
    host_identity: Identity,
}

pub(super) fn admit_for_start(authorization: &Authorization, manifest_pin: &ArtifactV1,
    clock: &OriginalClock) -> Result<ExecutionLaunchSpec, String>
{
    clock.check()?;
    let workload = &authorization.workload;
    require(authorization.execution_profile && authorization.creation_journal.is_some()
        && authorization.child_network_policy.is_some()
        && workload.profile == EXECUTION_PROFILE && workload.namespace_mode == "create-new"
        && workload.before_completion == "never-executed"
        && workload.failure_mode == "terminate-before-start"
        && manifest_pin.sha256 == workload.launch_manifest_sha256)?;
    digest_pin(&manifest_pin.sha256)?;
    digest_pin(&workload.launcher_binary_sha256)?;
    path_text(&manifest_pin.path)?;
    let manifest_file = protected_open(&manifest_pin.path, clock)?;
    let (mut manifest, raw) = HeldOriginal::read(ArtifactV1 {
        path: manifest_pin.path.clone(), sha256: manifest_pin.sha256.clone(),
    }, MAX_MANIFEST)?;
    manifest.require_private()?;
    let manifest_fingerprint = fingerprint(&metadata(&manifest_file, clock)?);
    require(manifest_fingerprint.0.3 == 0 && raw.is_ascii())?;
    let value = json::parse(&raw, MAX_MANIFEST)?;
    require(canonical_ascii_bytes(&value)? == raw)?;
    let parsed: ExecutionLaunchManifest = serde_json::from_value(value)
        .map_err(|_| "native execution launch manifest is not closed")?;
    require(parsed.api_version == EXECUTION_MANIFEST_SCHEMA && parsed.profile == EXECUTION_PROFILE
        && parsed.launcher_binary_sha256 == workload.launcher_binary_sha256)?;
    digest_pin(&parsed.execution_manifest_sha256)?;
    digest_pin(&parsed.launcher_binary_sha256)?;
    let (pid, tid) = source_process(clock)?;
    let proc = ProcOwner::open(pid, tid, clock)?;
    let host_namespace = proc.net(clock)?;
    let host_identity = namespace(&host_namespace, clock)?;
    require(host_identity.0 == authorization.network_owner.namespace_device
        && host_identity.1 == authorization.network_owner.namespace_inode
        && authorization.network_owner.owner_uid == 0)?;
    let (launcher_path, mut actual_launcher) = proc.executable(clock)?;
    let launcher = Executable::open(ArtifactV1 { path: launcher_path,
        sha256: parsed.launcher_binary_sha256 }, clock)?;
    require(fingerprint(&metadata(&actual_launcher, clock)?) == launcher.fingerprint
        && file_hash(&mut actual_launcher, MAX_EXECUTABLE, clock)? == launcher.pin)?;
    manifest.recheck()?;
    let mut result = ExecutionLaunchSpec { clock: clock as *const OriginalClock as usize,
        pid, tid, proc, manifest, manifest_path: manifest_pin.path.clone(), manifest_fingerprint,
        manifest_sha256: manifest_pin.sha256.clone(), execution_manifest_sha256: parsed.execution_manifest_sha256,
        launcher, actual_launcher, host_namespace, host_identity };
    result.check(clock)?;
    Ok(result)
}

impl ExecutionLaunchSpec {
    pub(super) fn check(&mut self, clock: &OriginalClock) -> Result<(), String> {
        require(self.clock == clock as *const OriginalClock as usize
            && source_process(clock)? == (self.pid, self.tid))?;
        self.proc.check(self.pid, self.tid, clock)?;
        self.manifest.require_private()?;
        self.manifest.recheck()?;
        self.manifest.require_private()?;
        let named_manifest = protected_open(&self.manifest_path, clock)?;
        require(fingerprint(&metadata(&named_manifest, clock)?) == self.manifest_fingerprint)?;
        self.launcher.check(clock)?;
        let (path, named_launcher) = self.proc.executable(clock)?;
        require(path == self.launcher.path
            && fingerprint(&metadata(&named_launcher, clock)?) == self.launcher.fingerprint
            && fingerprint(&metadata(&self.actual_launcher, clock)?) == self.launcher.fingerprint
            && file_hash(&mut self.actual_launcher, MAX_EXECUTABLE, clock)? == self.launcher.pin)?;
        require(fingerprint(&metadata(&self.actual_launcher, clock)?) == self.launcher.fingerprint)?;
        let current_namespace = self.proc.net(clock)?;
        require(namespace(&self.host_namespace, clock)? == self.host_identity
            && namespace(&current_namespace, clock)? == self.host_identity)?;
        self.proc.check(self.pid, self.tid, clock)?;
        require(source_process(clock)? == (self.pid, self.tid))?;
        clock.check()
    }

    // These strings are original associations only, not execution permission.
    pub(super) fn manifest_sha256(&self) -> &str { &self.manifest_sha256 }
    pub(super) fn execution_manifest_sha256(&self) -> &str { &self.execution_manifest_sha256 }
    pub(super) fn launcher_binary_sha256(&self) -> &str { &self.launcher.pin }
}

#[repr(C)]
struct CloneArgs {
    flags: u64, pidfd: u64, child_tid: u64, parent_tid: u64,
    exit_signal: u64, stack: u64, stack_size: u64, tls: u64,
}

#[repr(C)]
struct Rights { header: libc::cmsghdr, descriptors: [RawFd; 3] }
const RIGHTS_LENGTH: usize = std::mem::size_of::<libc::cmsghdr>() + 3 * std::mem::size_of::<RawFd>();

// Child path: stack-only scalar/ABI operations and direct syscalls. All signals
// except unblockable KILL/STOP remain masked from before clone. Never unwind,
// log, allocate, lock, call an inherited runtime, or drop parent Rust owners.
unsafe fn child_exit() -> ! {
    loop {
        libc::syscall(libc::SYS_exit_group, 127);
        libc::syscall(libc::SYS_exit, 127);
    }
}

unsafe fn child_trampoline(gate: RawFd, parent_pid: u32, parent_tid: libc::pid_t,
    manual_network_policy: bool) -> ! {
    if libc::syscall(libc::SYS_prctl, libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
        || libc::syscall(libc::SYS_getppid) != parent_pid as libc::c_long
        || libc::syscall(libc::SYS_tgkill, parent_pid, parent_tid, 0) != 0 { child_exit(); }
    // No parent TLS sockets, secret files, executable descriptors or stdio are
    // retained in the child. close_range support is mandatory, never emulated.
    if gate > 0 && libc::syscall(libc::SYS_close_range, 0u32, gate as u32 - 1, 0u32) != 0 { child_exit(); }
    if libc::syscall(libc::SYS_close_range, gate as u32 + 1, u32::MAX, 0u32) != 0 { child_exit(); }
    if manual_network_policy && !super::child_network_policy::apply() { child_exit(); }
    let ns = libc::syscall(libc::SYS_openat, libc::AT_FDCWD, b"/proc/self/ns/net\0".as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC, 0) as RawFd;
    if ns < 0 { child_exit(); }
    let socket = libc::syscall(libc::SYS_socket, libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_NETFILTER) as RawFd;
    if socket < 0 { child_exit(); }
    let mut address: libc::sockaddr_nl = std::mem::zeroed();
    address.nl_family = libc::AF_NETLINK as u16;
    if libc::syscall(libc::SYS_bind, socket, &address as *const libc::sockaddr_nl,
        std::mem::size_of::<libc::sockaddr_nl>()) != 0 { child_exit(); }
    let route = libc::syscall(libc::SYS_socket, libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, libc::NETLINK_ROUTE) as RawFd;
    if route < 0 || libc::syscall(libc::SYS_bind, route, &address as *const libc::sockaddr_nl,
        std::mem::size_of::<libc::sockaddr_nl>()) != 0 { child_exit(); }
    let mut byte = READY;
    let mut vector = libc::iovec { iov_base: (&mut byte as *mut u8).cast(), iov_len: 1 };
    let mut rights: Rights = std::mem::zeroed();
    rights.header.cmsg_len = RIGHTS_LENGTH as _;
    rights.header.cmsg_level = libc::SOL_SOCKET;
    rights.header.cmsg_type = libc::SCM_RIGHTS;
    rights.descriptors = [ns, socket, route];
    let mut message: libc::msghdr = std::mem::zeroed();
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = (&mut rights as *mut Rights).cast();
    message.msg_controllen = std::mem::size_of::<Rights>() as _;
    if libc::syscall(libc::SYS_sendmsg, gate, &message as *const libc::msghdr,
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) != 1 { child_exit(); }
    if libc::syscall(libc::SYS_getppid) != parent_pid as libc::c_long
        || libc::syscall(libc::SYS_tgkill, parent_pid, parent_tid, 0) != 0 { child_exit(); }
    let pid = libc::syscall(libc::SYS_getpid);
    let tid = libc::syscall(libc::SYS_gettid);
    libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSTOP);
    // An external continuation is not permission: exit without target exec.
    child_exit()
}

struct SignalMask { original: u64, restored: bool }
impl SignalMask {
    fn block() -> Result<Self, String> {
        let mask = u64::MAX;
        let mut original = 0u64;
        // Linux's kernel signal set has 64 signals. The raw interface also
        // blocks libc's reserved thread signals in this tiny clone interval.
        require(unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
            &mask as *const u64, &mut original as *mut u64, 8usize) } == 0)?;
        Ok(Self { original, restored: false })
    }
    fn restore(&mut self) -> Result<(), String> {
        require(unsafe { libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
            &self.original as *const u64, std::ptr::null_mut::<u64>(), 8usize) } == 0)?;
        self.restored = true;
        Ok(())
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        if !self.restored { let _ = self.restore(); }
    }
}

struct Child { pidfd: File, pid: libc::pid_t, cleanup_attempted: bool }
impl Child {
    fn wait(&self, options: i32) -> io::Result<libc::siginfo_t> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::waitid(P_PIDFD, self.pidfd.as_raw_fd() as libc::id_t, &mut info, options) };
        if result == 0 { Ok(info) } else { Err(io::Error::last_os_error()) }
    }
    fn stopped(&self, clock: &OriginalClock) -> Result<bool, String> {
        let info = checked(clock, || self.wait(libc::WSTOPPED | libc::WEXITED | libc::WCONTINUED
            | libc::WNOWAIT | libc::WNOHANG))?;
        if unsafe { info.si_pid() } == 0 { return Ok(false); }
        require(unsafe { info.si_pid() } == self.pid && info.si_code == libc::CLD_STOPPED
            && unsafe { info.si_status() } == libc::SIGSTOP)?;
        Ok(true)
    }
    fn terminate(&mut self) -> Result<(), String> {
        require(!self.cleanup_attempted)?;
        self.cleanup_attempted = true;
        // Cleanup is not a new operation allowance. One pidfd signal and at
        // most 100ms of nonblocking reap/poll, even after admission expires.
        let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal,
            self.pidfd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0u32) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err("native workload termination is uncertain".to_owned());
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            let info = self.wait(libc::WEXITED | libc::WNOHANG)
                .map_err(|_| "native workload reap is uncertain")?;
            if unsafe { info.si_pid() } == self.pid {
                require(matches!(info.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED))?;
                return Ok(());
            }
            if Instant::now() >= deadline { return Err("native workload reap is uncertain".to_owned()); }
            let remaining = deadline.saturating_duration_since(Instant::now()).as_millis().min(10) as i32;
            let mut poll = libc::pollfd { fd: self.pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut poll, 1, remaining) } < 0 {
                return Err("native workload cleanup poll is uncertain".to_owned());
            }
        }
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.cleanup_attempted && self.terminate().is_err() {
            let notice = b"native egress workload cleanup uncertain; target was never executed\n";
            unsafe { libc::write(libc::STDERR_FILENO, notice.as_ptr().cast(), notice.len()); }
        }
    }
}

fn socket_option(socket: &File, option: i32, clock: &OriginalClock) -> Result<i32, String> {
    checked(clock, || {
        let mut value = 0i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe { libc::getsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, option,
            (&mut value as *mut i32).cast(), &mut length) } != 0
            || length as usize != std::mem::size_of::<i32>() { Err(io::Error::last_os_error()) }
        else { Ok(value) }
    })
}

fn backend(socket: &File, ns: Identity, clock: &OriginalClock) -> Result<u32, String> {
    netlink_socket(socket, ns, libc::NETLINK_NETFILTER, clock)
}

fn netlink_socket(socket: &File, ns: Identity, protocol: i32, clock: &OriginalClock) -> Result<u32, String> {
    require(socket_option(socket, libc::SO_DOMAIN, clock)? == libc::AF_NETLINK
        && socket_option(socket, libc::SO_TYPE, clock)? == libc::SOCK_RAW
        && socket_option(socket, libc::SO_PROTOCOL, clock)? == protocol)?;
    let socket_namespace = checked(clock, || descriptor(unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGSKNS as _) }))?;
    require(namespace(&socket_namespace, clock)? == ns)?;
    let address = checked(clock, || {
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if unsafe { libc::getsockname(socket.as_raw_fd(), (&mut address as *mut libc::sockaddr_nl).cast(),
            &mut length) } != 0 || length as usize != std::mem::size_of::<libc::sockaddr_nl>() {
            Err(io::Error::last_os_error())
        } else { Ok(address) }
    })?;
    require(address.nl_family as i32 == libc::AF_NETLINK && address.nl_groups == 0 && address.nl_pid != 0)?;
    Ok(address.nl_pid)
}

fn receive(gate: &File, clock: &OriginalClock) -> Result<(File, File, File), String> {
    loop {
        clock.check()?;
        let mut byte = 0u8;
        let mut vector = libc::iovec { iov_base: (&mut byte as *mut u8).cast(), iov_len: 1 };
        let mut rights: Rights = unsafe { std::mem::zeroed() };
        rights.descriptors = [-1, -1, -1];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = (&mut rights as *mut Rights).cast();
        message.msg_controllen = std::mem::size_of::<Rights>() as _;
        let result = unsafe { libc::recvmsg(gate.as_raw_fd(), &mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if result < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                return Err("native workload descriptor handoff failed".to_owned());
            }
            let remaining = clock.instant_deadline()?.saturating_duration_since(Instant::now())
                .as_millis().min(10) as i32;
            let mut poll = libc::pollfd { fd: gate.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            require(unsafe { libc::poll(&mut poll, 1, remaining) } >= 0)?;
            continue;
        }
        // Adopt delivered descriptors immediately so every subsequent refusal
        // closes them; no authority is inferred from message text or fd numbers.
        let ns = descriptor(rights.descriptors[0]).map_err(|_| "native workload namespace absent")?;
        let socket = descriptor(rights.descriptors[1]).map_err(|_| "native workload backend absent")?;
        let route = descriptor(rights.descriptors[2]).map_err(|_| "native workload route backend absent")?;
        require(result == 1 && byte == READY && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && message.msg_controllen as usize == std::mem::size_of::<Rights>()
            && rights.header.cmsg_len as usize == RIGHTS_LENGTH
            && rights.header.cmsg_level == libc::SOL_SOCKET && rights.header.cmsg_type == libc::SCM_RIGHTS)?;
        clock.check()?;
        return Ok((ns, socket, route));
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WorkloadIdentity {
    pub(super) launcher_process_id: u32,
    pub(super) launcher_thread_id: u32,
    pub(super) child_process_id: u32,
    pub(super) pidfd_device: u64,
    pub(super) pidfd_inode: u64,
    pub(super) namespace_device: u64,
    pub(super) namespace_inode: u64,
    pub(super) backend_socket_device: u64,
    pub(super) backend_socket_inode: u64,
    pub(super) backend_port_id: u32,
}

pub(super) struct WorkloadOwner {
    // Cleanup runs before the durable permit and its original owner are dropped.
    child: Child,
    permit: CreationPermit,
    precreation: Arc<PrecreationOwner>,
    gate: File,
    gate_identity: Identity,
    namespace: File,
    namespace_identity: Identity,
    socket: File,
    socket_identity: Identity,
    route: File,
    route_identity: Identity,
    route_port_id: u32,
    pidfd_identity: Identity,
    identity: WorkloadIdentity,
    backend_duplicated: bool,
    attachment_duplicated: bool,
    stopped: bool,
}

impl WorkloadOwner {
    pub(super) fn create(precreation: Arc<PrecreationOwner>, permit: CreationPermit,
        clock: &OriginalClock) -> Result<Self, String> {
        require(std::ptr::eq(Arc::as_ptr(&precreation.clock), clock))?;
        permit.require_owner(&precreation)?;
        permit.check()?;
        let (parent_pid, parent_tid, host_identity, manual_network_policy) = {
            let spec = precreation.launch.try_borrow().map_err(|_| "native launch original already borrowed")?;
            (spec.pid, spec.tid, spec.host_identity, spec.manual_network_policy)
        };
        // This ABI profile is deliberately Linux 64-bit, with no emulation or
        // fallback to a numeric-PID/open-existing-namespace construction.
        require(cfg!(all(target_os = "linux", target_pointer_width = "64"))
            && RIGHTS_LENGTH == 28 && std::mem::size_of::<Rights>() == 32)?;
        let mut pair = [-1; 2];
        require(unsafe { libc::socketpair(libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0, pair.as_mut_ptr()) } == 0)?;
        let gate = descriptor(pair[0]).map_err(|_| "native workload parent gate failed")?;
        let child_gate = descriptor(pair[1]).map_err(|_| "native workload child gate failed")?;
        let gate_identity = identity(&metadata(&gate, clock)?);
        let mut pidfd = -1i32;
        let args = CloneArgs { flags: (libc::CLONE_NEWNET | libc::CLONE_PIDFD) as u64,
            pidfd: (&mut pidfd as *mut i32) as u64, child_tid: 0, parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64, stack: 0, stack_size: 0, tls: 0 };
        // The exact non-forgeable, durably read-back permit is consumed by this
        // owner and checked immediately before the sole child-creation syscall.
        permit.require_owner(&precreation)?;
        permit.check()?;
        let mut mask = SignalMask::block()?;
        clock.check()?;
        let child_pid = unsafe { libc::syscall(libc::SYS_clone3, &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>()) };
        if child_pid == 0 {
            unsafe { child_trampoline(child_gate.as_raw_fd(), parent_pid, parent_tid, manual_network_policy) }
        }
        // Install pidfd-only cleanup before any fallible post-clone operation.
        if child_pid < 0 { mask.restore()?; return Err("native workload clone3 unavailable or refused".to_owned()); }
        let child = Child { pidfd: descriptor(pidfd).map_err(|_| "native workload clone3 pidfd absent; cleanup uncertain")?,
            pid: child_pid as libc::pid_t, cleanup_attempted: false };
        mask.restore()?;
        drop(child_gate);
        require(child_pid <= i32::MAX as libc::c_long)?;
        let (namespace_file, socket, route) = receive(&gate, clock)?;
        loop {
            if child.stopped(clock)? { break; }
            let remaining = clock.instant_deadline()?.saturating_duration_since(Instant::now())
                .as_millis().min(2) as i32;
            require(unsafe { libc::poll(std::ptr::null_mut(), 0, remaining) } >= 0)?;
        }
        let ns_identity = namespace(&namespace_file, clock)?;
        require((ns_identity.0, ns_identity.1) != (host_identity.0, host_identity.1))?;
        let port = backend(&socket, ns_identity, clock)?;
        let socket_identity = identity(&metadata(&socket, clock)?);
        let route_identity = identity(&metadata(&route, clock)?);
        let route_port_id = netlink_socket(&route, ns_identity, libc::NETLINK_ROUTE, clock)?;
        let pidfd_identity = identity(&metadata(&child.pidfd, clock)?);
        let observed = WorkloadIdentity { launcher_process_id: parent_pid, launcher_thread_id: parent_tid as u32,
            child_process_id: child.pid as u32, pidfd_device: pidfd_identity.0, pidfd_inode: pidfd_identity.1,
            namespace_device: ns_identity.0, namespace_inode: ns_identity.1,
            backend_socket_device: socket_identity.0, backend_socket_inode: socket_identity.1, backend_port_id: port };
        let mut owner = Self { child, permit, precreation, gate, gate_identity, namespace: namespace_file,
            namespace_identity: ns_identity, socket, socket_identity, route, route_identity, route_port_id,
            pidfd_identity, identity: observed, backend_duplicated: false,
            attachment_duplicated: false, stopped: false };
        owner.check(clock)?;
        Ok(owner)
    }

    pub(super) fn check(&mut self, clock: &OriginalClock) -> Result<(), String> {
        require(!std::mem::replace(&mut self.stopped, true))?;
        require(std::ptr::eq(Arc::as_ptr(&self.precreation.clock), clock))?;
        self.permit.require_owner(&self.precreation)?;
        self.permit.check()?;
        require(self.child.stopped(clock)?
            && identity(&metadata(&self.child.pidfd, clock)?) == self.pidfd_identity
            && namespace(&self.namespace, clock)? == self.namespace_identity
            && identity(&metadata(&self.socket, clock)?) == self.socket_identity
            && identity(&metadata(&self.route, clock)?) == self.route_identity
            && netlink_socket(&self.route, self.namespace_identity, libc::NETLINK_ROUTE, clock)? == self.route_port_id
            && identity(&metadata(&self.gate, clock)?) == self.gate_identity
            && socket_option(&self.gate, libc::SO_DOMAIN, clock)? == libc::AF_UNIX
            && socket_option(&self.gate, libc::SO_TYPE, clock)? == libc::SOCK_SEQPACKET
            && backend(&self.socket, self.namespace_identity, clock)? == self.identity.backend_port_id)?;
        let mut byte = 0u8;
        let result = unsafe { libc::recv(self.gate.as_raw_fd(), (&mut byte as *mut u8).cast(), 1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT) };
        require(result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock)?;
        require(self.child.stopped(clock)?)?;
        self.permit.check()?;
        clock.check()?;
        self.stopped = false;
        Ok(())
    }

    /// Observed association only; callers must retain and recheck this owner.
    pub(super) fn identity(&self) -> &WorkloadIdentity { &self.identity }

    pub(super) fn creation_slot_sha256(&self) -> [u8; 32] { self.permit.slot_sha256() }
    pub(super) fn creation_record_sha256(&self) -> [u8; 32] { self.permit.record_sha256() }

    /// Source-owned aliases only; no external namespace or socket enters.
    pub(super) fn duplicate_attachment(&mut self, clock: &OriginalClock) -> Result<AttachmentDescriptors, String> {
        self.check(clock)?;
        require(!std::mem::replace(&mut self.attachment_duplicated, true))?;
        let (host_namespace, host_identity) = {
            let launch = self.precreation.launch.try_borrow().map_err(|_| "native launch original already borrowed")?;
            require(launch.manual_network_policy)?;
            (duplicate(&launch.host_namespace, clock)?, launch.host_identity)
        };
        let child_namespace = duplicate(&self.namespace, clock)?;
        let child_route = duplicate(&self.route, clock)?;
        require(namespace(&host_namespace, clock)? == host_identity
            && namespace(&child_namespace, clock)? == self.namespace_identity
            && identity(&metadata(&child_route, clock)?) == self.route_identity
            && netlink_socket(&child_route, self.namespace_identity, libc::NETLINK_ROUTE, clock)? == self.route_port_id)?;
        self.check(clock)?;
        Ok(AttachmentDescriptors { host_namespace, child_namespace, child_route,
            host_namespace_device: host_identity.0, host_namespace_inode: host_identity.1,
            child_namespace_device: self.namespace_identity.0, child_namespace_inode: self.namespace_identity.1,
            route_socket_device: self.route_identity.0, route_socket_inode: self.route_identity.1,
            route_port_id: self.route_port_id })
    }

    /// Exactly one private backend obtains a checked CLOEXEC alias of the
    /// actual child-created socket. The original remains under this owner.
    pub(super) fn duplicate_backend(&mut self, clock: &OriginalClock) -> Result<File, String> {
        self.check(clock)?;
        require(!std::mem::replace(&mut self.backend_duplicated, true))?;
        let duplicate = checked(clock, || descriptor(unsafe {
            libc::fcntl(self.socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3)
        }))?;
        let descriptor_flags = checked(clock, || {
            let value = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) };
            if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
        })?;
        let status_flags = checked(clock, || {
            let value = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFL) };
            if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
        })?;
        require(descriptor_flags & libc::FD_CLOEXEC != 0 && status_flags & libc::O_NONBLOCK != 0
            && identity(&metadata(&duplicate, clock)?) == self.socket_identity
            && backend(&duplicate, self.namespace_identity, clock)? == self.identity.backend_port_id)?;
        self.check(clock)?;
        Ok(duplicate)
    }

    /// Explicit closing path can report uncertainty. Drop is the final safety
    /// net; neither path starts the target or mutates an existing namespace.
    pub(super) fn terminate(mut self) -> Result<(), String> { self.child.terminate() }
}

fn duplicate(original: &File, clock: &OriginalClock) -> Result<File, String> {
    let result = checked(clock, || descriptor(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) }))?;
    require(identity(&metadata(&result, clock)?) == identity(&metadata(original, clock)?))?;
    Ok(result)
}

pub(super) struct AttachmentDescriptors {
    pub(super) host_namespace: File,
    pub(super) child_namespace: File,
    pub(super) child_route: File,
    pub(super) host_namespace_device: u64,
    pub(super) host_namespace_inode: u64,
    pub(super) child_namespace_device: u64,
    pub(super) child_namespace_inode: u64,
    pub(super) route_socket_device: u64,
    pub(super) route_socket_inode: u64,
    pub(super) route_port_id: u32,
}
