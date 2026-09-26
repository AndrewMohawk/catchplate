//! Held Linux custody of the actual gated namespace-init supervisor.
//!
//! These are unsigned kernel/file observations, not runtime-observer evidence,
//! executable mappings, or permission to control an arbitrary process. The
//! lifecycle supplies the actual inspected PID and independently admitted
//! supervisor digest and generation cgroup before releasing the worker gate.

use super::{boottime_now_ns_v11, canonical_plan_bytes, sha256, ControllerError, Digest, Result};
use crate::runtime_evidence::{
    verify_static_executable_fd_bounded, ExecutableRole, RuntimeNamespaceIdentityV12,
    StaticExecutableEvidenceV12,
};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

const PROC_MAGIC: libc::c_long = 0x9fa0;
const CGROUP2_MAGIC: libc::c_long = 0x63677270;
const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x00000010;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const CUSTODY_DOMAIN: &[u8] = b"serverware/controller-body-target-custody/v12\0";

pub(super) struct HeldBodyTargetV12 {
    owner_pid: libc::pid_t,
    host_pid: u32,
    start_ticks: u64,
    deadline: u64,
    pidfd: OwnedFd,
    pidfd_identity: NodeIdentity,
    proc: OwnedFd,
    proc_identity: NodeIdentity,
    ns_directory: OwnedFd,
    namespace_fds: Vec<HeldNamespace>,
    namespaces: RuntimeNamespaceIdentityV12,
    executable: OwnedFd,
    executable_identity: ExecutableIdentity,
    supervisor_static: StaticExecutableEvidenceV12,
    cgroup_root: OwnedFd,
    cgroup_root_identity: NodeIdentity,
    generation: OwnedFd,
    generation_identity: NodeIdentity,
    generation_path: String,
    cgroup: OwnedFd,
    cgroup_identity: NodeIdentity,
    cgroup_path: String,
    custody_sha256: Digest,
}

impl HeldBodyTargetV12 {
    pub(super) fn acquire(
        pid: u32,
        expected_supervisor_sha256: Digest,
        expected_generation_cgroup: &Path,
        deadline: u64,
    ) -> Result<Self> {
        live(deadline)?;
        if pid <= 1 || pid > i32::MAX as u32 || expected_supervisor_sha256 == [0; 32] {
            return Err(rejected("body target lacks a concrete supervisor PID or digest"));
        }
        let owner_pid = unsafe { libc::getpid() };
        let generation_path = generation_relative_path(expected_generation_cgroup)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
        live(deadline)?;
        require_pidfd_state(pidfd.as_raw_fd(), false, deadline)?;
        let pidfd_identity = node_identity(pidfd.as_raw_fd(), deadline)?;
        let proc_root = open_absolute_directory(c"/proc", deadline)?;
        require_filesystem(proc_root.as_raw_fd(), PROC_MAGIC, deadline)?;
        let pid_name = CString::new(pid.to_string()).map_err(|_| rejected("body PID is invalid"))?;
        let proc = open_at(proc_root.as_raw_fd(), &pid_name, true, false, deadline)?;
        let proc_identity = node_identity(proc.as_raw_fd(), deadline)?;
        let start_ticks = read_start_ticks(proc.as_raw_fd(), pid, deadline)?;
        require_namespace_init(proc.as_raw_fd(), pid, deadline)?;
        let cgroup_path = read_cgroup_path(proc.as_raw_fd(), deadline)?;
        if !strict_descendant(&cgroup_path, &generation_path) {
            return Err(rejected("body target cgroup is not an exact generation descendant"));
        }
        let ns_directory = open_at(proc.as_raw_fd(), c"ns", true, false, deadline)?;
        let mut namespace_fds = Vec::with_capacity(5);
        for (name, kind) in [
            (c"user", libc::CLONE_NEWUSER), (c"mnt", libc::CLONE_NEWNS),
            (c"pid", libc::CLONE_NEWPID), (c"net", libc::CLONE_NEWNET),
            (c"cgroup", libc::CLONE_NEWCGROUP),
        ] {
            // Only these source-fixed procfs namespace magic links are followed.
            let fd = open_at(ns_directory.as_raw_fd(), name, false, true, deadline)?;
            let identity = namespace_identity(fd.as_raw_fd(), kind, deadline)?;
            namespace_fds.push(HeldNamespace { name, kind, fd, identity });
        }
        let namespaces = RuntimeNamespaceIdentityV12 {
            user_namespace_inode: namespace_fds[0].identity.inode,
            mount_namespace_inode: namespace_fds[1].identity.inode,
            pid_namespace_inode: namespace_fds[2].identity.inode,
            network_namespace_inode: namespace_fds[3].identity.inode,
            cgroup_v2_path_sha256: sha256(cgroup_path.as_bytes()),
        };
        let system_root = open_absolute_directory(c"/", deadline)?;
        let cgroup_root = open_directory_components(
            system_root.as_raw_fd(), "/sys/fs/cgroup", deadline,
        )?;
        require_filesystem(cgroup_root.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let cgroup_root_identity = node_identity(cgroup_root.as_raw_fd(), deadline)?;
        let generation = open_directory_components(
            cgroup_root.as_raw_fd(), &generation_path, deadline,
        )?;
        let generation_identity = node_identity(generation.as_raw_fd(), deadline)?;
        require_filesystem(generation.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let cgroup = open_directory_components(cgroup_root.as_raw_fd(), &cgroup_path, deadline)?;
        let cgroup_identity = node_identity(cgroup.as_raw_fd(), deadline)?;
        require_filesystem(cgroup.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        require_cgroup_member(cgroup.as_raw_fd(), pid, deadline)?;
        // The fixed procfs exe magic link selects the current executable. No
        // caller-supplied filename or assumed Docker command substitutes for it.
        let executable = open_at(proc.as_raw_fd(), c"exe", false, true, deadline)?;
        let executable_identity = executable_identity(executable.as_raw_fd(), deadline)?;
        let measured = verify_static_executable_fd_bounded(
            executable.as_raw_fd(), ExecutableRole::ControllerOwnedRunner,
            MAX_EXECUTABLE_BYTES, deadline,
        ).map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
        if measured.content_sha256 != expected_supervisor_sha256
            || executable_identity != self::executable_identity(executable.as_raw_fd(), deadline)?
        {
            return Err(rejected("body target is not the exact admitted static supervisor"));
        }
        let mut held = Self {
            owner_pid, host_pid: pid, start_ticks, deadline, pidfd, pidfd_identity,
            proc, proc_identity, ns_directory, namespace_fds, namespaces,
            executable, executable_identity, supervisor_static: measured,
            cgroup_root, cgroup_root_identity,
            generation, generation_identity, generation_path, cgroup, cgroup_identity,
            cgroup_path, custody_sha256: [0; 32],
        };
        held.verify_live(deadline)?;
        let namespace_claims = held.namespace_fds.iter().map(|namespace| NamespaceClaim {
            kind: namespace.kind, identity: &namespace.identity,
        }).collect::<Vec<_>>();
        let claims = CustodyClaims {
            version: "serverware.controllerBodyTargetCustody/v12",
            host_pid: pid, start_ticks, pidfd: &held.pidfd_identity,
            proc: &held.proc_identity, supervisor_sha256: &expected_supervisor_sha256,
            executable: &held.executable_identity, namespaces: &held.namespaces,
            namespace_fds: &namespace_claims, cgroup_root: &held.cgroup_root_identity,
            generation: &held.generation_identity, generation_path: &held.generation_path,
            cgroup: &held.cgroup_identity, cgroup_path: &held.cgroup_path,
        };
        let canonical = canonical_plan_bytes(&claims)
            .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
        if canonical.len() > 32 * 1024 {
            return Err(rejected("body target custody metadata exceeds its fixed bound"));
        }
        let mut framed = Vec::with_capacity(CUSTODY_DOMAIN.len() + canonical.len());
        framed.extend_from_slice(CUSTODY_DOMAIN);
        framed.extend_from_slice(&canonical);
        held.custody_sha256 = sha256(&framed);
        held.check_scope(deadline)?;
        Ok(held)
    }

    pub(super) fn host_pid(&self) -> u32 { self.host_pid }
    pub(super) fn start_ticks(&self) -> u64 { self.start_ticks }
    pub(super) fn pidfd_inode(&self) -> u64 { self.pidfd_identity.inode }
    pub(super) fn namespaces(&self) -> &RuntimeNamespaceIdentityV12 { &self.namespaces }
    pub(super) fn cgroup_path_sha256(&self) -> Digest { self.namespaces.cgroup_v2_path_sha256 }
    pub(super) fn custody_sha256(&self) -> Digest { self.custody_sha256 }
    pub(super) fn supervisor_static(&self) -> &StaticExecutableEvidenceV12 { &self.supervisor_static }

    /// Borrow the exact nine held descriptors for the fixed observer channel.
    /// SCM_RIGHTS duplicates these open descriptions; root retains ownership.
    pub(super) fn observer_fds(&self, deadline: u64) -> Result<[RawFd; 9]> {
        self.verify_live(deadline)?;
        Ok([self.pidfd.as_raw_fd(), self.proc.as_raw_fd(), self.executable.as_raw_fd(),
            self.namespace_fds[0].fd.as_raw_fd(), self.namespace_fds[1].fd.as_raw_fd(),
            self.namespace_fds[2].fd.as_raw_fd(), self.namespace_fds[3].fd.as_raw_fd(),
            self.namespace_fds[4].fd.as_raw_fd(), self.cgroup.as_raw_fd()])
    }

    pub(super) fn verify_live(&self, deadline: u64) -> Result<()> {
        self.check_scope(deadline)?;
        if node_identity(self.pidfd.as_raw_fd(), deadline)? != self.pidfd_identity {
            return Err(rejected("body target pidfd identity changed"));
        }
        require_pidfd_state(self.pidfd.as_raw_fd(), false, deadline)?;
        if node_identity(self.proc.as_raw_fd(), deadline)? != self.proc_identity
            || read_start_ticks(self.proc.as_raw_fd(), self.host_pid, deadline)? != self.start_ticks
            || read_cgroup_path(self.proc.as_raw_fd(), deadline)? != self.cgroup_path
        {
            return Err(rejected("body target process or cgroup identity changed"));
        }
        require_namespace_init(self.proc.as_raw_fd(), self.host_pid, deadline)?;
        for namespace in &self.namespace_fds {
            let current = open_at(
                self.ns_directory.as_raw_fd(), namespace.name, false, true, deadline,
            )?;
            if namespace_identity(namespace.fd.as_raw_fd(), namespace.kind, deadline)? != namespace.identity
                || namespace_identity(current.as_raw_fd(), namespace.kind, deadline)? != namespace.identity
            {
                return Err(rejected("body target namespace identity changed"));
            }
        }
        let current_executable = open_at(self.proc.as_raw_fd(), c"exe", false, true, deadline)?;
        if executable_identity(self.executable.as_raw_fd(), deadline)? != self.executable_identity
            || executable_identity(current_executable.as_raw_fd(), deadline)? != self.executable_identity
        {
            return Err(rejected("body target no longer executes the held immutable supervisor"));
        }
        require_filesystem(self.cgroup_root.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let generation = open_directory_components(
            self.cgroup_root.as_raw_fd(), &self.generation_path, deadline,
        )?;
        let cgroup = open_directory_components(
            self.cgroup_root.as_raw_fd(), &self.cgroup_path, deadline,
        )?;
        if node_identity(self.cgroup_root.as_raw_fd(), deadline)? != self.cgroup_root_identity
            || node_identity(self.generation.as_raw_fd(), deadline)? != self.generation_identity
            || node_identity(generation.as_raw_fd(), deadline)? != self.generation_identity
            || node_identity(self.cgroup.as_raw_fd(), deadline)? != self.cgroup_identity
            || node_identity(cgroup.as_raw_fd(), deadline)? != self.cgroup_identity
        {
            return Err(rejected("body target generation or child cgroup directory changed"));
        }
        require_filesystem(cgroup.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        require_cgroup_member(cgroup.as_raw_fd(), self.host_pid, deadline)?;
        if read_start_ticks(self.proc.as_raw_fd(), self.host_pid, deadline)? != self.start_ticks
            || read_cgroup_path(self.proc.as_raw_fd(), deadline)? != self.cgroup_path
        {
            return Err(rejected("body target changed during custody revalidation"));
        }
        require_pidfd_state(self.pidfd.as_raw_fd(), false, deadline)?;
        self.check_scope(deadline)
    }

    /// Assert actual held-pidfd termination without following a reused PID,
    /// waiting, signalling, retrying, or deriving an exit status.
    pub(super) fn require_terminated(&self, deadline: u64) -> Result<()> {
        self.check_scope(deadline)?;
        if node_identity(self.pidfd.as_raw_fd(), deadline)? != self.pidfd_identity {
            return Err(rejected("body target terminal pidfd identity changed"));
        }
        require_pidfd_state(self.pidfd.as_raw_fd(), true, deadline)?;
        self.check_scope(deadline)
    }

    fn check_scope(&self, deadline: u64) -> Result<()> {
        if unsafe { libc::getpid() } != self.owner_pid || deadline > self.deadline {
            return Err(rejected("body target custody crossed a process or deadline boundary"));
        }
        live(deadline)
    }
}

struct HeldNamespace {
    name: &'static CStr,
    kind: i32,
    fd: OwnedFd,
    identity: NodeIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeIdentity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableIdentity {
    node: NodeIdentity, links: u64, size: u64,
    modified_sec: i64, modified_nsec: i64, changed_sec: i64, changed_nsec: i64,
}

#[derive(Serialize)]
struct NamespaceClaim<'a> { kind: i32, identity: &'a NodeIdentity }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustodyClaims<'a> {
    version: &'static str, host_pid: u32, start_ticks: u64,
    pidfd: &'a NodeIdentity, proc: &'a NodeIdentity, supervisor_sha256: &'a Digest,
    executable: &'a ExecutableIdentity, namespaces: &'a RuntimeNamespaceIdentityV12,
    namespace_fds: &'a [NamespaceClaim<'a>], cgroup_root: &'a NodeIdentity,
    generation: &'a NodeIdentity, generation_path: &'a str,
    cgroup: &'a NodeIdentity, cgroup_path: &'a str,
}

fn rejected(message: &'static str) -> ControllerError { ControllerError::Rejected(message) }

fn live(deadline: u64) -> Result<()> {
    if boottime_now_ns_v11()? >= deadline {
        return Err(rejected("body target original deadline expired"));
    }
    Ok(())
}

fn node_from_stat(stat: &libc::stat) -> NodeIdentity {
    NodeIdentity { device: stat.st_dev, inode: stat.st_ino,
        mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid }
}

fn stat_fd(fd: RawFd, deadline: u64) -> Result<libc::stat> {
    live(deadline)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if stat.st_ino == 0 { return Err(rejected("body target descriptor has no inode")); }
    Ok(stat)
}

fn node_identity(fd: RawFd, deadline: u64) -> Result<NodeIdentity> {
    Ok(node_from_stat(&stat_fd(fd, deadline)?))
}

fn require_filesystem(fd: RawFd, expected: libc::c_long, deadline: u64) -> Result<()> {
    live(deadline)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    if filesystem.f_type != expected as _ { return Err(rejected("body target filesystem is not the required kernel view")); }
    Ok(())
}

fn executable_identity(fd: RawFd, deadline: u64) -> Result<ExecutableIdentity> {
    let stat = stat_fd(fd, deadline)?;
    let mut flags: libc::c_uint = 0;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_uid != 0
        || stat.st_nlink != 1 || stat.st_size <= 0
        || stat.st_size as u64 > MAX_EXECUTABLE_BYTES || stat.st_mode & 0o022 != 0
        || unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0
        || flags & FS_IMMUTABLE_FL == 0
    {
        return Err(rejected("body target executable lost immutable root-owned regular identity"));
    }
    live(deadline)?;
    Ok(ExecutableIdentity { node: node_from_stat(&stat), links: stat.st_nlink as u64,
        size: stat.st_size as u64, modified_sec: stat.st_mtime, modified_nsec: stat.st_mtime_nsec,
        changed_sec: stat.st_ctime, changed_nsec: stat.st_ctime_nsec })
}

fn namespace_identity(fd: RawFd, kind: i32, deadline: u64) -> Result<NodeIdentity> {
    require_filesystem(fd, NSFS_MAGIC, deadline)?;
    let actual = unsafe { libc::ioctl(fd, NS_GET_NSTYPE) };
    live(deadline)?;
    if actual != kind { return Err(rejected("body target namespace descriptor has another kernel type")); }
    node_identity(fd, deadline)
}

fn open_absolute_directory(path: &CStr, deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY
        | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(fd)
}

fn open_at(parent: RawFd, name: &CStr, directory: bool, follow_kernel_link: bool, deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 }
        | if follow_kernel_link { 0 } else { libc::O_NOFOLLOW };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(fd)
}

fn canonical_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES && path.starts_with('/') && path.len() > 1
        && !path.ends_with('/')
        && !path.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b'\\')
        && path[1..].split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn generation_relative_path(path: &Path) -> Result<String> {
    let path = path.to_str().ok_or_else(|| rejected("generation cgroup path is not UTF-8"))?;
    if !canonical_path(path) { return Err(rejected("generation cgroup path is not canonical")); }
    let relative = path.strip_prefix("/sys/fs/cgroup/")
        .ok_or_else(|| rejected("generation cgroup is outside the fixed cgroup2 mount"))?;
    let relative = format!("/{relative}");
    if !canonical_path(&relative) { return Err(rejected("generation cgroup scope is empty or invalid")); }
    Ok(relative)
}

fn strict_descendant(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent).is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
}

fn open_directory_components(root: RawFd, path: &str, deadline: u64) -> Result<OwnedFd> {
    if !canonical_path(path) { return Err(rejected("body target kernel path is not canonical")); }
    let mut directory = open_at(root, c".", true, false, deadline)?;
    for part in path[1..].split('/') {
        let component = CString::new(part).map_err(|_| rejected("body target path contains NUL"))?;
        directory = open_at(directory.as_raw_fd(), &component, true, false, deadline)?;
    }
    Ok(directory)
}

fn read_bounded_at(parent: RawFd, name: &CStr, maximum: usize, filesystem: libc::c_long, deadline: u64) -> Result<Vec<u8>> {
    let fd = open_at(parent, name, false, false, deadline)?;
    require_filesystem(fd.as_raw_fd(), filesystem, deadline)?;
    if stat_fd(fd.as_raw_fd(), deadline)?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(rejected("body target kernel observation is not a regular pseudo-file"));
    }
    let mut bytes = Vec::with_capacity(maximum.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        live(deadline)?;
        let wanted = (maximum - bytes.len()).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), wanted, bytes.len() as libc::off_t) };
        let error = (count < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { break; }
        if count as usize > maximum - bytes.len() {
            return Err(rejected("body target kernel observation exceeds its fixed bound"));
        }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
    Ok(bytes)
}

fn read_start_ticks(proc: RawFd, pid: u32, deadline: u64) -> Result<u64> {
    let bytes = read_bounded_at(proc, c"stat", 16 * 1024, PROC_MAGIC, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("body target stat is not UTF-8"))?;
    let open = text.find('(').ok_or_else(|| rejected("body target stat lacks its command"))?;
    let close = text.rfind(')').ok_or_else(|| rejected("body target stat lacks its command terminator"))?;
    if close <= open || text[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err(rejected("body target stat belongs to another PID"));
    }
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let state = fields.next().ok_or_else(|| rejected("body target stat state is absent"))?;
    if state.len() != 1 || matches!(state, "Z" | "X" | "x") {
        return Err(rejected("body target stat is already terminal"));
    }
    let ticks = fields.nth(18).and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0).ok_or_else(|| rejected("body target start ticks are absent or invalid"))?;
    live(deadline)?;
    Ok(ticks)
}

fn require_namespace_init(proc: RawFd, pid: u32, deadline: u64) -> Result<()> {
    let bytes = read_bounded_at(proc, c"status", 64 * 1024, PROC_MAGIC, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("body target status is not UTF-8"))?;
    let mut lines = text.lines().filter_map(|line| line.strip_prefix("NSpid:"));
    let line = lines.next().ok_or_else(|| rejected("body target NSpid is absent"))?;
    if lines.next().is_some() { return Err(rejected("body target NSpid is duplicated")); }
    let mut count = 0usize;
    let mut last = 0u32;
    for token in line.split_ascii_whitespace() {
        let value = token.parse::<u32>().ok().filter(|value| *value > 0 && *value <= i32::MAX as u32)
            .ok_or_else(|| rejected("body target NSpid value is invalid"))?;
        if count == 0 && value != pid { return Err(rejected("body target NSpid host identity differs")); }
        count += 1;
        if count > 32 { return Err(rejected("body target PID namespace nesting exceeds its bound")); }
        last = value;
    }
    if count < 2 || last != 1 { return Err(rejected("body target is not the actual namespace-init supervisor")); }
    live(deadline)
}

fn read_cgroup_path(proc: RawFd, deadline: u64) -> Result<String> {
    let bytes = read_bounded_at(proc, c"cgroup", 16 * 1024, PROC_MAGIC, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("body target cgroup is not UTF-8"))?;
    let path = text.strip_prefix("0::").and_then(|value| value.strip_suffix('\n'))
        .filter(|value| canonical_path(value))
        .ok_or_else(|| rejected("body target lacks one canonical unified cgroup-v2 path"))?;
    live(deadline)?;
    Ok(path.to_owned())
}

fn require_cgroup_member(cgroup: RawFd, pid: u32, deadline: u64) -> Result<()> {
    let bytes = read_bounded_at(cgroup, c"cgroup.procs", 1024 * 1024, CGROUP2_MAGIC, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("body target cgroup membership is not UTF-8"))?;
    let mut found = false;
    let mut count = 0usize;
    for line in text.lines() {
        live(deadline)?;
        let value = line.parse::<u32>().ok().filter(|value| *value > 0 && *value <= i32::MAX as u32)
            .ok_or_else(|| rejected("body target cgroup member PID is invalid"))?;
        count += 1;
        if count > 65_536 { return Err(rejected("body target cgroup membership exceeds its source bound")); }
        found |= value == pid;
    }
    if !found { return Err(rejected("body target PID is not present in its held cgroup directory")); }
    live(deadline)
}

fn require_pidfd_state(fd: RawFd, terminated: bool, deadline: u64) -> Result<()> {
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
        if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0
            || (result != 0 && descriptor.revents & libc::POLLIN == 0)
            || (descriptor.revents & libc::POLLIN != 0) != terminated
        {
            return Err(rejected("body target pidfd is not in the required live or terminal state"));
        }
        return Ok(());
    }
}
