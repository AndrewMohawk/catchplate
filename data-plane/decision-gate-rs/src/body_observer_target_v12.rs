//! Receiving-side custody of the actual, still-gated body supervisor.
//!
//! The nine descriptors are independently joined to kernel observations, not
//! accepted as a caller-provided observation DTO. The launch's target_custody
//! remains an unsigned protocol echo: this owner neither invents its digest nor
//! treats it as authority. No tracing, signing, ready response or result exists
//! here. The independently admitted host service still owns its caller policy.

use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use crate::plan_protocol::body_launch_contract_v12::{
    CONTEXT_DIRECTORY, CONTEXT_NAME, RELEASE_NAME, MAX_CONTEXT_BYTES_V12,
};
use crate::plan_protocol::body_observer_contract_v12::BodyObserverLaunchV12;
use crate::runtime_evidence::{
    verify_static_executable_fd_bounded, ExecutableRole, StaticExecutableEvidenceV12,
};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const PROC_MAGIC: libc::c_long = 0x9fa0;
const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x10;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_KERNEL_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
struct NodeIdentity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    node: NodeIdentity, links: u64, size: u64,
    modified_sec: i64, modified_ns: i64, changed_sec: i64, changed_ns: i64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity { node: NodeIdentity, mount: u64 }

struct Namespace {
    fd: OwnedFd, name: &'static CStr, kind: i32, identity: NodeIdentity,
}

/// Actual retained descriptors, with no constructor from successful claims.
pub(crate) struct ReceivedBodyTargetV12 {
    owner_pid: libc::pid_t,
    host_pid: u32,
    start_ticks: u64,
    uid: u32,
    gid: u32,
    deadline: u64,
    proc_root: OwnedFd,
    proc_root_identity: NodeIdentity,
    fdinfo: OwnedFd,
    pidfd: OwnedFd,
    pidfd_identity: NodeIdentity,
    proc: OwnedFd,
    proc_identity: NodeIdentity,
    ns_directory: OwnedFd,
    ns_directory_identity: NodeIdentity,
    executable: OwnedFd,
    executable_identity: FileIdentity,
    _supervisor_static: StaticExecutableEvidenceV12,
    namespaces: Vec<Namespace>,
    cgroup_root: OwnedFd,
    cgroup_root_identity: NodeIdentity,
    cgroup: OwnedFd,
    cgroup_identity: NodeIdentity,
    cgroup_path: String,
    root: OwnedFd,
    root_identity: DirectoryIdentity,
    launch: OwnedFd,
    launch_identity: DirectoryIdentity,
    context: OwnedFd,
    context_identity: FileIdentity,
    context_mount: u64,
    context_original: Vec<u8>,
}

impl ReceivedBodyTargetV12 {
    pub(crate) fn acquire(launch: &BodyObserverLaunchV12, fds: [OwnedFd; 9],
        deadline: u64) -> PlanResult<Self> {
        root_owner()?;
        live(deadline)?;
        launch.validate()?;
        if deadline > launch.deadline_boottime_ns
            || deadline > launch.context.deadline_boottime_ns {
            return Err(invalid("received body target extends its original launch deadline"));
        }
        // Hold the complete selected originals/scalars before descriptor I/O.
        let host_pid = launch.target_pid;
        let start_ticks = launch.target_start;
        let expected_pidfd_inode = launch.target_pidfd_inode;
        let expected_executable: Digest = launch.context.runner.runtime_executable_sha256;
        let uid = launch.context.runner.execution_bounds.user_uid;
        let gid = launch.context.runner.execution_bounds.user_gid;
        let context_original = launch.context.original_bytes()?;
        if !(2..=i32::MAX as u32).contains(&host_pid) || start_ticks == 0
            || expected_pidfd_inode == 0 || expected_executable == [0; 32]
            || uid == 0 || gid == 0 {
            return Err(invalid("received body target lacks concrete independent launch scope"));
        }
        let mut distinct = BTreeSet::new();
        for fd in &fds {
            let raw = fd.as_raw_fd();
            let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            if raw < 3 || flags < 0 || flags & libc::FD_CLOEXEC == 0
                || !distinct.insert(raw) {
                return Err(invalid("received body target descriptors are not distinct close-on-exec custody"));
            }
        }
        live(deadline)?;
        let [pidfd, proc, executable, userns, mntns, pidns, netns, cgroupns, cgroup] = fds;
        let owner_pid = unsafe { libc::getpid() };
        let proc_root = open_directory(c"/proc", deadline)?;
        require_filesystem(proc_root.as_raw_fd(), PROC_MAGIC, deadline)?;
        let proc_root_identity = directory_node(proc_root.as_raw_fd(), deadline)?;
        let own_proc = open_at(proc_root.as_raw_fd(), c"self", true, true, deadline)?;
        if read_start_ticks(own_proc.as_raw_fd(), owner_pid as u32, deadline)? == 0 {
            return Err(invalid("observer does not have an actual host proc identity"));
        }
        require_process_status(own_proc.as_raw_fd(), owner_pid as u32, 0, 0, false, deadline)?;
        let fdinfo = open_at(own_proc.as_raw_fd(), c"fdinfo", true, false, deadline)?;
        require_filesystem(fdinfo.as_raw_fd(), PROC_MAGIC, deadline)?;
        let pidfd_identity = node_identity(pidfd.as_raw_fd(), deadline)?;
        if pidfd_identity.inode != expected_pidfd_inode {
            return Err(invalid("received pidfd inode differs from the handed-off launch scope"));
        }
        require_pidfd(pidfd.as_raw_fd(), fdinfo.as_raw_fd(), host_pid, deadline)?;
        let proc_identity = directory_node(proc.as_raw_fd(), deadline)?;
        require_filesystem(proc.as_raw_fd(), PROC_MAGIC, deadline)?;
        let named_proc = open_pid(proc_root.as_raw_fd(), host_pid, deadline)?;
        if directory_node(named_proc.as_raw_fd(), deadline)? != proc_identity
            || read_start_ticks(proc.as_raw_fd(), host_pid, deadline)? != start_ticks {
            return Err(invalid("received proc descriptor is not the exact live target"));
        }
        require_process_status(proc.as_raw_fd(), host_pid, uid, gid, true, deadline)?;
        let ns_directory = open_at(proc.as_raw_fd(), c"ns", true, false, deadline)?;
        let ns_directory_identity = directory_node(ns_directory.as_raw_fd(), deadline)?;
        let mut namespaces = Vec::with_capacity(5);
        for (fd, (name, kind)) in [userns, mntns, pidns, netns, cgroupns].into_iter().zip([
            (c"user", libc::CLONE_NEWUSER), (c"mnt", libc::CLONE_NEWNS),
            (c"pid", libc::CLONE_NEWPID), (c"net", libc::CLONE_NEWNET),
            (c"cgroup", libc::CLONE_NEWCGROUP),
        ]) {
            let identity = namespace_identity(fd.as_raw_fd(), kind, deadline)?;
            let named = open_at(ns_directory.as_raw_fd(), name, false, true, deadline)?;
            if namespace_identity(named.as_raw_fd(), kind, deadline)? != identity {
                return Err(invalid("received namespace descriptor belongs to another target"));
            }
            namespaces.push(Namespace { fd, name, kind, identity });
        }
        let executable_identity = immutable_executable(executable.as_raw_fd(), deadline)?;
        let named_executable = open_at(proc.as_raw_fd(), c"exe", false, true, deadline)?;
        if immutable_executable(named_executable.as_raw_fd(), deadline)? != executable_identity {
            return Err(invalid("received executable is not the actual target supervisor"));
        }
        let supervisor_static = verify_static_executable_fd_bounded(
            executable.as_raw_fd(), ExecutableRole::ControllerOwnedRunner,
            MAX_EXECUTABLE_BYTES, deadline,
        )?;
        if supervisor_static.content_sha256 != expected_executable
            || immutable_executable(executable.as_raw_fd(), deadline)? != executable_identity {
            return Err(invalid("received target does not execute the admitted immutable static supervisor"));
        }
        let cgroup_path = read_cgroup_path(proc.as_raw_fd(), deadline)?;
        let system_root = open_directory(c"/", deadline)?;
        let cgroup_root = open_components(system_root.as_raw_fd(), "/sys/fs/cgroup", deadline)?;
        require_filesystem(cgroup_root.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let cgroup_root_identity = directory_node(cgroup_root.as_raw_fd(), deadline)?;
        require_filesystem(cgroup.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let cgroup_identity = directory_node(cgroup.as_raw_fd(), deadline)?;
        let named_cgroup = open_components(cgroup_root.as_raw_fd(), &cgroup_path, deadline)?;
        if directory_node(named_cgroup.as_raw_fd(), deadline)? != cgroup_identity {
            return Err(invalid("received cgroup descriptor differs from actual proc membership"));
        }
        require_cgroup_member(cgroup.as_raw_fd(), host_pid, deadline)?;
        // Only source-fixed proc magic links are followed. Subsequent launch
        // resolution is one fixed no-follow child of this actual target root.
        let root = open_at(proc.as_raw_fd(), c"root", true, true, deadline)?;
        let root_identity = protected_directory(root.as_raw_fd(), false, fdinfo.as_raw_fd(), deadline)?;
        let launch_directory = open_launch(root.as_raw_fd(), deadline)?;
        let launch_identity = protected_directory(launch_directory.as_raw_fd(), true,
            fdinfo.as_raw_fd(), deadline)?;
        let context_name = fixed_name(CONTEXT_NAME)?;
        let context = open_at(launch_directory.as_raw_fd(), &context_name, false, false, deadline)?;
        let context_identity = protected_context(context.as_raw_fd(), deadline)?;
        let context_mount = mount_id(context.as_raw_fd(), fdinfo.as_raw_fd(), deadline)?;
        if context_mount != launch_identity.mount
            || read_original(context.as_raw_fd(), &context_identity, deadline)? != context_original {
            return Err(invalid("actual launch.json differs from the original received context"));
        }
        let held = Self {
            owner_pid, host_pid, start_ticks, uid, gid, deadline,
            proc_root, proc_root_identity, fdinfo, pidfd, pidfd_identity,
            proc, proc_identity, ns_directory, ns_directory_identity,
            executable, executable_identity, _supervisor_static: supervisor_static,
            namespaces, cgroup_root, cgroup_root_identity, cgroup, cgroup_identity, cgroup_path,
            root, root_identity, launch: launch_directory, launch_identity,
            context, context_identity, context_mount, context_original,
        };
        held.verify_gated(deadline)?;
        Ok(held)
    }

    pub(crate) fn host_pid(&self) -> u32 { self.host_pid }
    pub(crate) fn start_ticks(&self) -> u64 { self.start_ticks }
    pub(crate) fn pidfd(&self) -> RawFd { self.pidfd.as_raw_fd() }
    pub(crate) fn proc_fd(&self) -> RawFd { self.proc.as_raw_fd() }
    pub(crate) fn pid_namespace_fd(&self) -> RawFd { self.namespaces[2].fd.as_raw_fd() }
    pub(crate) fn pid_namespace_inode(&self) -> u64 { self.namespaces[2].identity.inode }
    pub(crate) fn deadline(&self) -> u64 { self.deadline }

    /// Borrow only this still-gated target's retained root for the fixed
    /// observer output acquisition. The caller must retain its own descriptor;
    /// this is not a post-death live-target verifier or arbitrary path inlet.
    pub(super) fn root_for_output(&self, launch: &BodyObserverLaunchV12,
        deadline: u64) -> PlanResult<RawFd> {
        launch.validate()?;
        if launch.context.original_bytes()? != self.context_original
            || launch.target_pid != self.host_pid || launch.target_start != self.start_ticks
            || launch.target_pidfd_inode != self.pidfd_identity.inode
            || deadline > launch.deadline_boottime_ns {
            return Err(invalid("observer output scope differs from the actual held target"));
        }
        self.verify_gated(deadline)?;
        Ok(self.root.as_raw_fd())
    }

    /// Live includes ptrace/group-stop states T/t, but never zombie/dead state.
    pub(crate) fn verify_live(&self, deadline: u64) -> PlanResult<()> {
        self.scope(deadline)?;
        if node_identity(self.pidfd.as_raw_fd(), deadline)? != self.pidfd_identity
            || directory_node(self.proc_root.as_raw_fd(), deadline)? != self.proc_root_identity {
            return Err(invalid("received target pidfd or proc root identity changed"));
        }
        require_filesystem(self.proc_root.as_raw_fd(), PROC_MAGIC, deadline)?;
        require_pidfd(self.pidfd.as_raw_fd(), self.fdinfo.as_raw_fd(), self.host_pid, deadline)?;
        let named_proc = open_pid(self.proc_root.as_raw_fd(), self.host_pid, deadline)?;
        if directory_node(self.proc.as_raw_fd(), deadline)? != self.proc_identity
            || directory_node(named_proc.as_raw_fd(), deadline)? != self.proc_identity
            || read_start_ticks(self.proc.as_raw_fd(), self.host_pid, deadline)? != self.start_ticks {
            return Err(invalid("received target process identity changed"));
        }
        require_process_status(self.proc.as_raw_fd(), self.host_pid, self.uid, self.gid, true, deadline)?;
        let ns_directory = open_at(self.proc.as_raw_fd(), c"ns", true, false, deadline)?;
        if directory_node(self.ns_directory.as_raw_fd(), deadline)? != self.ns_directory_identity
            || directory_node(ns_directory.as_raw_fd(), deadline)? != self.ns_directory_identity {
            return Err(invalid("received target namespace directory changed"));
        }
        for namespace in &self.namespaces {
            let named = open_at(ns_directory.as_raw_fd(), namespace.name, false, true, deadline)?;
            if namespace_identity(namespace.fd.as_raw_fd(), namespace.kind, deadline)? != namespace.identity
                || namespace_identity(named.as_raw_fd(), namespace.kind, deadline)? != namespace.identity {
                return Err(invalid("received target namespace identity changed"));
            }
        }
        let executable = open_at(self.proc.as_raw_fd(), c"exe", false, true, deadline)?;
        if immutable_executable(self.executable.as_raw_fd(), deadline)? != self.executable_identity
            || immutable_executable(executable.as_raw_fd(), deadline)? != self.executable_identity {
            return Err(invalid("received target no longer executes its retained static supervisor"));
        }
        require_filesystem(self.cgroup_root.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        require_filesystem(self.cgroup.as_raw_fd(), CGROUP2_MAGIC, deadline)?;
        let named_cgroup = open_components(self.cgroup_root.as_raw_fd(), &self.cgroup_path, deadline)?;
        if directory_node(self.cgroup_root.as_raw_fd(), deadline)? != self.cgroup_root_identity
            || directory_node(self.cgroup.as_raw_fd(), deadline)? != self.cgroup_identity
            || directory_node(named_cgroup.as_raw_fd(), deadline)? != self.cgroup_identity
            || read_cgroup_path(self.proc.as_raw_fd(), deadline)? != self.cgroup_path {
            return Err(invalid("received target cgroup identity changed"));
        }
        require_cgroup_member(self.cgroup.as_raw_fd(), self.host_pid, deadline)?;
        self.verify_context(deadline)?;
        if read_start_ticks(self.proc.as_raw_fd(), self.host_pid, deadline)? != self.start_ticks {
            return Err(invalid("received target changed during live revalidation"));
        }
        require_pidfd(self.pidfd.as_raw_fd(), self.fdinfo.as_raw_fd(), self.host_pid, deadline)?;
        self.scope(deadline)
    }

    pub(crate) fn verify_gated(&self, deadline: u64) -> PlanResult<()> {
        self.scope(deadline)?;
        require_release_absent(self.launch.as_raw_fd(), deadline)?;
        self.verify_live(deadline)?;
        require_release_absent(self.launch.as_raw_fd(), deadline)?;
        self.scope(deadline)
    }

    fn scope(&self, deadline: u64) -> PlanResult<()> {
        root_owner()?;
        if unsafe { libc::getpid() } != self.owner_pid || deadline > self.deadline {
            return Err(invalid("received body target crossed its process or original deadline"));
        }
        live(deadline)
    }

    fn verify_context(&self, deadline: u64) -> PlanResult<()> {
        let root = open_at(self.proc.as_raw_fd(), c"root", true, true, deadline)?;
        for fd in [self.root.as_raw_fd(), root.as_raw_fd()] {
            if protected_directory(fd, false, self.fdinfo.as_raw_fd(), deadline)? != self.root_identity {
                return Err(invalid("received target root custody changed"));
            }
        }
        let launch = open_launch(root.as_raw_fd(), deadline)?;
        for fd in [self.launch.as_raw_fd(), launch.as_raw_fd()] {
            if protected_directory(fd, true, self.fdinfo.as_raw_fd(), deadline)? != self.launch_identity {
                return Err(invalid("received target launch directory custody changed"));
            }
        }
        let context = open_at(launch.as_raw_fd(), &fixed_name(CONTEXT_NAME)?, false, false, deadline)?;
        for fd in [self.context.as_raw_fd(), context.as_raw_fd()] {
            if protected_context(fd, deadline)? != self.context_identity
                || mount_id(fd, self.fdinfo.as_raw_fd(), deadline)? != self.context_mount {
                return Err(invalid("received target launch original identity changed"));
            }
        }
        if read_original(self.context.as_raw_fd(), &self.context_identity, deadline)? != self.context_original {
            return Err(invalid("received target launch original bytes changed"));
        }
        live(deadline)
    }
}

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn root_owner() -> PlanResult<()> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(invalid("body observer target custody requires the actual root host owner"));
    }
    Ok(())
}

fn live(deadline: u64) -> PlanResult<()> {
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if clock.tv_sec < 0 || clock.tv_nsec < 0 || clock.tv_nsec >= 1_000_000_000
        || clock.tv_sec as u128 * 1_000_000_000 + clock.tv_nsec as u128 >= deadline as u128 {
        return Err(invalid("body observer target original deadline expired"));
    }
    Ok(())
}

fn stat(fd: RawFd, deadline: u64) -> PlanResult<libc::stat> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if fd < 3 || unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(invalid("body observer target descriptor cannot be measured"));
    }
    live(deadline)?;
    if value.st_ino == 0 { return Err(invalid("body observer target descriptor lacks an inode")); }
    Ok(value)
}

fn node(value: &libc::stat) -> NodeIdentity {
    NodeIdentity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid }
}

fn node_identity(fd: RawFd, deadline: u64) -> PlanResult<NodeIdentity> { Ok(node(&stat(fd, deadline)?)) }

fn directory_node(fd: RawFd, deadline: u64) -> PlanResult<NodeIdentity> {
    let value = stat(fd, deadline)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_nlink == 0 {
        return Err(invalid("body observer target directory descriptor is invalid"));
    }
    Ok(node(&value))
}

fn file_identity(value: &libc::stat) -> PlanResult<FileIdentity> {
    if value.st_size < 0 { return Err(invalid("body observer file has negative length")); }
    Ok(FileIdentity { node: node(value), links: value.st_nlink as u64, size: value.st_size as u64,
        modified_sec: value.st_mtime, modified_ns: value.st_mtime_nsec,
        changed_sec: value.st_ctime, changed_ns: value.st_ctime_nsec })
}

fn require_filesystem(fd: RawFd, expected: libc::c_long, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if value.f_type as u64 != expected as u64 { return Err(invalid("body observer target uses another kernel filesystem")); }
    Ok(())
}

fn readonly(fd: RawFd, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if value.f_flag & libc::ST_RDONLY == 0 { return Err(invalid("body target root or launch mount is writable")); }
    Ok(())
}

fn immutable_executable(fd: RawFd, deadline: u64) -> PlanResult<FileIdentity> {
    let value = stat(fd, deadline)?;
    let mut flags: libc::c_uint = 0;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_uid != 0
        || value.st_nlink != 1 || value.st_size <= 0 || value.st_size as u64 > MAX_EXECUTABLE_BYTES
        || value.st_mode & 0o022 != 0 || unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) } != 0
        || flags & FS_IMMUTABLE_FL == 0 {
        return Err(invalid("received executable lacks immutable root-owned regular custody"));
    }
    live(deadline)?;
    file_identity(&value)
}

fn namespace_identity(fd: RawFd, kind: i32, deadline: u64) -> PlanResult<NodeIdentity> {
    require_filesystem(fd, NSFS_MAGIC, deadline)?;
    let actual = unsafe { libc::ioctl(fd, NS_GET_NSTYPE) };
    live(deadline)?;
    if actual != kind { return Err(invalid("received namespace descriptor has the wrong kernel type")); }
    node_identity(fd, deadline)
}

fn open_directory(path: &CStr, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY
        | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(fd)
}

fn open_at(parent: RawFd, name: &CStr, directory: bool, kernel_link: bool,
    deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 }
        | if kernel_link { 0 } else { libc::O_NOFOLLOW };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    Ok(fd)
}

fn fixed_name(name: &str) -> PlanResult<CString> {
    if name.is_empty() || name.len() > 255 || name.contains('/') || matches!(name, "." | "..") {
        return Err(invalid("body observer source leaf name is invalid"));
    }
    CString::new(name).map_err(|_| invalid("body observer source leaf contains NUL"))
}

fn open_pid(proc_root: RawFd, pid: u32, deadline: u64) -> PlanResult<OwnedFd> {
    open_at(proc_root, &fixed_name(&pid.to_string())?, true, false, deadline)
}

fn canonical_path(path: &str) -> bool {
    path.len() > 1 && path.len() <= MAX_PATH_BYTES && path.starts_with('/') && !path.ends_with('/')
        && !path.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f || byte == b'\\')
        && path[1..].split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn open_components(root: RawFd, path: &str, deadline: u64) -> PlanResult<OwnedFd> {
    if !canonical_path(path) { return Err(invalid("actual body cgroup path is noncanonical")); }
    let mut directory = open_at(root, c".", true, false, deadline)?;
    for component in path[1..].split('/') {
        directory = open_at(directory.as_raw_fd(), &fixed_name(component)?, true, false, deadline)?;
    }
    Ok(directory)
}

fn read_bounded(fd: RawFd, maximum: usize, deadline: u64) -> PlanResult<Vec<u8>> {
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
        if count as usize > maximum - bytes.len() { return Err(invalid("body target original exceeds its source byte cap")); }
        bytes.extend_from_slice(&buffer[..count as usize]);
    }
}

fn read_kernel(parent: RawFd, name: &CStr, maximum: usize, filesystem: libc::c_long,
    deadline: u64) -> PlanResult<Vec<u8>> {
    let fd = open_at(parent, name, false, false, deadline)?;
    require_filesystem(fd.as_raw_fd(), filesystem, deadline)?;
    let before = node_identity(fd.as_raw_fd(), deadline)?;
    if before.mode & libc::S_IFMT != libc::S_IFREG { return Err(invalid("body observation is not a regular kernel pseudo-file")); }
    let bytes = read_bounded(fd.as_raw_fd(), maximum, deadline)?;
    if node_identity(fd.as_raw_fd(), deadline)? != before { return Err(invalid("body kernel pseudo-file identity changed")); }
    Ok(bytes)
}

fn text(bytes: &[u8]) -> PlanResult<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("body target kernel observation is not UTF-8"))
}

fn one_field<'a>(text: &'a str, prefix: &str) -> PlanResult<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next().ok_or_else(|| invalid("body target kernel field is absent"))?;
    if values.next().is_some() { return Err(invalid("body target kernel field is duplicated")); }
    Ok(value.trim())
}

fn mount_id(fd: RawFd, fdinfo: RawFd, deadline: u64) -> PlanResult<u64> {
    let bytes = read_kernel(fdinfo, &fixed_name(&fd.to_string())?, MAX_KERNEL_BYTES, PROC_MAGIC, deadline)?;
    one_field(text(&bytes)?, "mnt_id:")?.parse::<u64>().ok().filter(|value| *value > 0)
        .ok_or_else(|| invalid("body target descriptor lacks a positive kernel mount identity"))
}

fn require_pidfd(fd: RawFd, fdinfo: RawFd, pid: u32, deadline: u64) -> PlanResult<()> {
    let bytes = read_kernel(fdinfo, &fixed_name(&fd.to_string())?, MAX_KERNEL_BYTES, PROC_MAGIC, deadline)?;
    if one_field(text(&bytes)?, "Pid:")?.parse::<u32>().ok() != Some(pid) {
        return Err(invalid("received pidfd does not identify the actual held host PID"));
    }
    loop {
        live(deadline)?;
        let mut item = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let status = unsafe { libc::poll(&mut item, 1, 0) };
        let error = (status < 0).then(std::io::Error::last_os_error);
        live(deadline)?;
        if let Some(error) = error {
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if status != 0 || item.revents != 0 { return Err(invalid("received body pidfd is not live")); }
        return Ok(());
    }
}

fn read_start_ticks(proc: RawFd, pid: u32, deadline: u64) -> PlanResult<u64> {
    let bytes = read_kernel(proc, c"stat", MAX_KERNEL_BYTES, PROC_MAGIC, deadline)?;
    let value = text(&bytes)?;
    let open = value.find('(').ok_or_else(|| invalid("body target stat lacks its command"))?;
    let close = value.rfind(')').ok_or_else(|| invalid("body target stat lacks its command terminator"))?;
    if close <= open || value[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err(invalid("body target stat belongs to another PID"));
    }
    let mut fields = value[close + 1..].split_ascii_whitespace();
    let state = fields.next().ok_or_else(|| invalid("body target stat lacks state"))?;
    if state.len() != 1 || matches!(state, "Z" | "X" | "x") {
        return Err(invalid("body target stat is terminal"));
    }
    // T/t are live kernel states, not proof that this owner stopped anything.
    // The separate read-only gate additionally requires an untraced state.
    fields.nth(18).and_then(|value| value.parse::<u64>().ok()).filter(|value| *value > 0)
        .ok_or_else(|| invalid("body target start ticks are absent or invalid"))
}

fn require_process_status(proc: RawFd, pid: u32, uid: u32, gid: u32, namespace_init: bool,
    deadline: u64) -> PlanResult<()> {
    let bytes = read_kernel(proc, c"status", 64 * 1024, PROC_MAGIC, deadline)?;
    let status = text(&bytes)?;
    for (field, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let values: Vec<_> = one_field(status, field)?.split_ascii_whitespace().collect();
        if values.len() != 4 || values.iter().any(|value| value.parse::<u32>().ok() != Some(expected)) {
            return Err(invalid("body target process credentials differ from its retained scope"));
        }
    }
    let mut count = 0usize;
    let mut last = 0u32;
    for value in one_field(status, "NSpid:")?.split_ascii_whitespace() {
        let current = value.parse::<u32>().ok().filter(|value| *value > 0 && *value <= i32::MAX as u32)
            .ok_or_else(|| invalid("body target namespace PID is invalid"))?;
        if count == 0 && current != pid { return Err(invalid("body target namespace host PID differs")); }
        count += 1;
        if count > 32 { return Err(invalid("body target PID namespace nesting is excessive")); }
        last = current;
    }
    if (namespace_init && (count < 2 || last != 1)) || (!namespace_init && (count != 1 || last != pid)) {
        return Err(invalid("body target or observer is outside its actual host/namespace-init role"));
    }
    live(deadline)
}

fn read_cgroup_path(proc: RawFd, deadline: u64) -> PlanResult<String> {
    let bytes = read_kernel(proc, c"cgroup", MAX_KERNEL_BYTES, PROC_MAGIC, deadline)?;
    let path = text(&bytes)?.strip_prefix("0::").and_then(|value| value.strip_suffix('\n'))
        .filter(|value| canonical_path(value))
        .ok_or_else(|| invalid("body target lacks one exact unified cgroup-v2 path"))?;
    Ok(path.to_owned())
}

fn require_cgroup_member(cgroup: RawFd, pid: u32, deadline: u64) -> PlanResult<()> {
    let bytes = read_kernel(cgroup, c"cgroup.procs", 1024 * 1024, CGROUP2_MAGIC, deadline)?;
    let mut found = false;
    for (index, line) in text(&bytes)?.lines().enumerate() {
        live(deadline)?;
        if index >= 65_536 { return Err(invalid("body target cgroup membership exceeds its source bound")); }
        let value = line.parse::<u32>().ok().filter(|value| *value > 0 && *value <= i32::MAX as u32)
            .ok_or_else(|| invalid("body target cgroup member PID is invalid"))?;
        found |= value == pid;
    }
    if !found { return Err(invalid("body target is absent from its received cgroup descriptor")); }
    live(deadline)
}

fn protected_directory(fd: RawFd, launch: bool, fdinfo: RawFd, deadline: u64)
    -> PlanResult<DirectoryIdentity> {
    let identity = directory_node(fd, deadline)?;
    if identity.uid != 0 || identity.gid != 0 || identity.mode & 0o022 != 0
        || (launch && identity.mode & 0o7777 != 0o555) {
        return Err(invalid("body target root/launch directory is not protected root custody"));
    }
    readonly(fd, deadline)?;
    Ok(DirectoryIdentity { node: identity, mount: mount_id(fd, fdinfo, deadline)? })
}

fn open_launch(root: RawFd, deadline: u64) -> PlanResult<OwnedFd> {
    let name = CONTEXT_DIRECTORY.strip_prefix('/').ok_or_else(|| invalid("fixed body launch path is invalid"))?;
    open_at(root, &fixed_name(name)?, true, false, deadline)
}

fn protected_context(fd: RawFd, deadline: u64) -> PlanResult<FileIdentity> {
    let value = stat(fd, deadline)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_mode & 0o7777 != 0o444
        || value.st_uid != 0 || value.st_gid != 0 || value.st_nlink != 1
        || value.st_size <= 0 || value.st_size as u64 > MAX_CONTEXT_BYTES_V12 as u64 {
        return Err(invalid("body target launch.json is not its protected bounded original"));
    }
    readonly(fd, deadline)?;
    file_identity(&value)
}

fn read_original(fd: RawFd, expected: &FileIdentity, deadline: u64) -> PlanResult<Vec<u8>> {
    if protected_context(fd, deadline)? != *expected { return Err(invalid("body launch original identity changed before read")); }
    let bytes = read_bounded(fd, expected.size as usize, deadline)?;
    if bytes.len() as u64 != expected.size || protected_context(fd, deadline)? != *expected {
        return Err(invalid("body launch original changed during bounded read"));
    }
    Ok(bytes)
}

fn require_release_absent(launch: RawFd, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::fstatat(launch, fixed_name(RELEASE_NAME)?.as_ptr(),
        &mut value, libc::AT_SYMLINK_NOFOLLOW) };
    let error = (result < 0).then(std::io::Error::last_os_error);
    live(deadline)?;
    match error {
        Some(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Some(error) => Err(error.into()),
        None => Err(invalid("body target was released before receiving-side gated custody")),
    }
}
