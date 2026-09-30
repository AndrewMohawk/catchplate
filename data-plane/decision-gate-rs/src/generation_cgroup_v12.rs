//! Source-fixed cgroup2 delegation and generation process custody.
//!
//! The systemd254+ service runs in its delegated `supervisor` leaf. Generation
//! parents contain no processes: dockerd enters `daemon` before exec and its
//! containers use the sibling `containers` subtree. Kernel control files are
//! never fsynced. Cleanup only kills and removes this fixed cgroup hierarchy;
//! it does not delete ordinary filesystem trees or enroll target authority.

use super::{boottime_now_ns_v11, ControllerError, Result};
use super::runner_output_storage_v12::fd_mount_id;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};

const DELEGATED_ROOT: &str = "/sys/fs/cgroup/system.slice/serverware-coder-lifecycle-privileged-v12.service";
const HIERARCHY_ROOT: &str = "/system.slice/serverware-coder-lifecycle-privileged-v12.service";
const GENERATION_PREFIX: &str = "serverware-coder-v12-";
const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
const PROC_MAGIC: libc::c_long = 0x9fa0;
const MAX_CONTROL_BYTES: usize = 128 * 1024;
const MAX_GROUPS: usize = 4096;
const MAX_DEPTH: usize = 32;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

fn rejected(message: &'static str) -> ControllerError { ControllerError::Rejected(message) }

fn live(deadline: u64) -> Result<()> {
    if boottime_now_ns_v11()? >= deadline {
        return Err(rejected("generation cgroup original deadline expired"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

fn identity(fd: RawFd) -> Result<Identity> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Identity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid })
}

fn filesystem(fd: RawFd, expected: libc::c_long) -> Result<()> {
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.f_type as u64 != expected as u64 { return Err(rejected("generation control has an unexpected filesystem")); }
    Ok(())
}

fn directory(fd: RawFd) -> Result<Identity> {
    filesystem(fd, CGROUP2_MAGIC)?;
    let value = identity(fd)?;
    if value.mode & libc::S_IFMT != libc::S_IFDIR || value.uid != 0 || value.gid != 0
        || value.mode & 0o022 != 0 {
        return Err(rejected("generation cgroup is not a root-owned private directory"));
    }
    Ok(value)
}

fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> Result<OwnedFd> {
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn absolute_directory(path: &Path) -> Result<OwnedFd> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(rejected("generation cgroup path is not bounded and absolute"));
    }
    let mut held = open_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let text = name.to_str().ok_or_else(|| rejected("generation cgroup path is not UTF8"))?;
                let name = CString::new(text).map_err(|_| rejected("generation cgroup path contains NUL"))?;
                held = open_at(held.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let value = identity(held.as_raw_fd())?;
                if value.uid != 0 || value.gid != 0 || value.mode & 0o022 != 0 {
                    return Err(rejected("generation cgroup ancestor is not protected root custody"));
                }
            }
            _ => return Err(rejected("generation cgroup path is not canonical")),
        }
    }
    directory(held.as_raw_fd())?;
    Ok(held)
}

fn bounded_read(fd: RawFd, maximum: usize, deadline: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; maximum + 1];
    let mut offset = 0;
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(fd, bytes[offset..].as_mut_ptr().cast(),
            bytes.len() - offset, offset as libc::off_t) };
        live(deadline)?;
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 { bytes.truncate(offset); return Ok(bytes); }
        offset += count as usize;
        if offset > maximum { return Err(rejected("generation kernel control exceeds its source bound")); }
    }
}

fn control(group: RawFd, name: &CStr, writable: bool) -> Result<OwnedFd> {
    let fd = open_at(group, name, if writable { libc::O_WRONLY } else { libc::O_RDONLY })?;
    filesystem(fd.as_raw_fd(), CGROUP2_MAGIC)?;
    let value = identity(fd.as_raw_fd())?;
    if value.mode & libc::S_IFMT != libc::S_IFREG || value.uid != 0 || value.gid != 0
        || value.mode & 0o022 != 0 || fd_mount_id(fd.as_raw_fd())? != fd_mount_id(group)? {
        return Err(rejected("generation kernel control is not held root-owned cgroup2"));
    }
    Ok(fd)
}

fn read_control(group: RawFd, name: &CStr, deadline: u64) -> Result<Vec<u8>> {
    live(deadline)?;
    let fd = control(group, name, false)?;
    bounded_read(fd.as_raw_fd(), MAX_CONTROL_BYTES, deadline)
}

fn write_control(group: RawFd, name: &CStr, bytes: &[u8], deadline: u64) -> Result<()> {
    let fd = control(group, name, true)?;
    loop {
        live(deadline)?;
        let written = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        live(deadline)?;
        if written == bytes.len() as isize { return Ok(()); }
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        return Err(rejected("generation kernel control write was partial"));
    }
}

fn membership(pid: u32, deadline: u64) -> Result<String> {
    if pid == 0 || pid > i32::MAX as u32 { return Err(rejected("generation process PID is invalid")); }
    let proc = open_at(libc::AT_FDCWD, c"/proc", libc::O_RDONLY | libc::O_DIRECTORY)?;
    filesystem(proc.as_raw_fd(), PROC_MAGIC)?;
    let name = CString::new(pid.to_string()).map_err(|_| rejected("generation PID encoding failed"))?;
    let process = open_at(proc.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let file = open_at(process.as_raw_fd(), c"cgroup", libc::O_RDONLY)?;
    filesystem(file.as_raw_fd(), PROC_MAGIC)?;
    let bytes = bounded_read(file.as_raw_fd(), 4096, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("generation process cgroup is not UTF8"))?;
    let path = text.strip_prefix("0::").and_then(|value| value.strip_suffix('\n'))
        .ok_or_else(|| rejected("generation process is not in one unified cgroup"))?;
    if !path.starts_with('/') || path.contains('\n') || path.contains(" (deleted)") {
        return Err(rejected("generation process membership is not one live absolute cgroup"));
    }
    Ok(path.to_owned())
}

fn delegated(require_caller: bool, deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    if unsafe { libc::geteuid() } != 0 { return Err(rejected("generation cgroup owner must be root")); }
    let root = absolute_directory(Path::new(DELEGATED_ROOT))?;
    let mut value = [0u8; 2];
    let count = unsafe { libc::fgetxattr(root.as_raw_fd(), c"user.delegate".as_ptr(),
        value.as_mut_ptr().cast(), value.len()) };
    if count != 1 || value[0] != b'1' {
        return Err(rejected("generation service root is not actually systemd-delegated"));
    }
    if require_caller && membership(unsafe { libc::getpid() } as u32, deadline)?
        != format!("{HIERARCHY_ROOT}/supervisor") {
        return Err(rejected("generation controller is not in the delegated supervisor leaf"));
    }
    live(deadline)?;
    Ok(root)
}

fn generation_name(path: &Path) -> Result<CString> {
    let text = path.to_str().ok_or_else(|| rejected("generation path is not UTF8"))?;
    let prefix = format!("{DELEGATED_ROOT}/");
    let name = text.strip_prefix(&prefix).ok_or_else(|| rejected("generation target is outside its fixed delegation"))?;
    if name.len() > 255 || !name.starts_with(GENERATION_PREFIX) || name.len() == GENERATION_PREFIX.len()
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
        return Err(rejected("generation target is not one source-owned cgroup child"));
    }
    CString::new(name).map_err(|_| rejected("generation target contains NUL"))
}

fn domain(group: RawFd, empty: bool, deadline: u64) -> Result<()> {
    if read_control(group, c"cgroup.type", deadline)? != b"domain\n" {
        return Err(rejected("generation cgroup is not a valid domain"));
    }
    if empty && !read_control(group, c"cgroup.procs", deadline)?.is_empty() {
        return Err(rejected("generation domain parent contains direct processes"));
    }
    Ok(())
}

fn enabled(group: RawFd, deadline: u64) -> Result<BTreeSet<String>> {
    let bytes = read_control(group, c"cgroup.subtree_control", deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("generation controllers are not UTF8"))?;
    Ok(text.split_ascii_whitespace().map(str::to_owned).collect())
}

fn enable(group: RawFd, service_root: bool, deadline: u64) -> Result<()> {
    domain(group, true, deadline)?;
    let bytes = read_control(group, c"cgroup.controllers", deadline)?;
    let available = std::str::from_utf8(&bytes).map_err(|_| rejected("generation available controllers are not UTF8"))?;
    let available: BTreeSet<_> = available.split_ascii_whitespace().collect();
    if CONTROLLERS.iter().any(|name| !available.contains(name)) {
        return Err(rejected("generation requires delegated cpu memory and pids controllers"));
    }
    write_control(group, c"cgroup.subtree_control", b"+cpu +memory +pids\n", deadline)?;
    let actual = enabled(group, deadline)?;
    if CONTROLLERS.iter().any(|name| !actual.contains(*name)) || (!service_root && actual.len() != 3) {
        return Err(rejected("generation controller activation differs from its fixed source set"));
    }
    domain(group, true, deadline)
}

fn mkdir(parent: RawFd, name: &CStr, deadline: u64) -> Result<OwnedFd> {
    live(deadline)?;
    if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    directory(fd.as_raw_fd())?;
    if fd_mount_id(fd.as_raw_fd())? != fd_mount_id(parent)? {
        return Err(rejected("generation child crossed its held cgroup mount"));
    }
    live(deadline)?;
    Ok(fd)
}

#[derive(Debug)]
pub(super) struct HeldGenerationCgroupV12 {
    root: OwnedFd, generation: OwnedFd, daemon: OwnedFd, containers: OwnedFd,
    daemon_procs: OwnedFd, name: CString,
    root_identity: Identity, generation_identity: Identity,
    daemon_identity: Identity, containers_identity: Identity,
    mount: u64, owner_pid: libc::pid_t, deadline: u64,
    daemon_path: String, containers_path: String,
}

impl HeldGenerationCgroupV12 {
    pub(super) fn create(path: &Path, deadline: u64) -> Result<Self> {
        let name = generation_name(path)?;
        let root = delegated(true, deadline)?;
        enable(root.as_raw_fd(), true, deadline)?;
        let generation = mkdir(root.as_raw_fd(), &name, deadline)?;
        enable(generation.as_raw_fd(), false, deadline)?;
        let daemon = mkdir(generation.as_raw_fd(), c"daemon", deadline)?;
        let containers = mkdir(generation.as_raw_fd(), c"containers", deadline)?;
        enable(containers.as_raw_fd(), false, deadline)?;
        domain(daemon.as_raw_fd(), true, deadline)?;
        if !enabled(daemon.as_raw_fd(), deadline)?.is_empty() {
            return Err(rejected("generation daemon is not a controller-free leaf"));
        }
        let daemon_procs = control(daemon.as_raw_fd(), c"cgroup.procs", true)?;
        let name_text = name.to_str().map_err(|_| rejected("generation name changed encoding"))?;
        let held = Self {
            root_identity: directory(root.as_raw_fd())?, generation_identity: directory(generation.as_raw_fd())?,
            daemon_identity: directory(daemon.as_raw_fd())?, containers_identity: directory(containers.as_raw_fd())?,
            mount: fd_mount_id(root.as_raw_fd())?, owner_pid: unsafe { libc::getpid() }, deadline,
            daemon_path: format!("{HIERARCHY_ROOT}/{name_text}/daemon"),
            containers_path: format!("{HIERARCHY_ROOT}/{name_text}/containers"),
            root, generation, daemon, containers, daemon_procs, name,
        };
        live(deadline)?;
        Ok(held)
    }

    pub(super) fn container_parent(&self) -> &str { &self.containers_path }

    /// Caller must be the freshly forked child, before any exec or fork of its
    /// own. Only async-signal-safe libc and stack integer formatting are used.
    pub(super) unsafe fn enter_daemon_before_exec(&self) -> std::io::Result<()> {
        let pid = libc::getpid();
        if pid <= 0 || pid == self.owner_pid { return Err(std::io::Error::from_raw_os_error(libc::EPERM)); }
        let mut clock: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if clock.tv_sec < 0 || clock.tv_nsec < 0 || clock.tv_nsec >= 1_000_000_000
            || clock.tv_sec as u128 * 1_000_000_000 + clock.tv_nsec as u128 >= self.deadline as u128 {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut bytes = [0u8; 32];
        let mut offset = bytes.len() - 1;
        bytes[offset] = b'\n';
        let mut value = pid as u32;
        while value != 0 { offset -= 1; bytes[offset] = b'0' + (value % 10) as u8; value /= 10; }
        loop {
            if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if clock.tv_sec < 0 || clock.tv_nsec < 0 || clock.tv_nsec >= 1_000_000_000
                || clock.tv_sec as u128 * 1_000_000_000 + clock.tv_nsec as u128 >= self.deadline as u128 {
                return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
            }
            let count = libc::write(self.daemon_procs.as_raw_fd(), bytes[offset..].as_ptr().cast(), bytes.len() - offset);
            if count == (bytes.len() - offset) as isize { break; }
            if count < 0 && *libc::__errno_location() == libc::EINTR { continue; }
            if count < 0 { return Err(std::io::Error::last_os_error()); }
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if clock.tv_sec < 0 || clock.tv_nsec < 0 || clock.tv_nsec >= 1_000_000_000
            || clock.tv_sec as u128 * 1_000_000_000 + clock.tv_nsec as u128 >= self.deadline as u128 {
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        Ok(())
    }

    pub(super) fn verify_daemon(&self, pid: u32, deadline: u64) -> Result<()> {
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid { return Err(rejected("generation owner crossed a process boundary")); }
        let current = delegated(true, deadline)?;
        if directory(current.as_raw_fd())? != self.root_identity || fd_mount_id(current.as_raw_fd())? != self.mount {
            return Err(rejected("generation delegated root changed"));
        }
        for (parent, name, held, expected) in [
            (self.root.as_raw_fd(), self.name.as_c_str(), self.generation.as_raw_fd(), self.generation_identity),
            (self.generation.as_raw_fd(), c"daemon", self.daemon.as_raw_fd(), self.daemon_identity),
            (self.generation.as_raw_fd(), c"containers", self.containers.as_raw_fd(), self.containers_identity),
        ] {
            let named = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            if directory(named.as_raw_fd())? != expected || directory(held)? != expected
                || fd_mount_id(named.as_raw_fd())? != self.mount || fd_mount_id(held)? != self.mount {
                return Err(rejected("generation held hierarchy changed"));
            }
        }
        domain(self.root.as_raw_fd(), true, deadline)?;
        domain(self.generation.as_raw_fd(), true, deadline)?;
        domain(self.containers.as_raw_fd(), true, deadline)?;
        domain(self.daemon.as_raw_fd(), false, deadline)?;
        for (group, exact) in [(self.root.as_raw_fd(), false),
            (self.generation.as_raw_fd(), true), (self.containers.as_raw_fd(), true)] {
            let actual = enabled(group, deadline)?;
            if CONTROLLERS.iter().any(|name| !actual.contains(*name)) || (exact && actual.len() != 3) {
                return Err(rejected("generation held controller activation changed"));
            }
        }
        if !enabled(self.daemon.as_raw_fd(), deadline)?.is_empty() {
            return Err(rejected("generation daemon ceased to be a controller-free leaf"));
        }
        if membership(pid, deadline)? != self.daemon_path {
            return Err(rejected("actual daemon did not enter its held leaf before execution"));
        }
        let bytes = read_control(self.daemon.as_raw_fd(), c"cgroup.procs", deadline)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| rejected("daemon cgroup process list is not UTF8"))?;
        if !text.lines().any(|line| line.parse::<u32>().ok() == Some(pid)) {
            return Err(rejected("actual daemon PID is absent from its held leaf"));
        }
        live(deadline)
    }
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }

fn children(group: RawFd, deadline: u64) -> Result<Vec<CString>> {
    let duplicate = open_at(group, c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    use std::os::fd::IntoRawFd;
    let raw = duplicate.into_raw_fd();
    let pointer = unsafe { libc::fdopendir(raw) };
    if pointer.is_null() { unsafe { libc::close(raw); } return Err(std::io::Error::last_os_error().into()); }
    let stream = DirectoryStream(pointer);
    let mut names = Vec::new();
    let mut count = 0;
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 { return Err(std::io::Error::from_raw_os_error(error).into()); }
            break;
        }
        count += 1;
        if count > MAX_DIRECTORY_ENTRIES { return Err(rejected("generation cgroup directory inventory is excessive")); }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") { continue; }
        if name.to_bytes().len() > 255 || !name.to_bytes().iter().all(|&byte|
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) {
            return Err(rejected("generation cgroup child name is not source-bounded"));
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(group, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => names.push(name.to_owned()),
            libc::S_IFREG => {}
            _ => return Err(rejected("generation cgroup contains a non-kernel entry")),
        }
    }
    names.sort();
    live(deadline)?;
    Ok(names)
}

fn populated(group: RawFd, deadline: u64) -> Result<bool> {
    let bytes = read_control(group, c"cgroup.events", deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| rejected("generation events are not UTF8"))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("populated "));
    let value = values.next().ok_or_else(|| rejected("generation events lack population state"))?;
    if values.next().is_some() || !matches!(value, "0" | "1") {
        return Err(rejected("generation population state is malformed"));
    }
    Ok(value == "1")
}

fn remove_empty(parent: RawFd, name: &CStr, group: RawFd, mount: u64,
    depth: usize, remaining: &mut usize, deadline: u64) -> Result<()> {
    live(deadline)?;
    if depth > MAX_DEPTH || *remaining == 0 { return Err(rejected("generation cgroup cleanup inventory exceeds its bound")); }
    *remaining -= 1;
    let expected = directory(group)?;
    if fd_mount_id(group)? != mount || populated(group, deadline)? {
        return Err(rejected("generation cgroup cleanup crossed a mount or retained processes"));
    }
    for child in children(group, deadline)? {
        let fd = open_at(group, &child, libc::O_RDONLY | libc::O_DIRECTORY)?;
        remove_empty(group, &child, fd.as_raw_fd(), mount, depth + 1, remaining, deadline)?;
    }
    let named = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if directory(named.as_raw_fd())? != expected || fd_mount_id(named.as_raw_fd())? != mount
        || populated(group, deadline)? {
        return Err(rejected("generation cgroup identity changed before removal"));
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)
}

pub(super) fn remove_generation(path: &Path, deadline: u64) -> Result<()> {
    let name = generation_name(path)?;
    let root = match delegated(false, deadline) {
        Ok(root) => root,
        Err(ControllerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return live(deadline),
        Err(error) => return Err(error),
    };
    let generation = match open_at(root.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(group) => group,
        Err(ControllerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return live(deadline),
        Err(error) => return Err(error),
    };
    directory(generation.as_raw_fd())?;
    let mount = fd_mount_id(root.as_raw_fd())?;
    if fd_mount_id(generation.as_raw_fd())? != mount { return Err(rejected("generation kill crossed its delegated mount")); }
    write_control(generation.as_raw_fd(), c"cgroup.kill", b"1\n", deadline)?;
    while populated(generation.as_raw_fd(), deadline)? {
        live(deadline)?;
        if unsafe { libc::poll(std::ptr::null_mut(), 0, 10) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
        }
    }
    let mut remaining = MAX_GROUPS;
    remove_empty(root.as_raw_fd(), &name, generation.as_raw_fd(), mount, 0, &mut remaining, deadline)
}

pub(super) fn require_no_generation_children(root_path: &Path, deadline: u64) -> Result<()> {
    if root_path != Path::new(DELEGATED_ROOT) { return Err(rejected("generation startup root differs from source delegation")); }
    let root = match delegated(false, deadline) {
        Ok(root) => root,
        Err(ControllerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return live(deadline),
        Err(error) => return Err(error),
    };
    domain(root.as_raw_fd(), true, deadline)?;
    let mount = fd_mount_id(root.as_raw_fd())?;
    for name in children(root.as_raw_fd(), deadline)? {
        if !matches!(name.to_bytes(), b"supervisor" | b".control") {
            return Err(rejected("delegated root retains an unledgered generation or foreign subgroup"));
        }
        let leaf = open_at(root.as_raw_fd(), &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        directory(leaf.as_raw_fd())?;
        domain(leaf.as_raw_fd(), false, deadline)?;
        if fd_mount_id(leaf.as_raw_fd())? != mount || !children(leaf.as_raw_fd(), deadline)?.is_empty()
            || !enabled(leaf.as_raw_fd(), deadline)?.is_empty() {
            return Err(rejected("systemd supervisor/control subgroup is not an exact domain leaf"));
        }
    }
    live(deadline)
}
