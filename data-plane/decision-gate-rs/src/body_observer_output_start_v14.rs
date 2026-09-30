//! Actual read-only output custody acquired through the still-gated target.
//!
//! The destination comes only from the joined original launch context, not a
//! new path parameter or an assumed `/output`. Files are retained before
//! release. Later anchor checks deliberately tolerate writes and directory
//! timestamp changes: they prove neither stream EOF nor final output, actual
//! exit status, storage durability, a complete tmpfs profile or permission to
//! resume/sign. No create, write, hash, terminal publication or recovery exists.
//! This acquisition narrows otherwise admitted mount destinations to at most
//! 32 literal components and 4096 bytes; it never normalizes an alternate path.

use super::body_observer_target_v12::ReceivedBodyTargetV12;
use crate::plan_protocol::body_observer_contract_v12::BodyObserverLaunchV12;
use crate::plan_protocol::body_output_contract_v12::{
    stream_byte_limit, CONTROL_DIRECTORY, STDOUT_NAME, STDERR_NAME,
};
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::rc::Rc;

const PROC_MAGIC: libc::c_long = 0x9fa0;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENTS: usize = 32;
const MAX_FDINFO_BYTES: usize = 16 * 1024;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn live(deadline: u64) -> PlanResult<()> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid("observer output clock is invalid"));
    }
    let now = (value.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("observer output clock overflows"))?;
    if now >= deadline { return Err(invalid("observer output original deadline expired")); }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Node { device: u64, inode: u64, mode: u32, uid: u32, gid: u32 }

#[derive(Eq, PartialEq)]
struct InitialStamp {
    node: Node, links: u64, bytes: i64,
    modified_sec: i64, modified_ns: i64, changed_sec: i64, changed_ns: i64,
}

fn initial_stamp(fd: RawFd, deadline: u64) -> PlanResult<InitialStamp> {
    let value = stat(fd, deadline)?;
    Ok(InitialStamp { node: node(&value), links: value.st_nlink, bytes: value.st_size,
        modified_sec: value.st_mtime, modified_ns: value.st_mtime_nsec,
        changed_sec: value.st_ctime, changed_ns: value.st_ctime_nsec })
}

fn stat(fd: RawFd, deadline: u64) -> PlanResult<libc::stat> {
    live(deadline)?;
    let mut value = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    live(deadline)?;
    Ok(value)
}

fn node(value: &libc::stat) -> Node {
    Node { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid }
}

fn filesystem(fd: RawFd, expected: libc::c_long, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if value.f_type as u64 != expected as u64 { return Err(invalid("observer output filesystem differs")); }
    live(deadline)
}

fn open_at(parent: RawFd, name: &CStr, directory: bool, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let raw = unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY
        | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if raw < 3 { return Err(invalid("observer output descriptor aliases stdio")); }
    live(deadline)?;
    Ok(fd)
}

fn name(value: &str) -> PlanResult<CString> {
    if value.is_empty() || value.len() > 255 || !value.is_ascii()
        || value.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f)
        || value.contains('/') || matches!(value, "." | "..") {
        return Err(invalid("observer output name is not a bounded literal component"));
    }
    CString::new(value).map_err(|_| invalid("observer output name contains NUL"))
}

fn output_components(path: &str) -> PlanResult<Vec<CString>> {
    if path.len() > MAX_PATH_BYTES || !path.starts_with('/') || path.ends_with('/') {
        return Err(invalid("observer output destination is not bounded absolute scope"));
    }
    let components: Vec<_> = path[1..].split('/').collect();
    if components.is_empty() || components.len() > MAX_COMPONENTS {
        return Err(invalid("observer output destination has excessive depth"));
    }
    components.into_iter().map(name).collect()
}

fn mount_id(fd: RawFd, fdinfo: RawFd, deadline: u64) -> PlanResult<u64> {
    let descriptor = open_at(fdinfo, &name(&fd.to_string())?, false, deadline)?;
    filesystem(descriptor.as_raw_fd(), PROC_MAGIC, deadline)?;
    let mut original = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        live(deadline)?;
        let count = unsafe { libc::pread(descriptor.as_raw_fd(), chunk.as_mut_ptr().cast(),
            chunk.len(), original.len() as libc::off_t) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        live(deadline)?;
        if count == 0 { break; }
        if original.len() + count as usize > MAX_FDINFO_BYTES {
            return Err(invalid("observer output fdinfo exceeds its source bound"));
        }
        original.extend_from_slice(&chunk[..count as usize]);
    }
    let text = std::str::from_utf8(&original).map_err(|_| invalid("observer output fdinfo is not ASCII"))?;
    let mut found = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("mnt_id:") {
            let value = value.trim();
            if found.is_some() || value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("observer output fdinfo mount is not unique decimal"));
            }
            found = value.parse::<u64>().ok().filter(|value| *value != 0);
            if found.is_none() { return Err(invalid("observer output mount identity is invalid")); }
        }
    }
    found.ok_or_else(|| invalid("observer output fdinfo lacks a mount identity"))
}

struct Directory { fd: OwnedFd, identity: Node, mount: u64, name: Option<CString> }
struct Stream { fd: OwnedFd, identity: Node, mount: u64, name: CString }

fn directory(fd: OwnedFd, name: Option<CString>, uid: u32, gid: u32,
    exact_private: bool, fdinfo: RawFd, deadline: u64) -> PlanResult<Directory> {
    let value = stat(fd.as_raw_fd(), deadline)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFDIR || value.st_nlink == 0
        || value.st_uid != uid || value.st_gid != gid
        || (exact_private && value.st_mode & 0o7777 != 0o700)
        || (!exact_private && value.st_mode & 0o022 != 0) {
        return Err(invalid("observer output directory has the wrong protected identity"));
    }
    let mount = mount_id(fd.as_raw_fd(), fdinfo, deadline)?;
    Ok(Directory { fd, identity: node(&value), mount, name })
}

fn stream(parent: &Directory, fixed_name: &str, fdinfo: RawFd, deadline: u64) -> PlanResult<Stream> {
    let name = name(fixed_name)?;
    let fd = open_at(parent.fd.as_raw_fd(), &name, false, deadline)?;
    let value = stat(fd.as_raw_fd(), deadline)?;
    let mount = mount_id(fd.as_raw_fd(), fdinfo, deadline)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFREG || value.st_mode & 0o7777 != 0o600
        || value.st_uid != 0 || value.st_gid != 0 || value.st_nlink != 1 || value.st_size != 0
        || value.st_dev != parent.identity.device || mount != parent.mount {
        return Err(invalid("observer output stream is not an empty private same-mount original"));
    }
    Ok(Stream { fd, identity: node(&value), mount, name })
}

fn inventory(directory: RawFd, expected: &[&str], deadline: u64) -> PlanResult<()> {
    let fd = open_at(directory, c".", true, deadline)?.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(error.into());
    }
    struct Scan(*mut libc::DIR);
    impl Drop for Scan { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }
    let scan = Scan(stream);
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(scan.0) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            if error != 0 { return Err(std::io::Error::from_raw_os_error(error).into()); }
            break;
        }
        count += 1;
        if count > expected.len() + 2 { return Err(invalid("observer initial output inventory exceeds its bound")); }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw == b"." || raw == b".." { continue; }
        let entry = std::str::from_utf8(raw).map_err(|_| invalid("observer initial output name is not source-owned"))?;
        if !expected.contains(&entry) || !seen.insert(entry.to_owned()) {
            return Err(invalid("observer initial output has an unknown or duplicate entry"));
        }
    }
    if seen.len() != expected.len() { return Err(invalid("observer initial output inventory is incomplete")); }
    live(deadline)
}

/// Live retained descriptors, not a transferable accepted-output result.
pub(crate) struct HeldObserverOutputStartV14 {
    directories: Vec<Directory>,
    control: Directory,
    stdout: Stream,
    stderr: Stream,
    fdinfo: OwnedFd,
    context_original: Vec<u8>,
    deadline: u64,
    stream_limit: u64,
    output_bytes: u64,
    owner_pid: libc::pid_t,
    owner_tid: libc::pid_t,
    poisoned: Cell<bool>,
    _thread_affine: PhantomData<Rc<()>>,
}

impl HeldObserverOutputStartV14 {
    pub(crate) fn acquire(target: &ReceivedBodyTargetV12, launch: &BodyObserverLaunchV12,
        deadline: u64) -> PlanResult<Self> {
        let deadline = deadline.min(target.deadline()).min(launch.deadline_boottime_ns);
        let root = target.root_for_output(launch, deadline)?;
        let context_original = launch.context.original_bytes()?;
        let bounds = &launch.context.runner.execution_bounds;
        let stream_limit = stream_byte_limit(bounds.output_bytes)?;
        if bounds.output_inodes < 4 || bounds.user_uid == 0 || bounds.user_gid == 0 {
            return Err(invalid("observer initial outputs exceed admitted identity or inode scope"));
        }
        let components = output_components(&launch.context.runner.mount_policy.output_destination)?;
        // The fixed proc magic `self` is followed here; no caller-selected
        // proc name or target PID is reopened for output acquisition.
        let raw = unsafe { libc::open(c"/proc/self/fdinfo".as_ptr(), libc::O_RDONLY
            | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let fdinfo = unsafe { OwnedFd::from_raw_fd(raw) };
        if raw < 3 { return Err(invalid("observer fdinfo descriptor aliases stdio")); }
        filesystem(fdinfo.as_raw_fd(), PROC_MAGIC, deadline)?;
        let component_count = components.len();
        let mut directories = Vec::with_capacity(component_count + 1);
        directories.push(directory(open_at(root, c".", true, deadline)?, None,
            0, 0, false, fdinfo.as_raw_fd(), deadline)?);
        for (index, component) in components.into_iter().enumerate() {
            let parent = directories.last().ok_or_else(|| invalid("observer output root disappeared"))?;
            let is_output = index + 1 == component_count;
            let child = directory(open_at(parent.fd.as_raw_fd(), &component, true, deadline)?,
                Some(component), if is_output { bounds.user_uid } else { 0 },
                if is_output { bounds.user_gid } else { 0 }, is_output, fdinfo.as_raw_fd(), deadline)?;
            if is_output && child.mount == parent.mount {
                return Err(invalid("observer output is not a distinct retained mount"));
            }
            directories.push(child);
        }
        let output = directories.last().ok_or_else(|| invalid("observer output root is absent"))?;
        filesystem(output.fd.as_raw_fd(), TMPFS_MAGIC, deadline)?;
        let control_name = name(CONTROL_DIRECTORY)?;
        let control = directory(open_at(output.fd.as_raw_fd(), &control_name, true, deadline)?,
            Some(control_name), 0, 0, true, fdinfo.as_raw_fd(), deadline)?;
        if control.identity.device != output.identity.device || control.mount != output.mount {
            return Err(invalid("observer output control directory crossed the retained tmpfs"));
        }
        let stdout = stream(&control, STDOUT_NAME, fdinfo.as_raw_fd(), deadline)?;
        let stderr = stream(&control, STDERR_NAME, fdinfo.as_raw_fd(), deadline)?;
        if stdout.identity == stderr.identity { return Err(invalid("observer output streams alias one inode")); }
        let held = Self { directories, control, stdout, stderr, fdinfo, context_original,
            deadline, stream_limit, output_bytes: bounds.output_bytes,
            owner_pid: unsafe { libc::getpid() }, owner_tid: unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t },
            poisoned: Cell::new(true), _thread_affine: PhantomData };
        held.verify_initial_owned(target, launch, deadline)?;
        held.poisoned.set(false);
        Ok(held)
    }

    fn scope(&self, deadline: u64) -> PlanResult<()> {
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0 || unsafe { libc::getegid() } != 0
            || unsafe { libc::getpid() } != self.owner_pid
            || unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t } != self.owner_tid {
            return Err(invalid("observer output custody crossed its root process or thread"));
        }
        live(deadline)
    }

    fn verify_directory(&self, directory: &Directory, parent: Option<RawFd>,
        deadline: u64) -> PlanResult<()> {
        let current = stat(directory.fd.as_raw_fd(), deadline)?;
        if node(&current) != directory.identity || current.st_nlink == 0
            || mount_id(directory.fd.as_raw_fd(), self.fdinfo.as_raw_fd(), deadline)? != directory.mount {
            return Err(invalid("observer output retained directory anchor changed"));
        }
        if let Some(parent) = parent {
            let name = directory.name.as_ref().ok_or_else(|| invalid("observer output child name is absent"))?;
            let named = open_at(parent, name, true, deadline)?;
            if node(&stat(named.as_raw_fd(), deadline)?) != directory.identity
                || mount_id(named.as_raw_fd(), self.fdinfo.as_raw_fd(), deadline)? != directory.mount {
                return Err(invalid("observer output directory no longer has its retained name"));
            }
        }
        Ok(())
    }

    fn verify_stream(&self, stream: &Stream, deadline: u64) -> PlanResult<u64> {
        let current = stat(stream.fd.as_raw_fd(), deadline)?;
        let named = open_at(self.control.fd.as_raw_fd(), &stream.name, false, deadline)?;
        let observed = stat(named.as_raw_fd(), deadline)?;
        if node(&current) != stream.identity || node(&observed) != stream.identity
            || current.st_nlink != 1 || observed.st_nlink != 1
            || current.st_size < 0 || observed.st_size < 0
            || current.st_size as u64 > self.stream_limit || observed.st_size as u64 > self.stream_limit
            || mount_id(stream.fd.as_raw_fd(), self.fdinfo.as_raw_fd(), deadline)? != stream.mount
            || mount_id(named.as_raw_fd(), self.fdinfo.as_raw_fd(), deadline)? != stream.mount {
            return Err(invalid("observer output stream anchor or byte bound changed"));
        }
        // Different lengths/timestamps during active writes are not an EOF or
        // a stable original. Return only an upper bound for this anchor check.
        Ok((current.st_size as u64).max(observed.st_size as u64))
    }

    fn verify_retained_owned(&self, deadline: u64) -> PlanResult<()> {
        self.scope(deadline)?;
        filesystem(self.fdinfo.as_raw_fd(), PROC_MAGIC, deadline)?;
        for (index, directory) in self.directories.iter().enumerate() {
            let parent = index.checked_sub(1).map(|index| self.directories[index].fd.as_raw_fd());
            self.verify_directory(directory, parent, deadline)?;
        }
        let output = self.directories.last().ok_or_else(|| invalid("observer output root is absent"))?;
        filesystem(output.fd.as_raw_fd(), TMPFS_MAGIC, deadline)?;
        self.verify_directory(&self.control, Some(output.fd.as_raw_fd()), deadline)?;
        let stdout_bytes = self.verify_stream(&self.stdout, deadline)?;
        let stderr_bytes = self.verify_stream(&self.stderr, deadline)?;
        if stdout_bytes.checked_add(stderr_bytes).filter(|bytes| *bytes <= self.output_bytes).is_none() {
            return Err(invalid("observer stream anchors exceed the admitted output byte capacity"));
        }
        self.scope(deadline)
    }

    fn verify_initial_owned(&self, target: &ReceivedBodyTargetV12,
        launch: &BodyObserverLaunchV12, deadline: u64) -> PlanResult<()> {
        if launch.context.original_bytes()? != self.context_original {
            return Err(invalid("observer output original context changed"));
        }
        let root = target.root_for_output(launch, deadline)?;
        let retained_root = self.directories.first().ok_or_else(|| invalid("observer output retained root is absent"))?;
        if node(&stat(root, deadline)?) != retained_root.identity
            || mount_id(root, self.fdinfo.as_raw_fd(), deadline)? != retained_root.mount {
            return Err(invalid("observer output root differs from actual target custody"));
        }
        self.verify_retained_owned(deadline)?;
        let output = self.directories.last().ok_or_else(|| invalid("observer output root is absent"))?;
        let original_fds = [output.fd.as_raw_fd(), self.control.fd.as_raw_fd(),
            self.stdout.fd.as_raw_fd(), self.stderr.fd.as_raw_fd()];
        let mut before = Vec::with_capacity(original_fds.len());
        for fd in original_fds { before.push(initial_stamp(fd, deadline)?); }
        inventory(output.fd.as_raw_fd(), &[CONTROL_DIRECTORY], deadline)?;
        inventory(self.control.fd.as_raw_fd(), &[STDOUT_NAME, STDERR_NAME], deadline)?;
        for stream in [&self.stdout, &self.stderr] {
            if stat(stream.fd.as_raw_fd(), deadline)?.st_size != 0 {
                return Err(invalid("observer initial stream is not empty before release"));
            }
        }
        self.verify_retained_owned(deadline)?;
        for (fd, before) in original_fds.into_iter().zip(before) {
            if initial_stamp(fd, deadline)? != before {
                return Err(invalid("observer initial output inventory or streams changed during acquisition"));
            }
        }
        target.root_for_output(launch, deadline)?;
        self.scope(deadline)
    }

    pub(crate) fn verify_initial(&self, target: &ReceivedBodyTargetV12,
        launch: &BodyObserverLaunchV12, deadline: u64) -> PlanResult<()> {
        if self.poisoned.replace(true) { return Err(invalid("observer output custody is poisoned")); }
        self.verify_initial_owned(target, launch, deadline.min(self.deadline))?;
        self.poisoned.set(false);
        Ok(())
    }

    /// Anchor-only inspection. This can outlive the target; it does not call a
    /// live-target verifier and cannot assert EOF, final bytes or termination.
    pub(crate) fn verify_retained(&self, deadline: u64) -> PlanResult<()> {
        if self.poisoned.replace(true) { return Err(invalid("observer output custody is poisoned")); }
        self.verify_retained_owned(deadline.min(self.deadline))?;
        self.poisoned.set(false);
        Ok(())
    }
}
