//! Root-owned, write-once launch input for one already-admitted runner.
//!
//! The controller retains actual generation/directory/file descriptors and
//! immutable scope. Publication creates no authority: container read-only bind
//! admission belongs to the fixed lifecycle/inspect owner. The host context is
//! mode 0444 under a mode 0555 root-owned directory, not FS_IMMUTABLE. Clones
//! share publication state, and partial publication is never adopted/retried.

use super::{canonical_json_bytes_v12, sha256, ControllerError, Digest, Result};
use super::body_output_files_v12::live;
use super::runner_output_storage_v12::fd_mount_id;
use crate::plan_protocol::{canonical_bytes, ContainerCommand, LogicalLane, RunnerIdentity};
use crate::plan_protocol::body_launch_contract_v12::{BodyLaunchContextV12,
    CONTEXT_NAME, MAX_CONTEXT_BYTES_V12};
use serde_json::json;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64, inode: u64, mode: u32, uid: u32, gid: u32, links: u64,
    bytes: i64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}

impl Identity {
    fn object(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
            && self.uid == other.uid && self.gid == other.gid
    }

    fn directory(&self, mode: u32, require_gid_zero: bool) -> Result<()> {
        if self.mode & libc::S_IFMT != libc::S_IFDIR || self.uid != 0 || self.links == 0
            || self.mode & 0o7777 != mode || (require_gid_zero && self.gid != 0) {
            return Err(rejected("body launch directory lacks its exact root custody"));
        }
        Ok(())
    }

    fn original(&self) -> Result<()> {
        if self.mode & libc::S_IFMT != libc::S_IFREG || self.mode & 0o7777 != 0o444
            || self.uid != 0 || self.gid != 0 || self.links != 1 || self.bytes <= 0
            || self.bytes as u64 > MAX_CONTEXT_BYTES_V12 as u64 {
            return Err(rejected("body launch original is not its root-owned bounded read-only file"));
        }
        Ok(())
    }
}

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

fn identity(fd: RawFd) -> Result<Identity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Identity { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
        uid: stat.st_uid, gid: stat.st_gid, links: stat.st_nlink, bytes: stat.st_size,
        mtime: stat.st_mtime, mtime_ns: stat.st_mtime_nsec,
        ctime: stat.st_ctime, ctime_ns: stat.st_ctime_nsec })
}

fn open_at(parent: RawFd, name: &CStr, directory: bool) -> Result<OwnedFd> {
    let fd = unsafe { libc::openat(parent, name.as_ptr(), libc::O_RDONLY
        | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }) };
    if fd < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| rejected("body launch root path contains NUL"))?;
    open_at(libc::AT_FDCWD, &name, true)
}

struct Scan(*mut libc::DIR);
impl Drop for Scan { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }

fn inventory(directory: RawFd, published: bool, deadline: u64) -> Result<()> {
    live(deadline)?;
    let fd = open_at(directory, c".", true)?.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(error.into());
    }
    let scan = Scan(stream);
    let (mut entries, mut found) = (0usize, false);
    loop {
        live(deadline)?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(scan.0) };
        if entry.is_null() {
            let code = unsafe { *libc::__errno_location() };
            if code != 0 { return Err(std::io::Error::from_raw_os_error(code).into()); }
            break;
        }
        entries += 1;
        if entries > if published { 3 } else { 2 } {
            return Err(rejected("body launch directory has an excessive inventory"));
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." { continue; }
        if !published || found || name != CONTEXT_NAME.as_bytes() {
            return Err(rejected("body launch directory contains an unexpected original"));
        }
        found = true;
    }
    if found != published { return Err(rejected("body launch original is absent")); }
    live(deadline)
}

struct Published {
    directory_identity: Identity,
    file: File,
    file_identity: Identity,
    bytes: Vec<u8>,
    bytes_sha256: Digest,
    deadline: u64,
}

enum Publication { Empty(Identity), Published(Published), Poisoned }

struct Inner {
    generation_path: PathBuf,
    generation: OwnedFd,
    generation_identity: Identity,
    directory_path: PathBuf,
    directory_name: CString,
    directory: OwnedFd,
    directory_identity: Identity,
    mount: u64,
    plan_id: Digest,
    lane: LogicalLane,
    runner: RunnerIdentity,
    command: ContainerCommand,
    body_sha256: Digest,
    custody_sha256: Digest,
    publication: Mutex<Publication>,
}

#[derive(Clone)]
pub(super) struct HeldBodyLaunchV12 { inner: Arc<Inner> }

impl fmt::Debug for HeldBodyLaunchV12 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HeldBodyLaunchV12")
            .field("custody_sha256", &self.inner.custody_sha256).finish_non_exhaustive()
    }
}

impl Inner {
    fn anchors(&self, mode: u32, deadline: u64) -> Result<()> {
        live(deadline)?;
        let generation = identity(self.generation.as_raw_fd())?;
        generation.directory(0o700, false)?;
        let named_generation = open_directory(&self.generation_path)?;
        if !generation.object(&self.generation_identity)
            || identity(named_generation.as_raw_fd())? != generation
            || fd_mount_id(self.generation.as_raw_fd())? != self.mount
            || fd_mount_id(named_generation.as_raw_fd())? != self.mount {
            return Err(rejected("body launch generation anchor changed"));
        }
        let directory = identity(self.directory.as_raw_fd())?;
        directory.directory(mode, true)?;
        let named = open_at(self.generation.as_raw_fd(), &self.directory_name, true)?;
        if !directory.object(&self.directory_identity)
            || identity(named.as_raw_fd())? != directory
            || fd_mount_id(self.directory.as_raw_fd())? != self.mount
            || fd_mount_id(named.as_raw_fd())? != self.mount {
            return Err(rejected("body launch directory anchor changed"));
        }
        live(deadline)
    }

    fn verify_publication(&self, state: &Publication, deadline: u64) -> Result<()> {
        match state {
            Publication::Poisoned => Err(rejected("body launch publication is poisoned")),
            Publication::Empty(expected) => {
                self.anchors(0o700, deadline)?;
                inventory(self.directory.as_raw_fd(), false, deadline)?;
                if identity(self.directory.as_raw_fd())? != *expected {
                    return Err(rejected("empty body launch custody changed"));
                }
                live(deadline)
            }
            Publication::Published(original) => {
                let deadline = deadline.min(original.deadline);
                self.anchors(0o555, deadline)?;
                inventory(self.directory.as_raw_fd(), true, deadline)?;
                let named = open_at(self.directory.as_raw_fd(), c"launch.json", false)?;
                if identity(named.as_raw_fd())? != original.file_identity
                    || fd_mount_id(named.as_raw_fd())? != self.mount {
                    return Err(rejected("body launch original name differs from retained custody"));
                }
                let bytes = read_original(&original.file, &original.file_identity, self.mount, deadline)?;
                if bytes != original.bytes || sha256(&bytes) != original.bytes_sha256
                    || identity(self.directory.as_raw_fd())? != original.directory_identity {
                    return Err(rejected("body launch original or directory changed after publication"));
                }
                self.anchors(0o555, deadline)
            }
        }
    }
}

fn read_original(file: &File, expected: &Identity, mount: u64, deadline: u64) -> Result<Vec<u8>> {
    live(deadline)?;
    expected.original()?;
    if identity(file.as_raw_fd())? != *expected || fd_mount_id(file.as_raw_fd())? != mount {
        return Err(rejected("body launch retained original changed"));
    }
    let mut bytes = vec![0u8; expected.bytes as usize];
    let mut position = 0;
    while position < bytes.len() {
        live(deadline)?;
        let end = (position + 64 * 1024).min(bytes.len());
        let count = file.read_at(&mut bytes[position..end], position as u64)?;
        if count == 0 { return Err(rejected("body launch original ended early")); }
        position += count;
        live(deadline)?;
    }
    let mut extra = [0u8; 1];
    if file.read_at(&mut extra, bytes.len() as u64)? != 0
        || identity(file.as_raw_fd())? != *expected || fd_mount_id(file.as_raw_fd())? != mount {
        return Err(rejected("body launch original changed during readback"));
    }
    live(deadline)?;
    Ok(bytes)
}

pub(super) fn create(generation_root: &Path, plan_id: Digest, lane: LogicalLane,
    runner: &RunnerIdentity, command: &ContainerCommand, body_sha256: Digest,
    deadline: u64) -> Result<HeldBodyLaunchV12> {
    live(deadline)?;
    runner.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    command.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0
        || plan_id == [0; 32] || body_sha256 == [0; 32] || !generation_root.is_absolute() {
        return Err(rejected("body launch creation lacks fixed root ownership or admitted scope"));
    }
    let generation = open_directory(generation_root)?;
    let generation_identity = identity(generation.as_raw_fd())?;
    generation_identity.directory(0o700, false)?;
    let mount = fd_mount_id(generation.as_raw_fd())?;
    let name = format!("runner-launch-{}", lane.ordinal());
    let directory_name = CString::new(name.as_str())
        .map_err(|_| rejected("body launch source filename contains NUL"))?;
    if unsafe { libc::mkdirat(generation.as_raw_fd(), directory_name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let directory = open_at(generation.as_raw_fd(), &directory_name, true)?;
    let directory_identity = identity(directory.as_raw_fd())?;
    directory_identity.directory(0o700, true)?;
    if directory_identity.device != generation_identity.device
        || fd_mount_id(directory.as_raw_fd())? != mount {
        return Err(rejected("body launch creation crossed its retained generation mount"));
    }
    let runner_digest = sha256(&canonical_bytes(runner)
        .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?);
    let command_digest = sha256(&canonical_bytes(command)
        .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?);
    let custody_sha256 = sha256(&canonical_json_bytes_v12(&json!({
        "schema": "serverware.controllerBodyLaunchStorage/v12",
        "planId": plan_id, "lane": lane, "runnerIdentitySha256": runner_digest,
        "completeCommandSha256": command_digest, "bodySha256": body_sha256,
        "generationDevice": generation_identity.device, "generationInode": generation_identity.inode,
        "directoryDevice": directory_identity.device, "directoryInode": directory_identity.inode,
        "mountId": mount,
    }))?);
    let owner = HeldBodyLaunchV12 { inner: Arc::new(Inner {
        generation_path: generation_root.to_owned(), generation, generation_identity,
        directory_path: generation_root.join(name), directory_name, directory,
        directory_identity: directory_identity.clone(), mount, plan_id, lane,
        runner: runner.clone(), command: command.clone(), body_sha256, custody_sha256,
        publication: Mutex::new(Publication::Empty(directory_identity)),
    }) };
    owner.verify(deadline)?;
    Ok(owner)
}

impl HeldBodyLaunchV12 {
    pub(super) fn path(&self) -> &Path { &self.inner.directory_path }

    pub(super) fn identity_sha256(&self) -> Result<Digest> { Ok(self.inner.custody_sha256) }

    pub(super) fn verify(&self, deadline: u64) -> Result<()> {
        let state = self.inner.publication.lock()
            .map_err(|_| rejected("body launch publication lock is poisoned"))?;
        self.inner.verify_publication(&state, deadline)
    }

    pub(super) fn publish(&self, context: &BodyLaunchContextV12, deadline: u64) -> Result<Digest> {
        live(deadline)?;
        if context.deadline_boottime_ns > deadline {
            return Err(rejected("body launch context would extend the original publication deadline"));
        }
        let bytes = context.original_bytes()
            .map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
        let deadline = deadline.min(context.deadline_boottime_ns);
        live(deadline)?;
        if context.plan_id != self.inner.plan_id || context.lane != self.inner.lane
            || context.runner != self.inner.runner || context.body.command != self.inner.command
            || context.body.body_sha256 != self.inner.body_sha256 {
            return Err(rejected("body launch publication differs from its complete creation-time scope"));
        }
        let mut state = self.inner.publication.lock()
            .map_err(|_| rejected("body launch publication lock is poisoned"))?;
        if !matches!(&*state, Publication::Empty(_)) {
            return Err(rejected("body launch context was already published or publication failed"));
        }
        self.inner.verify_publication(&state, deadline)?;
        // All ambiguous write outcomes remain poisoned across every Arc clone.
        *state = Publication::Poisoned;
        let fd = unsafe { libc::openat(self.inner.directory.as_raw_fd(), c"launch.json".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW
                | libc::O_NONBLOCK | libc::O_CLOEXEC, 0o600) };
        if fd < 0 { return Err(std::io::Error::last_os_error().into()); }
        let mut writer = unsafe { File::from_raw_fd(fd) };
        for chunk in bytes.chunks(64 * 1024) {
            live(deadline)?;
            writer.write_all(chunk)?;
        }
        live(deadline)?;
        if unsafe { libc::fchmod(writer.as_raw_fd(), 0o444) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        writer.sync_all()?;
        live(deadline)?;
        let file_identity = identity(writer.as_raw_fd())?;
        file_identity.original()?;
        let file = File::from(open_at(self.inner.directory.as_raw_fd(), c"launch.json", false)?);
        let actual = read_original(&file, &file_identity, self.inner.mount, deadline)?;
        if actual != bytes { return Err(rejected("body launch original publication differs")); }
        drop(writer);
        if unsafe { libc::fchmod(self.inner.directory.as_raw_fd(), 0o555) } != 0
            || unsafe { libc::fsync(self.inner.directory.as_raw_fd()) } != 0
            || unsafe { libc::fsync(self.inner.generation.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let published = Published { directory_identity: identity(self.inner.directory.as_raw_fd())?,
            file, file_identity, bytes_sha256: sha256(&bytes), bytes,
            deadline };
        let proposed = Publication::Published(published);
        self.inner.verify_publication(&proposed, deadline)?;
        *state = proposed;
        live(deadline)?;
        Ok(context.context_sha256)
    }
}
