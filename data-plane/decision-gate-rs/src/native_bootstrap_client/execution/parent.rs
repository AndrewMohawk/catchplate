//! Read-only retained directory chains and the signed cgroup parent.
//! No ancestor creation, controller enablement or task migration is permitted.

use super::start_authority::Containment;
use super::super::{ensure, OriginalClock};
use crate::linux_statx::{self, Statx, BASIC_STATS};
use catchplate_decision_gate::cgroup_control_v1;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};

const FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
    | libc::O_NOFOLLOW | libc::O_NONBLOCK;
const MOUNT_ID: u32 = 0x1000;

#[derive(PartialEq, Eq)]
struct Identity { device: u64, inode: u64, mode: u32, uid: u32, gid: u32, mount: u64 }

fn identity(fd: BorrowedFd<'_>) -> Result<Identity, String> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let mut extended: Statx = unsafe { std::mem::zeroed() };
    ensure(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } == 0
        && linux_statx::statx(fd.as_raw_fd(), c"",
            libc::AT_EMPTY_PATH, BASIC_STATS | MOUNT_ID, &mut extended) == 0,
        "native start directory identity unavailable")?;
    ensure(extended.stx_mask & (BASIC_STATS | MOUNT_ID)
            == (BASIC_STATS | MOUNT_ID)
        && extended.stx_ino == stat.st_ino
        && libc::makedev(extended.stx_dev_major, extended.stx_dev_minor) == stat.st_dev
        && u32::from(extended.stx_mode) == stat.st_mode
        && extended.stx_uid == stat.st_uid && extended.stx_gid == stat.st_gid,
        "native start directory stat association changed")?;
    Ok(Identity { device: stat.st_dev, inode: stat.st_ino, mode: stat.st_mode,
        uid: stat.st_uid, gid: stat.st_gid, mount: extended.stx_mnt_id })
}

fn open(parent: i32, name: &CString) -> Result<File, String> {
    let raw = unsafe { libc::openat(parent, name.as_ptr(), FLAGS) };
    ensure(raw >= 0, "native start protected directory cannot be opened")?;
    Ok(unsafe { File::from_raw_fd(raw) })
}

struct Directory { file: File, name: CString, identity: Identity }

/// Only the actual descriptors and names are retained; no observation is
/// accepted as a replacement for a directory. This owner grants no mutation.
pub(super) struct DirectoryChain { directories: Vec<Directory>, pid: u32 }

impl DirectoryChain {
    pub(super) fn open(path: &str, device: u64, inode: u64, private: bool,
        clock: &OriginalClock) -> Result<Self, String>
    {
        clock.check()?;
        ensure(path.len() > 1 && path.len() <= 4096 && path.starts_with('/')
            && !path.contains('\\') && path.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            "native start directory path is not canonical ASCII")?;
        let components: Vec<&str> = path[1..].split('/').collect();
        ensure(components.len() <= 64 && components.iter().all(|name|
            !matches!(*name, "" | "." | "..") && name.len() <= 255),
            "native start directory components invalid")?;
        let mut directories: Vec<Directory> = Vec::with_capacity(components.len() + 1);
        for component in std::iter::once("/").chain(components) {
            clock.check()?;
            let name = CString::new(component).map_err(|_| "native start directory name invalid")?;
            let parent = directories.last().map_or(libc::AT_FDCWD, |held| held.file.as_raw_fd());
            let file = open(parent, &name)?;
            let observed = identity(file.as_fd())?;
            ensure(observed.mode & libc::S_IFMT == libc::S_IFDIR && observed.uid == 0
                && observed.mode & 0o022 == 0 && observed.inode != 0,
                "native start directory ancestor is not root-owned and protected")?;
            directories.push(Directory { file, name, identity: observed });
        }
        let last = directories.last().ok_or("native start directory absent")?;
        ensure(last.identity.device == device && last.identity.inode == inode
            && (!private || (last.identity.gid == 0 && last.identity.mode & 0o7777 == 0o700)),
            "native start final directory differs from its signed identity or mode")?;
        let held = Self { directories, pid: std::process::id() };
        held.check_identity()?;
        clock.check()?;
        Ok(held)
    }

    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.directories.last().expect("constructed nonempty directory chain").file.as_fd()
    }

    pub(super) fn sync(&self) -> Result<(), String> {
        self.check_identity()?;
        self.directories.last().ok_or("native start journal directory absent")?.file.sync_all()
            .map_err(|_| "native start journal directory durability unknown")?;
        self.check_identity()
    }

    /// Custody only, never a renewed admission allowance. Cleanup can inspect
    /// retained originals after the original admission clock has ended.
    pub(super) fn check_identity(&self) -> Result<(), String> {
        ensure(self.pid == std::process::id() && unsafe { libc::getuid() } == 0
            && unsafe { libc::geteuid() } == 0 && unsafe { libc::getgid() } == 0
            && unsafe { libc::getegid() } == 0 && !self.directories.is_empty(),
            "native start retained directory crossed process or privilege boundary")?;
        for (index, held) in self.directories.iter().enumerate() {
            let parent = if index == 0 { libc::AT_FDCWD }
                else { self.directories[index - 1].file.as_raw_fd() };
            let named = open(parent, &held.name)?;
            ensure(identity(held.file.as_fd())? == held.identity
                && identity(named.as_fd())? == held.identity,
                "native start directory no longer names its retained original")?;
            let flags = unsafe { libc::fcntl(held.file.as_raw_fd(), libc::F_GETFD) };
            ensure(flags >= 0 && flags & libc::FD_CLOEXEC != 0,
                "native start directory descriptor flags changed")?;
        }
        Ok(())
    }
}

pub(super) struct ParentOwner {
    chain: DirectoryChain,
    original: cgroup_control_v1::DirectoryObservationV1,
}

fn read_fixed(directory: BorrowedFd<'_>, name: &[u8]) -> Result<Vec<u8>, String> {
    let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr().cast(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    ensure(raw >= 0, "native start parent control unavailable")?;
    let file = unsafe { File::from_raw_fd(raw) };
    let observed = identity(file.as_fd())?;
    let parent = identity(directory)?;
    ensure(observed.mode & libc::S_IFMT == libc::S_IFREG && observed.uid == 0
        && observed.mode & 0o022 == 0 && observed.device == parent.device
        && observed.mount == parent.mount,
        "native start parent control is not on its protected cgroup mount")?;
    let mut bytes = [0u8; 4096];
    let count = unsafe { libc::pread(file.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    ensure(count > 0 && (count as usize) < bytes.len(),
        "native start parent control read is incomplete or exceeds bound")?;
    let mut last = 0u8;
    ensure(unsafe { libc::pread(file.as_raw_fd(), (&mut last as *mut u8).cast(), 1,
        count as libc::off_t) } == 0 && identity(file.as_fd())? == observed,
        "native start parent control changed during observation")?;
    ensure(bytes[..count as usize].is_ascii(), "native start parent control is not ASCII")?;
    Ok(bytes[..count as usize].to_vec())
}

impl ParentOwner {
    pub(super) fn open(spec: &Containment, clock: &OriginalClock) -> Result<Self, String> {
        let chain = DirectoryChain::open(&spec.parent_path, spec.parent_device,
            spec.parent_inode, false, clock)?;
        let original = cgroup_control_v1::verify_directory(chain.fd()).map_err(|e| e.to_string())?;
        let owner = Self { chain, original };
        owner.check(clock)?;
        Ok(owner)
    }

    pub(super) fn fd(&self) -> BorrowedFd<'_> { self.chain.fd() }

    pub(super) fn check(&self, clock: &OriginalClock) -> Result<(), String> {
        clock.check()?;
        self.chain.check_identity()?;
        ensure(cgroup_control_v1::verify_directory(self.fd()).map_err(|e| e.to_string())?
            == self.original, "native start cgroup parent identity changed")?;
        ensure(read_fixed(self.fd(), b"cgroup.type\0")? == b"domain\n",
            "native start requires a domain cgroup parent")?;
        clock.check()?;
        let enabled = read_fixed(self.fd(), b"cgroup.subtree_control\0")?;
        let text = std::str::from_utf8(&enabled).map_err(|_| "native start controllers invalid")?;
        let names: Vec<_> = text.split_ascii_whitespace().collect();
        ensure(["cpu", "memory", "pids"].iter().all(|name|
            names.iter().filter(|candidate| *candidate == name).count() == 1),
            "native start parent lacks already-enabled resource controllers")?;
        self.chain.check_identity()?;
        clock.check()
    }
}
