//! Actual cgroup-v2 descriptor observation and fixed-control preparation.
//!
//! There is no cgroup creation, task migration, kill write, deadline loop or
//! execution authority here. The owning caller retains its signed scope,
//! original absolute cleanup bound, leader pidfd and exact reap semantics.

use std::cell::Cell;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use crate::linux_statx::{self, Statx, BASIC_STATS, MNT_ID, SYNC_AS_STAT};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAX_EVENTS_BYTES: usize = 4096;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Io(error) => Some(error), Self::Invalid(_) => None }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// Kernel-observed directory data, not a signed identity or permission. No
/// method accepts an instance as a substitute for an actual descriptor.
#[derive(Debug, PartialEq, Eq)]
pub struct DirectoryObservationV1 {
    device: libc::dev_t,
    inode: libc::ino_t,
    mount_id: u64,
    mode: libc::mode_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}
impl DirectoryObservationV1 {
    pub fn device(&self) -> libc::dev_t { self.device }
    pub fn inode(&self) -> libc::ino_t { self.inode }
    pub fn mount_id(&self) -> u64 { self.mount_id }
    pub fn mode(&self) -> libc::mode_t { self.mode }
    pub fn uid(&self) -> libc::uid_t { self.uid }
    pub fn gid(&self) -> libc::gid_t { self.gid }
}

fn observation(stat: &libc::stat, statx: &Statx)
    -> Result<DirectoryObservationV1, Error>
{
    if statx.stx_mask & BASIC_STATS != BASIC_STATS
        || statx.stx_mask & MNT_ID == 0 || statx.stx_ino != stat.st_ino
        || statx.stx_size != stat.st_size as u64
        || u32::from(statx.stx_mode) != stat.st_mode
        || statx.stx_uid != stat.st_uid || statx.stx_gid != stat.st_gid
        || libc::makedev(statx.stx_dev_major, statx.stx_dev_minor) != stat.st_dev
    {
        return Err(Error::Invalid("cgroup descriptor stat/statx association mismatch"));
    }
    Ok(DirectoryObservationV1 {
        device: stat.st_dev, inode: stat.st_ino, mount_id: statx.stx_mnt_id,
        mode: stat.st_mode, uid: stat.st_uid, gid: stat.st_gid,
    })
}

fn descriptor(fd: BorrowedFd<'_>) -> Result<DirectoryObservationV1, Error> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: Statx = unsafe { zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0
        || linux_statx::statx(fd.as_raw_fd(), c"",
            libc::AT_EMPTY_PATH | SYNC_AS_STAT,
            BASIC_STATS | MNT_ID, &mut statx) != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    observation(&stat, &statx)
}

fn filesystem(fd: BorrowedFd<'_>) -> Result<(), Error> {
    let mut value: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut value) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if i128::from(value.f_type) != i128::from(CGROUP2_SUPER_MAGIC) {
        return Err(Error::Invalid("descriptor is not on cgroup v2"));
    }
    Ok(())
}

pub fn verify_directory(fd: BorrowedFd<'_>) -> Result<DirectoryObservationV1, Error> {
    let identity = descriptor(fd)?;
    filesystem(fd)?;
    if identity.mode & libc::S_IFMT != libc::S_IFDIR || identity.inode == 0
        || identity.uid != 0 || identity.mode & 0o022 != 0 {
        return Err(Error::Invalid("cgroup descriptor is not a protected cgroup-v2 directory"));
    }
    Ok(identity)
}

#[derive(Clone, Copy)]
enum Kind { Kill, Events }
impl Kind {
    fn name(self) -> &'static CStr {
        match self { Self::Kill => c"cgroup.kill", Self::Events => c"cgroup.events" }
    }
    fn flags(self) -> libc::c_int {
        libc::O_CLOEXEC | libc::O_NOFOLLOW | match self {
            Self::Kill => libc::O_WRONLY,
            Self::Events => libc::O_RDONLY | libc::O_NONBLOCK,
        }
    }
}

fn named(directory: BorrowedFd<'_>, kind: Kind) -> Result<DirectoryObservationV1, Error> {
    let mut stat: libc::stat = unsafe { zeroed() };
    let mut statx: Statx = unsafe { zeroed() };
    let flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;
    if unsafe { libc::fstatat(directory.as_raw_fd(), kind.name().as_ptr().cast(), &mut stat, flags) } != 0
        || linux_statx::statx(directory.as_raw_fd(), kind.name(),
            flags | SYNC_AS_STAT, BASIC_STATS | MNT_ID, &mut statx) != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    observation(&stat, &statx)
}

fn descriptor_flags(fd: BorrowedFd<'_>, expected_status: Option<libc::c_int>) -> Result<(), Error> {
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if descriptor_flags < 0 || status < 0 { return Err(io::Error::last_os_error().into()); }
    if descriptor_flags & libc::FD_CLOEXEC == 0
        || expected_status.is_some_and(|expected|
            status & (libc::O_ACCMODE | libc::O_NONBLOCK) != expected)
    {
        return Err(Error::Invalid("retained cgroup control descriptor flags changed"));
    }
    Ok(())
}

struct Control {
    directory: OwnedFd,
    directory_identity: DirectoryObservationV1,
    file: OwnedFd,
    file_identity: DirectoryObservationV1,
    kind: Kind,
    stopped: Cell<bool>,
}
impl Control {
    fn open(directory: BorrowedFd<'_>, kind: Kind) -> Result<Self, Error> {
        let directory_identity = verify_directory(directory)?;
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 { return Err(io::Error::last_os_error().into()); }
        let directory = unsafe { OwnedFd::from_raw_fd(duplicate) };
        if verify_directory(directory.as_fd())? != directory_identity {
            return Err(Error::Invalid("cgroup directory changed while retaining it"));
        }
        let raw = unsafe { libc::openat(directory.as_raw_fd(), kind.name().as_ptr().cast(), kind.flags()) };
        if raw < 0 { return Err(io::Error::last_os_error().into()); }
        let file = unsafe { OwnedFd::from_raw_fd(raw) };
        let file_identity = descriptor(file.as_fd())?;
        if file_identity.mode & libc::S_IFMT != libc::S_IFREG || file_identity.inode == 0
            || file_identity.device != directory_identity.device
            || file_identity.mount_id != directory_identity.mount_id {
            return Err(Error::Invalid("fixed cgroup control is not on the retained directory mount"));
        }
        let control = Self { directory, directory_identity, file, file_identity,
            kind, stopped: Cell::new(false) };
        control.check()?;
        Ok(control)
    }

    fn check_originals(&self) -> Result<(), Error> {
        descriptor_flags(self.directory.as_fd(), None)?;
        descriptor_flags(self.file.as_fd(),
            Some(self.kind.flags() & (libc::O_ACCMODE | libc::O_NONBLOCK)))?;
        if verify_directory(self.directory.as_fd())? != self.directory_identity
            || descriptor(self.file.as_fd())? != self.file_identity
            || named(self.directory.as_fd(), self.kind)? != self.file_identity {
            return Err(Error::Invalid("retained cgroup directory/control association changed"));
        }
        filesystem(self.file.as_fd())
    }

    fn check(&self) -> Result<(), Error> {
        if self.stopped.replace(true) { return Err(Error::Invalid("cgroup control owner is stopped")); }
        self.check_originals()?;
        self.stopped.set(false);
        Ok(())
    }
}

/// Availability-only retained preparation. No raw FD export or write method.
/// Opening this object cannot authorize or issue a kill.
pub struct PreparedKillV1 { control: Control }
impl PreparedKillV1 {
    pub fn open(directory: BorrowedFd<'_>) -> Result<Self, Error> {
        Ok(Self { control: Control::open(directory, Kind::Kill)? })
    }
    pub fn check(&self) -> Result<(), Error> { self.control.check() }
}

/// Retained read/poll owner. No accepted successful observation or caller data.
/// The caller supplies its existing absolute BOOTTIME wait and authority checks.
pub struct EventsV1 { control: Control }
impl EventsV1 {
    pub fn open(directory: BorrowedFd<'_>) -> Result<Self, Error> {
        Ok(Self { control: Control::open(directory, Kind::Events)? })
    }
    pub fn check(&self) -> Result<(), Error> { self.control.check() }

    /// Borrowed read-only events FD, for polling only. It carries no authority.
    pub fn poll_fd(&self) -> BorrowedFd<'_> { self.control.file.as_fd() }

    pub fn populated(&mut self) -> Result<bool, Error> {
        self.control.check()?;
        self.control.stopped.set(true);
        let populated = read_populated(self.control.file.as_raw_fd())?;
        self.control.check_originals()?;
        self.control.stopped.set(false);
        Ok(populated)
    }
}

fn read_populated(fd: RawFd) -> Result<bool, Error> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut bytes = [0u8; MAX_EVENTS_BYTES];
    let mut length = 0usize;
    loop {
        if length == bytes.len() { return Err(Error::Invalid("cgroup.events exceeds its fixed bound")); }
        let read = unsafe { libc::read(fd, bytes[length..].as_mut_ptr().cast(), bytes.len() - length) };
        if read > 0 {
            length = length.checked_add(read as usize).ok_or(Error::Invalid("cgroup.events length overflow"))?;
            continue;
        }
        if read == 0 { break; }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) if length > 0 => break,
            _ => return Err(error.into()),
        }
    }
    if !bytes[..length].is_ascii() { return Err(Error::Invalid("cgroup.events contains non-ASCII data")); }
    let text = std::str::from_utf8(&bytes[..length])
        .map_err(|_| Error::Invalid("cgroup.events is not valid ASCII"))?;
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or(Error::Invalid("cgroup.events contains an empty record"))?;
        let value = fields.next().ok_or(Error::Invalid("cgroup.events record lacks a value"))?;
        if fields.next().is_some() { return Err(Error::Invalid("cgroup.events record has extra fields")); }
        if name == "populated" {
            if populated.is_some() || !matches!(value, "0" | "1") {
                return Err(Error::Invalid("cgroup.events populated record is invalid"));
            }
            populated = Some(value == "1");
        }
    }
    populated.ok_or(Error::Invalid("cgroup.events lacks a populated record"))
}
