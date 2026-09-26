//! Local original-file custody, not execution admission or a durable receipt.
//!
//! An ext-family/XFS fstatfs magic is only a structural filesystem candidate:
//! the ext magic does not distinguish ext2, ext3 and ext4 or prove journaling.
//! Independent filesystem configuration, workload separation, preprovisioned
//! parent-entry durability, power-loss behavior and antirollback remain outside
//! this owner. File/directory fsync is the explicit local publication boundary.
//! O_NONBLOCK cannot cancel regular-file IO or fsync; before/after deadline
//! checks require an outer watchdog to bound a blocked kernel operation.
//! Failed publication leaves its files in place and permanently poisons the
//! owner. There is no deletion, recovery, overwrite or retry operation.

use super::super::boottime_ns;
use crate::plan_protocol::{PlanProtocolError, PlanResult};
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;

pub(super) const MAX_ORIGINAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 96;
const CHUNK_BYTES: usize = 64 * 1024;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

fn live(deadline: u64) -> PlanResult<()> {
    if boottime_ns()? >= deadline { return Err(invalid("history file custody deadline expired")); }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Filesystem { ExtFamily, Xfs }

fn filesystem(fd: RawFd, deadline: u64) -> PlanResult<Filesystem> {
    live(deadline)?;
    let mut value: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if value.f_type == 0xef53u64 as _ { Ok(Filesystem::ExtFamily) }
    else if value.f_type == 0x5846_5342u64 as _ { Ok(Filesystem::Xfs) }
    else { Err(invalid("history store is not an admitted filesystem structural candidate")) }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: i64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl Identity {
    fn same_anchor(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.mode == other.mode
            && self.uid == other.uid && self.gid == other.gid && self.links == other.links
    }

    fn directory(&self) -> PlanResult<()> {
        if self.inode == 0 || self.mode & libc::S_IFMT != libc::S_IFDIR
            || self.mode & 0o7777 != 0o700 || self.uid != 0 || self.gid != 0 || self.links == 0 {
            return Err(invalid("history store is not a private root-owned directory"));
        }
        Ok(())
    }

    fn file(&self, mode: u32, bytes: u64) -> PlanResult<()> {
        if self.inode == 0 || self.mode & libc::S_IFMT != libc::S_IFREG
            || self.mode & 0o7777 != mode || self.uid != 0 || self.gid != 0 || self.links != 1
            || self.size < 0 || self.size as u64 != bytes {
            return Err(invalid("history original is not its exact protected regular file"));
        }
        Ok(())
    }
}

fn identity(fd: RawFd, deadline: u64) -> PlanResult<Identity> {
    live(deadline)?;
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    Ok(Identity { device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink, size: value.st_size,
        mtime: value.st_mtime, mtime_ns: value.st_mtime_nsec,
        ctime: value.st_ctime, ctime_ns: value.st_ctime_nsec })
}

fn read_descriptor(fd: RawFd, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status_flags < 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)?;
    if descriptor_flags & libc::FD_CLOEXEC == 0 || status_flags & libc::O_ACCMODE != libc::O_RDONLY
        || status_flags & libc::O_PATH != 0 {
        return Err(invalid("history custody descriptor is not a real close-on-exec read descriptor"));
    }
    Ok(())
}

fn open_read(parent: RawFd, name: &CStr, directory: bool, deadline: u64) -> PlanResult<OwnedFd> {
    live(deadline)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    live(deadline)?;
    read_descriptor(owned.as_raw_fd(), deadline)?;
    Ok(owned)
}

fn sync(fd: RawFd, deadline: u64) -> PlanResult<()> {
    live(deadline)?;
    if unsafe { libc::fsync(fd) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    live(deadline)
}

fn empty_directory(fd: RawFd, expected: &Identity, deadline: u64) -> PlanResult<()> {
    let mut buffer = [0u8; 4096];
    let (mut dot, mut parent) = (false, false);
    // A fresh OFD starts at offset zero. Only the two dot entries and EOF are
    // allowed; no directory walk or cleanup of unexpected content is attempted.
    for _ in 0..3 {
        live(deadline)?;
        let count = unsafe { libc::syscall(libc::SYS_getdents64, fd, buffer.as_mut_ptr(), buffer.len()) };
        if count < 0 { return Err(std::io::Error::last_os_error().into()); }
        live(deadline)?;
        if count == 0 {
            return if dot && parent { Ok(()) } else { Err(invalid("history directory dot entries are incomplete")) };
        }
        if count as usize > buffer.len() { return Err(invalid("history directory read exceeded its bound")); }
        let mut offset = 0usize;
        while offset < count as usize {
            let remaining = &buffer[offset..count as usize];
            if remaining.len() < 24 { return Err(invalid("history directory entry is truncated")); }
            let length = u16::from_ne_bytes([remaining[16], remaining[17]]) as usize;
            if length < 24 || length > remaining.len() || length % 8 != 0 {
                return Err(invalid("history directory entry has an invalid length"));
            }
            let inode = u64::from_ne_bytes(remaining[..8].try_into()
                .map_err(|_| invalid("history directory entry inode is truncated"))?);
            let tail = &remaining[19..length];
            let end = tail.iter().position(|byte| *byte == 0)
                .ok_or_else(|| invalid("history directory entry lacks a name terminator"))?;
            if inode == 0 || remaining[18] != libc::DT_DIR {
                return Err(invalid("history directory contains a non-directory entry"));
            }
            match &tail[..end] {
                b"." if !dot && inode == expected.inode => dot = true,
                b".." if !parent => parent = true,
                _ => return Err(invalid("history directory is not empty")),
            }
            offset += length;
        }
    }
    Err(invalid("history directory census did not reach bounded EOF"))
}

fn safe_name(name: &CStr) -> PlanResult<()> {
    let bytes = name.to_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()
            || matches!(*byte, b'.' | b'_' | b'-')) {
        return Err(invalid("history original name is not a bounded safe leaf"));
    }
    Ok(())
}

fn write_original(fd: RawFd, original: &[u8], deadline: u64) -> PlanResult<()> {
    let mut written = 0usize;
    while written < original.len() {
        live(deadline)?;
        let end = original.len().min(written + CHUNK_BYTES);
        let count = unsafe { libc::write(fd, original[written..end].as_ptr().cast(), end - written) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        live(deadline)?;
        if count == 0 || count as usize > end - written { return Err(invalid("history original write made invalid progress")); }
        written += count as usize;
    }
    Ok(())
}

fn compare_original(fd: RawFd, original: &[u8], deadline: u64) -> PlanResult<()> {
    let mut buffer = [0u8; CHUNK_BYTES];
    let mut offset = 0usize;
    loop {
        live(deadline)?;
        let wanted = (original.len() - offset).min(buffer.len()).max(1);
        let count = unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), wanted, offset as libc::off_t) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        live(deadline)?;
        if count == 0 {
            return if offset == original.len() { Ok(()) } else { Err(invalid("history original readback is truncated")) };
        }
        let count = count as usize;
        if count > wanted || count > original.len() - offset || buffer[..count] != original[offset..offset + count] {
            return Err(invalid("history original readback differs from the exact original"));
        }
        offset += count;
    }
}

pub(super) struct HistoryStoreDirectoryV14 {
    descriptor: OwnedFd,
    stamp: Identity,
    filesystem: Filesystem,
    owner_pid: libc::pid_t,
    deadline: u64,
    poisoned: Cell<bool>,
    _same_thread: PhantomData<Rc<()>>,
}

impl HistoryStoreDirectoryV14 {
    pub(super) fn adopt(directory: OwnedFd, deadline: u64) -> PlanResult<Self> {
        live(deadline)?;
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err(invalid("history store owner is not root"));
        }
        read_descriptor(directory.as_raw_fd(), deadline)?;
        let before = identity(directory.as_raw_fd(), deadline)?;
        before.directory()?;
        let fs = filesystem(directory.as_raw_fd(), deadline)?;
        // flock is OFD-owned. Never lock the caller's possibly duplicated OFD:
        // reopen only '.' through the consumed descriptor, then join identities.
        let held = open_read(directory.as_raw_fd(), c".", true, deadline)?;
        if identity(held.as_raw_fd(), deadline)? != before || filesystem(held.as_raw_fd(), deadline)? != fs
            || identity(directory.as_raw_fd(), deadline)? != before {
            return Err(invalid("history directory changed during independent OFD adoption"));
        }
        drop(directory);
        live(deadline)?;
        if unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        live(deadline)?;
        empty_directory(held.as_raw_fd(), &before, deadline)?;
        if identity(held.as_raw_fd(), deadline)? != before {
            return Err(invalid("history directory changed during its empty census"));
        }
        let owner = Self { descriptor: held, stamp: before, filesystem: fs,
            owner_pid: unsafe { libc::getpid() }, deadline, poisoned: Cell::new(false), _same_thread: PhantomData };
        owner.verify(deadline)?;
        Ok(owner)
    }

    fn check(&self, deadline: u64, exact_stamp: bool) -> PlanResult<()> {
        live(deadline.min(self.deadline))?;
        if unsafe { libc::getpid() } != self.owner_pid || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getegid() } != 0 {
            return Err(invalid("history directory process ownership changed"));
        }
        let deadline = deadline.min(self.deadline);
        read_descriptor(self.descriptor.as_raw_fd(), deadline)?;
        let current = identity(self.descriptor.as_raw_fd(), deadline)?;
        current.directory()?;
        if !current.same_anchor(&self.stamp) || (exact_stamp && current != self.stamp)
            || filesystem(self.descriptor.as_raw_fd(), deadline)? != self.filesystem {
            return Err(invalid("history directory retained custody changed"));
        }
        Ok(())
    }

    pub(super) fn verify(&self, deadline: u64) -> PlanResult<()> {
        if self.poisoned.get() { return Err(invalid("history directory is permanently poisoned")); }
        let result = self.check(deadline, true);
        if result.is_err() { self.poisoned.set(true); }
        result
    }

    pub(super) fn publish(&mut self, name: &CStr, original: &[u8], deadline: u64) -> PlanResult<StoredOriginalV14> {
        if self.poisoned.replace(true) { return Err(invalid("history directory is permanently poisoned")); }
        // Even invalid names/lengths/deadlines poison this one publication
        // attempt. A panic cannot accidentally restore a usable owner either.
        let result = self.publish_once(name, original, deadline.min(self.deadline));
        if result.is_ok() { self.poisoned.set(false); }
        result
    }

    fn publish_once(&mut self, name: &CStr, original: &[u8], deadline: u64) -> PlanResult<StoredOriginalV14> {
        self.check(deadline, true)?;
        safe_name(name)?;
        if original.is_empty() || original.len() > MAX_ORIGINAL_BYTES {
            return Err(invalid("history original exceeds its fixed byte bound"));
        }
        live(deadline)?;
        let raw = unsafe { libc::openat(self.descriptor.as_raw_fd(), name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600 as libc::mode_t) };
        if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
        let writer = unsafe { OwnedFd::from_raw_fd(raw) };
        live(deadline)?;
        let created = identity(writer.as_raw_fd(), deadline)?;
        created.file(0o600, 0)?;
        if created.device != self.stamp.device || filesystem(writer.as_raw_fd(), deadline)? != self.filesystem {
            return Err(invalid("history original left its retained filesystem"));
        }
        write_original(writer.as_raw_fd(), original, deadline)?;
        let written = identity(writer.as_raw_fd(), deadline)?;
        written.file(0o600, original.len() as u64)?;
        if !written.same_anchor(&created) { return Err(invalid("history original changed during writing")); }
        live(deadline)?;
        if unsafe { libc::fchmod(writer.as_raw_fd(), 0o400) } != 0 { return Err(std::io::Error::last_os_error().into()); }
        live(deadline)?;
        sync(writer.as_raw_fd(), deadline)?;
        let stamp = identity(writer.as_raw_fd(), deadline)?;
        stamp.file(0o400, original.len() as u64)?;
        if stamp.device != created.device || stamp.inode != created.inode {
            return Err(invalid("history original identity changed before publication"));
        }
        drop(writer);
        let reader = open_read(self.descriptor.as_raw_fd(), name, false, deadline)?;
        if identity(reader.as_raw_fd(), deadline)? != stamp {
            return Err(invalid("history original fixed name differs from the written file"));
        }
        compare_original(reader.as_raw_fd(), original, deadline)?;
        if identity(reader.as_raw_fd(), deadline)? != stamp { return Err(invalid("history original changed during readback")); }
        self.check(deadline, false)?;
        sync(self.descriptor.as_raw_fd(), deadline)?;
        let current = identity(self.descriptor.as_raw_fd(), deadline)?;
        if !current.same_anchor(&self.stamp) { return Err(invalid("history directory changed during publication")); }
        self.stamp = current;
        let stored = StoredOriginalV14 { descriptor: reader, name: name.to_owned(), stamp,
            directory_anchor: current, deadline };
        self.check(deadline, true)?;
        stored.check(self, deadline)?;
        Ok(stored)
    }
}

pub(super) struct StoredOriginalV14 {
    descriptor: OwnedFd,
    name: CString,
    stamp: Identity,
    directory_anchor: Identity,
    deadline: u64,
}

impl StoredOriginalV14 {
    pub(super) fn bytes(&self) -> u64 { self.stamp.size as u64 }

    fn check(&self, directory: &HistoryStoreDirectoryV14, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.deadline).min(directory.deadline);
        directory.check(deadline, true)?;
        if !directory.stamp.same_anchor(&self.directory_anchor) {
            return Err(invalid("history original was presented to a different directory"));
        }
        read_descriptor(self.descriptor.as_raw_fd(), deadline)?;
        self.stamp.file(0o400, self.bytes())?;
        if identity(self.descriptor.as_raw_fd(), deadline)? != self.stamp {
            return Err(invalid("history original retained metadata changed"));
        }
        let named = open_read(directory.descriptor.as_raw_fd(), &self.name, false, deadline)?;
        if identity(named.as_raw_fd(), deadline)? != self.stamp
            || identity(self.descriptor.as_raw_fd(), deadline)? != self.stamp {
            return Err(invalid("history original named and retained identities differ"));
        }
        directory.check(deadline, true)
    }

    pub(super) fn verify(&self, directory: &HistoryStoreDirectoryV14, deadline: u64) -> PlanResult<()> {
        directory.verify(deadline)?;
        let result = self.check(directory, deadline);
        if result.is_err() { directory.poisoned.set(true); }
        result
    }
}
