//! Purpose-separated durable claim before creating a never-executed child.
//!
//! Existing records are consumed forever: no resume, repair, completion, attach,
//! deletion or second creation API. The permit retains the actual precreation
//! owner, protected directory lock and exact original inode throughout the child.

use super::{ExecutionParents, PrecreationOwner};
use super::reservation::{directory, file_identity, hex, open_directory, stat_at,
    Directory, DirectoryStream, FileIdentity};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"SWNEGCR1";
const SLOT_DOMAIN: &[u8] = b"serverware.nativeEgressCreationSlot/v1\0";
const RECORD_BYTES: usize = 73;
const MAX_RECORDS: usize = 64;

/// Data derived by the genuine owner from its retained v2 grant and originals.
/// `claim` never accepts a caller-supplied Spec or successful diagnostic.
#[derive(PartialEq, Eq)]
pub(super) struct Spec {
    pub(super) journal_path: PathBuf,
    pub(super) journal_device: u64,
    pub(super) journal_inode: u64,
    pub(super) journal_namespace: String,
    pub(super) capability_id: String,
    pub(super) scope_sha256: [u8; 32],
}

// Closed source-owned alternatives only. No trait, callback, supplied Spec or
// serialized success can substitute for either actual retained owner.
enum Owner { Legacy(Arc<PrecreationOwner>), Execution(Arc<ExecutionParents>) }
impl Owner {
    fn check(&self) -> Result<(), String> {
        match self { Self::Legacy(owner) => owner.check(), Self::Execution(owner) => owner.check() }
    }
    fn creation_spec(&self) -> Result<Spec, String> {
        match self { Self::Legacy(owner) => owner.creation_spec(),
            Self::Execution(owner) => owner.creation_spec() }
    }
}

struct Journal {
    owner: Owner,
    spec: Spec,
    directories: Vec<Directory>,
    slot: [u8; 32],
    name: CString,
    pid: u32,
}

/// Non-Clone, non-Debug, consuming creation capability. Only this module can
/// construct it, after exclusive durable publication and exact inode readback.
pub(super) struct CreationPermit {
    journal: Journal,
    record: File,
    identity: FileIdentity,
    original: [u8; RECORD_BYTES],
    stopped: Cell<bool>,
}

/// Distinct linear permission for a new execution lifecycle. It cannot be
/// passed to the old never-executed-child API or recovered from old records.
pub(in super::super) struct ExecutionCreationPermit { inner: CreationPermit }

fn require(value: bool, reason: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(reason.to_owned()) }
}

fn nonzero(value: &[u8]) -> bool { value.iter().any(|byte| *byte != 0) }

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn validate_spec(spec: &Spec) -> Result<(), String> {
    require(spec.journal_device > 0 && spec.journal_device <= i64::MAX as u64
        && spec.journal_inode > 0 && spec.journal_inode <= i64::MAX as u64
        && nonzero(&spec.scope_sha256) && identifier(&spec.journal_namespace)
        && (24..=128).contains(&spec.capability_id.len())
        && spec.capability_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "native egress creation journal has invalid signed associations")?;
    let path = spec.journal_path.to_str().ok_or("native egress creation path is not ASCII")?;
    require(path.len() > 1 && path.len() <= 4096 && path.starts_with('/')
        && !path.contains('\\') && path.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "native egress creation path is not canonical absolute ASCII")?;
    let mut count = 0;
    for component in path[1..].split('/') {
        count += 1;
        require(count <= 64 && component.len() <= 255 && !matches!(component, "" | "." | ".."),
            "native egress creation path has invalid components")?;
    }
    Ok(())
}

fn slot(spec: &Spec) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SLOT_DOMAIN);
    for value in [spec.journal_namespace.as_bytes(), spec.capability_id.as_bytes()] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}

impl Journal {
    fn fd(&self) -> RawFd {
        self.directories.last().expect("held creation journal directory").file.as_raw_fd()
    }

    fn current(&self) -> Result<(), String> {
        self.owner.check()?;
        require(self.owner.creation_spec()? == self.spec,
            "native egress creation owner changed its original scope")?;
        require(self.pid == std::process::id() && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0 && !self.directories.is_empty(),
            "native egress creation crossed a process or privilege boundary")?;
        for (index, held) in self.directories.iter().enumerate() {
            self.owner.check()?;
            let metadata = held.file.metadata().map_err(|_| "creation directory metadata failed")?;
            require(metadata.is_dir() && metadata.dev() == held.device && metadata.ino() == held.inode
                && metadata.uid() == 0 && metadata.gid() == held.gid && metadata.mode() == held.mode,
                "native egress creation held directory changed")?;
            let root = CString::new("/").expect("literal root path");
            let (parent, name) = if index == 0 { (libc::AT_FDCWD, root.as_c_str()) } else {
                (self.directories[index - 1].file.as_raw_fd(),
                    held.name.as_ref().ok_or("creation ancestor name is absent")?.as_c_str())
            };
            let named = stat_at(parent, name)?.ok_or("creation named directory disappeared")?;
            require(named.st_dev == held.device && named.st_ino == held.inode
                && named.st_uid == 0 && named.st_gid == held.gid && named.st_mode == held.mode,
                "native egress creation path no longer names its held directory")?;
        }
        self.owner.check()
    }

    // Cleanup seal only: no current proof, admission clock or new permission.
    // Bounded held/named originals are still checked; legacy permits have no
    // public path to this independent cleanup-integrity operation.
    fn cleanup_integrity(&self) -> Result<(), String> {
        let owner = match &self.owner {
            Owner::Execution(owner) => owner,
            Owner::Legacy(_) => return Err("legacy creation permit has no execution cleanup seal".to_owned()),
        };
        require(owner.sealed_creation_spec()? == self.spec,
            "execution creation sealed owner association changed")?;
        require(self.pid == std::process::id() && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0 && !self.directories.is_empty(),
            "execution creation cleanup crossed process or privilege identity")?;
        for (index, held) in self.directories.iter().enumerate() {
            let metadata = held.file.metadata().map_err(|_| "creation cleanup directory metadata failed")?;
            require(metadata.is_dir() && metadata.dev() == held.device && metadata.ino() == held.inode
                && metadata.uid() == 0 && metadata.gid() == held.gid && metadata.mode() == held.mode,
                "creation cleanup held directory changed")?;
            let root = CString::new("/").expect("literal root path");
            let (parent, name) = if index == 0 { (libc::AT_FDCWD, root.as_c_str()) } else {
                (self.directories[index - 1].file.as_raw_fd(),
                    held.name.as_ref().ok_or("creation cleanup ancestor is absent")?.as_c_str())
            };
            let named = stat_at(parent, name)?.ok_or("creation cleanup named directory disappeared")?;
            require(named.st_dev == held.device && named.st_ino == held.inode && named.st_uid == 0
                && named.st_gid == held.gid && named.st_mode == held.mode,
                "creation cleanup named directory changed")?;
        }
        Ok(())
    }

    fn read(&self, file: &File, name: &CStr, expected: Option<&FileIdentity>)
        -> Result<([u8; RECORD_BYTES], FileIdentity), String>
    {
        self.current()?;
        let before = file_identity(file, self.spec.journal_device, RECORD_BYTES as u64)?;
        if let Some(expected) = expected {
            require(before == *expected, "native egress creation record identity changed")?;
        }
        let mut raw = [0u8; RECORD_BYTES];
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            match file.read_at(&mut raw[offset..], offset as u64) {
                Ok(0) => return Err("native egress creation record is incomplete".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("native egress creation record read failed".to_owned()),
            }
            self.current()?;
        }
        require(file_identity(file, self.spec.journal_device, RECORD_BYTES as u64)? == before,
            "native egress creation record changed during readback")?;
        let named = stat_at(self.fd(), name)?.ok_or("native egress creation record disappeared")?;
        require(named.st_dev == before.device && named.st_ino == before.inode
            && named.st_uid == 0 && named.st_gid == 0 && named.st_nlink == 1
            && named.st_mode & libc::S_IFMT == libc::S_IFREG && named.st_mode & 0o7777 == 0o600
            && named.st_size == RECORD_BYTES as i64,
            "native egress creation named record changed")?;
        self.current()?;
        Ok((raw, before))
    }

    fn inventory(&self) -> Result<usize, String> {
        self.current()?;
        let dot = CString::new(".").expect("literal directory name");
        let fd = open_directory(self.fd(), &dot)?.into_raw_fd();
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            unsafe { libc::close(fd); }
            return Err("native egress creation inventory cannot be opened".to_owned());
        }
        let stream = DirectoryStream(pointer);
        let mut slots = BTreeSet::new();
        loop {
            self.current()?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                require(unsafe { *libc::__errno_location() } == 0,
                    "native egress creation inventory read failed")?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            require(slots.len() < MAX_RECORDS && bytes.len() == 70 && &bytes[64..] == b".claim"
                && bytes[..64].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
                "native egress creation inventory is unknown or exceeds its bound")?;
            require(name != self.name.as_c_str(),
                "native egress creation slot is already consumed; no retry or reattachment")?;
            let text = std::str::from_utf8(&bytes[..64]).map_err(|_| "creation slot name invalid")?;
            require(slots.insert(text.to_owned()), "native egress creation inventory repeats a slot")?;
            self.current()?;
            let fd = unsafe { libc::openat(self.fd(), name.as_ptr(), libc::O_RDONLY
                | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
            require(fd >= 0, "native egress creation inventory record cannot be opened")?;
            let file = unsafe { File::from_raw_fd(fd) };
            let (raw, _) = self.read(&file, name, None)?;
            let mut recorded_slot = [0u8; 32];
            recorded_slot.copy_from_slice(&raw[9..41]);
            require(&raw[..8] == MAGIC && raw[8] == 1 && nonzero(&recorded_slot)
                && hex(&recorded_slot) == text && nonzero(&raw[41..]),
                "native egress creation inventory has a foreign or incomplete record")?;
        }
        self.current()?;
        Ok(slots.len())
    }

    fn original(&self) -> [u8; RECORD_BYTES] {
        let mut raw = [0u8; RECORD_BYTES];
        raw[..8].copy_from_slice(MAGIC);
        raw[8] = 1;
        raw[9..41].copy_from_slice(&self.slot);
        raw[41..].copy_from_slice(&self.spec.scope_sha256);
        raw
    }

    fn publish(&self) -> Result<(File, FileIdentity, [u8; RECORD_BYTES]), String> {
        self.current()?;
        let raw = self.original();
        let fd = unsafe { libc::openat(self.fd(), self.name.as_ptr(), libc::O_RDWR | libc::O_CREAT
            | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600) };
        require(fd >= 0, "native egress creation exclusive claim refused; no creation is permitted")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        // Never unlink on any error, including partial writes or uncertain fsync.
        self.current()?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0,
            "native egress creation record permissions failed")?;
        file_identity(&file, self.spec.journal_device, 0)?;
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            match file.write(&raw[offset..]) {
                Ok(0) => return Err("native egress creation claim write stalled".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("native egress creation claim write failed".to_owned()),
            }
            self.current()?;
        }
        let identity = file_identity(&file, self.spec.journal_device, RECORD_BYTES as u64)?;
        self.current()?;
        file.sync_all().map_err(|_| "native egress creation claim durability is unknown")?;
        self.current()?;
        self.directories.last().ok_or("creation journal directory is absent")?.file.sync_all()
            .map_err(|_| "native egress creation directory durability is unknown")?;
        self.current()?;
        let (retained, _) = self.read(&file, &self.name, Some(&identity))?;
        require(retained == raw, "native egress creation durable original differs")?;
        self.current()?;
        Ok((file, identity, raw))
    }
}

impl CreationPermit {
    pub(super) fn check(&self) -> Result<(), String> {
        require(!self.stopped.get(), "native egress creation permit is permanently stopped")?;
        let result = (|| {
            self.journal.current()?;
            let (raw, _) = self.journal.read(&self.record, &self.journal.name, Some(&self.identity))?;
            require(raw == self.original && raw == self.journal.original(),
                "native egress creation claim no longer matches its genuine scope")?;
            self.journal.current()
        })();
        if result.is_err() { self.stopped.set(true); }
        result
    }

    pub(super) fn require_owner(&self, owner: &Arc<PrecreationOwner>) -> Result<(), String> {
        if !matches!(&self.journal.owner, Owner::Legacy(held) if Arc::ptr_eq(held, owner)) {
            self.stopped.set(true);
            return Err("native egress creation permit belongs to another actual owner".to_owned());
        }
        self.check()
    }

    /// Public-observation digests only; neither getter creates or renews authority.
    pub(super) fn record_sha256(&self) -> [u8; 32] { Sha256::digest(self.original).into() }
    pub(super) fn slot_sha256(&self) -> [u8; 32] { self.journal.slot }
}

pub(super) fn claim(owner: Arc<PrecreationOwner>) -> Result<CreationPermit, String> {
    claim_owned(Owner::Legacy(owner))
}

pub(super) fn claim_execution(owner: Arc<ExecutionParents>) -> Result<ExecutionCreationPermit, String> {
    let inner = claim_owned(Owner::Execution(owner))?;
    Ok(ExecutionCreationPermit { inner })
}

impl ExecutionCreationPermit {
    pub(in super::super) fn require_owner(&self, owner: &Arc<ExecutionParents>) -> Result<(), String> {
        if !matches!(&self.inner.journal.owner, Owner::Execution(held) if Arc::ptr_eq(held, owner)) {
            self.inner.stopped.set(true);
            return Err("execution creation permit belongs to another actual owner".to_owned());
        }
        self.inner.check()
    }

    pub(in super::super) fn check_cleanup_integrity(&self) -> Result<(), String> {
        let held = &self.inner;
        held.journal.cleanup_integrity()?;
        let before = file_identity(&held.record, held.journal.spec.journal_device, RECORD_BYTES as u64)?;
        require(before == held.identity, "execution creation cleanup record identity changed")?;
        let mut raw = [0u8; RECORD_BYTES];
        require(held.record.read_at(&mut raw, 0).map_err(|_| "creation cleanup read failed")? == raw.len(),
            "execution creation cleanup record is incomplete")?;
        require(raw == held.original && raw == held.journal.original()
            && file_identity(&held.record, held.journal.spec.journal_device, RECORD_BYTES as u64)? == before,
            "execution creation cleanup original changed")?;
        let named = stat_at(held.journal.fd(), &held.journal.name)?
            .ok_or("execution creation cleanup named record disappeared")?;
        require(named.st_dev == before.device && named.st_ino == before.inode && named.st_uid == 0
            && named.st_gid == 0 && named.st_nlink == 1 && named.st_mode & libc::S_IFMT == libc::S_IFREG
            && named.st_mode & 0o7777 == 0o600 && named.st_size == RECORD_BYTES as i64,
            "execution creation cleanup named original changed")?;
        held.journal.cleanup_integrity()
    }
}

fn claim_owned(owner: Owner) -> Result<CreationPermit, String> {
    owner.check()?;
    let spec = owner.creation_spec()?;
    validate_spec(&spec)?;
    require(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "native egress creation claim requires the actual root owner")?;
    let path = spec.journal_path.to_str().ok_or("creation journal path is not ASCII")?;
    let components: Vec<&str> = path[1..].split('/').collect();
    let root = CString::new("/").expect("literal root path");
    let mut directories = vec![directory(open_directory(libc::AT_FDCWD, &root)?, None, false)?];
    for (index, component) in components.iter().enumerate() {
        owner.check()?;
        let name = CString::new(*component).map_err(|_| "creation path component contains NUL")?;
        let parent = directories.last().ok_or("creation root directory is absent")?.file.as_raw_fd();
        directories.push(directory(open_directory(parent, &name)?, Some(name), index + 1 == components.len())?);
        owner.check()?;
    }
    let held = directories.last().ok_or("creation journal directory is absent")?;
    require(held.device == spec.journal_device && held.inode == spec.journal_inode,
        "native egress creation directory differs from its signed identity")?;
    owner.check()?;
    require(unsafe { libc::flock(held.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "native egress creation journal is already owned or cannot be locked")?;
    owner.check()?;
    let slot = slot(&spec);
    require(nonzero(&slot), "native egress creation slot digest is zero")?;
    let name = CString::new(format!("{}.claim", hex(&slot))).expect("fixed creation record name");
    let journal = Journal { owner, spec, directories, slot, name, pid: std::process::id() };
    journal.current()?;
    require(journal.inventory()? < MAX_RECORDS, "native egress creation journal is full")?;
    let (record, identity, original) = journal.publish()?;
    let permit = CreationPermit { journal, record, identity, original, stopped: Cell::new(false) };
    permit.check()?;
    Ok(permit)
}
