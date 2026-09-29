//! Irreversible start claim retained with the separate genuine creation claim.
//! No resume, repair, deletion, completion replay or second-attempt interface.

#[path = "outcome.rs"]
pub(super) mod outcome;
#[path = "outcome_record.rs"]
mod outcome_record;

use super::{parent::DirectoryChain, start::StartOwner};
use super::super::{egress::ExecutionCreationPermit, ensure};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;

const MAGIC: &[u8; 8] = b"SWNESTR1";
const SLOT_DOMAIN: &[u8] = b"serverware.nativeWorkloadStartSlot/v1\0";
const RECORD_BYTES: usize = 73;
const MAX_RECORDS: usize = 64;

#[derive(PartialEq, Eq)]
struct FileIdentity { device: u64, inode: u64, size: u64,
    modified: i64, modified_ns: i64, changed: i64, changed_ns: i64 }

fn identity(file: &File, device: u64, size: u64) -> Result<FileIdentity, String> {
    let m = file.metadata().map_err(|_| "native start claim metadata unavailable")?;
    ensure(m.is_file() && m.dev() == device && m.uid() == 0 && m.gid() == 0
        && m.mode() & 0o7777 == 0o600 && m.nlink() == 1 && m.size() == size,
        "native start claim ownership/mode/links/size invalid")?;
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    ensure(flags >= 0 && flags & libc::FD_CLOEXEC != 0,
        "native start claim descriptor is not close-on-exec")?;
    Ok(FileIdentity { device: m.dev(), inode: m.ino(), size: m.size(),
        modified: m.mtime(), modified_ns: m.mtime_nsec(), changed: m.ctime(), changed_ns: m.ctime_nsec() })
}

fn hex(value: &[u8]) -> String { value.iter().map(|b| format!("{b:02x}")).collect() }

struct Journal {
    owner: Arc<StartOwner>,
    directory: DirectoryChain,
    name: CString,
    original: [u8; RECORD_BYTES],
}

impl Journal {
    fn check_custody(&self) -> Result<(), String> {
        self.owner.check_cleanup_scope()?;
        self.directory.check_identity()
    }

    fn check_admission(&self) -> Result<(), String> {
        self.owner.check_admission()?;
        self.check_custody()?;
        self.owner.check_admission()
    }

    fn read(&self, file: &File, name: &CStr, expected: Option<&FileIdentity>)
        -> Result<([u8; RECORD_BYTES], FileIdentity), String>
    {
        self.check_custody()?;
        let device = self.owner.constraints().journal.device;
        let before = identity(file, device, RECORD_BYTES as u64)?;
        if let Some(expected) = expected {
            ensure(before == *expected, "native start retained claim identity changed")?;
        }
        let mut raw = [0u8; RECORD_BYTES];
        // One fixed-width read, no retry or newly acquired IO allowance. These
        // are local protected originals, not general streams or caller paths.
        let count = file.read_at(&mut raw, 0).map_err(|_| "native start claim readback failed")?;
        ensure(count == raw.len(), "native start claim readback is incomplete")?;
        let named = unsafe { libc::openat(self.directory.fd().as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(named >= 0, "native start claim name disappeared")?;
        let named = unsafe { File::from_raw_fd(named) };
        ensure(identity(file, device, RECORD_BYTES as u64)? == before
            && identity(&named, device, RECORD_BYTES as u64)? == before,
            "native start claim no longer names the retained original")?;
        self.check_custody()?;
        Ok((raw, before))
    }

    fn inventory(&self) -> Result<(), String> {
        if self.owner.constraints().journal.outcome_profile.as_deref() == Some(super::start_authority::OUTCOME_PROFILE) {
            return outcome::inventory(self);
        }
        self.check_admission()?;
        let raw = unsafe { libc::openat(self.directory.fd().as_raw_fd(), b".\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(raw >= 0, "native start journal inventory unavailable")?;
        let pointer = unsafe { libc::fdopendir(raw) };
        if pointer.is_null() {
            unsafe { libc::close(raw); }
            return Err("native start journal inventory unavailable".to_owned());
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }
        let stream = Stream(pointer);
        let mut names = BTreeSet::new();
        loop {
            self.check_admission()?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                ensure(unsafe { *libc::__errno_location() } == 0,
                    "native start journal inventory read failed")?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            ensure(names.len() < MAX_RECORDS && bytes.len() == 70 && &bytes[64..] == b".claim"
                && bytes[..64].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
                "native start journal contains an unknown or excessive record")?;
            ensure(name != self.name.as_c_str(),
                "native start slot is consumed; no retry or reattachment")?;
            ensure(names.insert(bytes.to_vec()), "native start journal repeats a record")?;
            let fd = unsafe { libc::openat(self.directory.fd().as_raw_fd(), name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
            ensure(fd >= 0, "native start journal record cannot be opened")?;
            let file = unsafe { File::from_raw_fd(fd) };
            let (raw, _) = self.read(&file, name, None)?;
            ensure(&raw[..8] == MAGIC && raw[8] == 1
                && raw[9..41].iter().any(|b| *b != 0) && raw[41..].iter().any(|b| *b != 0)
                && hex(&raw[9..41]).as_bytes() == &bytes[..64],
                "native start journal has a foreign or incomplete claim")?;
        }
        ensure(names.len() < MAX_RECORDS, "native start journal is full")?;
        self.check_admission()
    }

    fn publish(&self) -> Result<(File, FileIdentity), String> {
        self.check_admission()?;
        let raw = unsafe { libc::openat(self.directory.fd().as_raw_fd(), self.name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW
                | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600) };
        ensure(raw >= 0, "native start exclusive claim refused; no mutation is permitted")?;
        // Never unlink, even when write or fsync returns an uncertain result.
        let mut file = unsafe { File::from_raw_fd(raw) };
        self.check_admission()?;
        ensure(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0,
            "native start claim permissions unavailable")?;
        identity(&file, self.owner.constraints().journal.device, 0)?;
        self.check_admission()?;
        let written = file.write(&self.original).map_err(|_| "native start claim write failed")?;
        ensure(written == RECORD_BYTES, "native start claim write is partial; attempt consumed")?;
        self.check_admission()?;
        let observed = identity(&file, self.owner.constraints().journal.device, RECORD_BYTES as u64)?;
        file.sync_all().map_err(|_| "native start claim durability unknown")?;
        self.check_admission()?;
        self.directory.sync()?;
        self.check_admission()?;
        let (raw, _) = self.read(&file, &self.name, Some(&observed))?;
        ensure(raw == self.original, "native start durable claim differs")?;
        self.check_admission()?;
        Ok((file, observed))
    }
}

/// Only this module constructs a permit after both durable one-use claims.
/// The actual parent and creation owners remain retained, not converted to data.
pub(super) struct StartPermit {
    creation: ExecutionCreationPermit,
    record: File,
    identity: FileIdentity,
    journal: Journal,
    stopped: Cell<bool>,
    outcome_attempted: Cell<bool>,
    outcome_boottime: Cell<u64>,
}

impl StartPermit {
    pub(super) fn require_owner(&self, owner: &Arc<StartOwner>) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "native start permit is stopped")?;
        ensure(Arc::ptr_eq(&self.journal.owner, owner), "native start permit belongs to another owner")?;
        self.journal.check_admission()?;
        self.creation.require_owner(owner.parents())?;
        self.check_cleanup_integrity()?;
        self.journal.check_admission()?;
        self.stopped.set(false);
        Ok(())
    }

    /// No live proof/time check and no action authorization. This remains usable
    /// for cleanup diagnostics after an admission error poisons require_owner.
    pub(super) fn check_cleanup_integrity(&self) -> Result<(), String> {
        self.journal.check_custody()?;
        self.creation.check_cleanup_integrity()?;
        let (raw, _) = self.journal.read(&self.record, &self.journal.name, Some(&self.identity))?;
        ensure(raw == self.journal.original, "native start retained claim original changed")?;
        self.journal.check_custody()
    }
}

pub(super) fn claim(owner: Arc<StartOwner>) -> Result<StartPermit, String> {
    owner.begin_claim()?;
    let spec = &owner.constraints().journal;
    let directory = DirectoryChain::open(&spec.path, spec.device, spec.inode, true, owner.clock())?;
    owner.check_admission()?;
    ensure(unsafe { libc::flock(directory.fd().as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "native start journal is already owned or cannot be locked")?;
    owner.check_admission()?;
    let mut hash = Sha256::new();
    hash.update(SLOT_DOMAIN);
    for value in [spec.namespace.as_bytes(), owner.constraints().capability.capability_id.as_bytes()] {
        hash.update((value.len() as u32).to_be_bytes()); hash.update(value);
    }
    let slot: [u8; 32] = hash.finalize().into();
    let scope = owner.operation_sha256();
    ensure(slot.iter().any(|b| *b != 0) && scope.iter().any(|b| *b != 0),
        "native start slot/scope digest is zero")?;
    let name = CString::new(format!("{}.claim", hex(&slot))).expect("fixed start claim name");
    let mut original = [0u8; RECORD_BYTES];
    original[..8].copy_from_slice(MAGIC); original[8] = 1;
    original[9..41].copy_from_slice(&slot); original[41..].copy_from_slice(&scope);
    let journal = Journal { owner, directory, name, original };
    journal.inventory()?;
    let (record, identity) = journal.publish()?;
    // If this second journal is consumed or uncertain, the first claim remains
    // burned. Neither failure permits a cgroup or child creation attempt.
    let creation = journal.owner.parents().claim_creation()?;
    journal.check_admission()?;
    let permit = StartPermit { creation, record, identity, journal, stopped: Cell::new(false),
        outcome_attempted: Cell::new(false), outcome_boottime: Cell::new(0) };
    permit.require_owner(&permit.journal.owner)?;
    Ok(permit)
}
