//! Purpose-specific v2 custody of exact kernel transaction/transcript originals.
//! This local journal records attempts, not kernel success or rollback proof.
//! No record is deleted, replaced or repaired, including on partial publication.

use super::{EgressGuard, owners::{Owner, Phase}, reservation::{Spec, Directory, FileIdentity, DirectoryStream,
    directory, open_directory, stat_at, hex, file_identity, check_directories_owner as check_directories,
    check_directories_phase,
    duplicate_directories}};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::MetadataExt;

const MAGIC: &[u8; 8] = b"SWNEGRS2";
const PREFIX: usize = 137;
const MAX_TRANSACTION: usize = 64 * 1024;
const MAX_TRANSCRIPT: usize = 1024 * 1024;
const MAX_SLOTS: usize = 64;
const MAX_RECORDS: usize = 4 * MAX_SLOTS;
const IO_CHUNK: usize = 16 * 1024;

fn ensure(value: bool, reason: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(reason.to_owned()) }
}

fn nonzero(value: &[u8]) -> bool { value.iter().any(|byte| *byte != 0) }
fn digest(value: &[u8]) -> [u8; 32] { Sha256::digest(value).into() }
fn backend_name() -> CString { CString::new("backend.lock").expect("fixed backend lock name") }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage { Reserve = 1, Claim = 2, Observed = 3, Complete = 4 }

impl Stage {
    fn suffix(self) -> &'static str {
        match self { Self::Reserve => "reserve", Self::Claim => "claim",
            Self::Observed => "observed", Self::Complete => "complete" }
    }

    fn bounds(self) -> (usize, usize) {
        match self {
            Self::Reserve => (PREFIX + 5, PREFIX + 4 + MAX_TRANSACTION),
            Self::Claim => (PREFIX, PREFIX),
            Self::Observed => (PREFIX + 32 + 4 + 12, PREFIX + 32 + 4 + MAX_TRANSCRIPT),
            Self::Complete => (PREFIX + 64, PREFIX + 64),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Opened, Reserved, Claimed, Observed, Completed, Unknown }

pub(super) enum KernelClaimState {
    Fresh,
    AlreadyComplete { semantic_sha256: [u8; 32], evidence_sha256: [u8; 32] },
}

struct HeldRecord { file: File, identity: FileIdentity, name: CString }
struct Slot {
    mask: u8,
    association: [u8; 96],
    observed: Option<[u8; 32]>,
    completed_evidence: Option<[u8; 32]>,
}

pub(super) struct KernelReservation<'guard> {
    spec: Spec,
    guard: Owner<'guard>,
    directories: Vec<Directory>,
    records: RefCell<BTreeMap<Stage, HeldRecord>>,
    slot: String,
    pid: u32,
    state: State,
    transaction: Option<Vec<u8>>,
    transcript: Option<Vec<u8>>,
    evidence: Option<[u8; 32]>,
    semantic: Option<[u8; 32]>,
    fresh: bool,
    stopped: Cell<bool>,
}

/// Independent borrow/FD ownership keeps both locks alive after consuming the
/// reservation. It contains no callback, arbitrary path or copied success flag.
pub(super) struct BackendLock<'guard> {
    guard: Owner<'guard>,
    directories: Vec<Directory>,
    file: File,
    identity: FileIdentity,
    pid: u32,
    stopped: Cell<bool>,
}

fn named_file(parent: RawFd, name: &CStr, identity: &FileIdentity) -> Result<(), String> {
    let named = stat_at(parent, name)?.ok_or("egress kernel record disappeared")?;
    ensure(named.st_dev == identity.device && named.st_ino == identity.inode
        && named.st_uid == 0 && named.st_gid == 0 && named.st_nlink == 1
        && named.st_mode & libc::S_IFMT == libc::S_IFREG && named.st_mode & 0o7777 == 0o600
        && named.st_size >= 0 && named.st_size as u64 == identity.size,
        "egress kernel pathname no longer names its protected original")
}

impl BackendLock<'_> {
    pub(super) fn check(&self) -> Result<(), String> {
        self.check_phase(Phase::Admission)
    }
    pub(super) fn check_phase(&self, phase: Phase) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "egress backend lock owner is stopped")?;
        check_directories_phase(&self.directories, self.guard, self.pid, phase)?;
        ensure(file_identity(&self.file, self.identity.device, 0)? == self.identity,
            "egress backend lock original changed")?;
        let parent = self.directories.last().ok_or("egress backend directory absent")?.file.as_raw_fd();
        named_file(parent, &backend_name(), &self.identity)?;
        self.guard.check_phase(phase)?;
        self.stopped.set(false);
        Ok(())
    }

    pub(super) fn require_guard(&self, guard: &EgressGuard) -> Result<(), String> {
        self.require_owner(Owner::Diagnostic(guard))
    }
    pub(super) fn require_owner(&self, guard: Owner<'_>) -> Result<(), String> {
        ensure(self.guard.same(guard), "egress backend lock belongs to a different guard")?;
        self.check()
    }
}

// A transcript is only a bounded series of attempt/datagram originals. It is
// deliberately not parsed as a successful netlink ACK or semantic readback.
fn transcript(raw: &[u8]) -> Result<(), String> {
    ensure((12..=MAX_TRANSCRIPT).contains(&raw.len()) && &raw[..8] == b"SWNEGBE1",
        "egress kernel transcript framing is invalid")?;
    let count = u32::from_be_bytes(raw[8..12].try_into().map_err(|_| "egress event count invalid")?);
    ensure(count <= 512, "egress transcript event count exceeds its bound")?;
    let mut offset = 12usize;
    for _ in 0..count {
        ensure(raw.len() - offset >= 5, "egress transcript event is incomplete")?;
        let tag = raw[offset];
        ensure(matches!(tag, 1 | 2 | 3), "egress transcript event purpose is unknown")?;
        let length = u32::from_be_bytes(raw[offset + 1..offset + 5].try_into()
            .map_err(|_| "egress transcript event length invalid")?) as usize;
        offset += 5;
        ensure(length > 0 && length <= MAX_TRANSACTION && length <= raw.len() - offset
            && (tag != 1 || length <= 4096), "egress transcript event exceeds its original bound")?;
        offset += length;
    }
    ensure(offset == raw.len(), "egress transcript has trailing bytes")
}

fn validate_record(raw: &[u8], stage: Stage, slot: &str) -> Result<(), String> {
    let (minimum, maximum) = stage.bounds();
    ensure((minimum..=maximum).contains(&raw.len()), "egress kernel record length invalid")?;
    let identifier: [u8; 32] = raw[9..41].try_into().map_err(|_| "egress kernel slot invalid")?;
    ensure(&raw[..8] == MAGIC && raw[8] == stage as u8 && hex(&identifier) == slot
        && nonzero(&identifier) && nonzero(&raw[41..73]) && nonzero(&raw[73..105])
        && nonzero(&raw[105..PREFIX]), "egress kernel record version or association invalid")?;
    match stage {
        Stage::Reserve => {
            let length = u32::from_be_bytes(raw[PREFIX..PREFIX + 4].try_into()
                .map_err(|_| "egress transaction length invalid")?) as usize;
            ensure(length > 0 && length <= MAX_TRANSACTION && raw.len() == PREFIX + 4 + length
                && digest(&raw[PREFIX + 4..]).as_slice() == &raw[105..PREFIX],
                "egress retained transaction length or digest differs")?;
        }
        Stage::Claim => {},
        Stage::Observed => {
            let length = u32::from_be_bytes(raw[PREFIX + 32..PREFIX + 36].try_into()
                .map_err(|_| "egress evidence length invalid")?) as usize;
            ensure(length <= MAX_TRANSCRIPT && raw.len() == PREFIX + 36 + length
                && nonzero(&raw[PREFIX..PREFIX + 32])
                && digest(&raw[PREFIX + 36..]).as_slice() == &raw[PREFIX..PREFIX + 32],
                "egress retained transcript length or digest differs")?;
            transcript(&raw[PREFIX + 36..])?;
        }
        Stage::Complete => ensure(nonzero(&raw[PREFIX..PREFIX + 32])
            && nonzero(&raw[PREFIX + 32..]), "egress kernel completion digest is zero")?,
    }
    Ok(())
}

impl<'guard> KernelReservation<'guard> {
    fn fd(&self) -> RawFd {
        self.directories.last().expect("held kernel journal directory").file.as_raw_fd()
    }

    fn current(&self) -> Result<(), String> {
        check_directories(&self.directories, self.guard, self.pid)?;
        for held in self.records.borrow().values() {
            self.guard.check()?;
            ensure(file_identity(&held.file, self.spec.journal_device, held.identity.size)? == held.identity,
                "egress retained journal inode changed")?;
            named_file(self.fd(), &held.name, &held.identity)?;
        }
        self.guard.check()
    }

    fn name(&self, stage: Stage) -> CString {
        CString::new(format!("{}.{}", self.slot, stage.suffix())).expect("fixed kernel record name")
    }

    fn prefix(&self, stage: Stage) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PREFIX);
        raw.extend_from_slice(MAGIC); raw.push(stage as u8);
        raw.extend_from_slice(&self.spec.reservation_id);
        raw.extend_from_slice(&self.spec.association_sha256);
        raw.extend_from_slice(&self.spec.token_sha256);
        raw.extend_from_slice(&self.spec.intended_transaction_sha256);
        raw
    }

    fn record(&self, stage: Stage) -> Result<Vec<u8>, String> {
        let mut raw = self.prefix(stage);
        match stage {
            Stage::Reserve => {
                let transaction = self.transaction.as_ref().ok_or("egress exact transaction absent")?;
                raw.extend_from_slice(&(transaction.len() as u32).to_be_bytes()); raw.extend_from_slice(transaction);
            }
            Stage::Claim => {},
            Stage::Observed => {
                let original = self.transcript.as_ref().ok_or("egress exact transcript absent")?;
                raw.extend_from_slice(&self.evidence.ok_or("egress transcript digest absent")?);
                raw.extend_from_slice(&(original.len() as u32).to_be_bytes()); raw.extend_from_slice(original);
            }
            Stage::Complete => {
                raw.extend_from_slice(&self.semantic.ok_or("egress semantic digest absent")?);
                raw.extend_from_slice(&self.evidence.ok_or("egress evidence digest absent")?);
            }
        }
        validate_record(&raw, stage, &self.slot)?;
        Ok(raw)
    }

    fn exists(&self, stage: Stage) -> Result<bool, String> {
        self.current()?;
        let exists = stat_at(self.fd(), &self.name(stage))?.is_some();
        self.current()?;
        Ok(exists)
    }

    fn read(&self, name: &CStr, stage: Stage, slot: &str) -> Result<(Vec<u8>, File, FileIdentity), String> {
        self.current()?;
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(fd >= 0, "egress kernel record cannot be opened")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        let size = file.metadata().map_err(|_| "egress kernel record metadata failed")?.size();
        let (minimum, maximum) = stage.bounds();
        ensure((minimum as u64..=maximum as u64).contains(&size), "egress kernel record size invalid")?;
        let before = file_identity(&file, self.spec.journal_device, size)?;
        let mut raw = vec![0; size as usize];
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            let end = raw.len().min(offset + IO_CHUNK);
            match file.read(&mut raw[offset..end]) {
                Ok(0) => return Err("egress kernel record is incomplete".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("egress kernel record read failed".to_owned()),
            }
            self.current()?;
        }
        let mut extra = [0; 1];
        ensure(file.read(&mut extra).map_err(|_| "egress record trailing read failed")? == 0,
            "egress kernel record has trailing bytes")?;
        ensure(file_identity(&file, self.spec.journal_device, size)? == before,
            "egress kernel record changed during read")?;
        named_file(self.fd(), name, &before)?;
        validate_record(&raw, stage, slot)?;
        self.current()?;
        Ok((raw, file, before))
    }

    fn read_own(&self, stage: Stage) -> Result<Vec<u8>, String> {
        let name = self.name(stage);
        let (raw, file, identity) = self.read(&name, stage, &self.slot)?;
        {
            let mut records = self.records.borrow_mut();
            if let Some(held) = records.get(&stage) {
                ensure(held.identity == identity, "egress retained record identity was replaced")?;
            } else { records.insert(stage, HeldRecord { file, identity, name }); }
        }
        self.current()?;
        Ok(raw)
    }

    fn exact(&self, stage: Stage) -> Result<(), String> {
        ensure(self.read_own(stage)? == self.record(stage)?,
            "egress kernel record changes its exact original association")
    }

    fn publish(&self, stage: Stage) -> Result<(), String> {
        self.current()?;
        let raw = self.record(stage)?;
        let name = self.name(stage);
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT
            | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        ensure(fd >= 0, "egress exclusive record publication failed; outcome is consumed")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        ensure(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0, "egress record mode failed")?;
        file_identity(&file, self.spec.journal_device, 0)?;
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            let end = raw.len().min(offset + IO_CHUNK);
            match file.write(&raw[offset..end]) {
                Ok(0) => return Err("egress kernel record write stalled".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("egress kernel record write failed".to_owned()),
            }
            self.current()?;
        }
        let identity = file_identity(&file, self.spec.journal_device, raw.len() as u64)?;
        self.current()?;
        file.sync_all().map_err(|_| "egress kernel record durability failed")?;
        self.current()?;
        self.directories.last().ok_or("egress kernel directory absent")?.file.sync_all()
            .map_err(|_| "egress kernel directory durability failed")?;
        self.current()?;
        self.exact(stage)?;
        ensure(file_identity(&file, self.spec.journal_device, raw.len() as u64)? == identity,
            "egress published record changed during readback")?;
        named_file(self.fd(), &name, &identity)?;
        self.current()
    }

    fn backend_file(&self) -> Result<(File, FileIdentity), String> {
        self.current()?;
        let name = backend_name();
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(fd >= 0, "egress backend.lock must be independently preprovisioned")?;
        let file = unsafe { File::from_raw_fd(fd) };
        let identity = file_identity(&file, self.spec.journal_device, 0)?;
        named_file(self.fd(), &name, &identity)?;
        self.current()?;
        Ok((file, identity))
    }

    fn inventory(&self) -> Result<BTreeMap<String, Slot>, String> {
        self.current()?;
        let dot = CString::new(".").expect("literal directory name");
        let fd = open_directory(self.fd(), &dot)?.into_raw_fd();
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            unsafe { libc::close(fd); }
            return Err("egress kernel journal enumeration failed".to_owned());
        }
        let stream = DirectoryStream(pointer);
        let mut slots = BTreeMap::new();
        let (mut records, mut backend) = (0usize, false);
        loop {
            self.current()?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                ensure(unsafe { *libc::__errno_location() } == 0, "egress kernel inventory read failed")?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            if bytes == b"backend.lock" {
                ensure(!backend, "egress backend lock inventory repeats")?;
                self.backend_file()?; backend = true; continue;
            }
            records += 1;
            ensure(records <= MAX_RECORDS && bytes.len() <= 73, "egress kernel inventory exceeds its bound")?;
            let text = std::str::from_utf8(bytes).map_err(|_| "egress kernel filename invalid")?;
            let (slot, suffix) = text.split_once('.').ok_or("egress kernel filename invalid")?;
            ensure(slot.len() == 64 && slot.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "egress kernel slot name invalid")?;
            let stage = match suffix { "reserve" => Stage::Reserve, "claim" => Stage::Claim,
                "observed" => Stage::Observed, "complete" => Stage::Complete,
                _ => return Err("egress kernel record purpose unknown".to_owned()) };
            let (raw, _, _) = self.read(name, stage, slot)?;
            let association: [u8; 96] = raw[41..PREFIX].try_into().map_err(|_| "egress association invalid")?;
            let retained = slots.entry(slot.to_owned()).or_insert(Slot {
                mask: 0, association, observed: None, completed_evidence: None });
            let bit = 1 << (stage as u8 - 1);
            ensure(retained.mask & bit == 0 && retained.association == association,
                "egress kernel stages repeat or change association")?;
            retained.mask |= bit;
            if stage == Stage::Observed {
                retained.observed = Some(raw[PREFIX..PREFIX + 32].try_into().map_err(|_| "egress evidence invalid")?);
            } else if stage == Stage::Complete {
                retained.completed_evidence = Some(raw[PREFIX + 32..].try_into().map_err(|_| "egress completion invalid")?);
            }
            ensure(slots.len() <= MAX_SLOTS, "egress kernel slot capacity exhausted")?;
        }
        ensure(backend && slots.values().all(|slot| matches!(slot.mask, 1 | 3 | 7 | 15)
            && (slot.mask != 15 || slot.observed == slot.completed_evidence)),
            "egress kernel journal has missing predecessors, evidence or backend lock")?;
        self.current()?;
        Ok(slots)
    }

    fn check_inner(&self) -> Result<(), String> {
        self.current()?;
        if self.transaction.is_some() { self.exact(Stage::Reserve)?; }
        match self.state {
            State::Opened | State::Reserved => {},
            State::Claimed => {
                self.exact(Stage::Claim)?;
                ensure(!self.exists(Stage::Observed)? && !self.exists(Stage::Complete)?,
                    "egress later record appeared before publication")?;
            }
            State::Observed => {
                self.exact(Stage::Claim)?; self.exact(Stage::Observed)?;
                ensure(!self.exists(Stage::Complete)?, "egress completion appeared before publication")?;
            }
            State::Completed => {
                self.exact(Stage::Claim)?; self.exact(Stage::Observed)?; self.exact(Stage::Complete)?;
            }
            State::Unknown => return Err("egress kernel outcome is unknown and consumed".to_owned()),
        }
        self.current()
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "egress kernel reservation owner is stopped")?;
        self.check_inner()?;
        self.stopped.set(false);
        Ok(())
    }

    pub(super) fn retained_transaction(&self) -> Option<&[u8]> { self.transaction.as_deref() }

    pub(super) fn reserve_transaction(&mut self, raw: &[u8]) -> Result<(), String> {
        self.check()?;
        ensure(self.state == State::Opened && !raw.is_empty() && raw.len() <= MAX_TRANSACTION,
            "egress transaction reservation cannot be renewed")?;
        self.stopped.set(true); self.state = State::Unknown;
        let intent = digest(raw);
        ensure(nonzero(&intent), "egress intended transaction digest is zero")?;
        if let Some(retained) = self.transaction.as_ref() {
            ensure(retained == raw && self.spec.intended_transaction_sha256 == intent,
                "egress retained transaction differs from supplied original")?;
            self.exact(Stage::Reserve)?;
        } else {
            let inventory = self.inventory()?;
            ensure(!inventory.contains_key(&self.slot) && inventory.len() < MAX_SLOTS,
                "egress transaction slot is already present or full")?;
            self.spec.intended_transaction_sha256 = intent;
            self.transaction = Some(raw.to_vec());
            self.publish(Stage::Reserve)?;
        }
        self.state = State::Reserved; self.stopped.set(false);
        self.check()
    }

    pub(super) fn backend_lock(&self) -> Result<BackendLock<'guard>, String> {
        self.check()?;
        let (file, identity) = self.backend_file()?;
        ensure(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "egress backend is busy or cannot be locked")?;
        self.current()?;
        let directories = duplicate_directories(&self.directories)?;
        let owner = BackendLock { guard: self.guard, directories, file, identity,
            pid: self.pid, stopped: Cell::new(false) };
        owner.check()?; self.check()?;
        Ok(owner)
    }

    fn load_completed(&mut self) -> Result<KernelClaimState, String> {
        self.exact(Stage::Reserve)?; self.exact(Stage::Claim)?;
        let observed = self.read_own(Stage::Observed)?;
        ensure(observed[..PREFIX] == self.prefix(Stage::Observed), "egress observed association differs")?;
        let complete = self.read_own(Stage::Complete)?;
        ensure(complete[..PREFIX] == self.prefix(Stage::Complete)
            && observed[PREFIX..PREFIX + 32] == complete[PREFIX + 32..],
            "egress completion does not join its exact observed original")?;
        let evidence = observed[PREFIX..PREFIX + 32].try_into().map_err(|_| "egress evidence invalid")?;
        let semantic = complete[PREFIX..PREFIX + 32].try_into().map_err(|_| "egress semantic digest invalid")?;
        self.transcript = Some(observed[PREFIX + 36..].to_vec());
        self.evidence = Some(evidence); self.semantic = Some(semantic);
        self.fresh = false; self.state = State::Completed; self.stopped.set(false);
        self.check()?;
        Ok(KernelClaimState::AlreadyComplete { semantic_sha256: semantic, evidence_sha256: evidence })
    }

    pub(super) fn replay_completed(&mut self) -> Result<KernelClaimState, String> {
        self.check()?;
        ensure(self.state == State::Reserved, "egress completed replay is not newly admitted")?;
        self.stopped.set(true); self.state = State::Unknown;
        // No publication on this path, even if only a valid reservation exists.
        self.load_completed()
    }

    pub(super) fn claim(&mut self) -> Result<KernelClaimState, String> {
        self.check()?;
        ensure(self.state == State::Reserved, "egress kernel claim was already used")?;
        self.stopped.set(true); self.state = State::Unknown;
        if self.exists(Stage::Complete)? { return self.load_completed(); }
        ensure(!self.exists(Stage::Claim)? && !self.exists(Stage::Observed)?,
            "egress kernel claim is incomplete or unknown and consumed")?;
        self.publish(Stage::Claim)?;
        self.fresh = true; self.state = State::Claimed; self.stopped.set(false);
        self.check()?;
        Ok(KernelClaimState::Fresh)
    }

    pub(super) fn require_backend_claim(&self, guard: &EgressGuard,
        intended_sha256: [u8; 32]) -> Result<(), String> {
        self.require_owner_claim(Owner::Diagnostic(guard), intended_sha256)
    }
    pub(super) fn require_owner_claim(&self, guard: Owner<'_>,
        intended_sha256: [u8; 32]) -> Result<(), String> {
        self.check()?;
        ensure(self.guard.same(guard) && self.fresh && self.state == State::Claimed
            && intended_sha256 == self.spec.intended_transaction_sha256,
            "egress backend requires its own fresh exact transaction claim")?;
        self.check()
    }

    pub(super) fn observe(&mut self, raw: &[u8]) -> Result<[u8; 32], String> {
        self.check()?;
        ensure(self.fresh && self.state == State::Claimed, "egress observation requires this fresh claim")?;
        self.stopped.set(true); self.state = State::Unknown;
        transcript(raw)?;
        let evidence = digest(raw);
        ensure(nonzero(&evidence), "egress evidence digest is zero")?;
        self.transcript = Some(raw.to_vec()); self.evidence = Some(evidence);
        self.publish(Stage::Observed)?;
        self.state = State::Observed; self.stopped.set(false);
        self.check()?;
        Ok(evidence)
    }

    pub(super) fn complete(mut self, semantic_sha256: [u8; 32]) -> Result<(), String> {
        self.check()?;
        ensure(self.fresh && self.state == State::Observed && nonzero(&semantic_sha256),
            "egress completion requires fresh claimed originals and nonzero semantic digest")?;
        self.stopped.set(true); self.state = State::Unknown;
        self.semantic = Some(semantic_sha256);
        self.publish(Stage::Complete)?;
        self.state = State::Completed; self.stopped.set(false);
        self.check()
    }
}

pub(super) fn open_kernel(spec: Spec, guard: &EgressGuard) -> Result<KernelReservation<'_>, String> {
    open_kernel_owner(spec, Owner::Diagnostic(guard))
}

pub(super) fn open_kernel_owner(spec: Spec, guard: Owner<'_>) -> Result<KernelReservation<'_>, String> {
    guard.check()?;
    ensure(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0
        && spec.journal_device != 0 && spec.journal_inode != 0 && nonzero(&spec.reservation_id)
        && nonzero(&spec.association_sha256) && nonzero(&spec.token_sha256)
        && spec.intended_transaction_sha256 == [0; 32], "egress kernel opening scope invalid")?;
    let text = spec.journal_path.to_str().ok_or("egress kernel journal path is not UTF-8")?;
    ensure(text.starts_with('/') && text.len() <= 4096 && text != "/"
        && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) && !text.contains('\\'),
        "egress kernel journal path is not canonical absolute ASCII")?;
    let parts: Vec<&str> = text[1..].split('/').collect();
    ensure(parts.len() <= 64 && parts.iter().all(|part| !matches!(*part, "" | "." | "..") && part.len() <= 255),
        "egress kernel journal path has invalid components")?;
    let root = CString::new("/").expect("literal root path");
    let mut directories = vec![directory(open_directory(libc::AT_FDCWD, &root)?, None, false)?];
    for (index, part) in parts.iter().enumerate() {
        guard.check()?;
        let name = CString::new(*part).map_err(|_| "egress kernel journal component invalid")?;
        let parent = directories.last().ok_or("egress kernel root absent")?.file.as_raw_fd();
        directories.push(directory(open_directory(parent, &name)?, Some(name), index + 1 == parts.len())?);
        guard.check()?;
    }
    let held = directories.last().ok_or("egress kernel journal absent")?;
    ensure(held.device == spec.journal_device && held.inode == spec.journal_inode,
        "egress kernel journal differs from its signed identity")?;
    ensure(unsafe { libc::flock(held.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "egress kernel journal cannot be exclusively locked")?;
    let slot = hex(&spec.reservation_id);
    let mut owner = KernelReservation { spec, guard, directories, records: RefCell::new(BTreeMap::new()),
        slot, pid: std::process::id(), state: State::Opened, transaction: None, transcript: None,
        evidence: None, semantic: None, fresh: false, stopped: Cell::new(false) };
    let inventory = owner.inventory()?;
    if inventory.contains_key(&owner.slot) {
        let raw = owner.read_own(Stage::Reserve)?;
        ensure(raw[..105] == owner.prefix(Stage::Reserve)[..105],
            "egress retained slot belongs to a different operation or token")?;
        owner.spec.intended_transaction_sha256 = raw[105..PREFIX].try_into()
            .map_err(|_| "egress retained intent digest invalid")?;
        owner.transaction = Some(raw[PREFIX + 4..].to_vec());
    } else { ensure(inventory.len() < MAX_SLOTS, "egress kernel journal slot capacity exhausted")?; }
    owner.check()?;
    Ok(owner)
}
