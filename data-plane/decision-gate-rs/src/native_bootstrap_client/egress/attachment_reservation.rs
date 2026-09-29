//! Attachment-only durable intent/claim/original observation/completion custody.
//! Local files are not network success, repair or off-host rollback authority.

use super::{attachment::PreattachmentGuard, attachment_backend::AttachmentTranscript,
    attachment_readback::VerifiedAttachment, attachment_wire::AttachmentPlan, EgressGuard,
    owners::{AttachmentOwner, Owner, Phase},
    reservation::{Directory, DirectoryStream, FileIdentity, check_directories_owner as check_directories, check_directories_phase, directory,
        duplicate_directories, file_identity, hex, open_directory, stat_at}};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const MAGIC: &[u8; 8] = b"SWNATRS1";
const PREFIX: usize = 137;
const MAX_PLAN: usize = 64 * 1024;
const MAX_TRANSCRIPT: usize = 1024 * 1024;
const MAX_SEMANTIC: usize = 64 * 1024;
const MAX_SLOTS: usize = 64;
const CHUNK: usize = 16 * 1024;

pub(super) struct Spec {
    pub(super) journal_path: PathBuf,
    pub(super) journal_device: u64,
    pub(super) journal_inode: u64,
    pub(super) reservation_id: [u8; 32],
    pub(super) association_sha256: [u8; 32],
    pub(super) token_sha256: [u8; 32],
    pub(super) bridge_lock_path: PathBuf,
    pub(super) bridge_lock_device: u64,
    pub(super) bridge_lock_inode: u64,
}

pub(super) enum ClaimState { Fresh, Completed }
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage { Reserve = 1, Claim = 2, Observed = 3, Complete = 4 }
#[derive(PartialEq, Eq)]
enum State { Opened, Reserved, Claimed, Observed, Completed, Unknown }

impl Stage {
    fn suffix(self) -> &'static str {
        match self { Self::Reserve => "reserve", Self::Claim => "claim",
            Self::Observed => "observed", Self::Complete => "complete" }
    }
    fn bounds(self) -> (usize, usize) {
        match self { Self::Reserve => (PREFIX + 5, PREFIX + 4 + MAX_PLAN),
            Self::Claim => (PREFIX, PREFIX),
            Self::Observed => (PREFIX + 37, PREFIX + 36 + MAX_TRANSCRIPT),
            Self::Complete => (PREFIX + 69, PREFIX + 68 + MAX_SEMANTIC) }
    }
}

struct HeldRecord { file: File, identity: FileIdentity, name: CString }
struct Slot { mask: u8, association: [u8; 96], observed: Option<[u8; 32]>, completed: Option<[u8; 32]> }

pub(super) struct AttachmentReservation<'guard, 'egress> {
    spec: Spec,
    guard: AttachmentOwner<'guard, 'egress>,
    directories: Vec<Directory>,
    bridge: RefCell<Option<AttachmentBackendLock<'guard, 'egress>>>,
    records: RefCell<BTreeMap<Stage, HeldRecord>>,
    slot: String,
    pid: u32,
    state: State,
    intent: Option<Vec<u8>>,
    transcript: Option<Vec<u8>>,
    semantic: Option<Vec<u8>>,
    replay: bool,
    stopped: Cell<bool>,
}

/// This FD and the journal's duplicate share the actual acquired flock. Neither
/// a copied pathname nor a caller success flag can manufacture this owner.
pub(super) struct AttachmentBackendLock<'guard, 'egress> {
    guard: AttachmentOwner<'guard, 'egress>,
    directories: Vec<Directory>,
    name: CString,
    file: File,
    identity: FileIdentity,
    pid: u32,
    stopped: Cell<bool>,
}

fn ensure(value: bool, reason: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(reason.to_owned()) }
}
fn nonzero(value: &[u8]) -> bool { value.iter().any(|byte| *byte != 0) }
fn digest(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }

fn components(path: &PathBuf) -> Result<Vec<&str>, String> {
    let text = path.to_str().ok_or("attachment path is not UTF-8")?;
    ensure(text.starts_with('/') && text != "/" && text.len() <= 4096
        && text.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) && !text.contains('\\'),
        "attachment path is not canonical absolute ASCII")?;
    let parts: Vec<_> = text[1..].split('/').collect();
    ensure(parts.len() <= 64 && parts.iter().all(|part|
        !matches!(*part, "" | "." | "..") && part.len() <= 255), "attachment path components invalid")?;
    Ok(parts)
}

fn directories(parts: &[&str], final_private: bool, guard: &AttachmentOwner<'_, '_>)
    -> Result<Vec<Directory>, String>
{
    guard.check()?;
    let root = CString::new("/").expect("fixed root name");
    let mut held = vec![directory(open_directory(libc::AT_FDCWD, &root)?, None, false)?];
    for (index, part) in parts.iter().enumerate() {
        guard.check()?;
        let name = CString::new(*part).map_err(|_| "attachment path component invalid")?;
        let parent = held.last().ok_or("attachment root absent")?.file.as_raw_fd();
        held.push(directory(open_directory(parent, &name)?, Some(name),
            final_private && index + 1 == parts.len())?);
        guard.check()?;
    }
    check_directories(&held, guard.egress(), std::process::id())?;
    guard.check()?;
    Ok(held)
}

fn named_file(parent: RawFd, name: &CStr, identity: &FileIdentity) -> Result<(), String> {
    let named = stat_at(parent, name)?.ok_or("attachment protected pathname disappeared")?;
    ensure(named.st_dev == identity.device && named.st_ino == identity.inode
        && named.st_uid == 0 && named.st_gid == 0 && named.st_nlink == 1
        && named.st_mode & libc::S_IFMT == libc::S_IFREG && named.st_mode & 0o7777 == 0o600
        && named.st_size >= 0 && named.st_size as u64 == identity.size,
        "attachment protected pathname changed")
}

impl<'guard, 'egress> AttachmentBackendLock<'guard, 'egress> {
    pub(super) fn check(&self) -> Result<(), String> {
        self.check_phase(Phase::Admission)
    }
    pub(super) fn check_phase(&self, phase: Phase) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "attachment bridge lock owner stopped")?;
        self.guard.check_phase(phase)?;
        check_directories_phase(&self.directories, self.guard.egress(), self.pid, phase)?;
        ensure(file_identity(&self.file, self.identity.device, 0)? == self.identity,
            "attachment bridge lock original changed")?;
        named_file(self.directories.last().ok_or("attachment lock parent absent")?.file.as_raw_fd(),
            &self.name, &self.identity)?;
        self.guard.check_phase(phase)?;
        self.stopped.set(false);
        Ok(())
    }
    pub(super) fn require_guard(&self, guard: &PreattachmentGuard<'_>) -> Result<(), String> {
        self.require_owner(&AttachmentOwner::Diagnostic(guard))
    }
    pub(super) fn require_owner(&self, guard: &AttachmentOwner<'_, '_>) -> Result<(), String> {
        ensure(self.guard.same(guard), "attachment bridge lock owner differs")?;
        self.check()
    }
    fn duplicate(&self) -> Result<Self, String> {
        self.check()?;
        let file = self.file.try_clone().map_err(|_| "attachment bridge lock duplication failed")?;
        let identity = file_identity(&file, self.identity.device, 0)?;
        let result = Self { guard: self.guard.clone(), directories: duplicate_directories(&self.directories)?,
            name: self.name.clone(), file, identity, pid: self.pid, stopped: Cell::new(false) };
        result.check()?; self.check()?;
        Ok(result)
    }
}

fn length(raw: &[u8], offset: usize) -> Result<usize, String> {
    Ok(u32::from_be_bytes(raw.get(offset..offset + 4).ok_or("attachment length absent")?
        .try_into().map_err(|_| "attachment length invalid")?) as usize)
}

fn validate(raw: &[u8], stage: Stage, slot: &str) -> Result<(), String> {
    let (minimum, maximum) = stage.bounds();
    ensure((minimum..=maximum).contains(&raw.len()), "attachment record length invalid")?;
    let id: [u8; 32] = raw[9..41].try_into().map_err(|_| "attachment slot invalid")?;
    ensure(&raw[..8] == MAGIC && raw[8] == stage as u8 && hex(&id) == slot && nonzero(&id)
        && nonzero(&raw[41..73]) && nonzero(&raw[73..105]) && nonzero(&raw[105..PREFIX]),
        "attachment record purpose or association invalid")?;
    match stage {
        Stage::Reserve => ensure(raw.len() == PREFIX + 4 + length(raw, PREFIX)?
            && digest(&raw[PREFIX + 4..]).as_slice() == &raw[105..PREFIX],
            "attachment retained plan length or digest differs")?,
        Stage::Claim => {},
        Stage::Observed => ensure(raw.len() == PREFIX + 36 + length(raw, PREFIX + 32)?
            && nonzero(&raw[PREFIX..PREFIX + 32])
            && digest(&raw[PREFIX + 36..]).as_slice() == &raw[PREFIX..PREFIX + 32],
            "attachment transcript original differs")?,
        Stage::Complete => ensure(raw.len() == PREFIX + 68 + length(raw, PREFIX + 64)?
            && nonzero(&raw[PREFIX..PREFIX + 32]) && nonzero(&raw[PREFIX + 32..PREFIX + 64])
            && digest(&raw[PREFIX + 68..]).as_slice() == &raw[PREFIX + 32..PREFIX + 64],
            "attachment semantic original differs")?,
    }
    Ok(())
}

impl<'guard, 'egress> AttachmentReservation<'guard, 'egress> {
    fn fd(&self) -> RawFd { self.directories.last().expect("retained attachment journal").file.as_raw_fd() }
    fn current(&self) -> Result<(), String> {
        self.guard.check()?;
        check_directories(&self.directories, self.guard.egress(), self.pid)?;
        if let Some(lock) = self.bridge.borrow().as_ref() { lock.check()?; }
        for held in self.records.borrow().values() {
            self.guard.check()?;
            ensure(file_identity(&held.file, self.spec.journal_device, held.identity.size)? == held.identity,
                "attachment retained record changed")?;
            named_file(self.fd(), &held.name, &held.identity)?;
        }
        self.guard.check()
    }
    fn name(&self, stage: Stage) -> CString {
        CString::new(format!("{}.{}", self.slot, stage.suffix())).expect("fixed attachment record name")
    }
    fn prefix(&self, stage: Stage) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PREFIX);
        raw.extend_from_slice(MAGIC); raw.push(stage as u8);
        raw.extend_from_slice(&self.spec.reservation_id);
        raw.extend_from_slice(&self.spec.association_sha256);
        raw.extend_from_slice(&self.spec.token_sha256);
        raw.extend_from_slice(&self.intent.as_ref().map(|raw| digest(raw)).unwrap_or([0; 32]));
        raw
    }
    fn record(&self, stage: Stage) -> Result<Vec<u8>, String> {
        let mut raw = self.prefix(stage);
        match stage {
            Stage::Reserve => {
                let plan = self.intent.as_ref().ok_or("attachment exact intent absent")?;
                raw.extend_from_slice(&(plan.len() as u32).to_be_bytes()); raw.extend_from_slice(plan);
            },
            Stage::Claim => {},
            Stage::Observed => {
                let original = self.transcript.as_ref().ok_or("attachment transcript absent")?;
                raw.extend_from_slice(&digest(original));
                raw.extend_from_slice(&(original.len() as u32).to_be_bytes()); raw.extend_from_slice(original);
            },
            Stage::Complete => {
                let original = self.semantic.as_ref().ok_or("attachment semantic original absent")?;
                raw.extend_from_slice(&digest(self.transcript.as_ref().ok_or("attachment transcript absent")?));
                raw.extend_from_slice(&digest(original));
                raw.extend_from_slice(&(original.len() as u32).to_be_bytes()); raw.extend_from_slice(original);
            },
        }
        validate(&raw, stage, &self.slot)?;
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
        ensure(fd >= 0, "attachment record cannot be opened")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        let size = file.metadata().map_err(|_| "attachment record metadata failed")?.size();
        let (minimum, maximum) = stage.bounds();
        ensure((minimum as u64..=maximum as u64).contains(&size), "attachment record exceeds bound")?;
        let identity = file_identity(&file, self.spec.journal_device, size)?;
        let mut raw = vec![0; size as usize];
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            let end = raw.len().min(offset + CHUNK);
            match file.read(&mut raw[offset..end]) {
                Ok(0) => return Err("attachment record incomplete".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("attachment record read failed".to_owned()),
            }
            self.current()?;
        }
        let mut extra = [0; 1];
        ensure(file.read(&mut extra).map_err(|_| "attachment trailing read failed")? == 0
            && file_identity(&file, self.spec.journal_device, size)? == identity,
            "attachment record changed or has trailing bytes")?;
        named_file(self.fd(), name, &identity)?;
        validate(&raw, stage, slot)?; self.current()?;
        Ok((raw, file, identity))
    }
    fn read_own(&self, stage: Stage) -> Result<Vec<u8>, String> {
        let name = self.name(stage);
        let (raw, file, identity) = self.read(&name, stage, &self.slot)?;
        {
            let mut records = self.records.borrow_mut();
            if let Some(held) = records.get(&stage) {
                ensure(held.identity == identity, "attachment retained inode replaced")?;
            } else { records.insert(stage, HeldRecord { file, identity, name }); }
        }
        self.current()?;
        Ok(raw)
    }
    fn exact(&self, stage: Stage) -> Result<(), String> {
        ensure(self.read_own(stage)? == self.record(stage)?, "attachment exact record association changed")
    }
    fn publish(&self, stage: Stage) -> Result<(), String> {
        self.current()?;
        let raw = self.record(stage)?;
        let name = self.name(stage);
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT
            | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        ensure(fd >= 0, "attachment exclusive publication failed; outcome consumed")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        ensure(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0, "attachment record mode failed")?;
        file_identity(&file, self.spec.journal_device, 0)?;
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            let end = raw.len().min(offset + CHUNK);
            match file.write(&raw[offset..end]) {
                Ok(0) => return Err("attachment record write stalled".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("attachment record write failed".to_owned()),
            }
            self.current()?;
        }
        let identity = file_identity(&file, self.spec.journal_device, raw.len() as u64)?;
        file.sync_all().map_err(|_| "attachment record durability failed")?;
        self.current()?;
        self.directories.last().ok_or("attachment journal absent")?.file.sync_all()
            .map_err(|_| "attachment directory durability failed")?;
        self.current()?; self.exact(stage)?;
        ensure(file_identity(&file, self.spec.journal_device, raw.len() as u64)? == identity,
            "attachment publication changed during readback")?;
        named_file(self.fd(), &name, &identity)?;
        self.current()
    }
    fn inventory(&self) -> Result<BTreeMap<String, Slot>, String> {
        self.current()?;
        let fd = open_directory(self.fd(), &CString::new(".").expect("fixed dot"))?.into_raw_fd();
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() { unsafe { libc::close(fd); } return Err("attachment inventory failed".to_owned()); }
        let stream = DirectoryStream(pointer);
        let mut slots = BTreeMap::new();
        let mut records = 0;
        loop {
            self.current()?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                ensure(unsafe { *libc::__errno_location() } == 0, "attachment inventory read failed")?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            records += 1;
            ensure(records <= 4 * MAX_SLOTS && bytes.len() <= 73, "attachment inventory capacity exceeded")?;
            let text = std::str::from_utf8(bytes).map_err(|_| "attachment filename invalid")?;
            let (slot, suffix) = text.split_once('.').ok_or("attachment filename invalid")?;
            ensure(slot.len() == 64 && slot.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "attachment slot name invalid")?;
            let stage = match suffix { "reserve" => Stage::Reserve, "claim" => Stage::Claim,
                "observed" => Stage::Observed, "complete" => Stage::Complete,
                _ => return Err("attachment record purpose unknown".to_owned()) };
            let (raw, _, _) = self.read(name, stage, slot)?;
            let association = raw[41..PREFIX].try_into().map_err(|_| "attachment association invalid")?;
            let saved = slots.entry(slot.to_owned()).or_insert(Slot {
                mask: 0, association, observed: None, completed: None });
            let bit = 1 << (stage as u8 - 1);
            ensure(saved.mask & bit == 0 && saved.association == association,
                "attachment stages repeat or change association")?;
            saved.mask |= bit;
            if stage == Stage::Observed { saved.observed = Some(raw[PREFIX..PREFIX + 32].try_into()
                .map_err(|_| "attachment observed digest invalid")?); }
            if stage == Stage::Complete { saved.completed = Some(raw[PREFIX..PREFIX + 32].try_into()
                .map_err(|_| "attachment completed digest invalid")?); }
            ensure(slots.len() <= MAX_SLOTS, "attachment slot capacity exhausted")?;
        }
        ensure(slots.values().all(|slot| matches!(slot.mask, 1 | 3 | 7 | 15)
            && (slot.mask != 15 || slot.observed == slot.completed)), "attachment journal predecessor missing")?;
        self.current()?;
        Ok(slots)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "attachment reservation stopped")?;
        self.current()?;
        ensure(self.state != State::Unknown, "attachment outcome unknown and consumed")?;
        if self.intent.is_some() { self.exact(Stage::Reserve)?; }
        if matches!(self.state, State::Claimed | State::Observed | State::Completed) { self.exact(Stage::Claim)?; }
        if matches!(self.state, State::Observed | State::Completed) { self.exact(Stage::Observed)?; }
        if self.state == State::Completed { self.exact(Stage::Complete)?; }
        if self.state == State::Claimed {
            ensure(!self.exists(Stage::Observed)? && !self.exists(Stage::Complete)?, "attachment later record appeared")?;
        } else if self.state == State::Observed {
            ensure(!self.exists(Stage::Complete)?, "attachment completion appeared early")?;
        }
        self.current()?; self.stopped.set(false);
        Ok(())
    }
    pub(super) fn backend_lock(&self) -> Result<AttachmentBackendLock<'guard, 'egress>, String> {
        self.check()?;
        ensure(self.state == State::Opened && self.bridge.borrow().is_none(), "attachment lock cannot be reacquired")?;
        let parts = components(&self.spec.bridge_lock_path)?;
        let name = CString::new(*parts.last().ok_or("attachment bridge lock name absent")?)
            .map_err(|_| "attachment bridge lock name invalid")?;
        let held = directories(&parts[..parts.len() - 1], false, &self.guard)?;
        let parent = held.last().ok_or("attachment bridge lock parent absent")?.file.as_raw_fd();
        self.guard.check()?;
        let fd = unsafe { libc::openat(parent, name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(fd >= 0, "attachment bridge lock must be preprovisioned")?;
        let file = unsafe { File::from_raw_fd(fd) };
        let identity = file_identity(&file, self.spec.bridge_lock_device, 0)?;
        ensure(identity.inode == self.spec.bridge_lock_inode, "attachment bridge lock differs from signed inode")?;
        named_file(parent, &name, &identity)?;
        ensure(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "attachment bridge lock busy or unavailable")?;
        let owner = AttachmentBackendLock { guard: self.guard.clone(), directories: held, name, file, identity,
            pid: self.pid, stopped: Cell::new(false) };
        owner.check()?;
        let retained = owner.duplicate()?;
        *self.bridge.borrow_mut() = Some(retained);
        self.check()?;
        Ok(owner)
    }
    pub(super) fn reserve(&mut self, plan: &AttachmentPlan) -> Result<(), String> {
        self.check()?; plan.require_source(self.guard.egress(), Phase::Admission)?;
        ensure(self.state == State::Opened && self.bridge.borrow().is_some()
            && !plan.original().is_empty() && plan.original().len() <= MAX_PLAN
            && digest(plan.original()) == plan.sha256() && nonzero(&plan.sha256()),
            "attachment plan reservation scope invalid")?;
        self.stopped.set(true); self.state = State::Unknown;
        if let Some(original) = &self.intent {
            ensure(self.replay && original == plan.original(), "attachment retained intent differs")?;
            self.exact(Stage::Reserve)?;
        } else {
            let inventory = self.inventory()?;
            ensure(!inventory.contains_key(&self.slot) && inventory.len() < MAX_SLOTS,
                "attachment slot appeared or capacity exhausted")?;
            self.intent = Some(plan.original().to_vec()); self.publish(Stage::Reserve)?;
        }
        self.state = State::Reserved; self.stopped.set(false); self.check()
    }
    pub(super) fn claim(&mut self) -> Result<ClaimState, String> {
        self.check()?;
        ensure(self.state == State::Reserved, "attachment claim already consumed")?;
        self.stopped.set(true); self.state = State::Unknown;
        if self.replay {
            self.exact(Stage::Claim)?;
            let observed = self.read_own(Stage::Observed)?;
            let complete = self.read_own(Stage::Complete)?;
            ensure(observed[..PREFIX] == self.prefix(Stage::Observed)
                && complete[..PREFIX] == self.prefix(Stage::Complete)
                && observed[PREFIX..PREFIX + 32] == complete[PREFIX..PREFIX + 32],
                "attachment completed originals differ")?;
            self.transcript = Some(observed[PREFIX + 36..].to_vec());
            self.semantic = Some(complete[PREFIX + 68..].to_vec());
            self.state = State::Completed; self.stopped.set(false); self.check()?;
            return Ok(ClaimState::Completed);
        }
        ensure(!self.exists(Stage::Claim)? && !self.exists(Stage::Observed)? && !self.exists(Stage::Complete)?,
            "attachment prior claim is consumed")?;
        self.publish(Stage::Claim)?;
        self.state = State::Claimed; self.stopped.set(false); self.check()?;
        Ok(ClaimState::Fresh)
    }
    pub(super) fn require_claim(&self, guard: &EgressGuard, plan: &AttachmentPlan) -> Result<(), String> {
        self.require_source_claim(Owner::Diagnostic(guard), plan)
    }
    pub(super) fn require_source_claim(&self, guard: Owner<'_>, plan: &AttachmentPlan) -> Result<(), String> {
        self.check()?; plan.require_source(guard, Phase::Admission)?;
        ensure(self.guard.egress().same(guard) && !self.replay && self.state == State::Claimed
            && self.intent.as_deref() == Some(plan.original()), "attachment requires its own fresh exact claim")?;
        self.check()
    }
    pub(super) fn observe(&mut self, original: &AttachmentTranscript) -> Result<(), String> {
        self.check()?;
        ensure(!self.replay && self.state == State::Claimed && !original.original().is_empty()
            && original.original().len() <= MAX_TRANSCRIPT
            && original.owner_identity() == self.guard.egress().identity()
            && original.plan_sha256() == digest(self.intent.as_ref().ok_or("attachment intent absent")?),
            "attachment observation requires fresh own-plan typed originals")?;
        self.stopped.set(true); self.state = State::Unknown;
        self.transcript = Some(original.original().to_vec()); self.publish(Stage::Observed)?;
        self.state = State::Observed; self.stopped.set(false); self.check()
    }
    pub(super) fn complete(&mut self, plan: &AttachmentPlan, verified: &VerifiedAttachment) -> Result<(), String> {
        self.check()?; plan.require_source(self.guard.egress(), Phase::Admission)?;
        verified.require_source(self.guard.egress(), plan, Phase::Admission)?;
        ensure(!self.replay && self.state == State::Observed && self.intent.as_deref() == Some(plan.original())
            && !verified.original().is_empty() && verified.original().len() <= MAX_SEMANTIC
            && digest(self.transcript.as_ref().ok_or("attachment observed original absent")?) == verified.transcript_sha256(),
            "attachment completion requires exact genuine plan/transcript/semantic originals")?;
        self.stopped.set(true); self.state = State::Unknown;
        self.semantic = Some(verified.original().to_vec()); self.publish(Stage::Complete)?;
        self.state = State::Completed; self.stopped.set(false); self.check()
    }
    pub(super) fn completed_originals(&self) -> Result<(&[u8], &[u8]), String> {
        self.check()?;
        ensure(self.state == State::Completed, "attachment completion original absent")?;
        Ok((self.transcript.as_deref().ok_or("attachment transcript absent")?,
            self.semantic.as_deref().ok_or("attachment semantic original absent")?))
    }
}

pub(super) fn open<'guard, 'egress>(spec: Spec, guard: &'guard PreattachmentGuard<'egress>)
    -> Result<AttachmentReservation<'guard, 'egress>, String>
{
    open_owner(spec, AttachmentOwner::Diagnostic(guard))
}
pub(super) fn open_owner<'guard, 'egress>(spec: Spec, guard: AttachmentOwner<'guard, 'egress>)
    -> Result<AttachmentReservation<'guard, 'egress>, String>
{
    guard.check()?;
    ensure(spec.journal_device != 0 && spec.journal_inode != 0 && spec.bridge_lock_device != 0
        && spec.bridge_lock_inode != 0 && nonzero(&spec.reservation_id)
        && nonzero(&spec.association_sha256) && nonzero(&spec.token_sha256)
        && !spec.bridge_lock_path.starts_with(&spec.journal_path), "attachment journal opening scope invalid")?;
    components(&spec.bridge_lock_path)?;
    let held = directories(&components(&spec.journal_path)?, true, &guard)?;
    let last = held.last().ok_or("attachment journal absent")?;
    ensure(last.device == spec.journal_device && last.inode == spec.journal_inode,
        "attachment journal differs from signed identity")?;
    ensure(unsafe { libc::flock(last.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "attachment journal busy or unavailable")?;
    let mut owner = AttachmentReservation { slot: hex(&spec.reservation_id), spec, guard, directories: held,
        bridge: RefCell::new(None), records: RefCell::new(BTreeMap::new()), pid: std::process::id(),
        state: State::Opened, intent: None, transcript: None, semantic: None, replay: false, stopped: Cell::new(false) };
    let inventory = owner.inventory()?;
    if let Some(slot) = inventory.get(&owner.slot) {
        ensure(slot.mask == 15, "attachment existing incomplete slot is consumed; no retry")?;
        let original = owner.read_own(Stage::Reserve)?;
        ensure(original[..105] == owner.prefix(Stage::Reserve)[..105], "attachment completed slot scope differs")?;
        owner.intent = Some(original[PREFIX + 4..].to_vec()); owner.replay = true;
    } else { ensure(inventory.len() < MAX_SLOTS, "attachment slot capacity exhausted")?; }
    owner.check()?;
    Ok(owner)
}
