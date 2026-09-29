//! Egress-only local reserve/claim/complete records, not firewall authority.
//!
//! A durable claim precedes firewall mutation. Separately authorized stopped
//! child creation is outside this journal. Errors never remove or repair records;
//! completion digests are local associations, not raw evidence or kernel proof.

use super::EgressGuard;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const MAX_SLOTS: usize = 64;
const MAX_RECORDS: usize = 3 * MAX_SLOTS;
const BASE_BYTES: usize = 137;
const COMPLETE_BYTES: usize = 169;
const MAGIC: &[u8; 8] = b"SWNEGRS1";

pub(super) struct Spec {
    pub(super) journal_path: PathBuf,
    pub(super) journal_device: u64,
    pub(super) journal_inode: u64,
    pub(super) reservation_id: [u8; 32],
    pub(super) association_sha256: [u8; 32],
    pub(super) token_sha256: [u8; 32],
    pub(super) intended_transaction_sha256: [u8; 32],
}

pub(super) enum ClaimState {
    Fresh,
    AlreadyComplete([u8; 32]),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage { Reserve = 1, Claim = 2, Complete = 3 }

impl Stage {
    fn suffix(self) -> &'static str {
        match self {
            Self::Reserve => "reserve", Self::Claim => "claim", Self::Complete => "complete",
        }
    }

    fn size(self) -> usize {
        if self == Self::Complete { COMPLETE_BYTES } else { BASE_BYTES }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Reserved, Claimed, Completed, Unknown }

struct Directory {
    file: File,
    name: Option<CString>,
    device: u64,
    inode: u64,
    mode: u32,
    gid: u32,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64, inode: u64, size: u64,
    modified: i64, modified_ns: i64, changed: i64, changed_ns: i64,
}

/// Owns the same concrete guard and nonblocking directory lock, never a callback.
/// No Clone/Debug/public constructor; recorded digests grant no effect permission.
pub(super) struct Reservation<'a> {
    spec: Spec,
    guard: &'a EgressGuard,
    directories: Vec<Directory>,
    slot: String,
    pid: u32,
    state: State,
    observed: Option<[u8; 32]>,
    stopped: Cell<bool>,
}

fn ensure(value: bool, message: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}

fn nonzero(value: &[u8]) -> bool { value.iter().any(|byte| *byte != 0) }

fn directory(file: File, name: Option<CString>, final_directory: bool) -> Result<Directory, String> {
    let metadata = file.metadata().map_err(|_| "egress journal directory metadata failed")?;
    ensure(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "egress journal ancestors must be root-owned nonwritable directories")?;
    if final_directory {
        ensure(metadata.gid() == 0 && metadata.mode() & 0o7777 == 0o700,
            "egress journal must be root:root mode 0700")?;
    }
    Ok(Directory { file, name, device: metadata.dev(), inode: metadata.ino(),
        mode: metadata.mode(), gid: metadata.gid() })
}

fn open_directory(parent: RawFd, name: &CStr) -> Result<File, String> {
    let fd = unsafe { libc::openat(parent, name.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    ensure(fd >= 0, "egress journal directory cannot be opened without following links")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stat_at(parent: RawFd, name: &CStr) -> Result<Option<libc::stat>, String> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) { return Ok(None); }
        return Err("egress journal named-object metadata failed".to_owned());
    }
    Ok(Some(value))
}

fn hex(value: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn file_identity(file: &File, device: u64, size: u64) -> Result<FileIdentity, String> {
    let m = file.metadata().map_err(|_| "egress journal record metadata failed")?;
    ensure(m.is_file() && m.dev() == device && m.uid() == 0 && m.gid() == 0
        && m.mode() & 0o7777 == 0o600 && m.nlink() == 1 && m.size() == size,
        "egress journal record ownership, mode, links or size is invalid")?;
    Ok(FileIdentity { device: m.dev(), inode: m.ino(), size: m.size(),
        modified: m.mtime(), modified_ns: m.mtime_nsec(), changed: m.ctime(), changed_ns: m.ctime_nsec() })
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

impl Reservation<'_> {
    fn fd(&self) -> RawFd {
        self.directories.last().expect("held egress journal directory").file.as_raw_fd()
    }

    fn current(&self) -> Result<(), String> {
        self.guard.check()?;
        ensure(std::process::id() == self.pid && unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0,
            "egress reservation crossed a process or privilege boundary")?;
        for (index, held) in self.directories.iter().enumerate() {
            self.guard.check()?;
            let m = held.file.metadata().map_err(|_| "egress held directory metadata failed")?;
            ensure(m.is_dir() && m.dev() == held.device && m.ino() == held.inode
                && m.uid() == 0 && m.gid() == held.gid && m.mode() == held.mode,
                "egress held directory identity changed")?;
            let root = CString::new("/").expect("literal root path");
            let (parent, name) = if index == 0 { (libc::AT_FDCWD, root.as_c_str()) } else {
                (self.directories[index - 1].file.as_raw_fd(),
                    held.name.as_ref().ok_or("egress directory name is absent")?.as_c_str())
            };
            let named = stat_at(parent, name)?.ok_or("egress named directory disappeared")?;
            ensure(named.st_dev == held.device && named.st_ino == held.inode
                && named.st_uid == 0 && named.st_gid == held.gid && named.st_mode == held.mode,
                "egress journal pathname no longer names its held directory")?;
        }
        self.guard.check()
    }

    fn name(&self, stage: Stage) -> CString {
        CString::new(format!("{}.{}", self.slot, stage.suffix())).expect("fixed egress record filename")
    }

    fn record(&self, stage: Stage) -> Result<Vec<u8>, String> {
        let mut raw = vec![0u8; stage.size()];
        raw[..8].copy_from_slice(MAGIC);
        raw[8] = stage as u8;
        raw[9..41].copy_from_slice(&self.spec.reservation_id);
        raw[41..73].copy_from_slice(&self.spec.association_sha256);
        raw[73..105].copy_from_slice(&self.spec.token_sha256);
        raw[105..137].copy_from_slice(&self.spec.intended_transaction_sha256);
        if stage == Stage::Complete {
            let observed = self.observed.as_ref().ok_or("egress completion lacks actual readback digest")?;
            ensure(nonzero(observed), "egress observed-state digest is zero")?;
            raw[137..].copy_from_slice(observed);
        }
        Ok(raw)
    }

    fn exists(&self, stage: Stage) -> Result<bool, String> {
        self.current()?;
        let result = stat_at(self.fd(), &self.name(stage))?.is_some();
        self.current()?;
        Ok(result)
    }

    fn read(&self, name: &CStr, stage: Stage) -> Result<Vec<u8>, String> {
        self.current()?;
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        ensure(fd >= 0, "egress journal record cannot be opened")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = file_identity(&file, self.spec.journal_device, stage.size() as u64)?;
        let mut raw = vec![0u8; stage.size()];
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            match file.read(&mut raw[offset..]) {
                Ok(0) => return Err("egress journal record is incomplete".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("egress journal record read failed".to_owned()),
            }
            self.current()?;
        }
        let mut extra = [0u8; 1];
        self.current()?;
        ensure(file.read(&mut extra).map_err(|_| "egress journal trailing read failed")? == 0,
            "egress journal record has trailing bytes")?;
        ensure(file_identity(&file, self.spec.journal_device, stage.size() as u64)? == before,
            "egress journal record changed during read")?;
        let named = stat_at(self.fd(), name)?.ok_or("egress journal record disappeared")?;
        ensure(named.st_dev == before.device && named.st_ino == before.inode
            && named.st_uid == 0 && named.st_gid == 0 && named.st_nlink == 1
            && named.st_mode & libc::S_IFMT == libc::S_IFREG && named.st_mode & 0o7777 == 0o600
            && named.st_size == stage.size() as i64,
            "egress named journal record changed")?;
        self.current()?;
        Ok(raw)
    }

    fn exact(&self, stage: Stage) -> Result<(), String> {
        ensure(self.read(&self.name(stage), stage)? == self.record(stage)?,
            "egress slot has a different exact operation, token, intent or observed-state association")
    }

    fn read_completion(&self) -> Result<[u8; 32], String> {
        let raw = self.read(&self.name(Stage::Complete), Stage::Complete)?;
        let mut prefix = self.record(Stage::Reserve)?;
        prefix[8] = Stage::Complete as u8;
        ensure(raw[..BASE_BYTES] == prefix && nonzero(&raw[BASE_BYTES..]),
            "egress completion changes its reserved association or has no observed-state digest")?;
        let mut observed = [0u8; 32];
        observed.copy_from_slice(&raw[BASE_BYTES..]);
        self.current()?;
        Ok(observed)
    }

    fn publish(&self, stage: Stage) -> Result<(), String> {
        self.current()?;
        let raw = self.record(stage)?;
        let name = self.name(stage);
        let fd = unsafe { libc::openat(self.fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT
            | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        ensure(fd >= 0, "egress exclusive publication refused; state is not reusable")?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        // No error path removes the inode, even after permission/write/fsync failure.
        ensure(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0,
            "egress journal record permissions failed")?;
        file_identity(&file, self.spec.journal_device, 0)?;
        let mut offset = 0;
        while offset < raw.len() {
            self.current()?;
            match file.write(&raw[offset..]) {
                Ok(0) => return Err("egress journal record write stalled".to_owned()),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("egress journal record write failed".to_owned()),
            }
            self.current()?;
        }
        let published = file_identity(&file, self.spec.journal_device, raw.len() as u64)?;
        self.current()?;
        file.sync_all().map_err(|_| "egress journal record durability failed")?;
        self.current()?;
        self.directories.last().ok_or("egress journal is absent")?.file.sync_all()
            .map_err(|_| "egress journal directory durability failed")?;
        self.current()?;
        self.exact(stage)?;
        ensure(file_identity(&file, self.spec.journal_device, raw.len() as u64)? == published,
            "egress original record changed during durable readback")?;
        let named = stat_at(self.fd(), &name)?.ok_or("egress published record disappeared")?;
        ensure(named.st_dev == published.device && named.st_ino == published.inode,
            "egress readback no longer names the exclusively published record")?;
        self.current()
    }

    fn inventory(&self) -> Result<BTreeMap<String, (u8, [u8; 96])>, String> {
        self.current()?;
        let dot = CString::new(".").expect("literal directory name");
        let fd = open_directory(self.fd(), &dot)?.into_raw_fd();
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            unsafe { libc::close(fd); }
            return Err("egress journal directory enumeration failed".to_owned());
        }
        let stream = DirectoryStream(pointer);
        let mut slots = BTreeMap::new();
        let mut records = 0usize;
        loop {
            self.current()?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                ensure(unsafe { *libc::__errno_location() } == 0,
                    "egress journal directory read failed")?;
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            records += 1;
            ensure(records <= MAX_RECORDS && bytes.len() <= 73,
                "egress journal record count or name exceeds its fixed bound")?;
            let text = std::str::from_utf8(bytes).map_err(|_| "egress journal filename is not ASCII")?;
            let (slot, suffix) = text.split_once('.').ok_or("egress journal filename is invalid")?;
            ensure(slot.len() == 64 && slot.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "egress journal slot is not canonical lowercase hex")?;
            let stage = match suffix {
                "reserve" => Stage::Reserve, "claim" => Stage::Claim, "complete" => Stage::Complete,
                _ => return Err("egress journal record purpose is invalid".to_owned()),
            };
            let raw = self.read(name, stage)?;
            let mut identifier = [0u8; 32];
            identifier.copy_from_slice(&raw[9..41]);
            ensure(&raw[..8] == MAGIC && raw[8] == stage as u8 && hex(&identifier) == slot
                && nonzero(&identifier) && nonzero(&raw[41..73]) && nonzero(&raw[73..105])
                && nonzero(&raw[105..137]) && (stage != Stage::Complete || nonzero(&raw[137..])),
                "egress journal framing or association is invalid")?;
            let mut association = [0u8; 96];
            association.copy_from_slice(&raw[41..137]);
            let (bits, retained) = slots.entry(slot.to_owned()).or_insert((0u8, association));
            let bit = 1u8 << (stage as u8 - 1);
            ensure(*bits & bit == 0 && *retained == association,
                "egress journal stage repeats or changes its exact association")?;
            *bits |= bit;
            ensure(slots.len() <= MAX_SLOTS, "egress journal slot capacity is exhausted")?;
        }
        ensure(slots.values().all(|(mask, _)| matches!(*mask, 1 | 3 | 7)),
            "egress journal contains a stage without durable predecessors")?;
        self.current()?;
        Ok(slots)
    }

    fn check_inner(&self) -> Result<(), String> {
        self.current()?;
        self.exact(Stage::Reserve)?;
        match self.state {
            State::Reserved => {},
            State::Claimed => {
                self.exact(Stage::Claim)?;
                ensure(!self.exists(Stage::Complete)?, "egress completion appeared before publication")?;
            },
            State::Completed => { self.exact(Stage::Claim)?; self.exact(Stage::Complete)?; },
            State::Unknown => return Err("egress reservation outcome is unknown and consumed".to_owned()),
        }
        self.current()
    }

    pub(super) fn check(&self) -> Result<(), String> {
        ensure(!self.stopped.replace(true), "egress reservation owner is stopped")?;
        self.check_inner()?;
        self.stopped.set(false);
        Ok(())
    }

    pub(super) fn claim(&mut self) -> Result<ClaimState, String> {
        self.check()?;
        ensure(self.state == State::Reserved, "egress reservation was already used")?;
        self.stopped.set(true);
        self.state = State::Unknown;
        if self.exists(Stage::Complete)? {
            self.exact(Stage::Claim)?;
            let observed = self.read_completion()?;
            self.observed = Some(observed);
            self.state = State::Completed;
            self.stopped.set(false);
            self.check()?;
            return Ok(ClaimState::AlreadyComplete(observed));
        }
        ensure(!self.exists(Stage::Claim)?,
            "egress claim is incomplete or unknown; it cannot be retried")?;
        self.publish(Stage::Claim)?;
        self.state = State::Claimed;
        self.stopped.set(false);
        self.check()?;
        Ok(ClaimState::Fresh)
    }

    /// Only the parent actual effect/readback owner may reach this after Fresh.
    /// The digest is data, not a kernel-success receipt or permission callback.
    pub(super) fn complete(mut self, observed_state_sha256: [u8; 32]) -> Result<[u8; 32], String> {
        self.check()?;
        ensure(self.state == State::Claimed && nonzero(&observed_state_sha256),
            "egress completion requires a fresh claim and nonzero observed-state digest")?;
        self.stopped.set(true);
        self.state = State::Unknown;
        self.observed = Some(observed_state_sha256);
        self.publish(Stage::Complete)?;
        self.state = State::Completed;
        self.stopped.set(false);
        self.check()?;
        let retained = self.read_completion()?;
        ensure(retained == observed_state_sha256, "egress completed readback digest differs")?;
        self.check()?;
        Ok(retained)
    }
}

pub(super) fn reserve(spec: Spec, guard: &EgressGuard) -> Result<Reservation<'_>, String> {
    guard.check()?;
    ensure(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0
        && spec.journal_inode != 0 && nonzero(&spec.reservation_id)
        && nonzero(&spec.association_sha256) && nonzero(&spec.token_sha256)
        && nonzero(&spec.intended_transaction_sha256),
        "egress reservation requires root and nonzero independent signed associations")?;
    let text = spec.journal_path.to_str().ok_or("egress journal path is not UTF-8")?;
    ensure(text.starts_with('/') && text.len() <= 4096 && text != "/",
        "egress journal path is not a bounded absolute nonroot path")?;
    let parts: Vec<&str> = text[1..].split('/').collect();
    ensure(parts.len() <= 64 && parts.iter().all(|part| !part.is_empty() && *part != "." && *part != ".."
        && part.len() <= 255 && !part.as_bytes().contains(&0)),
        "egress journal path contains noncanonical or excessive components")?;
    let root = CString::new("/").expect("literal root path");
    let mut directories = vec![directory(open_directory(libc::AT_FDCWD, &root)?, None, false)?];
    for (index, part) in parts.iter().enumerate() {
        guard.check()?;
        let name = CString::new(*part).map_err(|_| "egress journal path contains NUL")?;
        let parent = directories.last().ok_or("egress root directory is absent")?.file.as_raw_fd();
        directories.push(directory(open_directory(parent, &name)?, Some(name), index + 1 == parts.len())?);
        guard.check()?;
    }
    let held = directories.last().ok_or("egress journal is absent")?;
    ensure(held.device == spec.journal_device && held.inode == spec.journal_inode,
        "egress journal differs from its independently signed directory identity")?;
    guard.check()?;
    ensure(unsafe { libc::flock(held.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "egress journal is already owned or cannot be locked")?;
    guard.check()?;
    let slot = hex(&spec.reservation_id);
    let owner = Reservation { spec, guard, directories, slot, pid: std::process::id(),
        state: State::Reserved, observed: None, stopped: Cell::new(false) };
    owner.current()?;
    let inventory = owner.inventory()?;
    if inventory.contains_key(&owner.slot) {
        owner.exact(Stage::Reserve)?;
    } else {
        ensure(inventory.len() < MAX_SLOTS, "egress journal has no room for a complete slot")?;
        owner.publish(Stage::Reserve)?;
    }
    owner.check()?;
    Ok(owner)
}
