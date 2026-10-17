//! Exclusive data staging after the parent authenticates the complete plan.
//!
//! This owner is not signature, release, or custody authority. It never writes
//! executable files or private role seeds. All new directories remain root-only
//! until every data file is durable and read back; final permissions come only
//! from the source-validated closure. Supplied originals and published state
//! are never removed, replaced, adopted, or retried. The existing fresh-ledger
//! initializer retains its own normal unpublished atomic-temp handling.
//! Blocking filesystem calls still require the parent's external watchdog.

use super::closure::Plan;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use zeroize::Zeroizing;

const ROOTS: [&str; 2] = ["/run/catchplate-preboot", "/run/catchplate-role-key-provisioning"];
const MAX_FILES: usize = 128;
const MAX_DIRECTORIES: usize = 256;
const MAX_ABSENT: usize = 128;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const LEDGER: &str = "/run/catchplate-preboot/attempt-ledger";
const LEDGER_UID: u32 = 65534;
const MAX_LEDGER_MANIFEST: usize = 1024;
const CHUNK: usize = 64 * 1024;
const DIRECTORY_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;
const READ_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

fn require(value: bool, message: &str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}
fn owned(fd: i32) -> Result<File, String> {
    require(fd >= 0, "preboot data descriptor unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn identity(file: &File) -> Result<Identity, String> {
    Ok(Identity::of(&file.metadata().map_err(|_| "preboot data metadata unavailable")?))
}

#[derive(Clone, PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, mode: u32, uid: u32, gid: u32 }
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self { dev: m.dev(), ino: m.ino(), mode: m.mode(), uid: m.uid(), gid: m.gid() }
    }
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    id: Identity, links: u64, length: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
impl Fingerprint {
    fn of(m: &Metadata) -> Self {
        Self { id: Identity::of(m), links: m.nlink(), length: m.len(), mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(), ctime: m.ctime(), ctime_ns: m.ctime_nsec() }
    }
    fn read(file: &File) -> Result<Self, String> {
        Ok(Self::of(&file.metadata().map_err(|_| "preboot file identity unavailable")?))
    }
}
struct Directory {
    file: File, id: Identity, parent: Option<usize>, name: CString,
}
struct Original {
    file: File, fingerprint: Fingerprint, parent: usize, name: CString, source: OriginalSource,
}
enum OriginalSource {
    Delivered(usize),
    // Only the source-fixed fresh custody ledger may create unsigned data.
    // These bytes are a local empty-state observation, not rollback authority.
    FreshLedger { bytes: Zeroizing<Vec<u8>>, sha256: String },
}

// No Deserialize, Clone or writable descriptor escapes. Owning the exact plan
// keeps its admitted bytes alive through the caller's final check and exec.
pub(super) struct Materialized {
    plan: Plan, directories: Vec<Directory>, indices: BTreeMap<String, usize>,
    originals: Vec<Original>, pid: libc::pid_t, poisoned: bool,
}

fn root_process(pid: libc::pid_t) -> Result<(), String> {
    let mut uid = [0; 3]; let mut gid = [0; 3];
    require(pid > 0 && unsafe { libc::getpid() } == pid
        && unsafe { libc::syscall(libc::SYS_gettid) } == pid as libc::c_long
        && unsafe { libc::getresuid(uid.as_mut_ptr(), uid.as_mut_ptr().add(1), uid.as_mut_ptr().add(2)) } == 0
        && unsafe { libc::getresgid(gid.as_mut_ptr(), gid.as_mut_ptr().add(1), gid.as_mut_ptr().add(2)) } == 0
        && uid == [0; 3] && gid == [0; 3], "preboot materializer lost its original root process")
}
fn path(value: &str) -> Result<(), String> {
    require(value.is_ascii() && value.len() <= 4096 && value.starts_with('/')
        && !value.bytes().any(|v| v < 32 || v == 127)
        && value[1..].split('/').all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
        && ROOTS.iter().any(|root| value == *root || value.strip_prefix(root).is_some_and(|tail| tail.starts_with('/'))),
        "preboot destination is not a canonical fixed-root path")
}
fn parts(value: &str) -> Result<(&str, CString), String> {
    let (parent, name) = value.rsplit_once('/').ok_or("preboot destination parent absent")?;
    Ok((parent, CString::new(name).map_err(|_| "preboot destination name invalid")?))
}
fn pin(bytes: &[u8]) -> String { format!("sha256:{}", hex::encode(Sha256::digest(bytes))) }

fn validate(plan: &Plan, check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String> {
    require(!plan.files.is_empty() && plan.files.len() <= MAX_FILES
        && !plan.directories.is_empty() && plan.directories.len() <= MAX_DIRECTORIES
        && plan.absent_paths.len() <= MAX_ABSENT, "preboot plan count exceeds source bounds")?;
    let mut directories = BTreeSet::new();
    let mut all = BTreeSet::new();
    for entry in &plan.directories {
        check()?; path(&entry.path)?;
        require([0o700, 0o755].contains(&entry.mode) && entry.uid != u32::MAX && entry.gid != u32::MAX
            && directories.insert(entry.path.as_str()) && all.insert(entry.path.as_str()),
            "preboot directory purpose, mode, owner or uniqueness differs")?;
        if ROOTS.contains(&entry.path.as_str()) {
            require(entry.uid == 0 && entry.gid == 0, "preboot staging root must remain root-owned")?;
        }
        require(!entry.path.starts_with(&format!("{LEDGER}/")), "preboot ledger cannot receive directories")?;
        if entry.path == LEDGER {
            require(entry.mode == 0o700 && entry.uid == LEDGER_UID && entry.gid == LEDGER_UID,
                "preboot fresh ledger requires its fixed final serving identity")?;
        }
    }
    require(directories.contains(LEDGER), "preboot fresh attempt ledger directory is absent")?;
    for entry in &plan.directories {
        let (parent, _) = parts(&entry.path)?;
        require(parent == "/run" || directories.contains(parent), "preboot directory parent is not in the closed plan")?;
    }
    let mut total = 0usize;
    for entry in &plan.files {
        check()?; path(&entry.path)?;
        require(!entry.path.starts_with(&format!("{LEDGER}/")), "preboot delivery cannot import ledger state")?;
        let (parent, _) = parts(&entry.path)?;
        total = total.checked_add(entry.bytes.len()).ok_or("preboot data total overflows")?;
        require(!entry.bytes.is_empty() && entry.bytes.len() <= MAX_FILE_BYTES && total <= MAX_TOTAL_BYTES
            && [0o400, 0o444].contains(&entry.mode) && entry.uid != u32::MAX && entry.gid != u32::MAX
            && directories.contains(parent) && all.insert(entry.path.as_str())
            && pin(&entry.bytes) == entry.sha256, "preboot data pin, bound, destination or owner differs")?;
        check()?;
    }
    for entry in &plan.absent_paths {
        check()?; path(entry)?;
        require(!entry.starts_with(&format!("{LEDGER}/")), "preboot ledger is not a private seed output area")?;
        let (parent, _) = parts(entry)?;
        require(directories.contains(parent) && all.insert(entry.as_str()),
            "preboot private output slot conflicts or has no approved parent")?;
    }
    check()
}

fn named(parent: &File, name: &CString, expected: &Identity) -> Result<(), String> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    require(unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0
        && stat.st_dev as u64 == expected.dev && stat.st_ino as u64 == expected.ino
        && stat.st_mode == expected.mode && stat.st_uid == expected.uid && stat.st_gid == expected.gid,
        "preboot original name no longer denotes its held inode")
}
fn absent(parent: &File, name: &CString) -> Result<(), String> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    require(result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "preboot private output slot is not absent")
}
fn sync(file: &File, check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String> {
    check()?;
    file.sync_all().map_err(|_| "preboot data durability is uncertain")?;
    check()
}
fn set_owner(file: &File, uid: u32, gid: u32, mode: u32,
    check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String>
{
    check()?;
    require(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "preboot data exact ownership unavailable")?;
    check()?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0,
        "preboot data exact permissions unavailable")?;
    check()
}
fn readback(file: &File, expected: &Fingerprint, bytes: &[u8], expected_pin: &str,
    check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String>
{
    check()?;
    require(Fingerprint::read(file)? == *expected, "preboot data changed before readback")?;
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    let mut offset = 0usize;
    let mut digest = Sha256::new();
    while offset < bytes.len() {
        check()?;
        let length = CHUNK.min(bytes.len() - offset);
        let count = match file.read_at(&mut buffer[..length], offset as u64) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => { check()?; continue; },
            Err(_) => return Err("preboot data readback failed".into()),
        };
        check()?;
        require(count > 0 && buffer[..count] == bytes[offset..offset + count],
            "preboot data readback differs from the exact original")?;
        digest.update(&buffer[..count]); offset += count;
    }
    check()?;
    let mut eof = [0u8; 1];
    require(file.read_at(&mut eof, bytes.len() as u64).map_err(|_| "preboot data EOF check failed")? == 0
        && format!("sha256:{}", hex::encode(digest.finalize())) == expected_pin
        && Fingerprint::read(file)? == *expected, "preboot data closing pin or identity differs")?;
    check()
}

impl Materialized {
    fn directories_unchanged(&self) -> Result<(), String> {
        for entry in &self.directories {
            require(identity(&entry.file)? == entry.id, "preboot held directory identity changed")?;
            if let Some(parent) = entry.parent { named(&self.directories[parent].file, &entry.name, &entry.id)?; }
        }
        Ok(())
    }
    fn absent_outputs(&self) -> Result<(), String> {
        for entry in &self.plan.absent_paths {
            let (parent, name) = parts(entry)?;
            let index = *self.indices.get(parent).ok_or("preboot absent-slot parent lost")?;
            absent(&self.directories[index].file, &name)?;
        }
        Ok(())
    }
    fn initialize_fresh_ledger(&mut self, check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String> {
        root_process(self.pid)?; check()?; self.directories_unchanged()?;
        let parent_index = *self.indices.get(LEDGER).ok_or("preboot ledger directory lost")?;
        let directory = &self.directories[parent_index];
        require(directory.id.mode == (libc::S_IFDIR | 0o700) && directory.id.uid == 0 && directory.id.gid == 0,
            "preboot ledger initialization requires the original root-private staging directory")?;
        // This directory was exclusively created above; nevertheless require
        // actual emptiness before entering the existing initializer, whose
        // own lock open intentionally also serves later runtime acquisition.
        let mut contents = std::fs::read_dir(LEDGER).map_err(|_| "preboot fresh ledger cannot be inspected")?;
        require(contents.next().is_none(), "preboot fresh ledger is not empty")?;
        drop(contents);
        self.directories_unchanged()?; check()?;
        catchplate_decision_gate::CustodyRuntime::initialize_attempt_ledger_directory(std::path::Path::new(LEDGER))
            .map_err(|_| "preboot fresh ledger initialization failed; partial state is retained")?;
        check()?; root_process(self.pid)?; self.directories_unchanged()?;
        let mut names = BTreeSet::new();
        for entry in std::fs::read_dir(LEDGER).map_err(|_| "preboot initialized ledger cannot be inspected")?.take(3) {
            check()?;
            let entry = entry.map_err(|_| "preboot initialized ledger entry unavailable")?;
            require(names.insert(entry.file_name()), "preboot initialized ledger name repeated")?;
        }
        require(names == BTreeSet::from([std::ffi::OsString::from("manifest.json"), std::ffi::OsString::from("ledger.lock")]),
            "preboot initializer did not produce exactly the two fresh ledger originals")?;
        let parent = &self.directories[parent_index].file;
        for (leaf, maximum) in [("manifest.json", MAX_LEDGER_MANIFEST), ("ledger.lock", 0usize)] {
            check()?;
            let name = CString::new(leaf).map_err(|_| "fixed ledger name invalid")?;
            let file = owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), READ_FLAGS) })?;
            let before = Fingerprint::read(&file)?;
            require(before.id.mode == (libc::S_IFREG | 0o600) && before.id.uid == 0 && before.id.gid == 0
                && before.links == 1 && before.length <= maximum as u64
                && (maximum == 0 || before.length > 0), "preboot fresh ledger original metadata differs")?;
            named(parent, &name, &before.id)?;
            let mut bytes = Zeroizing::new(vec![0; before.length as usize + 1]);
            let mut offset = 0;
            while offset < bytes.len() {
                check()?;
                let count = file.read_at(&mut bytes[offset..], offset as u64)
                    .map_err(|_| "preboot fresh ledger original read failed")?;
                check()?;
                if count == 0 { break; }
                offset += count;
            }
            require(offset == before.length as usize && Fingerprint::read(&file)? == before,
                "preboot fresh ledger changed during its original acquisition")?;
            bytes.truncate(offset);
            let sha256 = pin(&bytes);
            set_owner(&file, LEDGER_UID, LEDGER_UID, 0o600, check)?;
            sync(&file, check)?;
            let fingerprint = Fingerprint::read(&file)?;
            require(fingerprint.id.dev == before.id.dev && fingerprint.id.ino == before.id.ino
                && fingerprint.id.mode == (libc::S_IFREG | 0o600) && fingerprint.id.uid == LEDGER_UID
                && fingerprint.id.gid == LEDGER_UID && fingerprint.links == 1 && fingerprint.length == before.length,
                "preboot fresh ledger final identity differs")?;
            readback(&file, &fingerprint, &bytes, &sha256, check)?;
            named(parent, &name, &fingerprint.id)?;
            self.originals.push(Original { file, fingerprint, parent: parent_index, name,
                source: OriginalSource::FreshLedger { bytes, sha256 } });
        }
        sync(parent, check)?; self.directories_unchanged()?; check()
    }
    pub(super) fn recheck(&mut self, check: &mut impl FnMut() -> Result<(), String>) -> Result<(), String> {
        require(!std::mem::replace(&mut self.poisoned, true), "preboot materialization owner is poisoned")?;
        root_process(self.pid)?; check()?; self.directories_unchanged()?; self.absent_outputs()?;
        for original in &self.originals {
            check()?;
            let (bytes, sha256) = match &original.source {
                OriginalSource::Delivered(index) => {
                    let entry = &self.plan.files[*index];
                    (entry.bytes.as_slice(), entry.sha256.as_str())
                },
                OriginalSource::FreshLedger { bytes, sha256 } => (bytes.as_slice(), sha256.as_str()),
            };
            let parent = &self.directories[original.parent].file;
            named(parent, &original.name, &original.fingerprint.id)?;
            readback(&original.file, &original.fingerprint, bytes, sha256, check)?;
            named(parent, &original.name, &original.fingerprint.id)?;
        }
        self.directories_unchanged()?; self.absent_outputs()?; root_process(self.pid)?; check()?;
        self.poisoned = false;
        Ok(())
    }
}

pub(super) fn materialize(plan: Plan,
    check: &mut impl FnMut() -> Result<(), String>) -> Result<Materialized, String>
{
    let pid = unsafe { libc::getpid() };
    root_process(pid)?; check()?; validate(&plan, check)?;
    let root = owned(unsafe { libc::open(b"/\0".as_ptr().cast(), DIRECTORY_FLAGS) })?;
    let run_name = CString::new("run").map_err(|_| "fixed run name invalid")?;
    let run = owned(unsafe { libc::openat(root.as_raw_fd(), run_name.as_ptr(), DIRECTORY_FLAGS) })?;
    let mut directories = Vec::new();
    for (file, parent, name) in [(root, None, CString::new("").unwrap()), (run, Some(0), run_name)] {
        let id = identity(&file)?;
        require(id.mode & libc::S_IFMT == libc::S_IFDIR && id.uid == 0 && id.gid == 0 && id.mode & 0o022 == 0,
            "preboot filesystem anchors are not protected root directories")?;
        directories.push(Directory { file, id, parent, name });
    }
    let mut owner = Materialized { plan, directories, indices: BTreeMap::from([("/".into(), 0), ("/run".into(), 1)]),
        originals: Vec::new(), pid, poisoned: false };
    owner.directories_unchanged()?;
    let plan = &owner.plan;
    // No existing output root is ever adopted, even when its contents match.
    for root in ROOTS { let (_, name) = parts(root)?; absent(&owner.directories[1].file, &name)?; }
    let mut ordered: Vec<_> = (0..plan.directories.len()).collect();
    ordered.sort_by(|a, b| {
        let (a, b) = (&plan.directories[*a], &plan.directories[*b]);
        a.path.matches('/').count().cmp(&b.path.matches('/').count()).then(a.path.cmp(&b.path))
    });
    for plan_index in &ordered {
        let entry = &plan.directories[*plan_index];
        root_process(pid)?; check()?; owner.directories_unchanged()?;
        let (parent, name) = parts(&entry.path)?;
        let index = *owner.indices.get(parent).ok_or("preboot new directory parent absent")?;
        let parent = &owner.directories[index].file;
        require(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0,
            "preboot directory exclusive creation refused; partial state is retained")?;
        check()?;
        let file = owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) })?;
        let initial = identity(&file)?;
        require(initial.mode & libc::S_IFMT == libc::S_IFDIR && initial.uid == 0 && initial.gid == 0
            && initial.mode & 0o077 == 0, "preboot staging directory was not created root-private")?;
        set_owner(&file, 0, 0, 0o700, check)?;
        let id = identity(&file)?;
        require(id.dev == initial.dev && id.ino == initial.ino && id.mode & 0o7777 == 0o700,
            "preboot staging directory identity changed")?;
        named(parent, &name, &id)?; sync(&file, check)?; sync(parent, check)?;
        owner.indices.insert(entry.path.clone(), owner.directories.len());
        owner.directories.push(Directory { file, id, parent: Some(index), name });
    }
    owner.absent_outputs()?;
    for (plan_index, entry) in plan.files.iter().enumerate() {
        root_process(pid)?; check()?; owner.directories_unchanged()?;
        let (parent, name) = parts(&entry.path)?;
        let parent_index = *owner.indices.get(parent).ok_or("preboot data parent absent")?;
        let parent = &owner.directories[parent_index].file;
        let writer = owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o400) })?;
        check()?;
        let initial = writer.metadata().map_err(|_| "preboot fresh data metadata unavailable")?;
        require(initial.is_file() && initial.uid() == 0 && initial.gid() == 0 && initial.nlink() == 1
            && initial.len() == 0 && initial.mode() & 0o077 == 0, "preboot data was not a new root-private regular file")?;
        let mut offset = 0usize;
        while offset < entry.bytes.len() {
            root_process(pid)?; check()?;
            let end = (offset + CHUNK).min(entry.bytes.len());
            let written = match writer.write_at(&entry.bytes[offset..end], offset as u64) {
                Ok(written) => written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => { check()?; continue; },
                Err(_) => return Err("preboot data write outcome uncertain; partial state is retained".into()),
            };
            check()?; require(written > 0, "preboot data write made no progress")?; offset += written;
        }
        set_owner(&writer, entry.uid, entry.gid, entry.mode, check)?;
        sync(&writer, check)?;
        let fingerprint = Fingerprint::read(&writer)?;
        require(fingerprint.id.dev == initial.dev() && fingerprint.id.ino == initial.ino()
            && fingerprint.id.mode == (libc::S_IFREG | entry.mode) && fingerprint.id.uid == entry.uid
            && fingerprint.id.gid == entry.gid && fingerprint.links == 1 && fingerprint.length == entry.bytes.len() as u64,
            "preboot written data ownership or identity differs")?;
        named(parent, &name, &fingerprint.id)?;
        let file = owned(unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), READ_FLAGS) })?;
        readback(&file, &fingerprint, &entry.bytes, &entry.sha256, check)?;
        sync(parent, check)?; named(parent, &name, &fingerprint.id)?;
        drop(writer);
        owner.originals.push(Original { file, fingerprint, parent: parent_index, name,
            source: OriginalSource::Delivered(plan_index) });
    }
    owner.directories_unchanged()?; owner.absent_outputs()?;
    owner.initialize_fresh_ledger(check)?;
    // Children first. The root-private staging barrier opens last; no mutable
    // descriptors or arbitrary executable modes are handed to role processes.
    for plan_index in ordered.into_iter().rev() {
        let entry = &owner.plan.directories[plan_index];
        root_process(pid)?; check()?; owner.directories_unchanged()?;
        let index = *owner.indices.get(&entry.path).ok_or("preboot final directory absent")?;
        let current = &owner.directories[index];
        let old = current.id.clone();
        set_owner(&current.file, entry.uid, entry.gid, entry.mode, check)?;
        sync(&current.file, check)?;
        let id = identity(&current.file)?;
        require(id.dev == old.dev && id.ino == old.ino && id.mode == (libc::S_IFDIR | entry.mode)
            && id.uid == entry.uid && id.gid == entry.gid, "preboot final directory differs from approved metadata")?;
        let parent = current.parent.ok_or("preboot final directory parent absent")?;
        named(&owner.directories[parent].file, &current.name, &id)?;
        sync(&owner.directories[parent].file, check)?;
        owner.directories[index].id = id;
    }
    owner.recheck(check)?;
    Ok(owner)
}
