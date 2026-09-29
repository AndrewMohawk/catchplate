//! Fixed private CAS writes. No caller pathname, replacement, unlink or repair.
use super::*;
use std::{ffi::CString, fs::File, io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd},
    unix::fs::MetadataExt}, path::{Component, Path}};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity { device:u64, inode:u64, uid:u32, gid:u32, mode:u32 }
impl Identity {
    fn of(file: &File) -> Result<Self, V2RuntimeError> {
        let m = file.metadata().map_err(|_| fail("held CAS identity unavailable"))?;
        Ok(Self { device:m.dev(), inode:m.ino(), uid:m.uid(), gid:m.gid(), mode:m.mode() })
    }
}
struct Directory { file:File, identity:Identity, parent:Option<usize>, name:String }
struct Record { file:File, identity:Identity, parent:usize, name:String, length:u64, mode:u32 }
pub(super) enum RecordKind { Artifact, StateRequest, Result }
impl RecordKind {
    fn suffix(&self) -> &'static str { match self {
        Self::Artifact => "artifact", Self::StateRequest => "state-request",
        Self::Result => "result",
    } }
}

pub(super) struct Stored<'capture> {
    captured:&'capture VerifiedStaged<'capture>,
    directories:Vec<Directory>, records:Vec<Record>, lock:Record,
    uid:u32, gid:u32, root:usize, claims:usize, slot:String, deadline:u64,
}
impl<'capture> Stored<'capture> {
    pub(super) fn put(config: &Config, captured: &'capture VerifiedStaged<'capture>, request: &super::wire::StagedPutRequest,
        receipt: &StorageReceipt) -> Result<Self, V2RuntimeError> {
        current(config, captured.deadline_boottime_ns())?;
        captured.check()?;
        let process = config.custody_topology().process(Role::ImmutableArtifactLedger)
            .ok_or_else(|| fail("signed ledger process absent"))?;
        if unsafe { libc::getuid() } != process.uid || unsafe { libc::geteuid() } != process.uid
            || unsafe { libc::getgid() } != process.gid || unsafe { libc::getegid() } != process.gid {
            return Err(fail("private CAS writer is not actual signed ledger identity"));
        }
        let root_path = process.process_state_object_root();
        let directories = protected_root(&root_path, process.uid, process.gid)?;
        let root = directories.len() - 1;
        let deadline = captured.deadline_boottime_ns();
        captured.check()?;
        let (lock_file, created) = exclusive_or_existing(&directories[root].file, "staged-put.lock", 0o600)?;
        regular(&lock_file, process.uid, process.gid, 0o600, 0)?;
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(fail("another private CAS publication owns the lock"));
        }
        if created { captured.check()?; sync(&lock_file)?; captured.check()?; sync(&directories[root].file)?; }
        let lock = Record { identity:Identity::of(&lock_file)?, file:lock_file,
            parent:root, name:"staged-put.lock".to_owned(), length:0, mode:0o600 };
        let slot = receipt_wire::sha(&receipt_wire::original(&serde_json::json!({
            "domain":"serverware.responseV2.stagedPersistenceClaim/v1",
            "generationId":captured.generation_id(), "attemptId":captured.attempt_id(),
            "fencingToken":captured.fencing_token(), "purpose":receipt_wire::KIND }))?)[7..].to_owned();
        let mut owner = Self { captured, directories, records:Vec::new(), lock, uid:process.uid, gid:process.gid,
            root, claims:root, slot, deadline };
        owner.check(config)?;
        let (claims, _) = owner.directory(root, "staged-claims", true)?;
        owner.claims = claims;
        // Permanent attempt/fence consumption precedes any object write. A
        // missing response, partial file or different new nonce cannot reopen it.
        let claim_name = format!("{}.claim", owner.slot);
        owner.create_record(claims, &claim_name, &receipt_wire::original(request)?)?;
        owner.check(config)?;

        let locator = receipt.locator()?;
        let parts:Vec<_> = Path::new(&locator).components().collect();
        if parts.len() != 5 || parts.iter().any(|part| !matches!(part, Component::Normal(_))) {
            return Err(fail("canonical private CAS layout differs"));
        }
        let mut parent = root;
        let mut receipt_directory_fresh = false;
        for part in &parts[..4] {
            let name = part.as_os_str().to_str().ok_or_else(|| fail("CAS name encoding"))?;
            let (next, created) = owner.directory(parent, name, true)?;
            parent = next; receipt_directory_fresh = created;
        }
        let name = parts[4].as_os_str().to_str().ok_or_else(|| fail("CAS blob name encoding"))?;
        let receipt_name = format!("{}.receipt", &receipt.body.content_sha256[7..]);
        let receipt_raw = receipt_wire::original(receipt)?;
        let bytes = captured.bytes()?;
        if bytes.len() as u64 != receipt.body.content_length || receipt_wire::sha(&bytes) != receipt.body.content_sha256 {
            return Err(fail("retained capture bytes changed before storage"));
        }
        if receipt_directory_fresh {
            owner.create_record(parent, name, &bytes)?;
            owner.check(config)?;
            owner.create_record(parent, &receipt_name, &receipt_raw)?;
        } else {
            // Existing directories authorize nothing. Reuse requires both exact
            // named originals; missing or partial state is not repair permission.
            owner.retain_existing(parent, name, &bytes, None)?;
            owner.retain_existing(parent, &receipt_name, &receipt_raw, None)?;
        }
        owner.check(config)?;
        Ok(owner)
    }

    pub(super) fn record(&mut self, config: &Config, kind:RecordKind, bytes:&[u8]) -> Result<(), V2RuntimeError> {
        if bytes.is_empty() || bytes.len() > receipt_wire::META_BOUND { return Err(fail("retained put original exceeds bound")); }
        self.check(config)?;
        let name = format!("{}.{}", self.slot, kind.suffix());
        self.create_record(self.claims, &name, bytes)?;
        self.check(config)
    }
    pub(super) fn check(&self, config: &Config) -> Result<(), V2RuntimeError> {
        self.captured.check()?;
        current(config, self.deadline)?;
        for directory in &self.directories {
            if Identity::of(&directory.file)? != directory.identity { return Err(fail("held CAS directory changed")); }
            if let Some(parent) = directory.parent {
                named(&self.directories[parent].file, &directory.name, directory.identity)?;
            }
        }
        self.check_record(&self.lock)?;
        for record in &self.records { self.check_record(record)?; }
        Ok(())
    }
    fn check_record(&self, record:&Record) -> Result<(), V2RuntimeError> {
        regular(&record.file, self.uid, self.gid, record.mode, record.length)?;
        if Identity::of(&record.file)? != record.identity { return Err(fail("held CAS file changed")); }
        named(&self.directories[record.parent].file, &record.name, record.identity)
    }
    fn directory(&mut self, parent:usize, name:&str, create:bool) -> Result<(usize,bool), V2RuntimeError> {
        self.captured.check()?;
        deadline(self.deadline)?;
        let name_c = component(name)?;
        let mut created = false;
        if create {
            if unsafe { libc::mkdirat(self.directories[parent].file.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0 {
                created = true;
            } else if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(fail("create fixed CAS directory"));
            }
        }
        let file = open_at(&self.directories[parent].file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let id = Identity::of(&file)?;
        if id.uid != self.uid || id.gid != self.gid || id.mode & libc::S_IFMT != libc::S_IFDIR
            || id.mode & 0o7777 != 0o700 || id.device != self.directories[self.root].identity.device {
            return Err(fail("CAS directory identity/protection differs"));
        }
        named(&self.directories[parent].file, name, id)?;
        if created { self.captured.check()?; sync(&file)?; self.captured.check()?; sync(&self.directories[parent].file)?; }
        let index = self.directories.len();
        self.directories.push(Directory { file, identity:id, parent:Some(parent), name:name.to_owned() });
        deadline(self.deadline)?;
        Ok((index,created))
    }
    fn create_record(&mut self, parent:usize, name:&str, bytes:&[u8]) -> Result<(), V2RuntimeError> {
        self.captured.check()?;
        deadline(self.deadline)?;
        let mut file = open_at(&self.directories[parent].file, name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        let before = Identity::of(&file)?;
        regular(&file, self.uid, self.gid, 0o600, 0)?;
        for chunk in bytes.chunks(64 * 1024) {
            self.captured.check()?;
            deadline(self.deadline)?;
            file.write_all(chunk).map_err(|_| fail("CAS write uncertain"))?;
        }
        self.captured.check()?;
        sync(&file)?;
        self.captured.check()?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } != 0 { return Err(fail("seal CAS mode uncertain")); }
        self.captured.check()?; sync(&file)?;
        self.captured.check()?; sync(&self.directories[parent].file)?;
        let after = Identity::of(&file)?;
        if before.device != after.device || before.inode != after.inode || before.uid != after.uid || before.gid != after.gid {
            return Err(fail("created CAS identity changed"));
        }
        // Keep the actual created descriptor while independently reopening its
        // name. Equal bytes on a substituted inode are not this publication.
        let result = self.retain_existing(parent, name, bytes, Some(after));
        drop(file);
        result
    }
    fn retain_existing(&mut self, parent:usize, name:&str, expected:&[u8], created:Option<Identity>) -> Result<(), V2RuntimeError> {
        let mut file = open_at(&self.directories[parent].file, name, libc::O_RDONLY, 0)?;
        regular(&file, self.uid, self.gid, 0o400, expected.len() as u64)?;
        let identity = Identity::of(&file)?;
        if created.is_some_and(|original| original != identity) { return Err(fail("created CAS name was replaced")); }
        named(&self.directories[parent].file, name, identity)?;
        let mut buffer = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
        let mut offset = 0usize;
        while offset < expected.len() {
            self.captured.check()?;
            deadline(self.deadline)?;
            let wanted = buffer.len().min(expected.len() - offset);
            file.read_exact(&mut buffer[..wanted]).map_err(|_| fail("immutable CAS original unavailable"))?;
            if buffer[..wanted] != expected[offset..offset + wanted] { return Err(fail("immutable CAS original differs")); }
            offset += wanted;
        }
        let mut extra = [0u8;1];
        if file.read(&mut extra).map_err(|_| fail("CAS final read"))? != 0 { return Err(fail("CAS original has surplus bytes")); }
        if created.is_none() {
            // Seeing complete originals does not prove an earlier parent fsync
            // finished. Reused, byte-identical files get a fresh durability
            // barrier under this fresh claim; no bytes/modes/names are repaired.
            self.captured.check()?; sync(&file)?;
            self.captured.check()?; sync(&self.directories[parent].file)?;
        }
        let record = Record { file, identity, parent, name:name.to_owned(), length:expected.len() as u64, mode:0o400 };
        self.check_record(&record)?;
        self.records.push(record);
        deadline(self.deadline)
    }
}

fn protected_root(path:&Path, uid:u32, gid:u32) -> Result<Vec<Directory>, V2RuntimeError> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 || uid == 0 || gid == 0 { return Err(fail("private CAS root invalid")); }
    let parts:Vec<_> = path.components().collect();
    if parts.len() < 3 || parts.len() > 64 || !matches!(parts.first(), Some(Component::RootDir))
        || parts[1..].iter().any(|part| !matches!(part, Component::Normal(_))) { return Err(fail("private CAS root spelling")); }
    let raw = unsafe { libc::open(b"/\0".as_ptr().cast(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if raw < 0 { return Err(fail("open protected filesystem root")); }
    let file = unsafe { File::from_raw_fd(raw) };
    let id = Identity::of(&file)?;
    if id.uid != 0 || id.mode & libc::S_IFMT != libc::S_IFDIR || id.mode & 0o022 != 0 {
        return Err(fail("filesystem root protection differs"));
    }
    let mut result = vec![Directory { file, identity:id, parent:None, name:String::new() }];
    for part in &parts[1..] {
        let parent = result.len() - 1;
        let name = part.as_os_str().to_str().ok_or_else(|| fail("private CAS root UTF-8"))?;
        let file = open_at(&result[parent].file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let id = Identity::of(&file)?;
        if id.mode & libc::S_IFMT != libc::S_IFDIR || id.mode & 0o022 != 0 || ![0,uid].contains(&id.uid) {
            return Err(fail("private CAS ancestor protection differs"));
        }
        named(&result[parent].file, name, id)?;
        result.push(Directory { file, identity:id, parent:Some(parent), name:name.to_owned() });
    }
    let root = result.last().ok_or_else(|| fail("private CAS root absent"))?;
    if root.identity.uid != uid || root.identity.gid != gid || root.identity.mode & 0o7777 != 0o700 {
        return Err(fail("private CAS root must be preprovisioned ledger-owned0700"));
    }
    Ok(result)
}
fn component(name:&str) -> Result<CString,V2RuntimeError> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." || name.contains('/') {
        return Err(fail("fixed CAS component invalid"));
    }
    CString::new(name).map_err(|_| fail("CAS component NUL"))
}
fn open_at(parent:&File, name:&str, flags:i32, mode:libc::mode_t) -> Result<File,V2RuntimeError> {
    let name = component(name)?;
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, mode) };
    if raw < 0 { return Err(fail("fixed CAS open/create refused; no repair or retry")); }
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn exclusive_or_existing(parent:&File, name:&str, mode:libc::mode_t) -> Result<(File,bool),V2RuntimeError> {
    let c = component(name)?;
    let raw = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW, mode) };
    if raw >= 0 { return Ok((unsafe { File::from_raw_fd(raw) },true)); }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) { return Err(fail("private CAS lock creation")); }
    Ok((open_at(parent,name,libc::O_RDWR,0)?,false))
}
fn named(parent:&File, name:&str, expected:Identity) -> Result<(),V2RuntimeError> {
    let name = component(name)?;
    let mut value:libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } != 0
        || (Identity { device:value.st_dev, inode:value.st_ino, uid:value.st_uid, gid:value.st_gid, mode:value.st_mode }) != expected {
        return Err(fail("named CAS identity differs from retained descriptor"));
    }
    Ok(())
}
fn regular(file:&File, uid:u32, gid:u32, mode:u32, length:u64) -> Result<(),V2RuntimeError> {
    let m = file.metadata().map_err(|_| fail("CAS file metadata"))?;
    if !m.is_file() || m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != mode
        || m.nlink() != 1 || m.len() != length { return Err(fail("CAS file protection/length differs")); }
    Ok(())
}
fn sync(file:&File) -> Result<(),V2RuntimeError> { file.sync_all().map_err(|_| fail("CAS durability uncertain")) }
