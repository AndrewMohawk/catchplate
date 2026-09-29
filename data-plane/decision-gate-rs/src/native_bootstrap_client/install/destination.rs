//! Scoped destination mechanics, never installation or certificate authority.
//!
//! The parent retains the genuine proof/host/input guard and a durable Fresh
//! claim before install. Recovery originals survive every failure; no repair,
//! rollback, path discovery or fallback publication is provided here.

use super::InstallGuard;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest as _, Sha256};
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

const RECOVERY_NAME: &str = ".serverware-native-ca-install";
const LOCK_NAME: &str = "destination.lock";
const MAX_PEM: usize = 64 * 1024;
const MAX_DER: usize = 16 * 1024;
const MAX_ENTRIES: usize = 512;
const MAX_RECOVERY_BYTES: u64 = 16 * 1024 * 1024;
const DIRECTORY_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;
const FILE_FLAGS: i32 = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

pub(super) struct Spec {
    pub(super) destination: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
    pub(super) replace_existing: bool,
    pub(super) expected_existing_certificate_sha256: Option<[u8; 32]>,
}

fn ensure(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

fn name(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| "native install name contains NUL".to_owned())
}

fn open_at(parent: i32, entry: &CStr, flags: i32, guard: &InstallGuard)
    -> Result<Option<File>, String> {
    guard.check()?;
    let fd = unsafe { libc::openat(parent, entry.as_ptr(), flags, 0o600 as libc::mode_t) };
    let error = if fd < 0 { Some(io::Error::last_os_error()) } else { None };
    let file = if fd < 0 { None } else { Some(unsafe { File::from_raw_fd(fd) }) };
    guard.check()?;
    match error {
        Some(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Some(_) => Err("open native install held name without following links".to_owned()),
        None => Ok(file),
    }
}

fn required_at(parent: i32, entry: &CStr, flags: i32, guard: &InstallGuard)
    -> Result<File, String> {
    open_at(parent, entry, flags, guard)?.ok_or("native install resource is not preprovisioned".to_owned())
}

fn metadata(file: &File, guard: &InstallGuard) -> Result<Metadata, String> {
    guard.check()?;
    let result = file.metadata().map_err(|_| "inspect native install held original")?;
    guard.check()?;
    Ok(result)
}

type DirectoryStamp = (u64, u64, u32, u32, u32);
fn directory_stamp(value: &Metadata, private: bool) -> Result<DirectoryStamp, String> {
    ensure(value.is_dir() && value.uid() == 0 && value.gid() == 0
        && value.mode() & 0o022 == 0 && value.mode() & 0o7000 == 0
        && (!private || value.mode() & 0o7777 == 0o700),
        "native install directories must retain protected root ownership")?;
    Ok((value.dev(), value.ino(), value.mode(), value.uid(), value.gid()))
}

type FileStamp = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn file_stamp(value: &Metadata) -> FileStamp {
    (value.dev(), value.ino(), value.mode(), value.uid(), value.gid(), value.nlink(),
        value.len(), value.mtime(), value.mtime_nsec(), value.ctime(), value.ctime_nsec())
}

fn regular(value: &Metadata) -> Result<(), String> {
    ensure(value.is_file() && value.nlink() == 1 && value.len() <= MAX_PEM as u64
        && value.mode() & 0o7022 == 0 && value.mode() & 0o111 == 0,
        "native install certificate must be a bounded protected single-link regular file")
}

fn read_file(file: &File, guard: &InstallGuard) -> Result<(Vec<u8>, FileStamp), String> {
    let before = metadata(file, guard)?;
    regular(&before)?;
    ensure(before.len() > 0, "native install certificate is empty")?;
    let length = before.len() as usize;
    let mut raw = vec![0; length + 1];
    let mut offset = 0;
    while offset < raw.len() {
        guard.check()?;
        let end = raw.len().min(offset + 16 * 1024);
        let read = match file.read_at(&mut raw[offset..end], offset as u64) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read native install certificate original".to_owned()),
        };
        guard.check()?;
        if read == 0 { break; }
        offset += read;
    }
    ensure(offset == length && file_stamp(&metadata(file, guard)?) == file_stamp(&before),
        "native install certificate bytes or metadata changed during read")?;
    raw.truncate(length);
    Ok((raw, file_stamp(&before)))
}

fn canonical_pem(der: &[u8], guard: &InstallGuard) -> Result<Vec<u8>, String> {
    guard.check()?;
    ensure(!der.is_empty() && der.len() <= MAX_DER, "native install certificate DER exceeds bound")?;
    let (rest, _) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| "native install certificate DER is malformed")?;
    ensure(rest.is_empty(), "native install certificate DER has trailing bytes")?;
    let encoded = STANDARD.encode(der);
    let mut pem = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    ensure(pem.len() <= MAX_PEM, "native install certificate PEM exceeds bound")?;
    guard.check()?;
    Ok(pem)
}

fn pem_digest(raw: &[u8], guard: &InstallGuard) -> Result<[u8; 32], String> {
    guard.check()?;
    let text = std::str::from_utf8(raw).map_err(|_| "native install PEM is not UTF-8")?;
    let body = text.strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----\n"))
        .ok_or("native install original is not one canonical PEM certificate")?;
    let encoded: String = body.chars().filter(|character| *character != '\n').collect();
    let der = STANDARD.decode(encoded.as_bytes()).map_err(|_| "native install PEM base64 differs")?;
    ensure(canonical_pem(&der, guard)? == raw, "native install PEM encoding is not canonical")?;
    let digest = Sha256::digest(&der).into();
    guard.check()?;
    Ok(digest)
}

struct Directory { name: CString, file: File, stamp: DirectoryStamp }
struct Certificate { file: File, stamp: FileStamp, raw: Vec<u8>, digest: [u8; 32] }

impl Certificate {
    fn capture(file: File, guard: &InstallGuard) -> Result<Self, String> {
        let (raw, stamp) = read_file(&file, guard)?;
        let digest = pem_digest(&raw, guard)?;
        Ok(Self { file, stamp, raw, digest })
    }

    fn check(&self, guard: &InstallGuard) -> Result<(), String> {
        let (raw, stamp) = read_file(&self.file, guard)?;
        ensure(stamp == self.stamp && raw == self.raw, "native install held certificate changed")
    }

    fn renamed(&mut self, guard: &InstallGuard) -> Result<(), String> {
        // The one successful rename may change ctime, never identity/content,
        // ownership, mode, link count, length or data modification timestamp.
        let (raw, stamp) = read_file(&self.file, guard)?;
        let a = self.stamp;
        ensure((stamp.0, stamp.1, stamp.2, stamp.3, stamp.4, stamp.5, stamp.6, stamp.7, stamp.8)
            == (a.0, a.1, a.2, a.3, a.4, a.5, a.6, a.7, a.8) && raw == self.raw,
            "native install rename changed more than the expected name")?;
        self.stamp = stamp;
        guard.check()
    }
}

fn sync(file: &File, guard: &InstallGuard) -> Result<(), String> {
    guard.check()?;
    file.sync_all().map_err(|_| "synchronize native install original or directory")?;
    guard.check()
}

fn hexadecimal(raw: &[u8]) -> String {
    raw.iter().map(|value| format!("{value:02x}")).collect()
}

struct Entries(*mut libc::DIR);
impl Drop for Entries {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

fn recovery_capacity(directory: &File, files: usize, bytes: usize, guard: &InstallGuard)
    -> Result<(), String> {
    guard.check()?;
    // A fresh open file description avoids sharing a directory iteration
    // offset with the retained descriptor or any other reader.
    let scan = required_at(directory.as_raw_fd(), &name(".")?, DIRECTORY_FLAGS, guard)?;
    let fd = unsafe { libc::fcntl(scan.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure(fd >= 0, "duplicate native install recovery directory")?;
    let handle = unsafe { libc::fdopendir(fd) };
    if handle.is_null() {
        unsafe { libc::close(fd); }
        return Err("open native install recovery inventory".to_owned());
    }
    let entries = Entries(handle);
    let mut count = 0usize;
    let mut total = 0u64;
    loop {
        guard.check()?;
        unsafe { *libc::__errno_location() = 0; }
        let entry = unsafe { libc::readdir(entries.0) };
        if entry.is_null() {
            ensure(unsafe { *libc::__errno_location() } == 0, "read native install recovery inventory")?;
            break;
        }
        let entry = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if entry.to_bytes() == b"." || entry.to_bytes() == b".." { continue; }
        count += 1;
        ensure(count <= MAX_ENTRIES, "native install recovery file capacity is exhausted")?;
        let spelling = entry.to_str().map_err(|_| "native install recovery name is not ASCII")?;
        let digest = spelling.strip_prefix("pending-").or_else(|| spelling.strip_prefix("previous-"))
            .and_then(|value| value.strip_suffix(".pem"));
        ensure(spelling == LOCK_NAME || digest.map_or(false, |value| value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
            "native install recovery inventory has an unknown name")?;
        let file = required_at(directory.as_raw_fd(), entry, FILE_FLAGS, guard)?;
        let metadata = metadata(&file, guard)?;
        regular(&metadata)?;
        total = total.checked_add(metadata.len()).ok_or("native install recovery size overflow")?;
        ensure(total <= MAX_RECOVERY_BYTES, "native install recovery byte capacity is exhausted")?;
    }
    ensure(count + files <= MAX_ENTRIES && total + bytes as u64 <= MAX_RECOVERY_BYTES,
        "native install recovery capacity cannot retain this operation")?;
    guard.check()
}

pub(super) struct Destination<'a> {
    guard: &'a InstallGuard,
    directories: Vec<Directory>,
    recovery: Directory,
    lock: File,
    lock_stamp: FileStamp,
    leaf: CString,
    destination: String,
    uid: u32,
    gid: u32,
    replace_existing: bool,
    expected_old: Option<[u8; 32]>,
    current: Option<Certificate>,
    recovery_originals: Vec<(CString, Certificate)>,
    attempted: bool,
    failed: bool,
}

impl<'a> Destination<'a> {
    pub(super) fn prepare(spec: &Spec, guard: &'a InstallGuard) -> Result<Self, String> {
        guard.check()?;
        ensure(unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
            "native install destination requires its actual privileged process")?;
        ensure(spec.mode == 0o644 && spec.uid != u32::MAX && spec.gid != u32::MAX
            && spec.replace_existing == spec.expected_existing_certificate_sha256.is_some()
            && spec.expected_existing_certificate_sha256 != Some([0; 32]),
            "native install destination scope is invalid")?;
        ensure(spec.destination.starts_with('/') && spec.destination.len() <= 4096
            && !spec.destination.bytes().any(|byte| byte < 32 || byte == 127 || byte == b'\\'),
            "native install destination is not a bounded absolute path")?;
        let parts: Vec<_> = spec.destination[1..].split('/').collect();
        ensure(!parts.is_empty() && parts.len() <= 128 && parts.iter().all(|part|
            !part.is_empty() && *part != "." && *part != ".." && part.len() <= 255),
            "native install destination spelling contains traversal or empty components")?;
        let leaf = name(parts[parts.len() - 1])?;
        ensure(parts.last() != Some(&RECOVERY_NAME), "native install destination conflicts with recovery")?;
        let root = required_at(libc::AT_FDCWD, &name("/")?, DIRECTORY_FLAGS, guard)?;
        let root_stamp = directory_stamp(&metadata(&root, guard)?, false)?;
        let mut directories = vec![Directory { name: name("/")?, file: root, stamp: root_stamp }];
        for part in &parts[..parts.len() - 1] {
            ensure(*part != RECOVERY_NAME, "native install destination enters reserved recovery storage")?;
            let name = name(part)?;
            let file = required_at(directories.last().unwrap().file.as_raw_fd(), &name, DIRECTORY_FLAGS, guard)?;
            let stamp = directory_stamp(&metadata(&file, guard)?, false)?;
            directories.push(Directory { name, file, stamp });
        }
        let parent = directories.last().unwrap().file.as_raw_fd();
        let recovery_name = name(RECOVERY_NAME)?;
        let recovery = required_at(parent, &recovery_name, DIRECTORY_FLAGS, guard)?;
        let recovery_stamp = directory_stamp(&metadata(&recovery, guard)?, true)?;
        ensure(recovery_stamp.0 == directories.last().unwrap().stamp.0,
            "native install recovery must share the destination filesystem")?;
        let lock = required_at(recovery.as_raw_fd(), &name(LOCK_NAME)?,
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, guard)?;
        let lock_metadata = metadata(&lock, guard)?;
        ensure(lock_metadata.is_file() && lock_metadata.nlink() == 1 && lock_metadata.len() == 0
            && lock_metadata.uid() == 0 && lock_metadata.gid() == 0
            && lock_metadata.mode() & 0o7777 == 0o600,
            "native install destination lock is not its protected fixed original")?;
        guard.check()?;
        ensure(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "native install destination lock is unavailable; no retry")?;
        guard.check()?;
        let current = open_at(parent, &leaf, FILE_FLAGS, guard)?
            .map(|file| Certificate::capture(file, guard)).transpose()?;
        let mut result = Self { guard, directories,
            recovery: Directory { name: recovery_name, file: recovery, stamp: recovery_stamp },
            lock, lock_stamp: file_stamp(&lock_metadata), leaf, destination: spec.destination.clone(),
            uid: spec.uid, gid: spec.gid, replace_existing: spec.replace_existing,
            expected_old: spec.expected_existing_certificate_sha256, current,
            recovery_originals: Vec::new(), attempted: false, failed: false };
        result.check()?;
        Ok(result)
    }

    fn named_certificate(&self, parent: i32, name: &CStr, original: &Certificate) -> Result<(), String> {
        original.check(self.guard)?;
        let named = required_at(parent, name, FILE_FLAGS, self.guard)?;
        ensure(file_stamp(&metadata(&named, self.guard)?) == original.stamp,
            "native install named certificate differs from its retained inode")?;
        self.guard.check()
    }

    fn check_inner(&self) -> Result<(), String> {
        self.guard.check()?;
        let mut parent = libc::AT_FDCWD;
        for directory in &self.directories {
            ensure(directory_stamp(&metadata(&directory.file, self.guard)?, false)? == directory.stamp,
                "native install retained ancestor changed")?;
            let named = required_at(parent, &directory.name, DIRECTORY_FLAGS, self.guard)?;
            ensure(directory_stamp(&metadata(&named, self.guard)?, false)? == directory.stamp,
                "native install ancestor name changed")?;
            parent = directory.file.as_raw_fd();
        }
        ensure(directory_stamp(&metadata(&self.recovery.file, self.guard)?, true)? == self.recovery.stamp,
            "native install recovery owner changed")?;
        let recovery = required_at(parent, &self.recovery.name, DIRECTORY_FLAGS, self.guard)?;
        ensure(directory_stamp(&metadata(&recovery, self.guard)?, true)? == self.recovery.stamp,
            "native install recovery name changed")?;
        let lock = required_at(self.recovery.file.as_raw_fd(), &name(LOCK_NAME)?, FILE_FLAGS, self.guard)?;
        ensure(file_stamp(&metadata(&self.lock, self.guard)?) == self.lock_stamp
            && file_stamp(&metadata(&lock, self.guard)?) == self.lock_stamp,
            "native install destination lock original changed")?;
        match &self.current {
            Some(original) => self.named_certificate(parent, &self.leaf, original)?,
            None => ensure(open_at(parent, &self.leaf, FILE_FLAGS, self.guard)?.is_none(),
                "native install absent destination became occupied")?,
        }
        for (name, original) in &self.recovery_originals {
            self.named_certificate(self.recovery.file.as_raw_fd(), name, original)?;
        }
        self.guard.check()
    }

    pub(super) fn check(&mut self) -> Result<(), String> {
        ensure(!self.failed, "native install destination owner is stopped")?;
        self.failed = true;
        self.check_inner()?;
        self.failed = false;
        Ok(())
    }

    pub(super) fn installed_certificate_der_sha256(&mut self) -> Result<Option<[u8; 32]>, String> {
        self.check()?;
        if let Some(original) = &self.current {
            if original.stamp.3 != self.uid || original.stamp.4 != self.gid
                || original.stamp.2 & 0o7777 != 0o644 {
                self.failed = true;
                return Err("native install actual destination owner or mode differs from signed final scope".to_owned());
            }
            Ok(Some(original.digest))
        } else {
            Ok(None)
        }
    }

    fn publish_recovery(&self, name: &CStr, raw: &[u8], uid: u32, gid: u32, mode: u32)
        -> Result<Certificate, String> {
        self.guard.check()?;
        let file = required_at(self.recovery.file.as_raw_fd(), name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            self.guard)?;
        let mut offset = 0;
        while offset < raw.len() {
            self.guard.check()?;
            let end = raw.len().min(offset + 16 * 1024);
            let count = match file.write_at(&raw[offset..end], offset as u64) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("write native install recovery original".to_owned()),
            };
            ensure(count > 0, "native install recovery write did not progress")?;
            offset += count;
            self.guard.check()?;
        }
        self.guard.check()?;
        ensure(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
            "set native install exact signed file ownership")?;
        self.guard.check()?;
        ensure(unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } == 0,
            "set native install exact file mode")?;
        sync(&file, self.guard)?;
        let held = Certificate::capture(file, self.guard)?;
        ensure(held.raw == raw && held.stamp.3 == uid && held.stamp.4 == gid
            && held.stamp.2 & 0o7777 == mode,
            "native install staged original readback differs")?;
        self.named_certificate(self.recovery.file.as_raw_fd(), name, &held)?;
        sync(&self.recovery.file, self.guard)?;
        Ok(held)
    }

    fn install_inner(&mut self, der: &[u8], expected: [u8; 32]) -> Result<(), String> {
        let raw = canonical_pem(der, self.guard)?;
        ensure(expected != [0; 32] && <[u8; 32]>::from(Sha256::digest(der)) == expected,
            "native install actual certificate differs from the admitted original")?;
        match (&self.current, self.replace_existing, self.expected_old) {
            (None, false, None) => (),
            (Some(old), true, Some(expected_old)) if old.digest == expected_old => (),
            _ => return Err("native install destination is not the exact signed create/replacement state".to_owned()),
        }
        let old_length = self.current.as_ref().map_or(0, |old| old.raw.len());
        recovery_capacity(&self.recovery.file, if self.replace_existing { 2 } else { 1 },
            raw.len() + old_length, self.guard)?;
        let mut hash = Sha256::new();
        hash.update(b"serverware/native-install-destination-operation/v1\0");
        hash.update((self.destination.len() as u64).to_be_bytes());
        hash.update(self.destination.as_bytes());
        hash.update(self.uid.to_be_bytes());
        hash.update(self.gid.to_be_bytes());
        hash.update([u8::from(self.replace_existing)]);
        hash.update(self.expected_old.unwrap_or([0; 32]));
        hash.update(expected);
        let operation = hexadecimal(&hash.finalize());
        let pending_name = name(&format!("pending-{operation}.pem"))?;
        if let Some(old) = &self.current {
            let previous_name = name(&format!("previous-{operation}.pem"))?;
            let previous = self.publish_recovery(&previous_name, &old.raw, 0, 0, 0o600)?;
            self.recovery_originals.push((previous_name, previous));
        }
        let mut staged = self.publish_recovery(&pending_name, &raw, self.uid, self.gid, 0o644)?;
        self.check()?;
        self.named_certificate(self.recovery.file.as_raw_fd(), &pending_name, &staged)?;
        self.guard.check()?;
        let parent = self.directories.last().unwrap().file.as_raw_fd();
        let flags = if self.replace_existing { libc::RENAME_EXCHANGE } else { libc::RENAME_NOREPLACE };
        ensure(unsafe { libc::renameat2(self.recovery.file.as_raw_fd(), pending_name.as_ptr(),
            parent, self.leaf.as_ptr(), flags) } == 0,
            "native install atomic publication failed; outcome is not retry authority")?;
        self.guard.check()?;
        staged.renamed(self.guard)?;
        if let Some(mut old) = self.current.take() {
            old.renamed(self.guard)?;
            self.named_certificate(self.recovery.file.as_raw_fd(), &pending_name, &old)?;
            self.recovery_originals.push((pending_name, old));
        }
        self.current = Some(staged);
        sync(&self.recovery.file, self.guard)?;
        sync(&self.directories.last().unwrap().file, self.guard)?;
        self.check()?;
        ensure(self.installed_certificate_der_sha256()? == Some(expected),
            "native install final original certificate differs")?;
        self.guard.check()
    }

    pub(super) fn install(&mut self, actual_ca_der: &[u8], expected_der_sha256: [u8; 32])
        -> Result<(), String> {
        self.check()?;
        ensure(!self.attempted, "native install destination attempt is already spent")?;
        self.attempted = true;
        let result = self.install_inner(actual_ca_der, expected_der_sha256);
        if result.is_err() { self.failed = true; }
        result
    }
}
