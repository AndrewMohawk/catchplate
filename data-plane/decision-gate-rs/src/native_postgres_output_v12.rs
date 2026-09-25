//! Fixed native PostgreSQL originals, read only through retained directory FDs.
//!
//! Prepared source pins come from the independently admitted runner contract.
//! Output reports are cooperative observations: their actual bytes/log hashes
//! do not replace the controller's process, courier, runtime or destruction
//! proofs. No path, source inventory, work allowance or deadline is supplied by
//! a report. Logs are streamed, not accumulated into one aggregate allocation.

use super::{
    boottime_now_ns_v11, canonical_json_bytes_v11, digest_hex,
    ControllerError, Digest, Result,
};
use super::native_postgres_reports_v12::{self as reports, NativePostgresFileV12};
use super::runner_output_storage_v12::fd_mount_id;
use crate::plan_protocol::native_postgres_contract_v12::{
    self as contract, NativePostgresContractV12, MAX_LOG_BYTES,
    MAX_MANIFEST_BYTES, MAX_REPORT_BYTES, MAX_SOURCE_BYTES, MAX_SUMMARY_BYTES, SUITES,
};
use serde_json::json;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const MANIFEST_NAME: &str = "native-postgres-sources-v1.json";
const MANIFEST_SCHEMA: &str = "serverware.nativePostgresPreparedSources/v1";
const RUNTIME_NAME: &str = "runtime-result.json";
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const CHUNK_BYTES: usize = 64 * 1024;

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

fn live(deadline: u64) -> Result<()> {
    if boottime_now_ns_v11()? >= deadline {
        return Err(rejected("native PostgreSQL original read deadline expired"));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

fn identity(fd: RawFd) -> Result<Identity> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Identity {
        device: value.st_dev, inode: value.st_ino, mode: value.st_mode,
        uid: value.st_uid, gid: value.st_gid, links: value.st_nlink,
        size: value.st_size, mtime: value.st_mtime, mtime_ns: value.st_mtime_nsec,
        ctime: value.st_ctime, ctime_ns: value.st_ctime_nsec,
    })
}

#[derive(Clone, Copy)]
enum Policy {
    Prepared,
    Output { uid: u32, gid: u32 },
}

impl Policy {
    fn directory(self, value: &Identity) -> Result<()> {
        let valid = match self {
            Self::Prepared => value.uid == 0 && value.mode & 0o022 == 0,
            Self::Output { uid, gid } => value.uid == uid && value.gid == gid
                && value.mode & 0o7777 == 0o700,
        };
        if value.mode & libc::S_IFMT != libc::S_IFDIR || value.links == 0 || !valid {
            return Err(rejected("native directory is not its fixed protected identity"));
        }
        Ok(())
    }

    fn file(self, value: &Identity, minimum: usize, maximum: usize) -> Result<()> {
        let valid = match self {
            Self::Prepared => value.uid == 0 && value.mode & 0o022 == 0,
            Self::Output { uid, gid } => value.uid == uid && value.gid == gid
                && matches!(value.mode & 0o7777, 0o400 | 0o600),
        };
        if value.mode & libc::S_IFMT != libc::S_IFREG || value.links != 1 || !valid
            || value.size < 0 || (value.size as u64) < minimum as u64
            || value.size as u64 > maximum as u64 {
            return Err(rejected("native file is not its owned bounded regular original"));
        }
        Ok(())
    }

    fn filesystem(self, fd: RawFd) -> Result<()> {
        match self {
            Self::Prepared => {
                let mut value: libc::statvfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatvfs(fd, &mut value) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if value.f_flag & libc::ST_RDONLY == 0 {
                    return Err(rejected("native prepared input is not on a read-only mount"));
                }
            }
            Self::Output { .. } => {
                let mut value: libc::statfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatfs(fd, &mut value) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if value.f_type != TMPFS_MAGIC {
                    return Err(rejected("native output is not on its retained tmpfs"));
                }
            }
        }
        Ok(())
    }
}

fn leaf_name(name: &str) -> Result<CString> {
    if name.is_empty() || name.len() > 255 || !name.is_ascii()
        || name.contains('/') || matches!(name, "." | "..") {
        return Err(rejected("native input is not one source-fixed leaf name"));
    }
    CString::new(name).map_err(|_| rejected("native leaf name contains NUL"))
}

fn open_at(parent: RawFd, name: &CStr, directory: bool) -> Result<OwnedFd> {
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn same_named(parent: RawFd, name: &CStr, expected: &Identity,
    mount: u64, deadline: u64) -> Result<()> {
    live(deadline)?;
    let descriptor = open_at(parent, name, expected.mode & libc::S_IFMT == libc::S_IFDIR)?;
    if identity(descriptor.as_raw_fd())? != *expected
        || fd_mount_id(descriptor.as_raw_fd())? != mount {
        return Err(rejected("native retained descriptor differs from its current fixed name"));
    }
    live(deadline)
}

struct Directory {
    descriptor: OwnedFd,
    original: Identity,
    mount: u64,
    policy: Policy,
    borrowed: Option<RawFd>,
    parent: Option<(RawFd, CString)>,
}

impl Directory {
    fn root(borrowed: RawFd, policy: Policy, deadline: u64) -> Result<Self> {
        live(deadline)?;
        if borrowed < 3 { return Err(rejected("native root descriptor aliases stdio")); }
        let original = identity(borrowed)?;
        policy.directory(&original)?;
        policy.filesystem(borrowed)?;
        let mount = fd_mount_id(borrowed)?;
        // Independent directory description; never consume the borrowed offset.
        let descriptor = open_at(borrowed, c".", true)?;
        let result = Self { descriptor, original, mount, policy,
            borrowed: Some(borrowed), parent: None };
        result.verify(deadline)?;
        Ok(result)
    }

    fn child(&self, name: &str, deadline: u64) -> Result<Self> {
        self.verify(deadline)?;
        let name = leaf_name(name)?;
        let descriptor = open_at(self.fd(), &name, true)?;
        let original = identity(descriptor.as_raw_fd())?;
        self.policy.directory(&original)?;
        if original.device != self.original.device
            || fd_mount_id(descriptor.as_raw_fd())? != self.mount {
            return Err(rejected("native child directory crossed its retained mount"));
        }
        let result = Self { descriptor, original, mount: self.mount, policy: self.policy,
            borrowed: None, parent: Some((self.fd(), name)) };
        result.verify(deadline)?;
        self.verify(deadline)?;
        Ok(result)
    }

    fn fd(&self) -> RawFd { self.descriptor.as_raw_fd() }

    fn verify(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        if identity(self.fd())? != self.original || fd_mount_id(self.fd())? != self.mount {
            return Err(rejected("native retained directory changed during observation"));
        }
        self.policy.directory(&self.original)?;
        self.policy.filesystem(self.fd())?;
        if let Some(borrowed) = self.borrowed {
            if identity(borrowed)? != self.original || fd_mount_id(borrowed)? != self.mount {
                return Err(rejected("native borrowed root changed during observation"));
            }
        }
        if let Some((parent, name)) = &self.parent {
            same_named(*parent, name, &self.original, self.mount, deadline)?;
        }
        live(deadline)
    }

    fn inventory(&self, expected: &[String], deadline: u64) -> Result<()> {
        self.verify(deadline)?;
        let expected: BTreeSet<&str> = expected.iter().map(String::as_str).collect();
        let scan_fd = open_at(self.fd(), c".", true)?.into_raw_fd();
        let stream = unsafe { libc::fdopendir(scan_fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(scan_fd); }
            return Err(error.into());
        }
        let scan = DirectoryStream(stream);
        let mut seen = BTreeSet::new();
        let mut entries = 0usize;
        loop {
            live(deadline)?;
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(scan.0) };
            if entry.is_null() {
                let code = unsafe { *libc::__errno_location() };
                if code != 0 { return Err(std::io::Error::from_raw_os_error(code).into()); }
                break;
            }
            entries += 1;
            if entries > expected.len() + 2 {
                return Err(rejected("native directory contains an oversized or repeated inventory"));
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            let name = std::str::from_utf8(bytes)
                .map_err(|_| rejected("native directory contains a non-source filename"))?;
            if !expected.contains(name) || !seen.insert(name.to_owned()) {
                return Err(rejected("native directory contains an unknown or duplicate entry"));
            }
        }
        drop(scan);
        if seen.len() != expected.len() {
            return Err(rejected("native directory is missing a source-required file"));
        }
        self.verify(deadline)
    }
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

struct Leaf {
    file: File,
    parent: RawFd,
    name: CString,
    original: Identity,
    mount: u64,
    policy: Policy,
}

impl Leaf {
    fn open(parent: &Directory, name: &str, minimum: usize, maximum: usize,
        deadline: u64) -> Result<Self> {
        parent.verify(deadline)?;
        let name = leaf_name(name)?;
        let descriptor = open_at(parent.fd(), &name, false)?;
        let original = identity(descriptor.as_raw_fd())?;
        parent.policy.file(&original, minimum, maximum)?;
        if original.device != parent.original.device
            || fd_mount_id(descriptor.as_raw_fd())? != parent.mount {
            return Err(rejected("native leaf crossed its retained directory mount"));
        }
        let result = Self { file: File::from(descriptor), parent: parent.fd(), name,
            original, mount: parent.mount, policy: parent.policy };
        result.verify(deadline)?;
        Ok(result)
    }

    fn verify(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        if identity(self.file.as_raw_fd())? != self.original
            || fd_mount_id(self.file.as_raw_fd())? != self.mount {
            return Err(rejected("native original file changed during observation"));
        }
        self.policy.filesystem(self.file.as_raw_fd())?;
        same_named(self.parent, &self.name, &self.original, self.mount, deadline)
    }

    fn read(&mut self, retain_bytes: bool, deadline: u64) -> Result<(Digest, Vec<u8>)> {
        self.verify(deadline)?;
        let length = self.original.size as usize;
        let mut bytes = if retain_bytes { Vec::with_capacity(length) } else { Vec::new() };
        let mut hasher = Sha256::new();
        let mut remaining = length;
        let mut chunk = [0u8; CHUNK_BYTES];
        while remaining > 0 {
            live(deadline)?;
            let wanted = remaining.min(chunk.len());
            let count = self.file.read(&mut chunk[..wanted])?;
            if count == 0 { return Err(rejected("native original ended before its retained byte count")); }
            live(deadline)?;
            hasher.update(&chunk[..count]);
            if retain_bytes { bytes.extend_from_slice(&chunk[..count]); }
            remaining -= count;
            live(deadline)?;
        }
        live(deadline)?;
        let mut extra = [0u8; 1];
        if self.file.read(&mut extra)? != 0 {
            return Err(rejected("native original exceeds its retained byte count"));
        }
        live(deadline)?;
        let digest: Digest = hasher.finalize().into();
        self.verify(deadline)?;
        Ok((digest, bytes))
    }
}

/// Re-admit the fixed prepared manifest and all actual source scripts.
pub(super) fn admit_prepared(artifact_root: RawFd, source_root: RawFd,
    contract: &NativePostgresContractV12, deadline: u64) -> Result<()> {
    live(deadline)?;
    contract.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    let artifacts = Directory::root(artifact_root, Policy::Prepared, deadline)?;
    let sources = Directory::root(source_root, Policy::Prepared, deadline)?;
    let scripts = sources.child("scripts", deadline)?;
    let mut manifest = Leaf::open(&artifacts, MANIFEST_NAME, 2, MAX_MANIFEST_BYTES, deadline)?;
    let (manifest_digest, original) = manifest.read(true, deadline)?;
    if manifest_digest != contract.prepared_sources_sha256 {
        return Err(rejected("native prepared manifest differs from its independent signed pin"));
    }
    let rows: Vec<_> = SUITES.iter().zip(&contract.source_sha256).map(|(suite, digest)|
        json!({"path": suite.script, "sha256": format!("sha256:{}", digest_hex(digest))})).collect();
    // Construct the one permitted canonical document instead of accepting a
    // parsed manifest's inventory. All strings here are fixed ASCII or hex.
    live(deadline)?;
    let expected = canonical_json_bytes_v11(&json!({"schema": MANIFEST_SCHEMA, "scripts": rows}))?;
    if expected.len() > MAX_MANIFEST_BYTES || original != expected {
        return Err(rejected("native prepared manifest is not the exact canonical source inventory"));
    }
    live(deadline)?;
    let mut retained = Vec::with_capacity(SUITES.len());
    for (suite, expected) in SUITES.iter().zip(&contract.source_sha256) {
        live(deadline)?;
        let name = suite.script.strip_prefix("scripts/")
            .ok_or_else(|| rejected("native suite escaped its fixed scripts directory"))?;
        let mut source = Leaf::open(&scripts, name, 1, MAX_SOURCE_BYTES, deadline)?;
        let (observed, _) = source.read(false, deadline)?;
        if observed != *expected {
            return Err(rejected("native actual script differs from its independent prepared pin"));
        }
        retained.push(source);
    }
    for source in &retained { source.verify(deadline)?; }
    manifest.verify(deadline)?;
    scripts.verify(deadline)?;
    sources.verify(deadline)?;
    artifacts.verify(deadline)?;
    live(deadline)
}

/// Read actual fixed originals, reconcile them, and commit their exact inventory.
pub(super) fn collect(output_root: RawFd, uid: u32, gid: u32,
    contract: &NativePostgresContractV12, deadline: u64) -> Result<Digest> {
    live(deadline)?;
    contract.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    if uid == 0 || gid == 0 { return Err(rejected("native output requires an admitted nonroot owner")); }
    let root = Directory::root(output_root, Policy::Output { uid, gid }, deadline)?;
    let native = root.child("native-postgres", deadline)?;
    let report_dir = native.child("reports", deadline)?;
    let log_dir = native.child("logs", deadline)?;
    let native_names = vec!["runtime-result.json".to_owned(), "reports".to_owned(), "logs".to_owned()];
    let report_names: Vec<_> = (0..SUITES.len()).map(|index| format!("{index:02}.json")).collect();
    let paths = contract::expected_output_paths();
    let log_names: Vec<_> = paths.iter().filter_map(|path|
        path.strip_prefix("native-postgres/logs/").map(str::to_owned)).collect();
    if paths.len() != 33 || report_names.len() != 15 || log_names.len() != 17 {
        return Err(rejected("native source output inventory cardinality changed"));
    }
    native.inventory(&native_names, deadline)?;
    report_dir.inventory(&report_names, deadline)?;
    log_dir.inventory(&log_names, deadline)?;
    let mut retained = Vec::with_capacity(paths.len());
    let mut files = Vec::with_capacity(paths.len());
    let mut runtime = Leaf::open(&native, RUNTIME_NAME, 2, MAX_SUMMARY_BYTES, deadline)?;
    let (digest, summary) = runtime.read(true, deadline)?;
    files.push(NativePostgresFileV12 { path: format!("native-postgres/{RUNTIME_NAME}"),
        sha256: digest, bytes: runtime.original.size as u64 });
    retained.push(runtime);
    let mut originals = Vec::with_capacity(SUITES.len());
    for name in &report_names {
        let mut report = Leaf::open(&report_dir, name, 2, MAX_REPORT_BYTES, deadline)?;
        let (digest, bytes) = report.read(true, deadline)?;
        files.push(NativePostgresFileV12 { path: format!("native-postgres/reports/{name}"),
            sha256: digest, bytes: report.original.size as u64 });
        originals.push(bytes);
        retained.push(report);
    }
    for name in &log_names {
        // Empty logs are genuine files with the actual SHA256(empty), not
        // absent observations. Only this one bounded chunk buffer is used.
        let mut log = Leaf::open(&log_dir, name, 0, MAX_LOG_BYTES, deadline)?;
        let (digest, _) = log.read(false, deadline)?;
        files.push(NativePostgresFileV12 { path: format!("native-postgres/logs/{name}"),
            sha256: digest, bytes: log.original.size as u64 });
        retained.push(log);
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    live(deadline)?;
    let result = reports::reconcile(contract, &summary, &originals, &files)?;
    live(deadline)?;
    for original in &retained { original.verify(deadline)?; }
    native.inventory(&native_names, deadline)?;
    report_dir.inventory(&report_names, deadline)?;
    log_dir.inventory(&log_names, deadline)?;
    log_dir.verify(deadline)?;
    report_dir.verify(deadline)?;
    native.verify(deadline)?;
    root.verify(deadline)?;
    live(deadline)?;
    Ok(result)
}
