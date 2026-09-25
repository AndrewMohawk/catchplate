//! Retained-FD reads shared by fixed native and generic body-output owners.
//!
//! Read policies, no-follow opens, mount identity, complete metadata snapshots,
//! bounded inventories and chunk hashing are preserved from the native reader.
//! This module does not admit a manifest, choose a path set or claim execution.

use super::{boottime_now_ns_v11, ControllerError, Digest, Result};
use super::runner_output_storage_v12::fd_mount_id;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const CHUNK_BYTES: usize = 64 * 1024;

fn rejected(message: &'static str) -> ControllerError {
    ControllerError::Rejected(message)
}

pub(super) fn live(deadline: u64) -> Result<()> {
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

impl Identity {
    // File contents and directory inventories legitimately change while the
    // body runs. This anchor is not a completed-read metadata snapshot.
    fn same_anchor(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
            && self.mode == other.mode && self.uid == other.uid && self.gid == other.gid
    }
}

#[derive(Clone, Copy)]
pub(super) enum Policy {
    Prepared,
    Output { uid: u32, gid: u32 },
    Controller,
}

impl Policy {
    fn directory(self, value: &Identity) -> Result<()> {
        let valid = match self {
            Self::Prepared => value.uid == 0 && value.mode & 0o022 == 0,
            Self::Output { uid, gid } => value.uid == uid && value.gid == gid
                && value.mode & 0o7777 == 0o700,
            Self::Controller => value.uid == 0 && value.gid == 0
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
            Self::Controller => value.uid == 0 && value.gid == 0
                && value.mode & 0o7777 == 0o600,
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
            Self::Output { .. } | Self::Controller => {
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

pub(super) struct Directory {
    descriptor: OwnedFd,
    original: Identity,
    mount: u64,
    policy: Policy,
    borrowed: Option<RawFd>,
    parent: Option<(RawFd, CString)>,
}

impl Directory {
    pub(super) fn root(borrowed: RawFd, policy: Policy, deadline: u64) -> Result<Self> {
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

    pub(super) fn child(&self, name: &str, deadline: u64) -> Result<Self> {
        self.child_with_policy(name, self.policy, deadline)
    }

    pub(super) fn child_with_policy(&self, name: &str, policy: Policy,
        deadline: u64) -> Result<Self> {
        self.verify(deadline)?;
        let name = leaf_name(name)?;
        let descriptor = open_at(self.fd(), &name, true)?;
        let original = identity(descriptor.as_raw_fd())?;
        policy.directory(&original)?;
        if original.device != self.original.device
            || fd_mount_id(descriptor.as_raw_fd())? != self.mount {
            return Err(rejected("native child directory crossed its retained mount"));
        }
        let result = Self { descriptor, original, mount: self.mount, policy,
            borrowed: None, parent: Some((self.fd(), name)) };
        result.verify(deadline)?;
        self.verify(deadline)?;
        Ok(result)
    }

    pub(super) fn fd(&self) -> RawFd { self.descriptor.as_raw_fd() }

    pub(super) fn verify_anchor(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        let current = identity(self.fd())?;
        if !current.same_anchor(&self.original) || fd_mount_id(self.fd())? != self.mount {
            return Err(rejected("body output directory anchor changed"));
        }
        self.policy.directory(&current)?;
        self.policy.filesystem(self.fd())?;
        if let Some(borrowed) = self.borrowed {
            if !identity(borrowed)?.same_anchor(&self.original)
                || fd_mount_id(borrowed)? != self.mount {
                return Err(rejected("body output borrowed directory anchor changed"));
            }
        }
        if let Some((parent, name)) = &self.parent {
            let named = open_at(*parent, name, true)?;
            if !identity(named.as_raw_fd())?.same_anchor(&self.original)
                || fd_mount_id(named.as_raw_fd())? != self.mount {
                return Err(rejected("body output directory name changed"));
            }
        }
        live(deadline)
    }

    pub(super) fn snapshot_after_writes(&mut self, deadline: u64) -> Result<()> {
        self.verify_anchor(deadline)?;
        self.original = identity(self.fd())?;
        self.verify(deadline)
    }

    pub(super) fn sync(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        if unsafe { libc::fsync(self.fd()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        live(deadline)
    }

    pub(super) fn verify(&self, deadline: u64) -> Result<()> {
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

    pub(super) fn inventory(&self, expected: &[String], deadline: u64) -> Result<()> {
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

pub(super) struct Leaf {
    file: File,
    parent: RawFd,
    name: CString,
    original: Identity,
    mount: u64,
    policy: Policy,
}

impl Leaf {
    pub(super) fn byte_count(&self) -> u64 { self.original.size as u64 }

    pub(super) fn open(parent: &Directory, name: &str, minimum: usize, maximum: usize,
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

    pub(super) fn verify(&self, deadline: u64) -> Result<()> {
        live(deadline)?;
        if identity(self.file.as_raw_fd())? != self.original
            || fd_mount_id(self.file.as_raw_fd())? != self.mount {
            return Err(rejected("native original file changed during observation"));
        }
        self.policy.filesystem(self.file.as_raw_fd())?;
        same_named(self.parent, &self.name, &self.original, self.mount, deadline)
    }

    pub(super) fn matches_descriptor(&self, descriptor: RawFd, deadline: u64) -> Result<()> {
        self.verify(deadline)?;
        if identity(descriptor)? != self.original || fd_mount_id(descriptor)? != self.mount {
            return Err(rejected("controller stream writer differs from its retained original"));
        }
        live(deadline)
    }

    pub(super) fn finish_controller_write(&mut self, maximum: usize,
        deadline: u64) -> Result<()> {
        live(deadline)?;
        if !matches!(self.policy, Policy::Controller) {
            return Err(rejected("only a controller stream can finish a retained write"));
        }
        let current = identity(self.file.as_raw_fd())?;
        if !current.same_anchor(&self.original)
            || fd_mount_id(self.file.as_raw_fd())? != self.mount {
            return Err(rejected("controller stream anchor changed during capture"));
        }
        self.policy.file(&current, 0, maximum)?;
        same_named(self.parent, &self.name, &current, self.mount, deadline)?;
        self.file.sync_all()?;
        live(deadline)?;
        if identity(self.file.as_raw_fd())? != current {
            return Err(rejected("controller stream changed during final synchronization"));
        }
        self.original = current;
        self.verify(deadline)
    }

    pub(super) fn read(&mut self, retain_bytes: bool, deadline: u64) -> Result<(Digest, Vec<u8>)> {
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
