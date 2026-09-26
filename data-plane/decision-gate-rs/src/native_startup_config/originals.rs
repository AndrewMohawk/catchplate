//! Retained, independently pinned startup originals, not configuration authority.
//!
//! Canonical spelling and anchored no-follow opens reject symlink traversal.
//! Byte/hash and named/held identity checks are local observations; they do not
//! make mutable storage atomic, admit the pin, or isolate this process from a
//! hostile host. Blocking filesystem operations still need an outer watchdog.

use super::super::{is_sha256_digest, sha256_prefixed};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const MAX_ORIGINAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const DIRECTORY_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY
    | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const FILE_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_NOFOLLOW
    | libc::O_CLOEXEC | libc::O_NONBLOCK;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ArtifactV1 {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}

// Access time is intentionally excluded: actual reads may update it. Every
// stored field below is obtained from the opened file, never from a caller DTO.
type Fingerprint = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn fingerprint(metadata: &Metadata) -> Fingerprint {
    (metadata.dev(), metadata.ino(), metadata.mode(), metadata.uid(), metadata.gid(),
     metadata.nlink(), metadata.len(), metadata.mtime(), metadata.mtime_nsec(),
     metadata.ctime(), metadata.ctime_nsec())
}

fn canonical_path(path: &Path) -> Result<(), String> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.contains(&0)
        || !path.is_absolute() || path.file_name().is_none()
        || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("native startup original path is not bounded and absolute".to_owned());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| "resolve native startup original path")?;
    // Compare original bytes, not Path component equality, which can normalize
    // repeated separators or dot components. No alternative spelling is kept.
    if canonical.as_os_str().as_bytes() != bytes {
        return Err("native startup original path is not its exact canonical path".to_owned());
    }
    Ok(())
}

fn open_named(path: &Path, maximum: usize) -> Result<(File, Fingerprint), String> {
    canonical_path(path)?;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err("native startup original path lost its root".to_owned());
    }
    let names = components.map(|part| match part {
        Component::Normal(name) => CString::new(name.as_bytes())
            .map_err(|_| "native startup original path component is invalid".to_owned()),
        _ => Err("native startup original path contains traversal".to_owned()),
    }).collect::<Result<Vec<_>, _>>()?;
    let (leaf, ancestors) = names.split_last()
        .ok_or("native startup original path has no leaf")?;
    let mut directory = OpenOptions::new().read(true).custom_flags(DIRECTORY_FLAGS)
        .open("/").map_err(|_| "open native startup filesystem root")?;
    // canonicalize is not a race-safe no-follow guarantee. Every actual open
    // below independently uses an already held directory and one fixed name.
    for component in ancestors {
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), DIRECTORY_FLAGS) };
        if fd < 0 {
            return Err("open native startup original ancestor without symlinks".to_owned());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let fd = unsafe { libc::openat(directory.as_raw_fd(), leaf.as_ptr(), FILE_FLAGS) };
    if fd < 0 {
        return Err("open native startup original without symlinks".to_owned());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| "inspect native startup original")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("native startup original must be a bounded nonempty regular file".to_owned());
    }
    canonical_path(path)?;
    Ok((file, fingerprint(&metadata)))
}

fn read_original(file: &mut File, expected: Fingerprint, pin: &str, maximum: usize)
    -> Result<Vec<u8>, String>
{
    if fingerprint(&file.metadata().map_err(|_| "inspect held native startup original")?) != expected {
        return Err("native startup original identity changed".to_owned());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "seek native startup original")?;
    let expected_length = usize::try_from(expected.6)
        .map_err(|_| "native startup original length overflows")?;
    if expected_length == 0 || expected_length > maximum {
        return Err("native startup original length exceeds its bound".to_owned());
    }
    let capacity = expected_length.checked_add(1)
        .ok_or("native startup original read bound overflows")?;
    // One fixed allocation covers the admitted bytes and an EOF probe. A
    // growing file must not cause a secret-bearing Vec reallocation, and every
    // error path zeroizes whatever bytes were already obtained.
    let mut bytes = Zeroizing::new(vec![0u8; capacity]);
    let mut length = 0usize;
    while length < bytes.len() {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("read bounded native startup original".to_owned()),
        }
    }
    if length != expected_length
        || sha256_prefixed(&bytes[..length]) != pin
        || fingerprint(&file.metadata().map_err(|_| "reinspect native startup original")?) != expected
    {
        return Err("native startup original bytes or metadata differ from its pin".to_owned());
    }
    bytes.truncate(length);
    Ok(std::mem::take(&mut *bytes))
}

/// No Clone, public file accessor or successful-admission conversion. Keep this
/// owner until the caller's final publication/transition and recheck there.
pub(super) struct HeldOriginal {
    artifact: ArtifactV1,
    file: File,
    fingerprint: Fingerprint,
    maximum: usize,
    poisoned: bool,
}

impl HeldOriginal {
    /// Configuration carries service bearer tokens. Public policy/launch
    /// originals do not need this extra local discretionary-permission gate.
    /// Root access, ACL/mount provenance and hostile-host isolation remain
    /// outside this check; it does not claim encryption or independent custody.
    pub(super) fn require_private(&self) -> Result<(), String> {
        let metadata = self.file.metadata().map_err(|_| "inspect private startup original")?;
        let caller_uid = unsafe { libc::geteuid() };
        if self.poisoned || fingerprint(&metadata) != self.fingerprint
            || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1
            || (metadata.uid() != 0 && metadata.uid() != caller_uid)
        {
            return Err("native configuration must be owner-only, single-link and owned by root or the caller".to_owned());
        }
        Ok(())
    }

    pub(super) fn read(artifact: ArtifactV1, maximum: usize)
        -> Result<(Self, Vec<u8>), String>
    {
        let mut held = Self::open(artifact, maximum)?;
        let mut bytes = Zeroizing::new(read_original(&mut held.file,
            held.fingerprint, &held.artifact.sha256, held.maximum)?);
        held.recheck_name()?;
        Ok((held, std::mem::take(&mut *bytes)))
    }

    /// Check the same private metadata predicate before obtaining any private
    /// bytes, then retain zeroizing storage through all post-read checks.
    pub(super) fn read_private(artifact: ArtifactV1, maximum: usize)
        -> Result<(Self, Zeroizing<Vec<u8>>), String>
    {
        let mut held = Self::open(artifact, maximum)?;
        held.require_private()?;
        let bytes = Zeroizing::new(read_original(&mut held.file,
            held.fingerprint, &held.artifact.sha256, held.maximum)?);
        held.recheck_name()?;
        held.require_private()?;
        Ok((held, bytes))
    }

    fn open(artifact: ArtifactV1, maximum: usize) -> Result<Self, String> {
        if maximum == 0 || maximum > MAX_ORIGINAL_BYTES || !is_sha256_digest(&artifact.sha256) {
            return Err("native startup original bound or SHA-256 pin is invalid".to_owned());
        }
        let (file, fingerprint) = open_named(&artifact.path, maximum)?;
        Ok(Self { artifact, file, fingerprint, maximum, poisoned: false })
    }

    fn recheck_name(&self) -> Result<(), String> {
        let (_named, named_identity) = open_named(&self.artifact.path, self.maximum)?;
        if named_identity != self.fingerprint
            || fingerprint(&self.file.metadata().map_err(|_| "inspect retained startup original")?)
                != self.fingerprint
        {
            return Err("native startup original name or retained identity changed".to_owned());
        }
        Ok(())
    }

    pub(super) fn recheck(&mut self) -> Result<(), String> {
        if std::mem::replace(&mut self.poisoned, true) {
            return Err("native startup original owner is poisoned".to_owned());
        }
        let _original = Zeroizing::new(read_original(
            &mut self.file, self.fingerprint, &self.artifact.sha256, self.maximum)?);
        self.recheck_name()?;
        self.poisoned = false;
        Ok(())
    }
}
