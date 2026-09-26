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
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

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
    let mut bytes = Vec::with_capacity(expected.6 as usize);
    Read::by_ref(file).take(maximum as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| "read bounded native startup original")?;
    if bytes.len() as u64 != expected.6 || bytes.len() > maximum
        || sha256_prefixed(&bytes) != pin
        || fingerprint(&file.metadata().map_err(|_| "reinspect native startup original")?) != expected
    {
        return Err("native startup original bytes or metadata differ from its pin".to_owned());
    }
    Ok(bytes)
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
        if maximum == 0 || maximum > MAX_ORIGINAL_BYTES || !is_sha256_digest(&artifact.sha256) {
            return Err("native startup original bound or SHA-256 pin is invalid".to_owned());
        }
        let (mut file, fingerprint) = open_named(&artifact.path, maximum)?;
        let bytes = read_original(&mut file, fingerprint, &artifact.sha256, maximum)?;
        let held = Self { artifact, file, fingerprint, maximum, poisoned: false };
        held.recheck_name()?;
        Ok((held, bytes))
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
        read_original(&mut self.file, self.fingerprint, &self.artifact.sha256, self.maximum)?;
        self.recheck_name()?;
        self.poisoned = false;
        Ok(())
    }
}
