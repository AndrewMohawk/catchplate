//! Offline export of an operator-supplied policy, not policy selection or admission.

use super::{custody_seccomp_raw_bytes, Sha256Digest, StructurallyVerifiedCustodySeccompPolicy};
use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_BPF_BYTES: usize = 32768;
const USAGE: &str = "usage: catchplate-export-custody-seccomp --policy /absolute/policy.json --output /absolute/new/seccomp.bpf";

// Resolve every directory without following symlinks and retain the parent for
// the final openat. The caller must supply existing directories; none are made.
fn parent(path: &Path) -> Result<(File, CString), Box<dyn Error>> {
    if path.as_os_str().as_bytes().len() > 4096 {
        return Err("path exceeds 4096 bytes".into());
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err("paths must be absolute and contain only normal components".into());
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open("/")?;
    let mut remaining = components.peekable();
    while let Some(component) = remaining.next() {
        let Component::Normal(name) = component else {
            return Err("paths must contain only normal components".into());
        };
        let name = CString::new(name.as_bytes())?;
        if remaining.peek().is_none() {
            return Ok((directory, name));
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Err("path must name a file".into())
}

fn same_original(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn read_policy(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let (directory, name) = parent(path)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata()?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_POLICY_BYTES as u64 {
        return Err("policy must be a nonempty regular file of at most 4 MiB".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_POLICY_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len() || !same_original(&before, &file.metadata()?) {
        return Err("policy changed during bounded read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let (directory, name) = parent(path)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    // A failure retains the new partial file; there is no overwrite, repair,
    // cleanup or automatic retry, including when the output already exists.
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(0o444))?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let mut retained = Vec::new();
    (&mut file).take(MAX_BPF_BYTES as u64 + 1).read_to_end(&mut retained)?;
    if retained != bytes {
        return Err("new BPF file differs on held-file readback".into());
    }
    directory.sync_all()?;
    Ok(())
}

pub(crate) fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new("--policy")) {
        return Err(USAGE.into());
    }
    let policy_path = args.next().ok_or(USAGE)?;
    if args.next().as_deref() != Some(OsStr::new("--output")) {
        return Err(USAGE.into());
    }
    let output_path = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    // Decode directly into the complete existing deny_unknown_fields type:
    // wrappers, secrets, omitted fields and duplicate fields are not accepted.
    let policy: StructurallyVerifiedCustodySeccompPolicy =
        serde_json::from_slice(&read_policy(Path::new(&policy_path))?)
            .map_err(|_| "input is not the exact existing public custody seccomp policy")?;
    policy.validate()?;
    let bytes = custody_seccomp_raw_bytes(policy.exact_instructions());
    if bytes.is_empty() || bytes.len() > MAX_BPF_BYTES || bytes.len() % 8 != 0
        || Sha256Digest::compute(&bytes) != *policy.raw_bpf_sha256()
    {
        return Err("validated policy does not produce the exact bounded raw BPF".into());
    }
    write_new(Path::new(&output_path), &bytes)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "rawBpfSha256={}", policy.raw_bpf_sha256().as_str())?;
    writeln!(stdout, "structurallyVerifiedPolicySha256={}", policy.policy_sha256().as_str())?;
    writeln!(stdout, "independentApproval=false")?;
    writeln!(stdout, "Structural export only; independently authenticate the policy and artifact pins before admission.")?;
    Ok(())
}
