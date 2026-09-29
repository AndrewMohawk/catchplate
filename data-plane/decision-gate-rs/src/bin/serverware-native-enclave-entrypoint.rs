//! Fixed production image entrypoint. No shell, environment configuration,
//! caller-selected executable, or fallback to the legacy host data plane.
use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

fn device(directory: &File, name: &str, expected: Option<(u32, u32)>) -> Result<(), String> {
    let name = CString::new(name).map_err(|_| "invalid fixed device name")?;
    let mut observed: libc::stat = unsafe { std::mem::zeroed() };
    let mut result = unsafe {
        libc::fstatat(directory.as_raw_fd(), name.as_ptr(), &mut observed, libc::AT_SYMLINK_NOFOLLOW)
    };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        if let Some((major, minor)) = expected {
            let created = unsafe {
                libc::mknodat(directory.as_raw_fd(), name.as_ptr(),
                    libc::S_IFCHR | 0o600, libc::makedev(major, minor))
            };
            if created != 0 {
                return Err("native enclave loop-control creation failed".into());
            }
            result = unsafe {
                libc::fstatat(directory.as_raw_fd(), name.as_ptr(), &mut observed, libc::AT_SYMLINK_NOFOLLOW)
            };
        }
    }
    if result != 0 || observed.st_mode & libc::S_IFMT != libc::S_IFCHR
        || observed.st_uid != 0 || observed.st_nlink != 1 || libc::major(observed.st_rdev) != 10
        || expected.is_some_and(|(major, minor)| observed.st_rdev != libc::makedev(major, minor)
            || observed.st_gid != 0 || observed.st_mode & 0o7777 != 0o600)
    {
        return Err("native enclave device identity or protection differs".into());
    }
    Ok(())
}

fn main() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err("native enclave startup requires its fixed initial privilege".into());
    }
    // Only startup artifact locations/pins and the optional public-identity
    // output flag may follow. The gate's real CLI validates this exact list and
    // acquires protected originals. Selectors are fixed cold profiles, never
    // inferred from a returned configuration or an incoming request.
    let mut arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mode = match arguments.first().and_then(|v| v.to_str()) {
        Some("--measured-refresh-v7") => { arguments.remove(0); "--native-measured-refresh-startup" },
        Some("--guest-inspector-v8") => { arguments.remove(0); "--native-startup-inspector-v8" },
        Some("--measured-issuance-v9") => { arguments.remove(0); "--native-measured-issuance-startup-v9" },
        Some("--guest-cohort-v10") => { arguments.remove(0); "--native-guest-cohort-startup-v10" },
        _ => "--native-encrypted-startup",
    };
    if arguments.is_empty() || arguments.len() > 9 {
        return Err("native enclave startup requires configuration and launch artifacts with independent pins".into());
    }
    let fd = unsafe {
        libc::open(b"/dev\0".as_ptr().cast(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 { return Err("native enclave device directory unavailable".into()); }
    let directory = unsafe { File::from_raw_fd(fd) };
    // This local device check is only an early refusal, never attestation.
    // The genuine NSM owner and independently authorized release/KMS bindings
    // still decide whether startup can acquire authority and secret material.
    device(&directory, "nsm", None)?;
    device(&directory, "loop-control", Some((10, 237)))?;
    drop(directory);
    let error = Command::new("/usr/local/bin/serverware-decision-gate")
        .arg(mode)
        .args(arguments)
        .env_clear()
        .exec();
    Err(format!("native enclave gate exec failed: {error}"))
}
