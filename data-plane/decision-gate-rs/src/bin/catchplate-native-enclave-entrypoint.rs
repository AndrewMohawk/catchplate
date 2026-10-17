//! Fixed production image entrypoint. No shell, environment configuration,
//! caller-selected executable, or fallback to the legacy host data plane.
use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
#[path = "../native_preboot_delivery/mod.rs"]
mod native_preboot_delivery;

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
    // output flags may follow. The gate's real CLI validates this exact list and
    // acquires protected originals. Selectors are fixed cold profiles, never
    // inferred from a returned configuration or an incoming request.
    let mut arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let receive_configuration = arguments.first().is_some_and(|arg| arg == "--receive-configuration-v1");
    let receive_rotation = arguments.first().is_some_and(|arg| arg == "--receive-rotation-configuration-v2");
    let activation_receiver = arguments.first().is_some_and(|arg| arg == "--activation-receiver-v1");
    if (receive_configuration || receive_rotation || activation_receiver) && arguments.len() != 1 {
        return Err("native configuration delivery accepts no caller-selected paths, commands or overrides".into());
    }
    let mode = match arguments.first().and_then(|v| v.to_str()) {
        Some("--receive-configuration-v1") => { arguments.clear(); "--native-postboot-static-startup-v24" },
        Some("--receive-rotation-configuration-v2") => { arguments.clear(); "--native-static-credential-rotation-startup-v25" },
        Some("--measured-refresh-v7") => { arguments.remove(0); "--native-measured-refresh-startup" },
        Some("--guest-inspector-v8") => { arguments.remove(0); "--native-startup-inspector-v8" },
        Some("--measured-issuance-v9") => { arguments.remove(0); "--native-measured-issuance-startup-v9" },
        Some("--guest-cohort-v10") => { arguments.remove(0); "--native-guest-cohort-startup-v10" },
        Some("--measured-cleanup-v11") => { arguments.remove(0); "--native-measured-cleanup-startup-v11" },
        Some("--guest-role-keys-v12") => { arguments.remove(0); "--native-guest-role-keys-startup-v12" },
        Some("--measured-pending-retirement-v13") => { arguments.remove(0); "--native-measured-pending-retirement-startup-v13" },
        Some("--gate-cgroup-v14") => { arguments.remove(0); "--native-gate-cgroup-startup-v14" },
        Some("--measured-setup-v15") => { arguments.remove(0); "--native-measured-setup-startup-v15" },
        Some("--measured-capture-retirement-v16") => { arguments.remove(0); "--native-measured-capture-retirement-startup-v16" },
        Some("--measured-reconnect-v17") => { arguments.remove(0); "--native-measured-reconnect-startup-v17" },
        Some("--measured-succession-v18") => { arguments.remove(0); "--native-measured-succession-startup-v18" },
        Some("--measured-canary-delivery-v19") => { arguments.remove(0); "--native-measured-canary-delivery-startup-v19" },
        Some("--canary-heartbeat-v20") => { arguments.remove(0); "--native-canary-heartbeat-startup-v20" },
        Some("--canary-readiness-v21") => { arguments.remove(0); "--native-canary-readiness-startup-v21" },
        Some("--workload-trust-v22") => { arguments.remove(0); "--native-workload-trust-startup-v22" },
        Some("--static-credential-v23") => { arguments.remove(0); "--native-static-credential-startup-v23" },
        Some("--postboot-static-v24") => { arguments.remove(0); "--native-postboot-static-startup-v24" },
        Some("--static-credential-rotation-v25") => { arguments.remove(0); "--native-static-credential-rotation-startup-v25" },
        _ => "--native-encrypted-startup",
    };
    // v22 adds the separately pinned trust original (two flag/value pairs).
    // The new explicit role-4 export adds exactly one slot. Without that flag,
    // retain the previous ceilings and unchanged role-3 output contract.
    let maximum_arguments = (if mode == "--native-workload-trust-startup-v22" { 13 } else { 9 })
        + usize::from(arguments.iter().any(|arg| arg == "--response-proof-identity-stdout"
            || arg == "--response-proof-identity-vsock"));
    if !receive_configuration && !receive_rotation && !activation_receiver && (arguments.is_empty() || arguments.len() > maximum_arguments) {
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
    if activation_receiver {
        return catchplate_decision_gate::native_activation_receiver_bootstrap::run();
    }
    let mut delivery = if receive_configuration { Some(native_preboot_delivery::receive()?) }
        else if receive_rotation { Some(native_preboot_delivery::receive_rotation()?) } else { None };
    if let Some(owner) = &mut delivery {
        arguments = owner.arguments();
        owner.recheck()?;
    }
    let error = Command::new("/usr/local/bin/catchplate-decision-gate")
        .arg(mode)
        .args(arguments)
        .env_clear()
        .exec();
    Err(format!("native enclave gate exec failed: {error}"))
}
