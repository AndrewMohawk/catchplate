//! Fixed public-data relay; unsigned routing input is never native authority.
#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use std::{fs::OpenOptions, os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt}, path::{Component, PathBuf}};
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 || arguments[0] != "--configuration" {
        return Err("activation relay requires one configuration file".into());
    }
    let path = PathBuf::from(&arguments[1]);
    if !path.is_absolute() || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_))) {
        return Err("activation relay configuration path differs".into());
    }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path).map_err(|_| "activation relay configuration unavailable")?;
    let metadata = file.metadata().map_err(|_| "activation relay configuration metadata")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 4096 {
        return Err("activation relay configuration bound differs".into());
    }
    let fingerprint = |m: &std::fs::Metadata| (m.dev(), m.ino(), m.mode(), m.uid(), m.gid(),
        m.nlink(), m.len(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec());
    let mut bytes = vec![0; metadata.len() as usize];
    file.read_exact_at(&mut bytes, 0).map_err(|_| "activation relay configuration unreadable")?;
    let mut readback = vec![0; bytes.len()];
    file.read_exact_at(&mut readback, 0).map_err(|_| "activation relay configuration readback failed")?;
    let after = file.metadata().map_err(|_| "activation relay configuration metadata changed")?;
    if fingerprint(&metadata) != fingerprint(&after) || readback != bytes {
        return Err("activation relay configuration changed".into());
    }
    // A stable read of unsigned routing data is not a native authority or a
    // promise that the caller's host storage remains immutable after parsing.
    serverware_decision_gate::native_activation_relay::run(&bytes)
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(target_os = "linux")]
    if matches!(std::panic::catch_unwind(run), Ok(Ok(()))) { return; }
    eprintln!("native activation relay stopped; no retry or native readiness asserted");
    std::process::exit(1);
}
