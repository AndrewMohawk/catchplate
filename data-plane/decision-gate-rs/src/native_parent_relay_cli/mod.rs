//! Explicit one-endpoint parent relay entrypoint; no ambient configuration.
//!
//! Pins are independently supplied by the operator. HeldOriginal's anchored
//! byte/name/identity observations do not admit the configuration or make
//! host storage immutable. This public configuration carries no credentials.
//! Runtime destination and lifetime are fixed values, not live file reloads.

mod config;
mod signals;
#[path = "../native_verifier/json.rs"]
mod json;
#[path = "../native_startup_config/originals.rs"]
mod originals;

use config::{ConfigurationV1, MAX_CONFIGURATION_BYTES};
use originals::{ArtifactV1, HeldOriginal};
use catchplate_decision_gate::enclave_parent_relay_v1::serve_parent_relay_with_cancel_v1;
use catchplate_decision_gate::enclave_vsock_v1::VsockListenerV1;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn arguments() -> Result<ArtifactV1, String> {
    let mut arguments = std::env::args_os().skip(1);
    let mut path = None;
    let mut digest = None;
    // Exactly two pairs: no positional destination, alternate configuration
    // source, command, environment switch or permissive trailing arguments.
    for _ in 0..2 {
        let flag = arguments.next().ok_or("parent relay requires both pinned configuration flags")?;
        let value = arguments.next().ok_or("parent relay configuration flag lacks its value")?;
        match flag.to_str() {
            Some("--configuration") if path.is_none() => {
                ensure(value.len() <= 4096, "parent relay configuration path exceeds its bound")?;
                let candidate = PathBuf::from(value);
                ensure(candidate.is_absolute(), "parent relay configuration path must be absolute")?;
                path = Some(candidate);
            }
            Some("--configuration-sha256") if digest.is_none() => {
                let value = value.into_string()
                    .map_err(|_| "parent relay configuration digest is not UTF-8")?;
                ensure(super::is_sha256_digest(&value), "parent relay configuration digest is invalid")?;
                digest = Some(value);
            }
            _ => return Err("parent relay configuration flag is unknown or repeated".to_owned()),
        }
    }
    ensure(arguments.next().is_none(), "parent relay has unexpected arguments")?;
    Ok(ArtifactV1 {
        path: path.ok_or("parent relay configuration path is missing")?,
        sha256: digest.ok_or("parent relay configuration pin is missing")?,
    })
}

fn check_running(config: &ConfigurationV1, cancelled: &AtomicBool) -> Result<(), String> {
    config.check_live()?;
    ensure(!cancelled.load(Ordering::Acquire), "parent relay cancellation requested")
}

pub(super) fn run() -> Result<(), String> {
    let artifact = arguments()?;
    let (mut original, bytes) = HeldOriginal::read(artifact, MAX_CONFIGURATION_BYTES)
        .map_err(|_| "parent relay configuration original failed pinned acquisition")?;
    let config = ConfigurationV1::parse_original(&bytes)?;
    drop(bytes);

    let cancel = Arc::new(AtomicBool::new(false));
    // Same-thread owner blocks termination signals before relay workers exist,
    // then restores its registration only after the joined relay has returned.
    let _signals = signals::CancellationSignals::install(Arc::clone(&cancel))
        .map_err(|_| "parent relay cancellation registration failed")?;
    original.recheck()
        .map_err(|_| "parent relay configuration changed before listener bind")?;
    check_running(&config, &cancel)?;
    let listener = VsockListenerV1::bind(config.listen_port,
        config.expected_enclave_cid, config.deadline_boottime_ns)
        .map_err(|_| "parent relay fixed listener could not be bound")?;
    check_running(&config, &cancel)?;
    original.recheck()
        .map_err(|_| "parent relay configuration changed before serving")?;
    check_running(&config, &cancel)?;

    // Both owners remain in this frame for the whole joined run. There is no
    // post-serving filesystem read or completion receipt. Cancellation/expiry
    // remain errors, and blocked syscalls still need an outer watchdog.
    serve_parent_relay_with_cancel_v1(listener, config.target,
        config.expected_enclave_cid, config.workers, config.queue_capacity,
        config.deadline_boottime_ns, cancel)
        .map_err(|_| "parent relay serving stopped or failed".to_owned())
}
