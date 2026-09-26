//! Explicit fixed-endpoint parent ingress; opaque bytes, not TLS termination.
//!
//! Configuration pins require independent operator admission. Retained file
//! checks neither make host storage immutable nor authenticate a workload.
//! There are no secrets, environment defaults, HTTP/PROXY headers, wire-selected
//! endpoints or original-client-IP claims in this entrypoint.

mod config;
#[path = "../native_parent_relay_cli/signals.rs"]
mod signals;
#[path = "../native_verifier/json.rs"]
mod json;
#[path = "../native_startup_config/originals.rs"]
mod originals;

use config::{ConfigurationV1, MAX_CONFIGURATION_BYTES};
use originals::{ArtifactV1, HeldOriginal};
use serverware_decision_gate::enclave_parent_ingress_v1::serve_parent_ingress_v1;
use std::net::TcpListener;
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
    // Exactly two explicit pairs; neither endpoint can be supplied separately
    // from the pinned configuration or selected from connection input.
    for _ in 0..2 {
        let flag = arguments.next().ok_or("parent ingress requires both pinned configuration flags")?;
        let value = arguments.next().ok_or("parent ingress configuration flag lacks its value")?;
        match flag.to_str() {
            Some("--configuration") if path.is_none() => {
                ensure(value.len() <= 4096, "parent ingress configuration path exceeds its bound")?;
                let candidate = PathBuf::from(value);
                ensure(candidate.is_absolute(), "parent ingress configuration path must be absolute")?;
                path = Some(candidate);
            }
            Some("--configuration-sha256") if digest.is_none() => {
                let value = value.into_string()
                    .map_err(|_| "parent ingress configuration digest is not UTF-8")?;
                ensure(super::is_sha256_digest(&value), "parent ingress configuration digest is invalid")?;
                digest = Some(value);
            }
            _ => return Err("parent ingress configuration flag is unknown or repeated".to_owned()),
        }
    }
    ensure(arguments.next().is_none(), "parent ingress has unexpected arguments")?;
    Ok(ArtifactV1 {
        path: path.ok_or("parent ingress configuration path is missing")?,
        sha256: digest.ok_or("parent ingress configuration pin is missing")?,
    })
}

fn check_running(config: &ConfigurationV1, cancelled: &AtomicBool) -> Result<(), String> {
    config.check_live()?;
    ensure(!cancelled.load(Ordering::Acquire), "parent ingress cancellation requested")
}

pub(super) fn run() -> Result<(), String> {
    let artifact = arguments()?;
    let (mut original, bytes) = HeldOriginal::read(artifact, MAX_CONFIGURATION_BYTES)
        .map_err(|_| "parent ingress configuration original failed pinned acquisition")?;
    let config = ConfigurationV1::parse_original(&bytes)?;
    drop(bytes);

    let cancel = Arc::new(AtomicBool::new(false));
    // Reuse the same-thread signal owner before any serving workers start.
    // It remains live until joined serving or unwinding has completed.
    let _signals = signals::CancellationSignals::install(Arc::clone(&cancel))
        .map_err(|_| "parent ingress cancellation registration failed")?;
    original.recheck()
        .map_err(|_| "parent ingress configuration changed before listener bind")?;
    check_running(&config, &cancel)?;
    // SocketAddr is already a checked literal, so bind performs no DNS lookup.
    let listener = TcpListener::bind(config.listen_address)
        .map_err(|_| "parent ingress fixed listener could not be bound")?;
    check_running(&config, &cancel)?;
    original.recheck()
        .map_err(|_| "parent ingress configuration changed before serving")?;
    check_running(&config, &cancel)?;

    // Keep the pinned original and signal registration throughout serving.
    // No filesystem operation is added to shutdown and no completion receipt
    // is issued. Cancellation/expiry remain errors; no hard watchdog is claimed.
    serve_parent_ingress_v1(listener, config.listen_address,
        config.enclave_cid, config.enclave_port, config.workers,
        config.queue_capacity, config.deadline_boottime_ns, cancel)
        .map_err(|_| "parent ingress serving stopped or failed".to_owned())
}
