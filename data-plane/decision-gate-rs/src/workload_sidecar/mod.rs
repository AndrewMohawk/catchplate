//! A distinct retained-service profile; legacy bootstrap/admission is unchanged.
mod config;
mod lifetime;
mod local_connect;
mod server;
mod upstream;
#[path = "../native_startup_config/originals.rs"]
mod originals;
#[path = "../native_verifier/json.rs"]
mod json;

use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub(crate) fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && value.as_bytes()[7..].iter().any(|b| *b != b'0')
}
pub(crate) fn sha256_prefixed(value: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(value)) }
fn ensure(value: bool, message: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.to_owned()) }
}

pub(crate) fn run() -> Result<(), String> {
    // No environment-selected executable, policy, key, namespace or defaults.
    let mut args = std::env::args_os().skip(1);
    let mut path = None;
    let mut pin = None;
    while let Some(name) = args.next() {
        let value = args.next().ok_or("sidecar requires explicit flag/value pairs")?;
        match name.to_str() {
            Some("--configuration") if path.is_none() => path = Some(PathBuf::from(value)),
            Some("--configuration-sha256") if pin.is_none() => {
                pin = Some(value.into_string().map_err(|_| "sidecar pin is not ASCII")?);
            }
            _ => return Err("sidecar arguments are unsupported or repeated".to_owned()),
        }
    }
    let service = config::Service::open(
        path.ok_or("sidecar configuration is required")?,
        pin.ok_or("sidecar independent configuration pin is required")?)?;
    server::run(service)
}
