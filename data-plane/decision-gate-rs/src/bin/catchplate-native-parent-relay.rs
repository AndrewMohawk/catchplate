//! Standalone, explicitly pinned parent relay; no default deployment or target.

#[cfg(target_os = "linux")]
#[path = "../native_parent_relay_cli/mod.rs"]
mod native_parent_relay_cli;

// The reused held-original reader resolves these two thin helpers at its bin
// root. They hash original bytes only and do not confer configuration authority.
#[cfg(target_os = "linux")]
fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "linux")]
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        })
}

fn main() {
    // Neither parser errors nor unwinding diagnostics may print configuration
    // originals. Relay/signal owners still unwind and join before this catch.
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(target_os = "linux")]
    if matches!(std::panic::catch_unwind(native_parent_relay_cli::run), Ok(Ok(()))) {
        return;
    }
    eprintln!("native parent relay failed or stopped");
    std::process::exit(1);
}
