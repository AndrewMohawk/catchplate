//! Standalone pinned TCP-to-enclave ingress; no TLS identity or default target.

#[cfg(target_os = "linux")]
#[path = "../native_parent_ingress_cli/mod.rs"]
mod native_parent_ingress_cli;

// The shared held-original reader resolves these original-byte helpers at the
// binary root. Matching a digest is not independent configuration admission.
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
    // Static diagnostics only; normal unwind still drops signal/relay owners
    // and joins workers before this catch returns an unsuccessful exit.
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(target_os = "linux")]
    if matches!(std::panic::catch_unwind(native_parent_ingress_cli::run), Ok(Ok(()))) {
        return;
    }
    eprintln!("native parent ingress failed or stopped");
    std::process::exit(1);
}
