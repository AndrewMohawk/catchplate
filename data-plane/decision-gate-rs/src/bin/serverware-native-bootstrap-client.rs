//! One fixed native bootstrap evidence exchange, never an installer or proxy.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../native_bootstrap_client/mod.rs"]
mod native_bootstrap_client;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && value.as_bytes()[7..].iter().any(|byte| *byte != b'0')
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if matches!(std::panic::catch_unwind(native_bootstrap_client::run), Ok(Ok(()))) { return; }
    eprintln!("native bootstrap acquisition failed; outcome may be unknown; do not retry automatically");
    std::process::exit(1);
}
