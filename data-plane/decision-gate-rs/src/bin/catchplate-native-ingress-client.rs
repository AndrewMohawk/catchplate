//! One pinned native-ingress quotation exchange, never a general HTTP client.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../native_ingress_client/mod.rs"]
mod native_ingress_client;

// The reused held-original reader resolves these at the binary root. Digest
// equality is byte integrity, not independent admission of the supplied pin.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        })
        && value.as_bytes()[7..].iter().any(|byte| *byte != b'0')
}

fn main() {
    // Suppress input/key/parser diagnostics. Unwind still drops held originals
    // and the private connection before an unsuccessful process exit.
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if matches!(std::panic::catch_unwind(native_ingress_client::run), Ok(Ok(()))) {
        return;
    }
    eprintln!("native ingress client verification failed");
    std::process::exit(1);
}
