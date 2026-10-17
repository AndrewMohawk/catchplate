//! Purpose-fixed local CONNECT sidecar. No provider credentials or raw egress.
#[path = "../workload_sidecar/mod.rs"]
mod workload_sidecar;

fn is_sha256_digest(value: &str) -> bool { workload_sidecar::is_sha256_digest(value) }
fn sha256_prefixed(value: &[u8]) -> String { workload_sidecar::sha256_prefixed(value) }

fn main() {
    if workload_sidecar::run().is_err() {
        // Configuration paths, local tokens, certificates and request bytes are
        // never interpolated into a terminal diagnostic.
        eprintln!("workload sidecar stopped or refused admission; no automatic restart or renewal");
        std::process::exit(1);
    }
}
