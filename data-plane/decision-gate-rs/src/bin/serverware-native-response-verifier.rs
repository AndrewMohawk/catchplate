//! Fixed offline native-response verifier. The production packaging target
//! supplies the static Linux/amd64 executable; ordinary host builds do not.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../native_verifier/mod.rs"]
mod native_verifier;

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if native_verifier::run().is_ok() {
        return;
    }
    // Errors deliberately reveal no input, parser, certificate or path details.
    // The caller must require complete output and a successful exit, rejecting
    // partial writes/flush failures; it also owns the absolute watchdog.
    eprintln!("native response attestation verification failed");
    std::process::exit(1);
}
