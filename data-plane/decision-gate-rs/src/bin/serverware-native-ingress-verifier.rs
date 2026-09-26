//! Fixed offline native-ingress verifier. The production packaging target
//! supplies the static Linux/amd64 executable; ordinary host builds do not.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../native_verifier/mod.rs"]
mod native_verifier;

fn main() {
    // No panic or error diagnostics may reveal public-input contents, paths,
    // parser details or certificate material. Unwind still drops held inputs.
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if matches!(std::panic::catch_unwind(native_verifier::run_ingress), Ok(Ok(()))) {
        return;
    }
    // The invoking owner must require the complete result and successful exit,
    // reject partial output/flush failures, and enforce an external watchdog.
    eprintln!("native ingress attestation verification failed");
    std::process::exit(1);
}
