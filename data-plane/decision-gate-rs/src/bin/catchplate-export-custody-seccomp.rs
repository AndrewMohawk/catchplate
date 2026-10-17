//! Offline operator tool; never a mode of the measured custody guest.

#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = policy_shadow::seccomp_export::run() {
        eprintln!("custody seccomp export failed: {error}; any new partial output is retained");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("custody seccomp export requires Linux");
    std::process::exit(1);
}
