#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() { catchplate_decision_gate::native_shadow_verifier_supervisor_v1::run(); }
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() { std::process::exit(1); }
