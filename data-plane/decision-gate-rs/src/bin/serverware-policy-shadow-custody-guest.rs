//! Fixed native claimant entry, distinct from the legacy trusted-host service.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main() { policy_shadow::run_native_shadow_guest() }
#[cfg(not(target_os="linux"))]
fn main() { std::process::exit(1); }
