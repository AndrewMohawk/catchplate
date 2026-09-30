//! Fixed five-child proof cohort. No FD guessing or readiness projection.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_shadow_proof_cohort()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1)}
