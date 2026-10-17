//! Explicit root-only two-phase retrieval pair; never selected by FD guessing.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_shadow_retrieval_pair()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1)}
