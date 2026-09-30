//! Fixed root parent for native key admission, not the trusted-host server.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_shadow_guest_supervisor()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1);}
