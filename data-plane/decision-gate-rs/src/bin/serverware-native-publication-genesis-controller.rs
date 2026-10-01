//! Fixed no-argument cold commissioning controller; public Bundle bytes only.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_publication_genesis_controller()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1);}
