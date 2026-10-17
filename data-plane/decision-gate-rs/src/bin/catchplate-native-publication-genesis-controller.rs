//! Purpose-fixed cold controller: legacy no-args or explicit parked successor.
//! Stdout is the literal public Bundle only, never an installation result.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_publication_genesis_controller()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1);}
