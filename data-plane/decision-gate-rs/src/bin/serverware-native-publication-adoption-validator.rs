//! Fixed public-input validation only. No signing key or runtime owner exists.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){policy_shadow::run_native_publication_adoption_validator()}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1);}
