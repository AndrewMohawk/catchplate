//! Fixed root parent for native key admission, not the trusted-host server.
#[cfg(target_os="linux")]
#[path="../policy_shadow.rs"]
mod policy_shadow;
#[cfg(target_os="linux")]
fn main(){
    if std::env::args_os().len()==2 && std::env::args_os().nth(1).as_deref()==Some(std::ffi::OsStr::new("--driver-bootstrap")) {
        policy_shadow::run_native_shadow_driver_bootstrap_parent()
    }
    if std::env::args_os().len()==2 && std::env::args_os().nth(1).as_deref()==Some(std::ffi::OsStr::new("--activation-receiver")) {
        policy_shadow::run_native_shadow_guest_supervisor()
    }
    policy_shadow::run_native_shadow_guest_supervisor()
}
#[cfg(not(target_os="linux"))]
fn main(){std::process::exit(1);}
