//! Fixed private child. No CLI, environment, PID/path request or stdout protocol.
#[cfg(target_os = "linux")]
fn main() {
    let ok = std::env::args_os().count() == 1
        && std::env::vars_os().next().is_none()
        && serverware_decision_gate::run_guest_inspector().is_ok();
    // Failure is channel closure and nonzero exit, never a successful verdict
    // or disclosure of an original path/frame in an error log.
    unsafe { libc::_exit(if ok { 0 } else { 1 }) }
}
#[cfg(not(target_os = "linux"))]
fn main() { std::process::exit(1); }
