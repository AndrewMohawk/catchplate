#[cfg(target_os="linux")]
fn main() {
    if std::env::args_os().count()!=1 || std::env::vars_os().next().is_some()
        || catchplate_decision_gate::run_guest_role().is_err() {
        std::process::exit(1);
    }
}
#[cfg(not(target_os="linux"))]
fn main() { std::process::exit(1); }
