#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation-inspected") {
        policy_shadow::run_inspected_ordinary_custody_guest("bounded-cleanup-helper");
    }
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation") {
        policy_shadow::run_ordinary_custody_guest("bounded-cleanup-helper");
    }
    if let Err(error) =
        policy_shadow::run_bounded_cleanup_helper_from_env()
    {
        eprintln!(
            "policy-custody bounded-cleanup-helper failed closed: {error}"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-custody bounded-cleanup-helper requires Linux"
    );
    std::process::exit(1);
}
