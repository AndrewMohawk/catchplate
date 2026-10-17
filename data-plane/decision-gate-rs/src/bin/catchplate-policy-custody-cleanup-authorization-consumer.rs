#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-effects-inspected") {
        policy_shadow::run_effects_custody_guest("cleanup-authorization-consumer");
    }
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation-inspected") {
        policy_shadow::run_inspected_ordinary_custody_guest("cleanup-authorization-consumer");
    }
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation") {
        policy_shadow::run_ordinary_custody_guest("cleanup-authorization-consumer");
    }
    if let Err(error) =
        policy_shadow::run_cleanup_authorization_consumer_from_env()
    {
        eprintln!(
            "policy-custody cleanup-authorization-consumer failed closed: {error}"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-custody cleanup-authorization-consumer requires Linux"
    );
    std::process::exit(1);
}
