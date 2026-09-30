#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation") {
        policy_shadow::run_ordinary_custody_guest("recovery-target-provider");
    }
    if let Err(error) =
        policy_shadow::run_recovery_target_provider_from_env()
    {
        eprintln!(
            "policy-custody recovery-target-provider failed closed: {error}"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-custody recovery-target-provider requires Linux"
    );
    std::process::exit(1);
}
