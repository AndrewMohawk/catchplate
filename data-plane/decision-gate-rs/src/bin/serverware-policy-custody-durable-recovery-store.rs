#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation") {
        policy_shadow::run_ordinary_custody_guest("durable-recovery-store");
    }
    if let Err(error) =
        policy_shadow::run_durable_recovery_store_from_env()
    {
        eprintln!(
            "policy-custody durable-recovery-store failed closed: {error}"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-custody durable-recovery-store requires Linux"
    );
    std::process::exit(1);
}
