#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--guest-c9-commitment")=>policy_shadow::run_commitment_custody_guest("durable-recovery-store",false),
        Some("--guest-c9-commitment-inspected")=>policy_shadow::run_commitment_custody_guest("durable-recovery-store",true),
        _=>{},
    }
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation-inspected") {
        policy_shadow::run_inspected_ordinary_custody_guest("durable-recovery-store");
    }
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
