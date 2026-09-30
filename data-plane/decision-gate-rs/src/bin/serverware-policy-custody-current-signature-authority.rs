#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().nth(1).as_deref()==Some("--guest-c9-generation") {
        policy_shadow::run_ordinary_custody_guest("current-signature-authority");
    }
    if let Err(error) =
        policy_shadow::run_current_signature_authority_from_env()
    {
        eprintln!(
            "policy-custody current-signature-authority failed closed: {error}"
        );
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-custody current-signature-authority requires Linux"
    );
    std::process::exit(1);
}
