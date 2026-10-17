#[cfg(target_os = "linux")]
#[path = "../policy_shadow.rs"]
mod policy_shadow;

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) =
        policy_shadow::run_policy_shadow_custody_server_from_env()
    {
        eprintln!("policy-shadow custody failed closed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "policy-shadow custody requires Linux SOCK_SEQPACKET, pidfd, memfd seals, and cgroup v2"
    );
    std::process::exit(1);
}
