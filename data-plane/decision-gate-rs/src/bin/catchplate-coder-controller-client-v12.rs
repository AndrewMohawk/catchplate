#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[cfg(target_os = "linux")]
#[path = "../controller_v12.rs"]
mod controller_v12;
#[cfg(target_os = "linux")]
#[path = "../docker_contract.rs"]
mod docker_contract;
#[cfg(target_os = "linux")]
#[path = "../plan_protocol.rs"]
mod plan_protocol;
#[cfg(target_os = "linux")]
#[path = "../readiness.rs"]
mod readiness;
#[cfg(target_os = "linux")]
#[path = "../runtime_evidence.rs"]
mod runtime_evidence;
#[cfg(target_os = "linux")]
#[path = "../source_cas.rs"]
mod source_cas;
#[cfg(target_os = "linux")]
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[cfg(target_os = "linux")]
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;
#[cfg(target_os = "linux")]
#[path = "../controller_runtime_v12.rs"]
mod controller_runtime_v12;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("catchplate-coder-controller-client-v12: Linux is required");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    match controller_runtime_v12::run_client_cli() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("catchplate-coder-controller-client-v12: {error}");
            std::process::exit(1);
        }
    }
}
