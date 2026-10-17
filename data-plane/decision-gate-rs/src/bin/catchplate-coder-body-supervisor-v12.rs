#[cfg(target_os = "linux")]
#[path = "../plan_protocol.rs"]
mod plan_protocol;
#[cfg(target_os = "linux")]
#[path = "../runtime_evidence.rs"]
mod runtime_evidence;
#[cfg(target_os = "linux")]
#[path = "../body_supervisor_v12.rs"]
mod body_supervisor_v12;

// The inherited streams are payload originals. Neither platform rejection nor
// supervisor failure may add diagnostics or fabricated result/evidence bytes.
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    #[cfg(target_os = "linux")]
    let status = match std::panic::catch_unwind(body_supervisor_v12::run_body_supervisor_v12_cli) {
        Ok(Ok(status)) => status,
        _ => 125,
    };
    #[cfg(not(target_os = "linux"))]
    let status = 125;
    std::process::exit(status);
}
