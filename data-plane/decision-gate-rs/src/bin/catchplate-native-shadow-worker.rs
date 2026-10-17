#[cfg(target_os="linux")]
fn main() {
    // Private failures close the owned channel; no synthesized successful
    // verifier output, stderr secret dump, replacement worker or retry.
    if catchplate_decision_gate::native_shadow_workers::run().is_err() {
        std::process::exit(1);
    }
}
#[cfg(not(target_os="linux"))]
fn main() {std::process::exit(1);}
