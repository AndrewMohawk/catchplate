use serverware_decision_gate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use serverware_decision_gate::native_oauth_exchange_v1::BrowserTls;
use serverware_decision_gate::native_static_credential_browser_v1 as creation;
use serverware_decision_gate::native_static_credential_rotation_browser_v1 as rotation;
use std::sync::Arc;
fn signatures() {
    let _: fn(VsockStreamV1, Arc<BrowserTls>, u64) -> Result<creation::Accepted, String> = creation::Accepted::accept;
    let _: fn(VsockStreamV1, Arc<BrowserTls>, u64) -> Result<rotation::Accepted, String> = rotation::Accepted::accept;
    let _: fn(&creation::Accepted) -> Result<VsockShutdownV1, String> = creation::Accepted::shutdown_handle;
    let _: fn(&rotation::Accepted) -> Result<VsockShutdownV1, String> = rotation::Accepted::shutdown_handle;
    let _: fn(&mut creation::Accepted, &str, &[u8], Option<&str>, &str) -> Result<(), String> = creation::Accepted::respond;
    let _: fn(&mut rotation::Accepted, &str, &[u8], Option<&str>, &str) -> Result<(), String> = rotation::Accepted::respond;
}
fn main() {}
