use serverware_decision_gate::{CustodyRuntime, ProtocolError};
use serverware_decision_gate::enclave_runtime_identity_v1::EnclaveRuntimeIdentityV1;
use serverware_decision_gate::native_jit_review_open_v1::{Configuration, Owner};
use serverware_decision_gate::native_jit_review_browser_v1::Accepted;
use serverware_decision_gate::native_secret_broker_v1::Owner as BrokerOwner;
const _: fn(&CustodyRuntime, Configuration, &[u8], &mut BrokerOwner,
    &mut EnclaveRuntimeIdentityV1, &str, u64) -> Result<Owner, ProtocolError>
    = CustodyRuntime::configure_native_jit_review_open;
const _: fn(&CustodyRuntime, &mut Owner, &mut BrokerOwner, &mut EnclaveRuntimeIdentityV1,
    &mut Accepted, &str) -> Result<(), ProtocolError> = CustodyRuntime::handle_native_jit_review_open;
fn main() {}
