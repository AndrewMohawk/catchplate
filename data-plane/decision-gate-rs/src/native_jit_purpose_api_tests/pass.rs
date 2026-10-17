use catchplate_decision_gate::{CustodyRuntime, ProtocolError};
use catchplate_decision_gate::enclave_runtime_identity_v1::EnclaveRuntimeIdentityV1;
use catchplate_decision_gate::native_jit_review_v1::{Configuration, Owner, SignedReleasePair};
use catchplate_decision_gate::native_secret_broker_v1::Owner as BrokerOwner;

const _: fn(&CustodyRuntime, Configuration, &[u8], &mut BrokerOwner,
    &mut EnclaveRuntimeIdentityV1, &str, u64) -> Result<Owner, ProtocolError>
    = CustodyRuntime::configure_native_jit_review;
const _: fn(&CustodyRuntime, &mut Owner, &mut BrokerOwner, &mut EnclaveRuntimeIdentityV1,
    &[u8], &[u8], &[u8], &str, u64) -> Result<SignedReleasePair, ProtocolError>
    = CustodyRuntime::prepare_native_release_jit_review;
const _: fn(&SignedReleasePair) -> &str = SignedReleasePair::pair_original;
const _: fn(&SignedReleasePair) -> &str = SignedReleasePair::proof_original;
