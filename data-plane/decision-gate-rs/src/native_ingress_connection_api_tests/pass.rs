use serverware_decision_gate::enclave_runtime_identity_v1::{NativeIngressConnectionV1, QuotedMutualTlsIngressV1};
use std::sync::Arc;
fn observe(owner: &NativeIngressConnectionV1) { let _ = owner.connection(); let _: &Arc<QuotedMutualTlsIngressV1> = owner.ingress(); }
fn factory(ingress: &Arc<QuotedMutualTlsIngressV1>) -> Result<NativeIngressConnectionV1, String> { ingress.open_connection() }
fn main() {}
