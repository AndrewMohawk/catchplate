use serverware_decision_gate::native_secret_broker_v1::{validate_release_jit_review_originals, Owner};
fn forbidden(runtime: &[u8], parent: &[u8], child: &[u8]) -> Result<Owner, String> {
    validate_release_jit_review_originals(runtime, parent, child)
}
