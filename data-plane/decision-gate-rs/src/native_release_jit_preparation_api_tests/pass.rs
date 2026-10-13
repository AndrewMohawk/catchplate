use serverware_decision_gate::native_secret_broker_v1::validate_release_jit_review_originals;
const _: fn(&[u8], &[u8], &[u8]) -> Result<(), String> = validate_release_jit_review_originals;
pub fn validate(runtime: &[u8], parent: &[u8], child: &[u8]) -> Result<(), String> {
    validate_release_jit_review_originals(runtime, parent, child)
}
