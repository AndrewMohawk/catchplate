use catchplate_decision_gate::enclave_runtime_identity_v1::NativeIngressConnectionV1;
fn forbidden(owner: NativeIngressConnectionV1) {
    let _ = owner.into_parts();
}
fn main() {}
