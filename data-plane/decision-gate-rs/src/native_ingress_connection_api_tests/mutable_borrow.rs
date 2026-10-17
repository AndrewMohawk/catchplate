use catchplate_decision_gate::enclave_runtime_identity_v1::NativeIngressConnectionV1;
fn forbidden(owner: &mut NativeIngressConnectionV1) {
    owner.connection().send_close_notify();
}
fn main() {}
