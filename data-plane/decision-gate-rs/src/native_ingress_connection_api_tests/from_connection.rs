use catchplate_decision_gate::enclave_runtime_identity_v1::NativeIngressConnectionV1;
fn forbidden(owner: &NativeIngressConnectionV1) {
    let _ = NativeIngressConnectionV1::from_connection(owner.connection());
}
fn main() {}
