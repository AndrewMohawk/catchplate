use serverware_decision_gate::native_jit_review_v1::Owner;
fn requires_clone<T: Clone>() {}
pub fn duplicate() { requires_clone::<Owner>(); }
