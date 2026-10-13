use serverware_decision_gate::native_jit_review_v1::SignedReleasePair;
pub fn mutate(pair: &SignedReleasePair) -> &mut str {
    pair.proof_original()
}
