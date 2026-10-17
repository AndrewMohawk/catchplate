use catchplate_decision_gate::native_jit_review_v1::SignedReleasePair;
pub fn construct(pair_original: String, proof_original: String) -> SignedReleasePair {
    SignedReleasePair { pair_original, proof_original }
}
