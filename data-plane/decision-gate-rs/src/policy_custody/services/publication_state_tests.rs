//! Pure literal-state/snapshot controls only. No grant, history, process owner,
//! durable journal, trusted clock, or independently approved baseline fixture.
use super::*;
use crate::policy_shadow::{PublicationReconciliationReceiptWire as Receipt,
    PublicationReconciliationState, PolicyShadowCustodySignerRole, CanonicalEd25519Signature,
    hash_domain_frames, signature_preimage};
use super::super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use super::super::super::production_dispatch::{ClosedProductionDispatchRequestV4 as Dispatch,
    ProductionDispatchBindingV4 as Binding};
use super::super::super::protocol::PolicyCustodyOperation;
use ed25519_dalek::Signer;

fn digest(label: &str) -> Sha256Digest { Sha256Digest::compute(label.as_bytes()) }
fn receipt(revision: u64) -> String {
    let key = SigningKey::from_bytes(&[37;32]);
    let mut receipt = Receipt {
        state: PublicationReconciliationState::Uninstalled, publication_revision: revision,
        predecessor_generation_sha256: None, committed_generation_sha256: None, published_generation_sha256: None,
        first_ingress_sequence: None, last_ingress_sequence: None, ledger_event_ordinal: 0,
        ledger_head_sha256: digest("synthetic-ledger"), spool_root_sha256: digest("synthetic-spool"),
        prepared_publication_sha256: None, trusted_observed_at_unix_nanos: 100,
        trusted_time_checkpoint_sha256: digest("synthetic-time"), persistence_receipt_sha256: digest("synthetic-persistence-not-evidence"),
        retrieval_id_sha256: digest("synthetic-retrieval-not-evidence"), retrieval_proof_sha256: digest("synthetic-proof-not-evidence"),
        signer_role: PolicyShadowCustodySignerRole::PublicationReconciliation, signing_key_id: digest("synthetic-native-key"),
        signing_key_spki_sha256: verifying_key_spki_sha256(&key.verifying_key()).unwrap(),
        signature: CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode([0u8;64])), signed_receipt_sha256: digest("placeholder"),
    };
    let payload = receipt.canonical_payload().unwrap();
    // This is an intrinsic wire fixture, not the production proof-scope
    // authority signature. State deliberately makes no authentication claim.
    receipt.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(key.sign(&signature_preimage(
        PolicyShadowCustodySignerRole::PublicationReconciliation.signature_domain(), &payload)).to_bytes()));
    receipt.signed_receipt_sha256 = hash_domain_frames(b"catchplate.policyShadowPublicationReconciliationReceipt/v1",
        &[&payload, receipt.signature.0.as_bytes()]);
    receipt.validate_deserialized_invariants().unwrap();
    String::from_utf8(encode_canonical_frame(&receipt).unwrap()).unwrap()
}
fn epoch(key: &SigningKey) -> AuthorityEpochRefV3 {
    AuthorityEpochRefV3 { api_version: "catchplate.policyCustodyAuthorityHistory/v3".into(),
        authority_role: HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore),
        authority_epoch_sequence: 1, authority_epoch_sha256: digest("epoch"), checkpoint_sequence: 1,
        checkpoint_sha256: digest("checkpoint"), checkpoint_authority_key_id: digest("checkpoint-key"),
        checkpoint_authority_key_spki_sha256: digest("checkpoint-spki"), service_signing_key_id: digest("service-key"),
        service_signing_key_spki_sha256: verifying_key_spki_sha256(&key.verifying_key()).unwrap(),
        endpoint_process_identity_sha256: digest("process"), endpoint_generation: 1, service_generation: 1,
        operation_generation: 1, durable_epoch: 1, durable_epoch_head_sha256: digest("durable"),
        deployment_generation_sha256: digest("deployment") }
}
fn snapshot(state: &State) -> (Snapshot, SigningKey) {
    let key = SigningKey::from_bytes(&[53;32]);
    let request = Dispatch::RecoverCurrentState { binding: Binding::from_verified_parent_permit(
        PolicyCustodyOperation::RecoverCurrentState, digest("operation"), digest("request"), digest("durable-request"),
        digest("fence"), digest("configuration"), digest("driver"), digest("descriptors"), digest("generation"), 10, 20, 30).unwrap() };
    let value = Snapshot::sign(request, digest("native-grant"), state.current_receipt_original.clone(),
        state.pending_prepared_original.clone(), epoch(&key), 12, &key).unwrap();
    (value, key)
}

#[test]
fn baseline_is_literal_and_cannot_be_created_from_absence() {
    let raw = receipt(1);
    let state = State::admitted(&raw).unwrap();
    assert_eq!(state.current_receipt_original, raw);
    assert!(state.pending_prepared_original.is_none());
    for bad in ["", "{}", "null", "{\"state\":\"uninstalled\"}"] { assert!(State::admitted(bad).is_err()); }
}

#[test]
fn altered_intrinsic_receipt_is_not_repaired_or_recannonicalized() {
    let raw = receipt(1);
    let mut value: Receipt = decode_canonical_frame(raw.as_bytes()).unwrap();
    value.ledger_head_sha256 = digest("changed-ledger");
    assert!(State::admitted(&String::from_utf8(encode_canonical_frame(&value).unwrap()).unwrap()).is_err());
    assert!(State::admitted(&(raw + "\n")).is_err());
}

#[test]
fn independently_changed_baseline_changes_state_identity() {
    let first = State::admitted(&receipt(1)).unwrap();
    let second = State::admitted(&receipt(2)).unwrap();
    assert_ne!(first.sha256().unwrap(), second.sha256().unwrap());
}

#[test]
fn actual_snapshot_signature_binds_exact_receipt_and_request() {
    let state = State::admitted(&receipt(1)).unwrap();
    let (original, key) = snapshot(&state);
    original.verify_with_key(&epoch(&key), &key.verifying_key()).unwrap();
    state.require_snapshot(&original).unwrap();
    let mut changed = original.clone();
    changed.current_receipt_original = receipt(2);
    changed.state_sha256 = wire::state_sha(&changed.current_receipt_original, &None).unwrap();
    assert!(changed.verify_with_key(&epoch(&key), &key.verifying_key()).is_err());
    assert!(state.require_snapshot(&changed).is_err());
    let mut changed = original;
    changed.native_grant_sha256 = digest("another-native-grant");
    assert!(changed.verify_with_key(&epoch(&key), &key.verifying_key()).is_err());
}

#[test]
fn even_authentic_snapshot_cannot_replace_durable_local_state() {
    let first = State::admitted(&receipt(1)).unwrap();
    let second = State::admitted(&receipt(2)).unwrap();
    let (other, key) = snapshot(&second);
    other.verify_with_key(&epoch(&key), &key.verifying_key()).unwrap();
    assert!(first.require_snapshot(&other).is_err());
}

#[test]
fn snapshot_preserves_original_clock_interval_and_exact_role() {
    let state = State::admitted(&receipt(1)).unwrap();
    let (original, key) = snapshot(&state);
    for sample in [0, 9, 20, 30] {
        let mut changed = original.clone(); changed.observed_at_boottime_nanos = sample;
        assert!(changed.validate().is_err());
    }
    let mut wrong_epoch = epoch(&key);
    wrong_epoch.authority_role = HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::CurrentSignatureAuthority);
    assert!(original.verify_with_key(&wrong_epoch, &key.verifying_key()).is_err());
    let mut changed = original; changed.state_sha256 = digest("changed-state");
    assert!(state.require_snapshot(&changed).is_err());
}
