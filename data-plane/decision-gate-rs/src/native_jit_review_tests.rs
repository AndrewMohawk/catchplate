//! Real local clock/ordinary-owner refusal; no synthetic native authority.
use super::*;

#[test]
fn request_deadline_is_frozen_conservatively_before_io_and_not_renewed() {
    assert!(freeze_deadline(Instant::now()).is_err());
    let before = native_canary_transport::boottime_ns().unwrap();
    let original = Instant::now() + Duration::from_secs(1);
    let frozen = freeze_deadline(original).unwrap();
    let after = native_canary_transport::boottime_ns().unwrap();
    assert!(before < frozen && frozen <= after + 1_000_000_000);
    let source = include_str!("native_release_jit_preparation.rs");
    let actual = source.split("pub(super) fn prepare_and_submit").nth(1).unwrap();
    assert_eq!(actual.matches("freeze_deadline(").count(), 1);
    assert!(actual.find("freeze_deadline(").unwrap() < actual.find("post_release_authorization_http_on_deadline(").unwrap());
    assert!(actual.contains("retained.request.deadline, original_boottime_deadline"));
}

#[test]
fn ordinary_state_cannot_enter_the_native_custody_owner_path() {
    let state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
    assert!(state.native_jit_review.is_none() && state.native_secret_broker.is_none());
    let original = Instant::now() + Duration::from_secs(1);
    let frozen = freeze_deadline(original).unwrap();
    assert!(prepare(&state, b"{}", b"{}", b"{}", original, frozen).is_err());
    assert!(state.native_jit_review.is_none() && state.native_secret_broker.is_none());
}
