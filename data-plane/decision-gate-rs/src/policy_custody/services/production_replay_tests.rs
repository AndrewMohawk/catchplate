use super::State;

// Synthetic bytes exercise the exact reducer used by the production bridge.
// These controls do not authenticate requests/results, perform journal I/O,
// contact an authority, or establish cleanup/worker ownership.
const REQUEST: &[u8] = b"synthetic exact request";
const OTHER: &[u8] = b"different exact request";

fn recovered(maximum_records: usize, maximum_bytes: usize) -> State {
    let mut state = State::new(maximum_records, maximum_bytes, 0);
    assert!(!state.ready());
    state.finish_recovery().unwrap();
    assert!(state.ready());
    state
}

#[test]
fn completion_requires_both_durable_steps_in_order() {
    let mut state = recovered(4, 1_000_000);
    assert_eq!(state.next_sequence().unwrap(), 1);
    assert_eq!(state.begin(REQUEST, 100, 200).unwrap(), 1);
    assert!(!state.ready());
    assert!(state.next_sequence().is_err());
    state.start_persisted().unwrap();
    assert!(!state.ready());
    state.complete(150).unwrap();
    assert!(state.ready());
    assert_eq!(state.next_sequence().unwrap(), 3);
    assert_eq!(state.begin(OTHER, 100, 200).unwrap(), 3);
    state.start_persisted().unwrap();
    state.complete(200).unwrap();
    assert!(state.ready());
    assert_eq!(state.next_sequence().unwrap(), 5);
}

#[test]
fn premature_or_duplicate_durable_readback_permanently_fences() {
    let mut early = recovered(8, 1_000_000);
    early.begin(REQUEST, 100, 200).unwrap();
    assert!(early.complete(100).is_err());
    assert!(early.start_persisted().is_err());
    assert!(early.complete(100).is_err());
    assert!(!early.ready());

    let mut duplicate = recovered(8, 1_000_000);
    duplicate.begin(REQUEST, 100, 200).unwrap();
    duplicate.start_persisted().unwrap();
    assert!(duplicate.start_persisted().is_err());
    assert!(duplicate.complete(100).is_err());
    assert!(!duplicate.ready());
}

#[test]
fn failed_attempt_cannot_be_reopened_or_completed_by_retry() {
    let mut loading = State::new(8, 1_000_000, 0);
    assert!(loading.begin(REQUEST, 100, 200).is_err());
    assert!(loading.finish_recovery().is_err());
    assert!(!loading.ready());

    for durable in [false, true] {
        let mut state = recovered(8, 1_000_000);
        state.begin(REQUEST, 100, 200).unwrap();
        if durable {
            state.start_persisted().unwrap();
        }
        assert!(state.begin(REQUEST, 100, 200).is_err());
        assert!(state.complete(100).is_err());
        assert!(state.start_persisted().is_err());
        assert!(state.begin(OTHER, 100, 200).is_err());
        assert!(!state.ready());
    }
}

#[test]
fn recovery_refuses_orphan_start_and_accepts_exact_complete_pair() {
    let mut orphan = State::new(8, 1_000_000, 0);
    orphan.recover_start(REQUEST, 100).unwrap();
    assert!(orphan.finish_recovery().is_err());
    assert!(orphan.recover_complete(REQUEST, 100).is_err());
    assert!(orphan.begin(REQUEST, 100, 200).is_err());
    assert!(!orphan.ready());

    let mut complete = State::new(8, 1_000_000, 0);
    complete.recover_start(REQUEST, 100).unwrap();
    complete.recover_complete(REQUEST, 150).unwrap();
    complete.finish_recovery().unwrap();
    assert!(complete.ready());
    assert_eq!(complete.begin(OTHER, 100, 200).unwrap(), 3);
}

#[test]
fn recovery_rejects_changed_original_and_overlapping_starts() {
    let mut changed = State::new(8, 1_000_000, 0);
    changed.recover_start(REQUEST, 100).unwrap();
    assert!(changed.recover_complete(OTHER, 100).is_err());
    assert!(changed.recover_complete(REQUEST, 100).is_err());
    assert!(changed.finish_recovery().is_err());

    let mut overlap = State::new(8, 1_000_000, 0);
    overlap.recover_start(REQUEST, 100).unwrap();
    assert!(overlap.recover_start(OTHER, 100).is_err());
    assert!(overlap.recover_complete(REQUEST, 100).is_err());
    assert!(overlap.finish_recovery().is_err());
}

#[test]
fn legacy_completed_prefix_is_preserved_but_cannot_follow_new_starts() {
    let mut legacy = State::new(8, 1_000_000, 0);
    legacy.recover_complete(REQUEST, 100).unwrap();
    legacy.recover_complete(OTHER, 100).unwrap();
    legacy.finish_recovery().unwrap();
    assert!(legacy.ready());
    assert_eq!(legacy.begin(REQUEST, 100, 200).unwrap(), 3);

    let mut mixed = State::new(8, 1_000_000, 0);
    mixed.recover_complete(OTHER, 100).unwrap();
    mixed.recover_start(REQUEST, 100).unwrap();
    mixed.recover_complete(REQUEST, 100).unwrap();
    assert!(mixed.recover_complete(OTHER, 100).is_err());
    assert!(mixed.finish_recovery().is_err());
}

#[test]
fn reservation_counts_two_physical_records_not_one_logical_exchange() {
    let mut one = recovered(1, 1_000_000);
    assert!(one.begin(REQUEST, 100, 200).is_err());
    assert!(!one.ready());

    let mut three = recovered(3, 1_000_000);
    three.begin(REQUEST, 100, 200).unwrap();
    three.start_persisted().unwrap();
    three.complete(100).unwrap();
    assert_eq!(three.next_sequence().unwrap(), 3);
    assert!(three.begin(OTHER, 100, 200).is_err());
    assert!(!three.ready());

    let mut recovered_limit = State::new(1, 1_000_000, 0);
    recovered_limit.recover_start(REQUEST, 100).unwrap();
    assert!(recovered_limit.recover_complete(REQUEST, 100).is_err());
    assert!(recovered_limit.finish_recovery().is_err());
}

#[test]
fn byte_reservation_includes_head_both_originals_and_checked_overflow() {
    // Independently spell out the documented conservative physical budget.
    let limit = 4096 + 3 * (REQUEST.len() + 100) + 4096
        + 3 * (REQUEST.len() + 200) + 4096;
    let mut exact = recovered(2, limit);
    exact.begin(REQUEST, 100, 200).unwrap();
    exact.start_persisted().unwrap();
    exact.complete(200).unwrap();
    assert!(exact.ready());

    let mut short = recovered(2, limit - 1);
    assert!(short.begin(REQUEST, 100, 200).is_err());
    assert!(!short.ready());
    for (start, response) in [(usize::MAX, 200), (100, usize::MAX)] {
        let mut overflow = recovered(2, usize::MAX);
        assert!(overflow.begin(REQUEST, start, response).is_err());
        assert!(!overflow.ready());
    }

    let mut actual = State::new(2, 4103, 0);
    actual.recover_start(REQUEST, 3).unwrap();
    actual.recover_complete(REQUEST, 4).unwrap();
    actual.finish_recovery().unwrap();
    assert!(actual.ready());
    let mut too_small = State::new(2, 4102, 0);
    too_small.recover_start(REQUEST, 3).unwrap();
    assert!(too_small.recover_complete(REQUEST, 4).is_err());
    assert!(too_small.finish_recovery().is_err());
    assert!(State::new(2, 4095, 0).finish_recovery().is_err());
    assert!(State::new(2, 5000, 5001).finish_recovery().is_err());
    assert!(State::new(0, 1_000_000, 0).finish_recovery().is_err());
}
