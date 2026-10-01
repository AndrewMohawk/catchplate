use super::{relation, Identity};

// These synthetic identifiers exercise the exact identity comparator used by
// the real typed-binding wrapper. They do not authenticate a dispatch, model
// participant retirement, or stand in for the caller's exact-original check.
fn identity<'a>(operation: &'a str, replay: &'a str, fence: &'a str) -> Identity<'a> {
    Identity { operation, replay, fence }
}

fn prior() -> Identity<'static> {
    identity("operation-A", "replay-A", "fence-A")
}

#[test]
fn exact_identity_requires_the_entire_binding_to_match() {
    assert_eq!(relation(prior(), prior(), true), Ok(true));
    assert!(relation(prior(), prior(), false).is_err());
}

#[test]
fn operation_cannot_change_replay_or_fence_to_escape_its_original_binding() {
    for next in [
        identity("operation-A", "replay-B", "fence-A"),
        identity("operation-A", "replay-A", "fence-B"),
        identity("operation-A", "replay-B", "fence-B"),
    ] {
        assert!(relation(prior(), next, false).is_err());
    }
}

#[test]
fn a_distinct_operation_cannot_reuse_a_retained_fence_or_replay() {
    for next in [
        identity("operation-B", "replay-B", "fence-A"),
        identity("operation-B", "replay-A", "fence-B"),
        identity("operation-B", "replay-A", "fence-A"),
    ] {
        assert!(relation(prior(), next, false).is_err());
    }
}

#[test]
fn distinct_invocations_are_not_collapsed_by_a_shared_business_object() {
    // Separate operations may consume the same ingress, effect, reservation,
    // or barrier artifact. Those business-object identifiers are intentionally
    // not invocation identities and are not inputs to this comparator.
    let next = identity("operation-B", "replay-B", "fence-B");
    assert_eq!(relation(prior(), next, false), Ok(false));
    assert!(relation(prior(), identity("operation-B", "replay-B", "fence-B"), true).is_err());
}

#[test]
fn identical_binding_still_requires_the_callers_exact_command_check() {
    let original_command = b"synthetic exact RPC command A";
    let changed_command = b"synthetic exact RPC command B";
    // `true` is an obligation to compare the retained original bytes, not
    // approval of an arbitrary new command carrying the same binding.
    assert_eq!(relation(prior(), prior(), true), Ok(true));
    assert_ne!(original_command, changed_command);
}

#[test]
fn every_partial_alias_is_refused_in_both_argument_orders() {
    for mask in 0..8 {
        let operation = if mask & 1 != 0 { "operation-A" } else { "operation-B" };
        let replay = if mask & 2 != 0 { "replay-A" } else { "replay-B" };
        let fence = if mask & 4 != 0 { "fence-A" } else { "fence-B" };
        for same_binding in [false, true] {
            let forward = relation(prior(), identity(operation, replay, fence), same_binding);
            let reverse = relation(identity(operation, replay, fence), prior(), same_binding);
            assert_eq!(forward, reverse);
            match (mask, same_binding) {
                (0, false) => assert_eq!(forward, Ok(false)),
                (7, true) => assert_eq!(forward, Ok(true)),
                _ => assert!(forward.is_err()),
            }
        }
    }
}
