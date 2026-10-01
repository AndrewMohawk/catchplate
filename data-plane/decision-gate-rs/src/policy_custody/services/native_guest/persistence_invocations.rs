//! Identity relation for already-authenticated final persistence originals.
//! This reducer supplies no signatures, filesystem durability or remote proof.

pub(crate) const MAX_INVOCATIONS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) operation_id: String,
    pub(crate) termination_fence: String,
    pub(crate) replay_id: String,
    pub(crate) request_original_sha256: String,
    pub(crate) reply_original_sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Index(Vec<Identity>);

impl Index {
    /// Exact replay is observable but must never create a second record.
    pub(crate) fn replay(&self, candidate: &Identity) -> Result<bool, &'static str> {
        for prior in &self.0 {
            if prior.operation_id == candidate.operation_id
                || prior.termination_fence == candidate.termination_fence
                || prior.replay_id == candidate.replay_id
            {
                return if prior == candidate { Ok(true) } else {
                    Err("persistence invocation reuses an operation, fence or replay identity")
                };
            }
        }
        Ok(false)
    }

    /// Used for both committed writes and recovered physical records.
    pub(crate) fn record(&mut self, candidate: Identity) -> Result<(), &'static str> {
        if self.replay(&candidate)? {
            return Err("persistence invocation has duplicate committed originals");
        }
        if self.0.len() >= MAX_INVOCATIONS {
            return Err("persistence invocation capacity exhausted");
        }
        self.0.push(candidate);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Opaque identity commitments only: these controls claim no authentication.
    fn identity(n: usize) -> Identity {
        Identity { operation_id: format!("operation-{n}"), termination_fence: format!("fence-{n}"),
            replay_id: format!("replay-{n}"), request_original_sha256: format!("request-{n}"),
            reply_original_sha256: format!("reply-{n}") }
    }

    #[test]
    fn exact_replay_does_not_add_a_committed_record() {
        let mut index = Index::default(); let first = identity(1);
        index.record(first.clone()).unwrap(); let retained = index.clone();
        assert_eq!(index.replay(&first), Ok(true)); assert_eq!(index, retained);
        assert!(index.record(first).is_err()); assert_eq!(index, retained);
    }

    #[test]
    fn same_operation_cannot_change_fence_or_replay() {
        let mut index = Index::default(); let first = identity(1); index.record(first.clone()).unwrap();
        for change in [0, 1] {
            let mut next = first.clone();
            if change == 0 { next.termination_fence = "other-fence".into(); }
            else { next.replay_id = "other-replay".into(); }
            assert!(index.replay(&next).is_err());
        }
    }

    #[test]
    fn another_operation_cannot_alias_the_fence() {
        let mut index = Index::default(); index.record(identity(1)).unwrap();
        let mut next = identity(2); next.termination_fence = identity(1).termination_fence;
        assert!(index.record(next).is_err()); assert_eq!(index.0.len(), 1);
    }

    #[test]
    fn another_operation_cannot_alias_the_replay_id() {
        let mut index = Index::default(); index.record(identity(1)).unwrap();
        let mut next = identity(2); next.replay_id = identity(1).replay_id;
        assert!(index.record(next).is_err()); assert_eq!(index.0.len(), 1);
    }

    #[test]
    fn final_request_and_reply_originals_are_both_immutable() {
        let mut index = Index::default(); let first = identity(1); index.record(first.clone()).unwrap();
        for change in [0, 1] {
            let mut next = first.clone();
            if change == 0 { next.request_original_sha256 = "other-request".into(); }
            else { next.reply_original_sha256 = "other-reply".into(); }
            assert!(index.replay(&next).is_err());
        }
    }

    #[test]
    fn distinct_invocations_remain_admissible() {
        let mut index = Index::default(); index.record(identity(1)).unwrap();
        assert_eq!(index.replay(&identity(2)), Ok(false)); index.record(identity(2)).unwrap();
        assert_eq!(index.replay(&identity(1)), Ok(true)); assert_eq!(index.replay(&identity(2)), Ok(true));
    }

    #[test]
    fn recovery_and_live_recording_have_the_same_fixed_bound() {
        let mut index = Index::default();
        for n in 0..MAX_INVOCATIONS { index.record(identity(n)).unwrap(); }
        assert!(index.record(identity(MAX_INVOCATIONS)).is_err());
        assert_eq!(index.replay(&identity(0)), Ok(true)); assert_eq!(index.0.len(), MAX_INVOCATIONS);
    }
}
