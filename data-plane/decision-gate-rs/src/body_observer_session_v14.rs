//! Persisted initial gated custody, not a running observation session.
//!
//! This composition owns the actual stopped initial history and its protected
//! original store together. Persistence supplies neither execution policy nor
//! terminal/output authority. There are no Ready, resume or running-state APIs.

use super::body_observer_history_acquire_v14::HeldInitialBodyHistoryV14;
use super::body_observer_history_store_v14::HistoryOriginalStoreV14;
use crate::plan_protocol::{Digest, PlanProtocolError, PlanResult};
use std::cell::Cell;
use std::os::fd::OwnedFd;

fn invalid(message: &'static str) -> PlanProtocolError { PlanProtocolError::Invalid(message) }

pub(crate) struct BodyObservationSessionV14 {
    // Rust drops fields in declaration order: actual fail-closed worker custody
    // must run before the retained store closes, including partial acquisition.
    initial: HeldInitialBodyHistoryV14,
    store: Option<HistoryOriginalStoreV14>,
    poisoned: Cell<bool>,
    stored_bytes: u64,
}

impl BodyObservationSessionV14 {
    pub(crate) fn persist_initial(
        initial: HeldInitialBodyHistoryV14,
        directory: OwnedFd,
    ) -> PlanResult<Self> {
        // Move custody first, before any fallible observation or publication.
        // The optional slot is private acquisition state, never a public mode
        // that permits absent persistence or disables gated verification.
        let mut held = Self { initial, store: None, poisoned: Cell::new(true), stored_bytes: 0 };
        let deadline = held.initial.deadline();
        held.store = Some(HistoryOriginalStoreV14::persist_initial(directory, &held.initial, deadline)?);
        held.stored_bytes = held.store()?.stored_bytes();
        // Store publication already brackets its actual writes/readback with
        // gated initial verification. Only join the resulting scalar summary.
        held.verify_summary()?;
        held.poisoned.set(false);
        Ok(held)
    }

    fn store(&self) -> PlanResult<&HistoryOriginalStoreV14> {
        self.store.as_ref().ok_or_else(|| invalid("gated observation session has no retained initial store"))
    }

    fn verify_summary(&self) -> PlanResult<()> {
        let store = self.store()?;
        if self.initial.event_count() != 1 || store.event_count() != 1 || self.stored_bytes == 0
            || store.stored_bytes() != self.stored_bytes
            || store.head_sha256() != self.initial.head_sha256() {
            return Err(invalid("gated observation session store differs from its actual initial history"));
        }
        Ok(())
    }

    fn verify_owned(&self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.initial.deadline());
        // The store owns the gated/store/gated bracket; do not repeat complete
        // maps/backing observations at this composition layer.
        self.store()?.verify(&self.initial, deadline)?;
        self.verify_summary()
    }

    pub(crate) fn verify_gated(&self, deadline: u64) -> PlanResult<()> {
        if self.poisoned.replace(true) {
            return Err(invalid("gated observation session is poisoned or already being verified"));
        }
        // On every error or unwind the poison remains set. A later read cannot
        // rehabilitate this session; explicit abort and scalar inspection remain.
        self.verify_owned(deadline)?;
        self.poisoned.set(false);
        Ok(())
    }

    pub(crate) fn deadline(&self) -> u64 { self.initial.deadline() }

    /// Originally persisted byte count, not a fresh store-admission result.
    pub(crate) fn stored_bytes(&self) -> u64 { self.stored_bytes }

    /// Original initial-history identity, not permission or currentness.
    pub(crate) fn history_head_sha256(&self) -> Digest { self.initial.head_sha256() }

    pub(crate) fn abort(self, deadline: u64) -> PlanResult<()> {
        let deadline = deadline.min(self.initial.deadline());
        // Partial move intentionally aborts/reaps actual custody before other
        // fields drop. Poison never prevents cleanup or creates a fresh window.
        self.initial.abort(deadline)
    }
}
