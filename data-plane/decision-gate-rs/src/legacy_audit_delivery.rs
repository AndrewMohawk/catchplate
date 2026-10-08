//! In-process retry ownership for the non-production bearer audit protocol.
//!
//! Once a batch may have reached the receiver, its exact body and event IDs
//! stay here until a matching authenticated acknowledgement arrives. New queue
//! entries cannot merge with it. This is not a durable crash-recovery journal
//! and is never a substitute for the measured native prepare/commit owner.
use super::{
    discard_unsendable_queued_audit_event, post_serialized_legacy_audit_batch,
    release_audit_batch_reservations, requeue_audit_batch, AuditEvent, AuditPostError,
    AuditPostFailure, GateState, MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES,
};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

struct PreparedBatch {
    body: Zeroizing<Vec<u8>>,
    events: Vec<AuditEvent>,
    outcome_uncertain: bool,
}

#[derive(Default)]
pub(super) struct PendingDelivery {
    batches: VecDeque<PreparedBatch>,
}

fn serialized_body(events: &[AuditEvent]) -> Result<Zeroizing<Vec<u8>>, AuditPostError> {
    if events.is_empty() || events.len() > 200 {
        return Err(AuditPostError::not_sent(
            "legacy audit pending event count is outside its bound",
        ));
    }
    let body = Zeroizing::new(
        serde_json::to_vec(&json!({"events": events}))
            .map_err(|_| AuditPostError::not_sent("serialize immutable legacy audit batch"))?,
    );
    if body.len() > MAX_CONTROL_PLANE_AUDIT_BATCH_BODY_BYTES {
        return Err(AuditPostError::local_too_large(
            "immutable legacy audit batch exceeds wire bound",
        ));
    }
    Ok(body)
}

impl PendingDelivery {
    fn publish_counts(&self, state: &GateState) {
        state.audit_pending_events.store(
            self.batches
                .iter()
                .map(|batch| batch.events.len() as u64)
                .sum(),
            Ordering::Relaxed,
        );
        state
            .audit_pending_batches
            .store(self.batches.len() as u64, Ordering::Relaxed);
    }

    fn advance(&mut self, state: &GateState) -> Result<(), AuditPostError> {
        while let Some(batch) = self.batches.front() {
            let count = batch.events.len() as u64;
            match post_serialized_legacy_audit_batch(state, &batch.body, batch.events.len()) {
                Ok(()) => {
                    let finished = self
                        .batches
                        .pop_front()
                        .expect("pending legacy audit batch");
                    release_audit_batch_reservations(state, &finished.events);
                    state.audit_sent.fetch_add(count, Ordering::Relaxed);
                    self.publish_counts(state);
                }
                Err(error) if error.request_too_large() && !batch.outcome_uncertain => {
                    state.audit_send_failed.fetch_add(count, Ordering::Relaxed);
                    if batch.events.len() == 1 {
                        let rejected = self
                            .batches
                            .pop_front()
                            .expect("rejected legacy audit batch");
                        release_audit_batch_reservations(state, &rejected.events);
                        discard_unsendable_queued_audit_event(state, &rejected.events[0]);
                        self.publish_counts(state);
                        eprintln!("discarding unsendable audit event");
                        continue;
                    }
                    // Only a definitely rejected original may be split. Prepare
                    // both children before replacing it, preserving their order
                    // and every reservation if preparation itself fails.
                    let middle = batch.events.len() / 2;
                    let earlier_body = serialized_body(&batch.events[..middle])?;
                    let later_body = serialized_body(&batch.events[middle..])?;
                    let mut earlier = self
                        .batches
                        .pop_front()
                        .expect("splittable legacy audit batch")
                        .events;
                    let later = earlier.split_off(middle);
                    self.batches.push_front(PreparedBatch {
                        body: later_body,
                        events: later,
                        outcome_uncertain: false,
                    });
                    self.batches.push_front(PreparedBatch {
                        body: earlier_body,
                        events: earlier,
                        outcome_uncertain: false,
                    });
                    self.publish_counts(state);
                }
                Err(error) => {
                    state.audit_send_failed.fetch_add(count, Ordering::Relaxed);
                    // A local refusal says nothing about an earlier attempt.
                    // Uncertainty is monotonic until the exact batch is ACKed;
                    // a later signed 413 cannot undo a possibly committed POST.
                    self.batches
                        .front_mut()
                        .expect("uncertain legacy audit batch")
                        .outcome_uncertain |= error.kind == AuditPostFailure::OutcomeUnknown;
                    self.publish_counts(state);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

pub(super) fn retry(state: &GateState) -> Result<(), AuditPostError> {
    if state.measured_audit.is_some() || state.is_production {
        return Err(AuditPostError::not_sent(
            "legacy audit retry cannot own a measured or production batch",
        ));
    }
    let mut pending = state
        .legacy_audit_pending
        .lock()
        .map_err(|_| AuditPostError::not_sent("legacy audit pending mutex poisoned"))?;
    pending.advance(state)
}

pub(super) fn flush(state: &GateState, batch: Vec<AuditEvent>) -> Result<(), AuditPostError> {
    if state.measured_audit.is_some() || state.is_production {
        requeue_audit_batch(state, batch);
        return Err(AuditPostError::not_sent(
            "legacy audit delivery cannot own a measured or production batch",
        ));
    }
    let mut pending = match state.legacy_audit_pending.lock() {
        Ok(pending) => pending,
        Err(_) => {
            requeue_audit_batch(state, batch);
            return Err(AuditPostError::not_sent(
                "legacy audit pending mutex poisoned",
            ));
        }
    };
    if !pending.batches.is_empty() {
        // This incoming batch has NOT been attempted. A duplicate worker may
        // return its queue slots, but never replace the unresolved original.
        requeue_audit_batch(state, batch);
        return Err(AuditPostError::not_sent(
            "legacy audit original remains unresolved",
        ));
    }
    let body = match serialized_body(&batch) {
        Ok(body) => body,
        Err(error) => {
            requeue_audit_batch(state, batch);
            return Err(error);
        }
    };
    pending.batches.push_back(PreparedBatch {
        body,
        events: batch,
        outcome_uncertain: false,
    });
    pending.publish_counts(state);
    pending.advance(state)
}

#[cfg(test)]
#[path = "legacy_audit_delivery_tests.rs"]
mod tests;
