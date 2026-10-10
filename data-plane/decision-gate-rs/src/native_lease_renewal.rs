//! Scoped native renewal using the existing lease classification and refresh gates.
//!
//! Queue ownership includes pending accounting, so cancellation does not leave
//! scopes marked pending. This adds no background release authorization: the
//! existing classifier still excludes controlled dispatch secrets, and refresh
//! receives no request or release authority. In-flight refresh retains its
//! existing transport/singleflight bounds; scoped ownership joins it, rather
//! than claiming that a stop flag can interrupt a blocking operation.

use crate::native_runtime_lifetime::{spawn_task, NativeRuntimeLifetimeV1};
use super::{
    active_credential_lease_background_candidates, current_snapshot, digest_json,
    refresh_scoped_credential_material_singleflight, CredentialLeaseGenerationKey,
    CredentialLeaseRenewalPendingGuard, CredentialLeaseRenewalTask, GateState,
    CREDENTIAL_LEASE_RENEW_BEFORE, CREDENTIAL_LEASE_SINGLEFLIGHT_TIMEOUT,
};
use serde_json::json;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::Scope;
use std::time::{Duration, Instant};

const RECEIVE_TICK: Duration = Duration::from_millis(50);

struct QueuedRenewal {
    task: CredentialLeaseRenewalTask,
    // Constructed before sending, not after receiving. A rejected send or the
    // last receiver's destruction drops this guard for every unconsumed item.
    _pending: CredentialLeaseRenewalPendingGuard,
}

pub(super) fn start<'scope, 'env: 'scope>(
    scope: &'scope Scope<'scope, 'env>,
    state: Arc<GateState>,
    lifetime: Arc<NativeRuntimeLifetimeV1>,
) -> Result<(), String> {
    lifetime.check()?;
    let worker_count = state.credential_lease_renewal_workers;
    let queue_capacity = state.credential_lease_renewal_queue_capacity;
    let interval_ms = state.credential_lease_renewal_poll_interval_ms;
    if !(1..=32).contains(&worker_count)
        || !(1..=65_536).contains(&queue_capacity)
        || !(50..=1_000).contains(&interval_ms)
    {
        lifetime.fail("invalid native credential renewal bounds");
        return Err("native credential renewal bounds are invalid".to_owned());
    }
    let interval = Duration::from_millis(interval_ms);
    let (sender, receiver) = mpsc::sync_channel::<QueuedRenewal>(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let pending = Arc::new(Mutex::new(HashSet::<CredentialLeaseGenerationKey>::new()));

    for worker_index in 0..worker_count {
        let worker_state = Arc::clone(&state);
        let worker_receiver = Arc::clone(&receiver);
        let worker_lifetime = Arc::clone(&lifetime);
        spawn_task(
            scope,
            &lifetime,
            format!("native-credential-renewal-{worker_index}"),
            move || {
                while worker_lifetime.wait(Duration::ZERO)? {
                    let received = worker_receiver.lock()
                        .map_err(|_| "native credential renewal receiver was poisoned")?
                        .recv_timeout(RECEIVE_TICK);
                    let queued = match received {
                        Ok(queued) => queued,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            if worker_lifetime.is_stopped() { return Ok(()); }
                            return Err("native credential renewal queue disconnected".to_owned());
                        }
                    };
                    if !worker_lifetime.wait(Duration::ZERO)? { return Ok(()); }
                    let task = &queued.task;
                    // Preserve legacy transient-failure behavior: no error text
                    // or secret is logged, and the next coordinator pass may retry.
                    // Panic and infrastructure failures reach spawn_task instead.
                    if refresh_scoped_credential_material_singleflight(
                        &worker_state,
                        &task.snapshot,
                        &task.key.scope,
                        task.key.purpose,
                        None,
                    ).is_err() {
                        eprintln!(
                            "credential lease renewal failed scope_sha256={}",
                            digest_json(&json!({
                                "principal_id":task.key.scope.principal_id,
                                "route_id":task.key.scope.route_id,
                                "credential_id":task.key.scope.credential_id,
                            }))
                        );
                    }
                    // queued owns the pending guard through the entire refresh,
                    // including unwinding; this iteration releases it exactly once.
                }
                Ok(())
            },
        )?;
    }
    // No start-stack receiver survives to retain canceled queued tasks. The last
    // scoped worker owns queue destruction once all in-flight refreshes return.
    drop(receiver);
    let coordinator_lifetime = Arc::clone(&lifetime);
    spawn_task(
        scope,
        &lifetime,
        "native-credential-renewal-coordinator".to_owned(),
        move || {
            while coordinator_lifetime.wait(Duration::ZERO)? {
                let snapshot = current_snapshot(&state);
                for candidate in active_credential_lease_background_candidates(
                    &state,
                    &snapshot,
                    CREDENTIAL_LEASE_RENEW_BEFORE,
                ) {
                    if !coordinator_lifetime.wait(Duration::ZERO)? { return Ok(()); }
                    if state.credential_lease_url.is_none() { continue; }
                    let key = CredentialLeaseGenerationKey::new(
                        &snapshot, &candidate.scope, candidate.purpose, None,
                    );
                    // Prepare owned guard fields before registering/counting;
                    // no fallible clone remains between accounting and ownership.
                    let guard_key = key.clone();
                    let pending_key = key.clone();
                    let guard_pending = Arc::clone(&pending);
                    let guard_state = Arc::clone(&state);
                    let inserted = pending.lock()
                        .map_err(|_| "native credential renewal pending set was poisoned")?
                        .insert(pending_key);
                    if !inserted { continue; }
                    state.credential_lease_renewal_queued.fetch_add(1, Ordering::Relaxed);
                    let guard = CredentialLeaseRenewalPendingGuard {
                        pending: guard_pending, state: guard_state, key: guard_key,
                    };
                    let queued = QueuedRenewal {
                        task: CredentialLeaseRenewalTask {
                            snapshot: Arc::clone(&snapshot), key,
                            // Shared task metadata only: the native executor
                            // above retains its existing lifetime/transport path.
                            deadline: Instant::now() + CREDENTIAL_LEASE_SINGLEFLIGHT_TIMEOUT,
                        },
                        _pending: guard,
                    };
                    match sender.try_send(queued) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(queued)) => {
                            drop(queued);
                            state.credential_lease_renewal_queue_full
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::TrySendError::Disconnected(queued)) => {
                            drop(queued);
                            if coordinator_lifetime.is_stopped() { return Ok(()); }
                            return Err("native credential renewal workers disconnected".to_owned());
                        }
                    }
                }
                if !coordinator_lifetime.wait(interval)? { return Ok(()); }
            }
            Ok(())
        },
    )?;
    Ok(())
}
