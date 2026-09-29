//! Scoped native policy, audit and health work under one nonrenewing lifetime.
//!
//! Reuses the actual operation owners, not detached legacy worker starters.
//! Transient policy/audit/health failures preserve their existing fail-closed
//! retry state. Cancellation is checked around synchronous work; it cannot
//! interrupt a blocked kernel call, mutex or external verifier. The outer
//! lifecycle must join every task and retain its separate hard watchdog.

use super::native_runtime_lifetime::{spawn_task, NativeRuntimeLifetimeV1};
use super::{
    audit_enabled, flush_audit_batch, pop_audit_batch,
    probe_response_observation_v2_once, refresh_policy_snapshot, requeue_audit_batch,
    GateState, RESPONSE_PROOF_CUSTODY_HEALTH_PROBE_INTERVAL,
};
use std::sync::Arc;
use std::thread::Scope;
use std::time::Duration;

pub(super) fn start<'scope, 'env: 'scope>(
    scope: &'scope Scope<'scope, 'env>,
    state: Arc<GateState>,
    lifetime: Arc<NativeRuntimeLifetimeV1>,
    policy_interval: Duration,
    audit_interval: Duration,
) -> Result<(), String> {
    lifetime.check()?;
    if !(Duration::from_millis(50)..=Duration::from_secs(60)).contains(&policy_interval)
        || !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&audit_interval)
    {
        return Err("native background interval is outside its fixed bounds".to_owned());
    }
    let observation = state.response_observation_v2_client.clone()
        .ok_or("native background work requires response-observation v2 custody")?;

    if state.credential_currentness.enabled() {
        let holder_state = Arc::clone(&state);
        let holder_lifetime = Arc::clone(&lifetime);
        spawn_task(scope, &lifetime, "native-credential-currentness".to_owned(), move || {
            while keep_running(&holder_lifetime)? {
                super::credential_currentness::poll_once(&holder_state)?;
                if !holder_lifetime.wait(Duration::from_millis(100))? { return Ok(()); }
            }
            Ok(())
        })?;
    }

    let policy_state = Arc::clone(&state);
    let policy_lifetime = Arc::clone(&lifetime);
    spawn_task(scope, &lifetime, "native-policy-refresh".to_owned(), move || {
        while keep_running(&policy_lifetime)? {
            if refresh_policy_snapshot(&policy_state, false).is_err() {
                // The existing refresh operation records its bounded failure
                // and leaves the last good snapshot; never log returned text.
                eprintln!("native policy refresh failed; retaining last good snapshot");
            }
            if !keep_running(&policy_lifetime)? || !policy_lifetime.wait(policy_interval)? {
                return Ok(());
            }
        }
        Ok(())
    })?;

    if audit_enabled(&state) {
        let audit_state = Arc::clone(&state);
        let audit_lifetime = Arc::clone(&lifetime);
        spawn_task(scope, &lifetime, "native-audit-flush".to_owned(), move || {
            while keep_running(&audit_lifetime)? {
                if audit_state.measured_audit.is_some() && super::native_audit_owner::retry(&audit_state).is_err() {
                    if !audit_lifetime.wait(Duration::from_secs(1))? { return Ok(()); }
                    continue;
                }
                let batch = pop_audit_batch(&audit_state);
                if batch.is_empty() {
                    if !audit_lifetime.wait(audit_interval)? { return Ok(()); }
                    continue;
                }
                // pop reserves required events. Return that exact batch through
                // the existing reservation-aware requeue before stopping.
                match keep_running(&audit_lifetime) {
                    Ok(true) => {}
                    stopped => {
                        requeue_audit_batch(&audit_state, batch);
                        return stopped.map(|_| ());
                    }
                }
                let failed = flush_audit_batch(&audit_state, batch).is_err();
                if !keep_running(&audit_lifetime)? { return Ok(()); }
                if failed {
                    // flush already requeues retryable failures and preserves
                    // the existing oversized-batch splitting/drop accounting.
                    eprintln!("native audit batch send failed");
                    if !audit_lifetime.wait(Duration::from_secs(1))? { return Ok(()); }
                }
            }
            Ok(())
        })?;
    }

    let proof_state = Arc::clone(&state);
    let proof_lifetime = Arc::clone(&lifetime);
    spawn_task(scope, &lifetime, "native-proof-health".to_owned(), move || {
        while keep_running(&proof_lifetime)? {
            proof_state.response_proof_signer.probe_custody_once();
            if !keep_running(&proof_lifetime)?
                || !proof_lifetime.wait(RESPONSE_PROOF_CUSTODY_HEALTH_PROBE_INTERVAL)?
            {
                return Ok(());
            }
        }
        Ok(())
    })?;

    let observation_lifetime = Arc::clone(&lifetime);
    spawn_task(scope, &lifetime, "native-observation-health".to_owned(), move || {
        // Startup's synchronous pinned probe belongs to the outer lifecycle.
        // Preserve the legacy one-second delay before each periodic check.
        while observation_lifetime.wait(Duration::from_secs(1))? {
            let bound = observation_lifetime.remaining()?.min(Duration::from_secs(2));
            probe_response_observation_v2_once(&observation, bound);
            if !keep_running(&observation_lifetime)? { return Ok(()); }
        }
        Ok(())
    })?;
    lifetime.check()
}

fn keep_running(lifetime: &NativeRuntimeLifetimeV1) -> Result<bool, String> {
    if lifetime.is_stopped() { return Ok(false); }
    lifetime.check()?;
    Ok(true)
}
