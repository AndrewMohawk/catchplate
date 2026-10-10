//! Publication-coordinated background renewal for admitted operator-static
//! scopes. This grants no request, provider, native, or replay authority.
use super::*;

fn refused() -> String {
    "operator background credential renewal unavailable".to_owned()
}

pub(super) fn execute(state: &GateState, task: &CredentialLeaseRenewalTask) -> Result<(), String> {
    if task.key != CredentialLeaseGenerationKey::new(
        &task.snapshot,
        &task.key.scope,
        task.key.purpose,
        None,
    ) {
        return Err(refused());
    }
    if credential_lease_background_renewal_status(
        state,
        &task.snapshot,
        &task.key.scope,
        task.key.purpose,
    ) != CredentialLeaseRenewalStatus::Due {
        return Ok(());
    }
    if !operator_static_preparation::admitted(
        state,
        &task.snapshot,
        &task.key.scope,
        None,
        None,
    )? {
        return refresh_scoped_credential_material_singleflight(
            state,
            &task.snapshot,
            &task.key.scope,
            task.key.purpose,
            None,
        );
    }

    // Queue time is already part of this task's one original budget. Clamp it
    // to the independently admitted finite application identity, never reset it
    // when a worker, singleflight leader, or publication lane is acquired.
    let app_remaining = operator_static_preparation::principal_expiry(
        &task.snapshot,
        &task.key.scope,
    )?
    .checked_sub(now_epoch_ms())
    .and_then(|remaining| u64::try_from(remaining).ok())
    .ok_or_else(refused)?;
    let deadline = task.deadline.min(
        Instant::now()
            .checked_add(Duration::from_millis(app_remaining))
            .ok_or_else(refused)?,
    );
    check_credential_operation_deadline(Some(deadline))?;

    refresh_scoped_credential_material_singleflight_with_leader(
        state,
        &task.snapshot,
        &task.key.scope,
        task.key.purpose,
        None,
        None,
        Some(deadline),
        |original_deadline| {
            if original_deadline != Some(deadline) {
                return Err(refused());
            }
            // Election has finished and its map mutex has been released. A
            // follower never owns this lane or SH while waiting for its leader.
            // No snapshot, cache, receiver, pending, or dispatch lock is held.
            let publication = operator_audit_publication::acquire_credential_on_deadline(
                state,
                deadline,
            )?
            .ok_or_else(refused)?;
            refresh_policy_snapshot_guarded(state, true, Some(&publication))?;
            publication.check()?;

            // Synchronize first, then validate the original task unchanged. A
            // newly published policy is not authority to retarget this task.
            if !snapshot_is_active(state, &task.snapshot)
                || !operator_static_preparation::admitted(
                    state,
                    &task.snapshot,
                    &task.key.scope,
                    None,
                    None,
                )?
            {
                return Err(refused());
            }
            match credential_lease_background_renewal_status(
                state,
                &task.snapshot,
                &task.key.scope,
                task.key.purpose,
            ) {
                CredentialLeaseRenewalStatus::Ineligible => return Err(refused()),
                CredentialLeaseRenewalStatus::Fresh => {}
                CredentialLeaseRenewalStatus::Due => {
                    refresh_scoped_credential_material_on_deadline(
                        state,
                        &task.snapshot,
                        &task.key.scope,
                        task.key.purpose,
                        None,
                        None,
                        Some(deadline),
                    )?;
                }
            }
            // SH spans signed response verification and exact cache insertion.
            // Failure is terminal for this flight; there is no acquisition retry.
            publication.check()
        },
    )
}
