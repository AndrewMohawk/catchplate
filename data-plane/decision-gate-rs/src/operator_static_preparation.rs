//! Freshness preparation before an ordinary operator-static decision is fixed.
//! This is not send authority, a lease extension, or a provider-request retry.
use super::*;
use super::operator_static_preparation_diagnostics::{Attempt, Stage};

fn refused() -> String {
    "operator static credential preparation unavailable".to_owned()
}

/// Shared by selection and the two deadline-carrying acquisition/cache seams.
/// A signed provider label alone never admits this development-only path.
pub(super) fn admitted(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    request_authority: Option<&CredentialLeaseRequestAuthority>,
    release_authorization: Option<&CredentialLeaseReleaseAuthorization>,
) -> Result<bool, String> {
    if !state.policy_shadow.is_operator_demo()
        || state.is_production
        || state.response_proof_signer.release_profile() != ReleaseProfile::Legacy
        || state.proxy_ingress_attestation.mode != operator_demo::INGRESS_MODE
        || state.native_serving_privileges.is_some()
        || state.native_secret_broker.is_some()
        || state.native_policy_bytes.is_some()
        || state.native_runtime_lifetime.is_some()
        || state.native_upstream_relays.is_some()
        || state.native_enrollment_authorizer.is_some()
        || state.measured_refresh.is_some()
        || state.measured_cleanup.is_some()
        || state.measured_pending_retirement.is_some()
        || state.measured_capture_retirement.is_some()
        || state.measured_issuance.is_some()
        || state.measured_setup.is_some()
        || state.measured_static_credential.is_some()
        || state.measured_static_credential_rotation.is_some()
        || state.measured_reconnect.is_some()
        || state.measured_succession.is_some()
        || state.measured_audit.is_some()
        || state.measured_canary_delivery.is_some()
        || state.policy_shadow_generation_control.is_some()
        || state.atomic_release_authorization_enabled
        || state.credential_currentness.enabled()
        || state
            .credential_lease_recipient_attestation_command
            .is_some()
        || request_authority.is_some()
        || release_authorization.is_some()
    {
        return Ok(false);
    }
    let Some(credential) = snapshot.credentials.get(&scope.credential_id) else {
        return Ok(false);
    };
    if credential.kind() != "static" || credential.provider != "operator-demo" {
        return Ok(false);
    }
    validate_credential_lease_scope(snapshot, scope)?;
    let route = snapshot
        .routes
        .iter()
        .find(|route| route.id == scope.route_id)
        .ok_or_else(refused)?;
    if route.response_observation.is_some()
        || credential_scope_requires_release_authorization(state, snapshot, scope)?
    {
        return Ok(false);
    }
    let binding = &route.adapter_config["credentialBinding"];
    if binding["credentialType"].as_str() != Some("static")
        || binding["provider"].as_str() != Some("operator-demo")
        || credential
            .provider_subject
            .as_deref()
            .is_none_or(str::is_empty)
        || !binding["subjects"].as_array().is_some_and(|subjects| {
            subjects.len() == 1 && subjects[0].as_str() == credential.provider_subject.as_deref()
        })
    {
        return Err(refused());
    }
    let permit = state
        .policy_shadow
        .operator_effect_permit(snapshot, &scope.route_id)?
        .ok_or_else(refused)?;
    permit.validate(&snapshot.hash)?;
    operator_audit_publication::require_local_verifier(&state.policy_trust_root_source)?;
    if !snapshot_is_active(state, snapshot) || !policy_trust_is_fresh(state) {
        return Err(refused());
    }
    principal_expiry(snapshot, scope)?;
    Ok(true)
}

pub(super) fn principal_expiry(snapshot: &Snapshot, scope: &CredentialLeaseScope) -> Result<u128, String> {
    snapshot
        .principals
        .iter()
        .find(|principal| principal.id == scope.principal_id)
        .and_then(|principal| match &principal.proxy_authorization {
            Some(ProxyAuthorizationPolicy::BearerToken {
                expires_at_ms: Some(expiry),
                ..
            }) if *expiry > now_epoch_ms() => Some(*expiry),
            _ => None,
        })
        .ok_or_else(refused)
}

fn margin() -> Result<(u128, Instant), String> {
    Ok((
        now_epoch_ms()
            .checked_add(CREDENTIAL_LEASE_RENEW_BEFORE.as_millis())
            .ok_or_else(refused)?,
        Instant::now()
            .checked_add(CREDENTIAL_LEASE_RENEW_BEFORE)
            .ok_or_else(refused)?,
    ))
}

fn generation_with_margin(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
) -> Result<Option<CredentialLeaseGeneration>, String> {
    let generations = state.credential_generations.lock().map_err(|_| refused())?;
    let (epoch, monotonic) = margin()?;
    Ok(generations
        .get(scope)
        .filter(|generation| {
            generation.profile == ReleaseProfile::Legacy
                && credential_generation_valid_after(generation, snapshot, epoch, monotonic)
        })
        .cloned())
}

/// Both caches are examined together, after their locks have been acquired.
/// The pin is the generation selected before dispatch-secret acquisition. A
/// concurrent new static generation is a refusal, never a reconciliation.
fn pair_with_margin(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    pin: &CredentialLeaseGeneration,
) -> Result<Option<CredentialLeaseInfo>, String> {
    let active = state.snapshot.read().map_err(|_| refused())?;
    if active.epoch != snapshot.epoch || !Arc::ptr_eq(&active, snapshot) {
        return Err(refused());
    }
    let leases = state.credential_leases.lock().map_err(|_| refused())?;
    let generations = state.credential_generations.lock().map_err(|_| refused())?;
    let (epoch, monotonic) = margin()?;
    let generation = generations.get(scope).ok_or_else(refused)?;
    if generation.profile != pin.profile
        || generation.version != pin.version
        || generation.metadata_sha256 != pin.metadata_sha256
        || generation.metadata != pin.metadata
    {
        return Err(refused());
    }
    if !credential_generation_valid_after(generation, snapshot, epoch, monotonic) {
        return Err(refused());
    }
    Ok(leases
        .get(&CredentialLeaseCacheKey::new_bound(scope, None, None))
        .filter(|lease| {
            lease.profile == ReleaseProfile::Legacy
                && lease.scope == *scope
                && lease.version == pin.version
                && lease.metadata_sha256 == pin.metadata_sha256
                && lease.metadata == pin.metadata
                && lease.request_authority.is_none()
                && lease.release_authorization.is_none()
                && credential_secret_lease_valid_after(lease, snapshot, epoch, monotonic)
        })
        .map(lease_info))
}

/// None means an excluded owner/request and keeps its old acquisition path.
/// Once selected, every failure is terminal for this preparation, not fallback.
pub(super) fn prepare_if_admitted(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    proof_requested: bool,
) -> Result<Option<CredentialLeaseInfo>, String> {
    if proof_requested || !admitted(state, snapshot, scope, None, None)? {
        return Ok(None);
    }
    let deadline = Instant::now()
        .checked_add(CREDENTIAL_LEASE_SINGLEFLIGHT_TIMEOUT)
        .ok_or_else(refused)?;
    prepare_on_deadline(state, snapshot, scope, deadline).map(Some)
}

pub(super) fn prepare_on_deadline(
    state: &GateState,
    snapshot: &Arc<Snapshot>,
    scope: &CredentialLeaseScope,
    deadline: Instant,
) -> Result<CredentialLeaseInfo, String> {
    check_credential_operation_deadline(Some(deadline))?;
    if !admitted(state, snapshot, scope, None, None)? {
        return Err(refused());
    }
    let diagnostic = Attempt::after_admission(state, snapshot, scope);
    // The ordinary app identity is finite too; neither the shared fifteen-second
    // budget nor a broker response can extend its remaining lifetime.
    let app_remaining = diagnostic.observe(Stage::AdmissionDeadline, principal_expiry(snapshot, scope))?
        .checked_sub(now_epoch_ms())
        .and_then(|remaining| u64::try_from(remaining).ok())
        .ok_or_else(refused);
    let app_remaining = diagnostic.observe(Stage::AdmissionDeadline, app_remaining)?;
    let deadline = deadline.min(diagnostic.observe(Stage::AdmissionDeadline,
        Instant::now()
            .checked_add(Duration::from_millis(app_remaining))
            .ok_or_else(refused))?,
    );
    diagnostic.observe(Stage::AdmissionDeadline, check_credential_operation_deadline(Some(deadline)))?;
    mark_credential_lease_activity(state, snapshot, scope);
    let pin = match diagnostic.observe(Stage::GenerationLookup, generation_with_margin(state, snapshot, scope))? {
        Some(generation) => generation,
        None => {
            diagnostic.observe(Stage::GenerationRefresh, refresh_scoped_credential_material_singleflight_on_deadline(
                state,
                snapshot,
                scope,
                CredentialLeasePurpose::GenerationMetadata,
                None,
                None,
                Some(deadline),
            ))?;
            let generation = diagnostic.observe(Stage::GenerationMargin, generation_with_margin(state, snapshot, scope))?;
            diagnostic.observe(Stage::GenerationMargin, generation.ok_or_else(refused))?
        }
    };
    diagnostic.observe(Stage::Binding, validate_runtime_credential_binding(snapshot, scope, &pin.metadata))?;
    diagnostic.observe(Stage::Binding, check_credential_operation_deadline(Some(deadline)))?;
    if diagnostic.observe(Stage::PairBeforeSecret, pair_with_margin(state, snapshot, scope, &pin))?.is_none() {
        diagnostic.observe(Stage::SecretRefresh, refresh_scoped_credential_material_singleflight_on_deadline(
            state,
            snapshot,
            scope,
            CredentialLeasePurpose::DispatchSecret,
            None,
            None,
            Some(deadline),
        ))?;
    }
    // No further acquisition, even if either renewed value is already short.
    if !diagnostic.observe(Stage::FinalAdmission, admitted(state, snapshot, scope, None, None))? {
        return diagnostic.observe(Stage::FinalAdmission, Err(refused()));
    }
    let info = diagnostic.observe(Stage::FinalPair, pair_with_margin(state, snapshot, scope, &pin))?;
    let info = diagnostic.observe(Stage::FinalPair, info.ok_or_else(refused))?;
    diagnostic.observe(Stage::FinalDeadline, check_credential_operation_deadline(Some(deadline)))?;
    Ok(info)
}
