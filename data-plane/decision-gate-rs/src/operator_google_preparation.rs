//! Shared request-owned freshness for independently admitted ordinary Google/X.
//! Admission remains provider-disjoint; no Google marker admits an X account.
//! A canonical decision pins its generation. Audit ACK precedes secret copying;
//! neither a renewed envelope nor this owner extends an existing send binding.
use super::*;

const BUDGET: Duration = Duration::from_secs(10);

fn refused() -> String {
    "operator Google release preparation unavailable".to_owned()
}

struct Pin {
    snapshot: Arc<Snapshot>,
    scope: CredentialLeaseScope,
    generation: CredentialLeaseGeneration,
}

pub(super) struct Request {
    deadline: Instant,
    claimed: bool,
    pin: Option<Pin>,
}

impl Request {
    /// Called at buffered-forward entry, before decision/acquisition. No later
    /// stage may replace this clock; application admission can only shorten it.
    pub(super) fn new(original_deadline: Instant) -> Self {
        Self { deadline: original_deadline.min(Instant::now() + BUDGET), claimed: false, pin: None }
    }

    pub(super) fn acquire_if_admitted(
        &mut self, state: &GateState, snapshot: &Arc<Snapshot>,
        scope: &CredentialLeaseScope, proof_requested: bool,
    ) -> Result<Option<CredentialLeaseInfo>, String> {
        if self.claimed { return Err(refused()); }
        if proof_requested || operator_google_reconciliation::admitted(
            state, snapshot, scope, None, None,
        )?.is_none() { return Ok(None); }
        let route = snapshot.routes.iter().find(|route| route.id == scope.route_id).ok_or_else(refused)?;
        if streaming_response_policy(&response_policy_for_route(route)).is_some() { return Ok(None); }
        self.claimed = true;
        let admission_monotonic = Instant::now();
        let remaining = operator_static_preparation::principal_expiry(snapshot, scope)?
            .checked_sub(now_epoch_ms()).and_then(|value| u64::try_from(value).ok())
            .ok_or_else(refused)?;
        self.deadline = self.deadline.min(admission_monotonic
            .checked_add(Duration::from_millis(remaining)).ok_or_else(refused)?);
        check_credential_operation_deadline(Some(self.deadline))?;
        // Existing signed no-envelope reconciliation remains pre-canonical and
        // receives this same original deadline, including flight wait/cache.
        let info = ensure_scoped_credential_lease_on_deadline(
            state, snapshot, scope, None, None, Some(self.deadline),
        )?;
        let active = state.snapshot.read().map_err(|_| refused())?;
        if active.epoch != snapshot.epoch || !Arc::ptr_eq(&active, snapshot) { return Err(refused()); }
        let generations = state.credential_generations.lock().map_err(|_| refused())?;
        let generation = generations.get(scope).ok_or_else(refused)?;
        if generation.profile != ReleaseProfile::Legacy
            || !credential_generation_valid_after(generation, snapshot, now_epoch_ms(), Instant::now())
            || generation.version != info.version || generation.metadata_sha256 != info.metadata_sha256
            || generation.metadata != info.metadata || !info.secret_available
        { return Err(refused()); }
        check_credential_operation_deadline(Some(self.deadline))?;
        self.pin = Some(Pin { snapshot: Arc::clone(snapshot), scope: scope.clone(), generation: generation.clone() });
        Ok(Some(info))
    }

    pub(super) fn prepare_release_if_admitted(
        &mut self, state: &GateState, snapshot: &Arc<Snapshot>, decision: &Value,
        method: &str, url: &Url, proof_requested: bool,
    ) -> Result<Option<SecretLease>, String> {
        if !self.claimed { return Ok(None); }
        // Consumption precedes all effects. Failure is terminal, not fallback
        // to the generic acquisition/reconciliation path or another audit ACK.
        let pin = self.pin.take().ok_or_else(refused)?;
        if proof_requested || !Arc::ptr_eq(&pin.snapshot, snapshot)
            || decision.get("client_request_digest").is_some_and(|value| !value.is_null())
            || decision.get("release_authorization").is_some_and(|value| !value.is_null())
            || decision.get("allowed").and_then(Value::as_bool) != Some(true)
            || decision.get("action").and_then(Value::as_str) != Some("allow")
            || decision.pointer("/jit/required").and_then(Value::as_bool) != Some(false)
            || decision.get("principal_id").and_then(Value::as_str) != Some(pin.scope.principal_id.as_str())
            || decision.get("route_id").and_then(Value::as_str) != Some(pin.scope.route_id.as_str())
            || decision.get("credential_ref").and_then(Value::as_str) != Some(pin.scope.credential_id.as_str())
            || decision.get("credential_version").and_then(Value::as_u64) != Some(pin.generation.version)
        { return Err(refused()); }
        let route = decision_route_context(snapshot, decision, method, url).map_err(|_| refused())?;
        if route.route.credential_ref.as_deref() != Some(pin.scope.credential_id.as_str()) { return Err(refused()); }
        let canonical = decision.get("canonical_request").and_then(Value::as_object).ok_or_else(refused)?;
        let version = pin.generation.version.to_string();
        for (name, expected) in [("principal", pin.scope.principal_id.as_str()),
            ("route_id", pin.scope.route_id.as_str()), ("credential_ref", pin.scope.credential_id.as_str()),
            ("credential_version", version.as_str()), ("policy_hash", snapshot.hash.as_str())]
        {
            if canonical.get(name).and_then(Value::as_str) != Some(expected) { return Err(refused()); }
        }
        require_pin(state, snapshot, &pin, self.deadline)?;
        validate_runtime_credential_binding(snapshot, &pin.scope, &pin.generation.metadata)?;
        // No cache/snapshot guard is held over the existing signed durable ACK.
        if !record_required_credential_release_start_for_scope_on_deadline(
            state, decision, method, url, &pin.scope, pin.generation.version, Some(self.deadline),
        ) { return Err("required credential release audit unavailable".to_owned()); }
        require_pin(state, snapshot, &pin, self.deadline)?;
        select_after_ack(state, snapshot, &pin, self.deadline).map(Some)
    }
}

fn same_generation(left: &CredentialLeaseGeneration, right: &CredentialLeaseGeneration) -> bool {
    left.profile == right.profile && left.policy_hash == right.policy_hash
        && left.version == right.version && left.metadata_sha256 == right.metadata_sha256
        && left.metadata == right.metadata
}

fn require_pin(state: &GateState, snapshot: &Arc<Snapshot>, pin: &Pin, deadline: Instant) -> Result<(), String> {
    check_credential_operation_deadline(Some(deadline))?;
    operator_google_reconciliation::admitted(state, snapshot, &pin.scope, None, None)?.ok_or_else(refused)?;
    let active = state.snapshot.read().map_err(|_| refused())?;
    if active.epoch != snapshot.epoch || !Arc::ptr_eq(&active, snapshot)
        || !Arc::ptr_eq(snapshot, &pin.snapshot) { return Err(refused()); }
    let generations = state.credential_generations.lock().map_err(|_| refused())?;
    let current = generations.get(&pin.scope).ok_or_else(refused)?;
    if !same_generation(current, &pin.generation) || !credential_generation_floor_matches(current, snapshot) {
        return Err(refused());
    }
    check_credential_operation_deadline(Some(deadline))
}

fn margin(required: Duration) -> Result<(u128, Instant), String> {
    Ok((now_epoch_ms().checked_add(required.as_millis()).ok_or_else(refused)?,
        Instant::now().checked_add(required).ok_or_else(refused)?))
}

fn generation_with_margin(
    state: &GateState, snapshot: &Arc<Snapshot>, pin: &Pin, required: Duration,
) -> Result<Option<CredentialLeaseGeneration>, String> {
    let generations = state.credential_generations.lock().map_err(|_| refused())?;
    let current = generations.get(&pin.scope).ok_or_else(refused)?;
    if !same_generation(current, &pin.generation) { return Err(refused()); }
    let (epoch, monotonic) = margin(required)?;
    Ok(credential_generation_valid_after(current, snapshot, epoch, monotonic).then(|| current.clone()))
}

/// Read both caches together and sample clocks after acquiring their locks.
/// `copy` is called only after the ACK and after all exact-pair checks pass.
fn pair_with_margin<T>(
    state: &GateState, snapshot: &Arc<Snapshot>, pin: &Pin,
    copy: impl FnOnce(&SecretLease) -> T,
) -> Result<Option<T>, String> {
    let active = state.snapshot.read().map_err(|_| refused())?;
    if active.epoch != snapshot.epoch || !Arc::ptr_eq(&active, snapshot) { return Err(refused()); }
    let leases = state.credential_leases.lock().map_err(|_| refused())?;
    let generations = state.credential_generations.lock().map_err(|_| refused())?;
    let current = generations.get(&pin.scope).ok_or_else(refused)?;
    if !same_generation(current, &pin.generation) { return Err(refused()); }
    let (epoch, monotonic) = margin(CREDENTIAL_LEASE_RENEW_BEFORE)?;
    if !credential_generation_valid_after(current, snapshot, epoch, monotonic) { return Ok(None); }
    Ok(leases.get(&CredentialLeaseCacheKey::new_bound(&pin.scope, None, None))
        .filter(|lease| lease.profile == pin.generation.profile && lease.scope == pin.scope
            && lease.version == pin.generation.version && lease.metadata_sha256 == pin.generation.metadata_sha256
            && lease.metadata == pin.generation.metadata && lease.request_authority.is_none()
            && lease.release_authorization.is_none()
            && credential_secret_lease_valid_after(lease, snapshot, epoch, monotonic))
        .map(copy))
}

fn refresh_pinned(
    state: &GateState, snapshot: &Arc<Snapshot>, pin: &Pin,
    purpose: CredentialLeasePurpose, deadline: Instant,
) -> Result<(), String> {
    require_pin(state, snapshot, pin, deadline)?;
    refresh_scoped_credential_material_singleflight_with_leader(
        state, snapshot, &pin.scope, purpose, None, None, Some(deadline), |leader_deadline| {
            let result = (|| {
                let deadline = leader_deadline.ok_or_else(refused)?.min(deadline);
                require_pin(state, snapshot, pin, deadline)?;
                let expected = if purpose == CredentialLeasePurpose::DispatchSecret {
                    Some(generation_with_margin(state, snapshot, pin,
                        CREDENTIAL_LEASE_REQUEST_TIMEOUT.checked_add(CREDENTIAL_LEASE_RENEW_BEFORE)
                            .ok_or_else(refused)?)?.ok_or_else(refused)?)
                } else { None };
                let material = match fetch_scoped_credential_lease_attempt_on_deadline(
                    state, snapshot, &pin.scope, purpose, expected.as_ref(), None, None, Some(deadline),
                )? {
                    operator_google_reconciliation::FetchOutcome::Material(material) => material,
                    // Verification is still performed by the existing fetcher.
                    // Its proof cannot authorize changing this canonical pin.
                    operator_google_reconciliation::FetchOutcome::GenerationAdvanced(_) => return Err(refused()),
                };
                require_pin(state, snapshot, pin, deadline)?;
                match material {
                    CredentialLeaseMaterial::GenerationMetadata(generation) => {
                        if purpose != CredentialLeasePurpose::GenerationMetadata
                            || !same_generation(&generation, &pin.generation) { return Err(refused()); }
                        cache_scoped_credential_generation_on_deadline(
                            state, snapshot, &pin.scope, generation, Some(deadline),
                        )?;
                    }
                    CredentialLeaseMaterial::DispatchSecret(lease) => {
                        if purpose != CredentialLeasePurpose::DispatchSecret
                            || lease.profile != pin.generation.profile || lease.scope != pin.scope
                            || lease.version != pin.generation.version || lease.metadata_sha256 != pin.generation.metadata_sha256
                            || lease.metadata != pin.generation.metadata || lease.request_authority.is_some()
                            || lease.release_authorization.is_some() { return Err(refused()); }
                        cache_scoped_credential_lease_on_deadline(
                            state, snapshot, &pin.scope, *lease, Some(deadline),
                        )?;
                    }
                }
                require_pin(state, snapshot, pin, deadline)
            })();
            if result.is_ok() { state.credential_lease_refresh_success.fetch_add(1, Ordering::Relaxed); }
            else { state.credential_lease_refresh_failed.fetch_add(1, Ordering::Relaxed); }
            result
        },
    )?;
    // A waiter can join an earlier pre-decision leader. Only its exact matching
    // cached result is usable, never its authority to reconcile a newer version.
    require_pin(state, snapshot, pin, deadline)
}

fn select_after_ack(state: &GateState, snapshot: &Arc<Snapshot>, pin: &Pin, deadline: Instant) -> Result<SecretLease, String> {
    require_pin(state, snapshot, pin, deadline)?;
    if let Some(lease) = pair_with_margin(state, snapshot, pin, Clone::clone)? {
        require_pin(state, snapshot, pin, deadline)?;
        return Ok(lease);
    }
    // A metadata lease must cover the first secret fetch's maximum three-second
    // budget plus the final one-second margin. Refresh metadata at most once.
    let required = CREDENTIAL_LEASE_REQUEST_TIMEOUT.checked_add(CREDENTIAL_LEASE_RENEW_BEFORE).ok_or_else(refused)?;
    if generation_with_margin(state, snapshot, pin, required)?.is_none() {
        refresh_pinned(state, snapshot, pin, CredentialLeasePurpose::GenerationMetadata, deadline)?;
        generation_with_margin(state, snapshot, pin, required)?.ok_or_else(refused)?;
    }
    // A concurrent same-generation renewal may already supply the exact pair.
    if let Some(lease) = pair_with_margin(state, snapshot, pin, Clone::clone)? {
        require_pin(state, snapshot, pin, deadline)?;
        return Ok(lease);
    }
    refresh_pinned(state, snapshot, pin, CredentialLeasePurpose::DispatchSecret, deadline)?;
    let lease = pair_with_margin(state, snapshot, pin, Clone::clone)?.ok_or_else(refused)?;
    require_pin(state, snapshot, pin, deadline)?;
    Ok(lease)
}
