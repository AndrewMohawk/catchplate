//! Actual owned native runtime orchestration, not release/configuration admission.
//! The native entrypoint consumes its prepared state and never invokes legacy
//! environment-driven startup or detached legacy worker constructors.

use super::*;

pub(super) struct NativeRuntimeSettingsV1 {
    proxy_workers: usize,
    proxy_queue_capacity: usize,
    policy_interval: Duration,
    audit_interval: Duration,
}

impl NativeRuntimeSettingsV1 {
    pub(super) fn new(proxy_workers: usize, proxy_queue_capacity: usize,
        policy_interval: Duration, audit_interval: Duration) -> Result<Self, String>
    {
        if !(1..=24).contains(&proxy_workers) || !(1..=4096).contains(&proxy_queue_capacity)
            || !(Duration::from_millis(50)..=Duration::from_secs(60)).contains(&policy_interval)
            || !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&audit_interval)
        {
            return Err("native runtime worker, queue or interval settings exceed their fixed bounds".to_owned());
        }
        Ok(Self { proxy_workers, proxy_queue_capacity, policy_interval, audit_interval })
    }
}

struct StopBeforeJoin(Arc<NativeRuntimeLifetimeV1>);
impl Drop for StopBeforeJoin {
    fn drop(&mut self) { self.0.stop(); }
}

pub(super) fn run(listener: VsockListenerV1, prepared: NativeTlsGateV1,
    settings: NativeRuntimeSettingsV1) -> Result<(), String>
{
    let NativeTlsGateV1 { mut state, ingress, deadline } = prepared;
    let lifetime = NativeRuntimeLifetimeV1::new(deadline)?;
    // The cold constructor creates a fresh unshared Arc. Install cancellation
    // before any background or serving clone can acquire this state.
    let cold = Arc::get_mut(&mut state)
        .ok_or("native runtime state was shared before lifecycle ownership")?;
    if !cold.is_production || cold.native_runtime_lifetime.is_some()
        || cold.native_upstream_relays.is_none() || cold.native_policy_bytes.is_none()
    {
        return Err("native runtime requires unused actual native preparation".to_owned());
    }
    cold.native_runtime_lifetime = Some(Arc::clone(&lifetime));
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err("native runtime requires its actual custody signer".to_owned());
    };
    signer.transport.require_native()?;
    {
        let mut authority = state.mitm_authority.as_ref()
            .ok_or("native runtime requires its actual TLS authority")?
            .lock().map_err(|_| "native runtime authority is poisoned".to_owned())?;
        let MitmAuthority::Native(identity) = &mut *authority else {
            return Err("native runtime rejects imported PEM TLS authority".to_owned());
        };
        identity.verify_quoted_ingress(&ingress, deadline)?;
        identity.verify_tls_scope(OffsetDateTime::now_utc(), deadline)?;
        signer.transport.verify_native_identity(identity, deadline)?;
    }
    let (config, attestation) = materialize_native_proxy_ingress(&ingress, deadline)?;
    if state.proxy_ingress_attestation.value() != attestation.value() {
        return Err("native runtime ingress metadata differs from its held TLS configuration".to_owned());
    }
    native_service_remaining(&state)?.ok_or("native runtime lost its service transport")?;
    lifetime.check()?;
    state.response_proof_signer.probe_custody_once();
    lifetime.check()?;
    if !state.response_proof_signer.proof_dispatch_ready() {
        return Err("native runtime custody startup probe failed".to_owned());
    }
    let v2 = state.response_observation_v2_client.as_ref()
        .ok_or("native runtime requires the existing observation v2 client")?;
    if !probe_response_observation_v2_once(v2, lifetime.remaining()?.min(Duration::from_secs(2))) {
        return Err("native runtime observation v2 startup probe failed".to_owned());
    }
    lifetime.check()?;
    let snapshot = current_snapshot(&state);
    if !snapshot_is_active(&state, &snapshot) {
        return Err("native runtime prepared policy is no longer active and fresh".to_owned());
    }
    native_upstream_remaining(&state, &snapshot.hash)?
        .ok_or("native runtime lost its provider transport")?;
    drop(snapshot);

    // No background handle can escape this scope. The guard is INSIDE the
    // callback, so cancellation is signalled before implicit joining even if
    // startup fails midway or the serving callback unwinds.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        thread::scope(|scope| -> Result<(), String> {
            let _stop_before_join = StopBeforeJoin(Arc::clone(&lifetime));
            native_background_workers::start(scope, Arc::clone(&state), Arc::clone(&lifetime),
                settings.policy_interval, settings.audit_interval)?;
            native_lease_renewal::start(scope, Arc::clone(&state), Arc::clone(&lifetime))?;
            wait_for_hot_generations(&state, &lifetime)?;
            ingress.verify_live(deadline)?;
            lifetime.check()?;
            serve_vsock_proxy(listener, Arc::clone(&state), config,
                settings.proxy_workers, settings.proxy_queue_capacity, deadline,
                Arc::clone(&lifetime))
        })
    }));
    lifetime.stop();
    // Both scoped groups have now joined, including failed partial starts.
    // Retain the actual ingress/private-key owners until that point. This is
    // cooperative cancellation; a blocked syscall still requires a watchdog.
    drop(ingress);
    let result = match result {
        Ok(result) => result,
        Err(_) => {
            lifetime.fail("native runtime orchestration panicked");
            Err("native runtime orchestration panicked".to_owned())
        }
    };
    match lifetime.failure() {
        Some(failure) => Err(failure),
        None => result,
    }
}

fn wait_for_hot_generations(state: &GateState, lifetime: &NativeRuntimeLifetimeV1)
    -> Result<(), String>
{
    // Match the bounded readiness window without speculative cold-scope
    // prefetch. The existing renewal classifier can refresh only genuinely hot
    // scopes, and controlled dispatch still needs fresh operation authority.
    let until = Instant::now().checked_add(lifetime.remaining()?.min(Duration::from_secs(3)))
        .ok_or("native generation readiness deadline overflow")?;
    loop {
        lifetime.check()?;
        let snapshot = current_snapshot(state);
        if !snapshot_is_active(state, &snapshot) {
            return Err("native runtime policy lost freshness before accepting traffic".to_owned());
        }
        if !state.response_proof_signer.proof_dispatch_ready()
            || state.response_observation_v2_client.as_ref()
                .is_none_or(|client| client.healthy.load(Ordering::Acquire) != 1)
        {
            return Err("native runtime custody health changed before accepting traffic".to_owned());
        }
        if credential_generations_ready(state, &snapshot) { return lifetime.check(); }
        let wait = until.checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("native runtime hot credential generations did not become ready")?;
        if !lifetime.wait(wait.min(Duration::from_millis(25)))? {
            return Err("native runtime stopped before accepting traffic".to_owned());
        }
    }
}
