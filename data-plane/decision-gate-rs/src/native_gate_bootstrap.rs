//! Initial native policy acquisition before constructing or sharing GateState.
//! Supplied configuration/checkpoint/proof owners still require independent
//! release, custody and off-host freshness admission. This is not a CLI mode.

use super::*;

const MAX_NATIVE_POLICY_BYTES: usize = 8 * 1024 * 1024;

struct NativeConfiguredResolver(Arc<NativeUpstreamRelaysV1>);
impl UpstreamResolver for NativeConfiguredResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        self.0.resolved_addresses(host, port).map(|addresses| addresses.into_iter()
            .map(|address| SocketAddr::new(address, port)).collect())
    }
}

/// Recompile the retained original bytes with a fresh native trust response.
/// No policy pathname or environment-provided signing-key override is read.
pub(super) fn load_native_snapshot(bytes: &[u8], source: &PolicyTrustRootSource,
    binary_digest: &str) -> Result<Snapshot, String> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_POLICY_BYTES {
        return Err("native policy original must contain 1..8388608 bytes".to_owned());
    }
    let PolicyTrustRootSource::AttestedControlPlane {
        native_transport: Some(transport), ..
    } = source else {
        return Err("native policy acquisition requires its retained transport".to_owned());
    };
    transport.relays.remaining()?;
    let raw = strict_json_value_from_slice(bytes)
        .map_err(|_| "native policy original is not strict JSON".to_owned())?;
    let trust_root = load_policy_trust_root(source)?;
    compile_signed_snapshot_for_source(raw, trust_root, binary_digest, true, source)
}

/// Inputs are unshared cold configuration/proof values, not a host GateState.
/// The snapshot, HTTP clients, resolver and native authority are created here.
pub(super) fn prepare_native_tls_gate_state(
    mut inputs: GateStateInputs,
    proof: ResponseProofSigningMaterial,
    mut bootstrap: EnclaveBootstrapV1,
    policy_bytes: &[u8],
    expected_signing_key_id: &str,
    control_plane_config: &ControlPlaneClientConfig,
    minimum_sequence: u64,
    minimum_rollback_epoch: u64,
) -> Result<NativeTlsGateV1, String> {
    super::native_gate_inputs::validate_native_gate_inputs(&inputs, &proof)?;
    if policy_bytes.is_empty() || policy_bytes.len() > MAX_NATIVE_POLICY_BYTES
        || !is_sha256_digest(expected_signing_key_id)
        || minimum_sequence == 0 || minimum_rollback_epoch == 0 {
        return Err("native policy input, signing-key pin or monotonic floor is invalid".to_owned());
    }
    bootstrap.verify_live(OffsetDateTime::now_utc())?;
    let relays = Arc::clone(bootstrap.relays(OffsetDateTime::now_utc())?);
    let trust_url = match &inputs.policy_trust_root_source {
        PolicyTrustRootSource::AttestedControlPlane { url,
            verifier: Some(ControlPlaneAttestationVerifier::Pinned(_)), native_transport: None, .. } => url.as_str(),
        _ => return Err("native bootstrap requires an unused pinned-verifier trust source".to_owned()),
    };
    let mut urls = vec![trust_url];
    urls.extend([inputs.audit_url.as_deref(), inputs.grant_consume_url.as_deref(),
        inputs.rate_limit_consume_url.as_deref(), inputs.release_authorization_base_url.as_deref()]
        .into_iter().flatten());
    let proxy = relays.service_proxy(&urls)?;
    let audit_client = control_plane_config.builder(Duration::from_secs(2))
        .https_only(true).pool_max_idle_per_host(0).proxy(proxy.clone()).build()
        .map_err(|_| "build initial native service client".to_owned())?;
    let trust_client = control_plane_config.builder(Duration::from_secs(5))
        .https_only(true).pool_max_idle_per_host(0).proxy(proxy).build()
        .map_err(|_| "build initial native trust client".to_owned())?;
    let broker_url = inputs.credential_lease_url.as_deref()
        .ok_or("native bootstrap requires a credential broker URL")?;
    let credential_client = control_plane_config.builder(Duration::from_secs(3))
        .https_only(true).proxy(relays.broker_proxy(broker_url)?).build()
        .map_err(|_| "build initial native credential client".to_owned())?;
    if let PolicyTrustRootSource::AttestedControlPlane { native_transport, .. } = &mut inputs.policy_trust_root_source {
        *native_transport = Some(NativeControlPlaneTransport {
            client: trust_client, relays: Arc::clone(&relays),
            expected_policy_signing_key_id: expected_signing_key_id.to_owned(),
        });
    }
    // Measure this executable through the existing actual-byte reader. Neither
    // a caller's binary label nor the measured digest alone is release admission.
    let binary_digest = current_binary_digest()?;
    if inputs.binary_digest != binary_digest {
        return Err("native bootstrap binary digest differs from this executable".to_owned());
    }
    let mut snapshot = load_native_snapshot(policy_bytes, &inputs.policy_trust_root_source, &binary_digest)?;
    snapshot.epoch = 1;
    snapshot.trust_generation = 1;
    bootstrap.bind_policy(native_lease_digest_bytes(&snapshot.hash)?, OffsetDateTime::now_utc())?;
    validate_production_release_authorization_policy(&snapshot, true, inputs.atomic_release_authorization_enabled)?;
    inputs.policy_shadow_generation_control.as_ref()
        .ok_or("native bootstrap requires production shadow control")?
        .authorize_startup_active_snapshot(&snapshot)?;
    validate_response_proof_signer_policy_binding(&snapshot, &proof.signer)?;
    if snapshot.policy_sequence < minimum_sequence || snapshot.rollback_epoch < minimum_rollback_epoch {
        return Err("native policy is below its supplied monotonic floors".to_owned());
    }
    validate_policy_high_water(&snapshot, &inputs.policy_high_water)?;
    if inputs.policy_high_water.policy_hash != snapshot.hash {
        return Err("native bootstrap requires an already current policy checkpoint".to_owned());
    }
    // Pure consistency only: no local file creation or candidate-derived
    // checkpoint substitutes for independently latest off-host witness state.
    let (mut identity, ingress, held_relays, deadline) = bootstrap.into_parts(OffsetDateTime::now_utc())?;
    if !Arc::ptr_eq(&relays, &held_relays) {
        return Err("native bootstrap lost its original relay owner".to_owned());
    }
    let ResponseProofSigner::Custody(signer) = &proof.signer else {
        return Err("native bootstrap lost its custody signer".to_owned());
    };
    // Join the actual key's role-4 binding to this actual CA and complete scope,
    // and permanently narrow key use to this cohort's original deadline. A
    // hello label or public-key equality alone cannot establish that ownership.
    signer.transport.verify_native_identity(&mut identity, deadline)?;
    // Both values originate only from the closed v5/v6 cold configuration. Keep
    // actual generated-key owners; no caller-provided readiness result enters
    // the state, and neither operation renews the cohort's original deadline.
    let mut secret_broker = match inputs.prepared_secret_broker.take() {
        Some(prepared) => Some(prepared.bind(&mut identity,
            inputs.native_serving_privileges.as_ref().ok_or("native serving privilege owner absent")?, deadline)?),
        None => None,
    };
    if let Some(broker) = &mut secret_broker {
        // The expected binding comes from the actual executable measurement,
        // admitted policy and same ingress-instance inputs, never from the
        // envelope's claimed binding. No GateState exists while tokens open.
        native_service_tokens::install(&mut inputs, broker, &mut identity,
            &binary_digest, &snapshot.hash, deadline)?;
    }
    native_service_tokens::ready(&inputs)?;
    let native_jit_review = match inputs.measured_jit_review.take() {
        Some(config) => Some(signer.transport.configure_jit_review(config,
            &inputs.jit_review_assignment.take().ok_or("JIT postboot assignment absent")?,
            secret_broker.as_mut().ok_or("JIT actual broker absent")?, &mut identity,
            &binary_digest, deadline)?),
        None => None,
    };
    let native_jit_review_open = match inputs.measured_jit_review_open.take() {
        Some(config) => Some(native_jit_review_open::prepare(config,
            &inputs.jit_review_open_assignment.take().ok_or("opening postboot assignment absent")?,
            &inputs, secret_broker.as_mut().ok_or("opening actual broker absent")?,
            &mut identity, signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_refresh = match inputs.measured_refresh.take() {
        Some(config) => Some(native_oauth_refresh::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native refresh broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_audit = match inputs.measured_audit.take() {
        Some(config) => Some(native_audit_transport::prepare(config, control_plane_config, &relays,
            inputs.audit_url.as_deref().ok_or("native measured audit URL absent")?, &mut identity, deadline)?),
        None => None,
    };
    let measured_canary_delivery = match inputs.measured_canary_delivery.take() {
        Some(config) => Some(native_canary_delivery::prepare(config,&inputs,control_plane_config,&relays,&mut identity,deadline)?),
        None => None,
    };
    if [inputs.measured_static_credential.is_some(), inputs.measured_static_credential_rotation.is_some(), inputs.measured_issuance.is_some(), inputs.measured_setup.is_some(), inputs.measured_reconnect.is_some(), inputs.measured_succession.is_some()]
        .into_iter().filter(|selected| *selected).count() > 1 {
        return Err("native browser/helper purpose must be selected once at cold startup".to_owned());
    }
    let measured_succession = match inputs.measured_succession.take() {
        Some(config) => Some(native_oauth_succession::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native succession broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_reconnect = match inputs.measured_reconnect.take() {
        Some(config) => Some(native_oauth_reconnect::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native reconnect broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_static_credential = match inputs.measured_static_credential.take() {
        Some(config) => Some(native_static_credential::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native static credential broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_static_credential_rotation = match inputs.measured_static_credential_rotation.take() {
        Some(config) => Some(native_static_credential_rotation::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native static rotation broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_setup = match inputs.measured_setup.take() {
        Some(config) => Some(native_oauth_setup::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native Setup broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_issuance = match inputs.measured_issuance.take() {
        Some(config) => Some(native_oauth_exchange::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native initial issuance broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let (_, attestation) = materialize_native_proxy_ingress(&ingress, deadline)?;
    // Neither audit membership nor refresh configuration grants retirement.
    let measured_cleanup = match inputs.measured_cleanup.take() {
        Some(config) => Some(native_oauth_cleanup::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native cleanup broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    // Staged pending retirement is a distinct purpose; neither refresh
    // cleanup nor initial issuance supplies its permission.
    let measured_pending_retirement = match inputs.measured_pending_retirement.take() {
        Some(config) => Some(native_oauth_pending_retirement::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native pending retirement broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let measured_capture_retirement = match inputs.measured_capture_retirement.take() {
        Some(config) => Some(native_oauth_capture_retirement::prepare(config, &inputs,
            secret_broker.as_mut().ok_or("native capture retirement broker absent")?, &mut identity,
            signer, &binary_digest, deadline)?),
        None => None,
    };
    let mut state = inputs.into_state(GateStateRuntime {
        snapshot: Arc::new(snapshot), audit_client, credential_lease_client: credential_client,
        upstream_resolver: Arc::new(NativeConfiguredResolver(Arc::clone(&relays))),
        proxy_ingress_attestation: attestation, mitm_authority: Some(MitmAuthority::Native(identity)),
        response_proof: proof,
    })?;
    state.native_policy_bytes = Some(Arc::from(policy_bytes));
    state.native_upstream_relays = Some(held_relays);
    state.native_secret_broker = secret_broker.map(Mutex::new);
    state.native_jit_review = native_jit_review.map(Mutex::new);
    state.native_jit_review_open = native_jit_review_open.map(Mutex::new);
    state.measured_refresh = measured_refresh.map(Mutex::new);
    state.measured_cleanup = measured_cleanup.map(Mutex::new);
    state.measured_pending_retirement = measured_pending_retirement.map(Mutex::new);
    state.measured_capture_retirement = measured_capture_retirement.map(Mutex::new);
    state.measured_issuance = measured_issuance.map(Mutex::new);
    state.measured_setup = measured_setup.map(Mutex::new);
    state.measured_static_credential = measured_static_credential.map(Mutex::new);
    state.measured_static_credential_rotation = measured_static_credential_rotation.map(Mutex::new);
    state.measured_reconnect = measured_reconnect.map(Mutex::new);
    state.measured_succession = measured_succession.map(Mutex::new);
    state.measured_audit = measured_audit.map(Mutex::new);
    state.measured_canary_delivery = measured_canary_delivery.map(Mutex::new);
    if state.measured_canary_delivery.is_some() { native_canary_delivery::initialize(&state)?; }
    if state.measured_audit.is_some() { native_audit_owner::initialize(&state)?; }
    if state.measured_refresh.is_some() { native_oauth_refresh::initialize(&state)?; }
    if state.measured_cleanup.is_some() { native_oauth_cleanup::initialize(&state)?; }
    if state.measured_pending_retirement.is_some() { native_oauth_pending_retirement::initialize(&state)?; }
    if state.measured_capture_retirement.is_some() { native_oauth_capture_retirement::initialize(&state)?; }
    if state.measured_issuance.is_some() { native_oauth_exchange::initialize(&state)?; }
    if state.measured_setup.is_some() { native_oauth_setup::initialize(&state)?; }
    if state.measured_reconnect.is_some() { native_oauth_reconnect::initialize(&state)?; }
    if state.measured_succession.is_some() { native_oauth_succession::initialize(&state)?; }
    ingress.verify_live(deadline)?;
    native_service_remaining(&state)?;
    let state=Arc::new(state);
    if state.measured_canary_delivery.is_some() {
        state.policy_shadow.bind_native_observation_owner(&state)?;
    }
    Ok(NativeTlsGateV1 { state, ingress, deadline })
}
