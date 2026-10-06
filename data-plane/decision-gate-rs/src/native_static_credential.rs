//! Native-only static intake. Public candidate/proof responses are not writer
//! receipts. The portal must independently authorize and commit the candidate.
use super::*;
use serverware_decision_gate::native_static_credential_v1::{Configuration, Prepared, Reply};
use serverware_decision_gate::native_static_credential_browser_v1::{self as browser_wire, Accepted, Kind};
use serverware_decision_gate::native_oauth_exchange_v1::BrowserTls;
use serverware_decision_gate::native_secret_broker_v1 as broker;
use serverware_decision_gate::enclave_vsock_v1::VsockShutdownV1;

pub(super) struct Owner {
    config: Configuration, ingress: Arc<BrowserTls>,
    listener: Option<VsockListenerV1>, poisoned: bool,
}

pub(super) fn prepare(config: Configuration, inputs: &GateStateInputs, actual: &mut broker::Owner,
    identity: &mut EnclaveRuntimeIdentityV1, signer: &CustodyResponseProofSigner,
    binary: &str, deadline: u64) -> Result<Owner, String> {
    config.validate()?;
    if inputs.server_instance_id.as_deref() != Some(config.instance_id.as_str())
        || inputs.credential_currentness.as_ref().map(|v|v.deployment_id.as_str()) != Some(config.deployment_id.as_str())
        || !matches!(&inputs.service_tokens, native_service_tokens::Source::Installed) {
        return Err("static intake requires encrypted service, instance and currentness owners".to_owned());
    }
    signer.transport.verify_native_identity(identity, deadline)?;
    let ingress = identity.prepare_browser_ingress(&config.intake_origin, OffsetDateTime::now_utc(), deadline)?;
    let listener = VsockListenerV1::bind(config.browser_vsock_port, 2, deadline)
        .map_err(|_|"static intake fixed-parent listener unavailable")?;
    actual.configure_static_credential(config.clone(), Arc::clone(&ingress), identity,
        &signer.boot_id, &signer.key_id, &signer.control_plane_response_signing_key_id, binary, deadline)?;
    Ok(Owner { config, ingress, listener: Some(listener), poisoned: false })
}

fn evidence(state: &GateState, prepared: &Prepared, deadline: u64) -> Result<Value, String> {
    native_service_remaining(state)?;
    let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else {
        return Err("static native signer absent".to_owned());
    };
    let mut held = state.mitm_authority.as_ref().ok_or("static actual CA absent")?
        .lock().map_err(|_|"static identity owner poisoned")?;
    let MitmAuthority::Native(identity) = &mut *held else { return Err("static refuses imported CA".to_owned()); };
    signer.transport.static_credential_evidence(identity, prepared, &state.binary_digest, deadline)
}

fn browser(state: &GateState, owner: &mut Owner, mut request: Accepted) -> Result<(), String> {
    if owner.poisoned { return Err("static browser owner poisoned".to_owned()); }
    native_service_remaining(state)?;
    if matches!(request.kind(), Kind::Page) {
        let (page, csp) = browser_wire::page(&owner.config.portal_origin)?;
        return request.respond("text/html; charset=utf-8", &page, None, &csp);
    }
    let _serial = state.native_oauth_serial.try_lock().map_err(|_|"another native operation is live")?;
    let mut helper = state.native_secret_broker.as_ref().ok_or("static helper absent")?
        .lock().map_err(|_|"static helper poisoned")?;
    let result = (|| {
        let deadline = request.deadline();
        match helper.static_credential_browser(&request)? {
            Reply::Retained { candidate, browser_nonce } if matches!(request.kind(), Kind::Intake) => {
                let cookie = browser_wire::cookie(candidate["credentialId"].as_str().ok_or("static candidate ID absent")?,
                    &browser_nonce, candidate["expiresAtEpochNs"].as_u64().ok_or("static candidate expiry absent")?)?;
                let body = serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"serverware.nativeStaticCredentialCandidateResponse/v1", "candidate":candidate}))?;
                request.respond("application/json", &body, Some(&cookie), "default-src 'none'; frame-ancestors 'none'")
            },
            Reply::Prepared(prepared) if matches!(request.kind(), Kind::Prepare) => {
                let public = prepared.wire(evidence(state, &prepared, deadline)?)?;
                let body = serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&json!({
                    "apiVersion":"serverware.nativeStaticCredentialPreparationResponse/v1",
                    "argumentsOriginal":public["argumentsOriginal"], "evidence":public["evidence"]}))?;
                request.respond("application/json", &body, None, "default-src 'none'; frame-ancestors 'none'")
            },
            _ => Err("static browser/helper phase mismatch".to_owned()),
        }
    })();
    if result.is_err() { owner.poisoned = true; }
    result
}

pub(super) fn start<'scope,'env:'scope>(scope: &'scope thread::Scope<'scope,'env>, state: Arc<GateState>,
    lifetime: Arc<NativeRuntimeLifetimeV1>) -> Result<(),String> {
    let Some(owner) = &state.measured_static_credential else { return Ok(()); };
    let (listener, ingress, port) = {
        let mut held = owner.lock().map_err(|_|"static browser owner poisoned")?;
        if held.poisoned { return Err("static browser owner unavailable".to_owned()); }
        (held.listener.take().ok_or("static browser listener already consumed")?, Arc::clone(&held.ingress), held.config.browser_vsock_port)
    };
    let active: Arc<Mutex<Option<VsockShutdownV1>>> = Arc::new(Mutex::new(None));
    let stopping = Arc::clone(&lifetime); let shutdown = Arc::clone(&active);
    native_runtime_lifetime::spawn_task(scope, &lifetime, "native-static-browser-cancellation".to_owned(), move|| {
        while !stopping.is_stopped() { if !stopping.wait(Duration::from_millis(25))? { break; } }
        if let Some(stream) = shutdown.lock().map_err(|_|"static shutdown owner poisoned")?.as_ref() { let _ = stream.shutdown(); }
        Ok(())
    })?;
    let serving = Arc::clone(&lifetime);
    native_runtime_lifetime::spawn_task(scope, &lifetime, "native-static-browser".to_owned(), move|| {
        while !serving.is_stopped() {
            serving.check()?;
            let stream = match listener.accept_cancellable(serving.deadline(), serving.stopped_flag()) {
                Ok(value) => value, Err(_) if serving.is_stopped() => return Ok(()),
                Err(_) => return Err("static browser accept failed".to_owned()),
            };
            let deadline = broker::now()?.checked_add(30_000_000_000).ok_or("static browser interval overflow")?.min(serving.deadline());
            stream.verify_accepted_local_port(port, deadline).map_err(|_|"static browser original listener changed")?;
            *active.lock().map_err(|_|"static shutdown owner poisoned")? = Some(stream.shutdown_handle().map_err(|_|"static shutdown original unavailable")?);
            // Cancellation may already have observed the prior empty slot.
            // After publishing this exact stream, close that race before TLS.
            if serving.is_stopped() {
                if let Some(handle) = active.lock().map_err(|_|"static shutdown owner poisoned")?.take() { let _ = handle.shutdown(); }
                return Ok(());
            }
            let outcome = match Accepted::accept(stream, Arc::clone(&ingress), deadline) {
                Ok(request) => {
                    let mut owner = state.measured_static_credential.as_ref().ok_or("static owner lost")?
                        .lock().map_err(|_|"static browser owner poisoned")?;
                    browser(&state, &mut owner, request)
                },
                // Malformed framing/TLS never entered the private helper.
                Err(_) => Ok(()),
            };
            active.lock().map_err(|_|"static shutdown owner poisoned")?.take();
            if serving.is_stopped() { return Ok(()); }
            outcome?;
        }
        Ok(())
    })
}
