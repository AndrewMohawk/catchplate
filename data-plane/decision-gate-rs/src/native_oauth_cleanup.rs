//! Actual gate driver for independently authorized family retirement.
//! No credential/client plaintext crosses this module; immutable ciphertext
//! preparations and independently signed exact writer originals reach helper.
use super::*;
use catchplate_decision_gate::native_oauth_cleanup_v1::{self as wire, Configuration, Reply};
use catchplate_decision_gate::native_secret_broker_v1 as broker;
use std::collections::BTreeSet;

pub(super) struct Owner { config: Configuration, endpoint: String, poisoned: bool }

pub(super) fn prepare(config: Configuration, inputs: &gate_state_init::GateStateInputs,
    actual: &mut broker::Owner, identity: &mut EnclaveRuntimeIdentityV1,
    signer: &CustodyResponseProofSigner, binary: &str, deadline: u64) -> Result<Owner, String> {
    config.validate()?;
    if inputs.server_instance_id.as_deref() != Some(config.instance_id.as_str())
        || inputs.credential_currentness.as_ref().map(|value| value.deployment_id.as_str()) != Some(config.deployment_id.as_str())
        || !matches!(&inputs.service_tokens, native_service_tokens::Source::Installed) {
        return Err("cleanup requires the same actual instance, currentness and encrypted service owners".to_owned());
    }
    signer.transport.verify_native_identity(identity, deadline)?;
    let mut endpoint = Url::parse(inputs.credential_lease_url.as_deref().ok_or("cleanup lease origin absent")?)
        .map_err(|_|"cleanup control plane URL")?;
    if endpoint.scheme() != "https" || endpoint.path() != "/api/data-plane/credential-leases" || endpoint.query().is_some()
        || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("cleanup requires the exact retained credential service origin".to_owned());
    }
    endpoint.set_path("/api/data-plane/oauth-refresh-cleanup");
    actual.configure_cleanup(config.clone(), identity, &signer.boot_id, &signer.key_id,
        &signer.control_plane_response_signing_key_id, binary, deadline)?;
    Ok(Owner { config, endpoint: endpoint.to_string(), poisoned: false })
}

fn execute(state: &GateState, owner: &mut Owner, credential: &str, recovery: bool, deadline: Instant) -> Result<(), String> {
    if owner.poisoned || owner.config.target(credential).is_err() { return Err("cleanup owner unavailable or credential unassigned".to_owned()); }
    // Shared with the actual issuance/refresh drivers; not the broker lock or
    // currentness drain lock, and never a grant to contact the provider.
    let _serial = state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let result = (|| {
        let opening = broker::now()?;
        let remaining = custody_deadline_remaining(deadline, "measured cleanup original")?;
        let boot_deadline = opening.checked_add(u64::try_from(remaining.as_nanos()).map_err(|_|"cleanup interval overflow")?)
            .ok_or("cleanup deadline overflow")?;
        let relays = state.native_upstream_relays.as_ref().ok_or("cleanup fixed relays absent")?;
        let helper = state.native_secret_broker.as_ref().ok_or("cleanup actual helper absent")?;
        let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else { return Err("cleanup native signer absent".to_owned()); };
        let mut reply = helper.lock().map_err(|_|"cleanup helper lock poisoned")?.begin_cleanup(credential, boot_deadline, relays)?;
        let mut attempted = BTreeSet::new();
        loop {
            custody_deadline_remaining(deadline, "measured cleanup original")?;
            native_service_remaining(state)?;
            match reply {
                Reply::Complete(done) => {
                    if done.work_id != credential || !recovery && matches!(done.status.as_str(), "no-local-claim" | "outcome-unknown") {
                        return Err("cleanup completion belongs to another original".to_owned());
                    }
                    return Ok(());
                },
                Reply::Prepared(prepared) => {
                    if prepared.work_id() != credential || !attempted.insert(prepared.phase_key()?)
                        || attempted.len() > 6 || recovery && prepared.operation() != "oauth.measured-refresh-cleanup.recover" {
                        return Err("cleanup cannot replay a phase or contact during recovery".to_owned());
                    }
                    let evidence = {
                        let mut guard = state.mitm_authority.as_ref().ok_or("cleanup identity absent")?
                            .lock().map_err(|_|"cleanup identity lock poisoned")?;
                        let MitmAuthority::Native(identity) = &mut *guard else { return Err("cleanup refuses imported identity".to_owned()); };
                        signer.transport.cleanup_evidence(identity, &prepared, &state.binary_digest, boot_deadline)?
                    };
                    // No identity/broker/currentness lock spans the controlled
                    // writer or all-holder barrier wait. Its drain worker can
                    // acknowledge this same gate's active sends concurrently.
                    let body = catchplate_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence)?)?;
                    let remaining = custody_deadline_remaining(deadline, "measured cleanup request")?;
                    let mut response = state.credential_lease_client.post(&owner.endpoint)
                        .header("X-Catchplate-Data-Plane-Token", state.credential_lease_token.as_deref().ok_or("cleanup service token absent")?)
                        .header("Content-Type", "application/json").body(body)
                        .timeout(remaining).send().map_err(|_|"cleanup writer response uncertain; no resubmission")?;
                    if !response.status().is_success() { return Err("cleanup writer refused; no fallback or resubmission".to_owned()); }
                    let raw = read_bounded_control_plane_response_body(&mut response, 8 * 1024 * 1024, "measured cleanup")?;
                    let mut original: Value = catchplate_decision_gate::native_oauth_cleanup_v1::response_document(&raw)?;
                    if original["apiVersion"] != wire::HTTP_RESPONSE || original.as_object().is_none_or(|v| v.len() != 4
                        || !["apiVersion","requestOriginal","responseOriginal","currentnessBarrierSha256"].iter().all(|name|v.contains_key(*name))) {
                        return Err("cleanup response originals are not closed".to_owned());
                    }
                    original.as_object_mut().ok_or("cleanup response object")?.remove("apiVersion");
                    custody_deadline_remaining(deadline, "measured cleanup receipt")?;
                    // Helper independently verifies signature, root, exact
                    // pending input and definite commit before its next phase.
                    reply = helper.lock().map_err(|_|"cleanup helper lock poisoned")?
                        .cleanup_receipt(original, credential, boot_deadline, relays)?;
                },
            }
        }
    })();
    if result.is_err() { owner.poisoned = true; }
    result
}

/// Explicit independently signed cold targets, once before serving. Captured
/// outcome recovery is read-only; neither failure nor missing ACK is retried.
pub(super) fn initialize(state: &GateState) -> Result<(), String> {
    let Some(owner) = &state.measured_cleanup else { return Ok(()); };
    let mut owner = owner.lock().map_err(|_|"cleanup operation owner poisoned")?;
    let targets = owner.config.targets.clone();
    for target in targets {
        let remaining = native_service_remaining(state)?.ok_or("cleanup original native lifetime absent")?.min(Duration::from_secs(30));
        let deadline = Instant::now().checked_add(remaining).ok_or("cleanup deadline overflow")?;
        execute(state, &mut owner, &target.work_id()?, target.recovery, deadline)?;
    }
    Ok(())
}
