//! Actual gate driver for measured due-refresh and explicit captured recovery.
//! No credential/client plaintext crosses this module; immutable ciphertext
//! preparations and independently signed exact writer originals reach helper.
use super::*;
use serverware_decision_gate::native_oauth_refresh_v1::{self as wire, Configuration, Reply};
use serverware_decision_gate::native_secret_broker_v1 as broker;
use std::collections::BTreeSet;

pub(super) struct Owner { config: Configuration, endpoint: String, poisoned: bool }

pub(super) fn prepare(config: Configuration, inputs: &gate_state_init::GateStateInputs,
    actual: &mut broker::Owner, identity: &mut EnclaveRuntimeIdentityV1,
    signer: &CustodyResponseProofSigner, binary: &str, deadline: u64) -> Result<Owner, String> {
    config.validate()?;
    if inputs.server_instance_id.as_deref() != Some(config.instance_id.as_str())
        || inputs.credential_currentness.as_ref().map(|value| value.deployment_id.as_str()) != Some(config.deployment_id.as_str())
        || !matches!(&inputs.service_tokens, native_service_tokens::Source::Installed) {
        return Err("refresh requires the same actual instance, currentness and encrypted service owners".to_owned());
    }
    signer.transport.verify_native_identity(identity, deadline)?;
    let mut endpoint = Url::parse(inputs.credential_lease_url.as_deref().ok_or("refresh lease origin absent")?)
        .map_err(|_|"refresh control plane URL")?;
    if endpoint.scheme() != "https" || endpoint.path() != "/api/data-plane/credential-leases" || endpoint.query().is_some()
        || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("refresh requires the exact retained credential service origin".to_owned());
    }
    endpoint.set_path("/api/data-plane/oauth-refresh");
    actual.configure_refresh(config.clone(), identity, &signer.boot_id, &signer.key_id,
        &signer.control_plane_response_signing_key_id, binary, deadline)?;
    Ok(Owner { config, endpoint: endpoint.to_string(), poisoned: false })
}

fn execute(state: &GateState, owner: &mut Owner, credential: &str, recovery: Option<u64>, deadline: Instant) -> Result<(), String> {
    if owner.poisoned || !owner.config.contains(credential) { return Err("refresh owner unavailable or credential unassigned".to_owned()); }
    // Only one private OAuth contact/capture protocol owns the helper at a
    // time. This is not the broker or send-drain lock; currentness can drain.
    let _serial = state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let result = (|| {
        let opening = broker::now()?;
        let remaining = custody_deadline_remaining(deadline, "measured refresh original")?;
        let boot_deadline = opening.checked_add(u64::try_from(remaining.as_nanos()).map_err(|_|"refresh interval overflow")?)
            .ok_or("refresh deadline overflow")?;
        let relays = state.native_upstream_relays.as_ref().ok_or("refresh fixed relays absent")?;
        let helper = state.native_secret_broker.as_ref().ok_or("refresh actual helper absent")?;
        let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else { return Err("refresh native signer absent".to_owned()); };
        let mut reply = helper.lock().map_err(|_|"refresh helper lock poisoned")?.begin_refresh(credential, recovery, boot_deadline, relays)?;
        let mut attempted = BTreeSet::new();
        loop {
            custody_deadline_remaining(deadline, "measured refresh original")?;
            native_service_remaining(state)?;
            match reply {
                Reply::Complete(done) => {
                    if done.credential_id != credential || done.credential_version == 0
                        || recovery.is_none() && done.status == "observed-complete" {
                        return Err("refresh completion belongs to another original".to_owned());
                    }
                    return Ok(());
                },
                Reply::Prepared(prepared) => {
                    if prepared.credential_id() != credential || !attempted.insert(prepared.operation().to_owned())
                        || attempted.len() > 5 || recovery.is_some() && prepared.operation() == "oauth.measured-refresh.claim" {
                        return Err("refresh cannot replay a phase or contact during recovery".to_owned());
                    }
                    let evidence = {
                        let mut guard = state.mitm_authority.as_ref().ok_or("refresh identity absent")?
                            .lock().map_err(|_|"refresh identity lock poisoned")?;
                        let MitmAuthority::Native(identity) = &mut *guard else { return Err("refresh refuses imported identity".to_owned()); };
                        signer.transport.refresh_evidence(identity, &prepared, &state.binary_digest, boot_deadline)?
                    };
                    // No identity/broker/currentness lock spans the controlled
                    // writer or all-holder barrier wait. Its drain worker can
                    // acknowledge this same gate's active sends concurrently.
                    let body = serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence)?)?;
                    let remaining = custody_deadline_remaining(deadline, "measured refresh request")?;
                    let mut response = state.credential_lease_client.post(&owner.endpoint)
                        .header("X-Serverware-Data-Plane-Token", state.credential_lease_token.as_deref().ok_or("refresh service token absent")?)
                        .header("Content-Type", "application/json").body(body)
                        .timeout(remaining).send().map_err(|_|"refresh writer response uncertain; no resubmission")?;
                    if !response.status().is_success() { return Err("refresh writer refused; no fallback or resubmission".to_owned()); }
                    let raw = read_bounded_control_plane_response_body(&mut response, 8 * 1024 * 1024, "measured refresh")?;
                    let mut original: Value = serverware_decision_gate::native_oauth_refresh_v1::response_document(&raw)?;
                    if original["apiVersion"] != wire::HTTP_RESPONSE || original.as_object().is_none_or(|v| v.len() != 4
                        || !["apiVersion","requestOriginal","responseOriginal","currentnessBarrierSha256"].iter().all(|name|v.contains_key(*name))) {
                        return Err("refresh response originals are not closed".to_owned());
                    }
                    original.as_object_mut().ok_or("refresh response object")?.remove("apiVersion");
                    custody_deadline_remaining(deadline, "measured refresh receipt")?;
                    // Helper independently verifies signature, root, exact
                    // pending input and definite commit before its next phase.
                    reply = helper.lock().map_err(|_|"refresh helper lock poisoned")?
                        .refresh_receipt(original, credential, boot_deadline, relays)?;
                },
            }
        }
    })();
    if result.is_err() { owner.poisoned = true; }
    result
}

pub(super) fn before_generation(state: &GateState, credential: &str, deadline: Instant) -> Result<(), String> {
    let Some(owner) = &state.measured_refresh else { return Ok(()); };
    let mut owner = owner.lock().map_err(|_|"refresh operation owner poisoned")?;
    if !owner.config.contains(credential) { return Ok(()); }
    execute(state, &mut owner, credential, None, deadline)
}

/// Explicit independently pinned cold recovery targets, once before serving.
/// No failed operation is discovered and automatically retried here.
pub(super) fn initialize(state: &GateState) -> Result<(), String> {
    let Some(owner) = &state.measured_refresh else { return Ok(()); };
    let mut owner = owner.lock().map_err(|_|"refresh recovery owner poisoned")?;
    let targets = owner.config.recovery_targets.clone();
    for target in targets {
        let remaining = native_service_remaining(state)?.ok_or("refresh original native lifetime absent")?.min(Duration::from_secs(30));
        let deadline = Instant::now().checked_add(remaining).ok_or("refresh recovery deadline overflow")?;
        execute(state, &mut owner, &target.credential_id, Some(target.credential_version), deadline)?;
    }
    Ok(())
}
