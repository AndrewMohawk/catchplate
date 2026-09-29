//! Actual gate driver for independently authorized staged-pending family retirement.
//! No credential/client plaintext crosses this module; immutable ciphertext
//! preparations and independently signed exact writer originals reach helper.
use super::*;
use serverware_decision_gate::native_oauth_pending_retirement_v1::{self as wire, Configuration, Reply};
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
        return Err("pending retirement requires the same actual instance, currentness and encrypted service owners".to_owned());
    }
    signer.transport.verify_native_identity(identity, deadline)?;
    let mut endpoint = Url::parse(inputs.credential_lease_url.as_deref().ok_or("pending retirement lease origin absent")?)
        .map_err(|_|"pending retirement control plane URL")?;
    if endpoint.scheme() != "https" || endpoint.path() != "/api/data-plane/credential-leases" || endpoint.query().is_some()
        || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("pending retirement requires the exact retained credential service origin".to_owned());
    }
    endpoint.set_path(wire::HTTP_PATH);
    actual.configure_pending_retirement(config.clone(), identity, &signer.boot_id, &signer.key_id,
        &signer.control_plane_response_signing_key_id, binary, deadline)?;
    Ok(Owner { config, endpoint: endpoint.to_string(), poisoned: false })
}

fn execute(state: &GateState, owner: &mut Owner, pending: &str, recovery: bool, deadline: Instant) -> Result<(), String> {
    if owner.poisoned || owner.config.target(pending).is_err() { return Err("pending retirement owner unavailable or pending unassigned".to_owned()); }
    // Shared with the actual issuance/refresh drivers; not the broker lock or
    // currentness drain lock, and never a grant to contact the provider.
    let _serial = state.native_oauth_serial.try_lock().map_err(|_|"another original OAuth operation is live")?;
    let result = (|| {
        let opening = broker::now()?;
        let remaining = custody_deadline_remaining(deadline, "measured pending retirement original")?;
        let boot_deadline = opening.checked_add(u64::try_from(remaining.as_nanos()).map_err(|_|"pending retirement interval overflow")?)
            .ok_or("pending retirement deadline overflow")?;
        let relays = state.native_upstream_relays.as_ref().ok_or("pending retirement fixed relays absent")?;
        let helper = state.native_secret_broker.as_ref().ok_or("pending retirement actual helper absent")?;
        let ResponseProofSigner::Custody(signer) = &state.response_proof_signer else { return Err("pending retirement native signer absent".to_owned()); };
        let mut reply = helper.lock().map_err(|_|"pending retirement helper lock poisoned")?.begin_pending_retirement(pending, boot_deadline, relays)?;
        let mut attempted = BTreeSet::new();
        loop {
            custody_deadline_remaining(deadline, "measured pending retirement original")?;
            native_service_remaining(state)?;
            match reply {
                Reply::Complete(done) => {
                    if done.pending_id != pending || !recovery && matches!(done.status.as_str(), "no-local-claim" | "outcome-unknown") {
                        return Err("pending retirement completion belongs to another original".to_owned());
                    }
                    return Ok(());
                },
                Reply::Prepared(prepared) => {
                    if prepared.pending_id() != pending || !attempted.insert(prepared.phase_key()?)
                        || attempted.len() > 6 || recovery && prepared.operation() != "oauth.measured-pending-retirement.recover" {
                        return Err("pending retirement cannot replay a phase or contact during recovery".to_owned());
                    }
                    let evidence = {
                        let mut guard = state.mitm_authority.as_ref().ok_or("pending retirement identity absent")?
                            .lock().map_err(|_|"pending retirement identity lock poisoned")?;
                        let MitmAuthority::Native(identity) = &mut *guard else { return Err("pending retirement refuses imported identity".to_owned()); };
                        signer.transport.pending_retirement_evidence(identity, &prepared, &state.binary_digest, boot_deadline)?
                    };
                    // No identity/broker/currentness lock spans the controlled
                    // writer or all-holder barrier wait. Its drain worker can
                    // acknowledge this same gate's active sends concurrently.
                    let body = serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes(&prepared.wire(evidence)?)?;
                    let remaining = custody_deadline_remaining(deadline, "measured pending retirement request")?;
                    let mut response = state.credential_lease_client.post(&owner.endpoint)
                        .header("X-Serverware-Data-Plane-Token", state.credential_lease_token.as_deref().ok_or("pending retirement service token absent")?)
                        .header("Content-Type", "application/json").body(body)
                        .timeout(remaining).send().map_err(|_|"pending retirement writer response uncertain; no resubmission")?;
                    if !response.status().is_success() { return Err("pending retirement writer refused; no fallback or resubmission".to_owned()); }
                    let raw = read_bounded_control_plane_response_body(&mut response, 8 * 1024 * 1024, "measured pending retirement")?;
                    let mut original: Value = serverware_decision_gate::native_oauth_refresh_v1::response_document(&raw)?;
                    if original["apiVersion"] != wire::HTTP_RESPONSE || original.as_object().is_none_or(|v| v.len() != 4
                        || !["apiVersion","requestOriginal","responseOriginal","currentnessBarriers"].iter().all(|name|v.contains_key(*name))) {
                        return Err("pending retirement response originals are not closed".to_owned());
                    }
                    original.as_object_mut().ok_or("pending retirement response object")?.remove("apiVersion");
                    custody_deadline_remaining(deadline, "measured pending retirement receipt")?;
                    // Helper independently verifies signature, root, exact
                    // pending input and definite commit before its next phase.
                    reply = helper.lock().map_err(|_|"pending retirement helper lock poisoned")?
                        .pending_retirement_receipt(original, pending, boot_deadline, relays)?;
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
    let Some(owner) = &state.measured_pending_retirement else { return Ok(()); };
    let mut owner = owner.lock().map_err(|_|"pending retirement operation owner poisoned")?;
    let targets = owner.config.targets.clone();
    for target in targets {
        let remaining = native_service_remaining(state)?.ok_or("pending retirement original native lifetime absent")?.min(Duration::from_secs(30));
        let deadline = Instant::now().checked_add(remaining).ok_or("pending retirement deadline overflow")?;
        execute(state, &mut owner, &target.pending_id()?, target.recovery, deadline)?;
    }
    Ok(())
}
