//! Binary-only cold v6 transition. No token placeholder, environment lookup,
//! receipt-selected mode or general decryption callback enters GateState.

use super::gate_state_init::GateStateInputs;
use super::{validate_configured_internal_service_tokens, MAX_INTERNAL_SERVICE_TOKEN_FILE_BYTES};
use catchplate_decision_gate::enclave_runtime_identity_v1::EnclaveRuntimeIdentityV1;
use catchplate_decision_gate::native_secret_broker_v1::{Owner,
    service_tokens::{Binding, Envelope, Tokens}};

pub(super) enum Source {
    Legacy,
    Pending(Envelope),
    Installed,
    Failed,
}

fn binding(inputs: &GateStateInputs, binary: &str, policy: &str) -> Result<Binding, String> {
    Ok(Binding {
        api_version: "catchplate.nativeServiceTokensBinding/v1".to_owned(),
        instance_id: inputs.server_instance_id.as_ref()
            .ok_or("native service tokens require the actual instance")?.clone(),
        data_plane_binary_digest: binary.to_owned(),
        policy_hash: policy.to_owned(),
        atomic_release_authorization_enabled: inputs.atomic_release_authorization_enabled,
        credential_lease_url: inputs.credential_lease_url.as_ref()
            .ok_or("native service tokens require the credential endpoint")?.clone(),
        grant_consume_url: inputs.grant_consume_url.clone(),
        rate_limit_consume_url: inputs.rate_limit_consume_url.clone(),
        release_authorization_base_url: inputs.release_authorization_base_url.clone(),
    })
}

fn endpoints(inputs: &GateStateInputs) -> Result<(), String> {
    if inputs.audit_token.is_some() || inputs.audit_url.is_none()
        || inputs.credential_lease_url.is_none()
        || (inputs.atomic_release_authorization_enabled && inputs.release_authorization_base_url.is_none())
        || (!inputs.atomic_release_authorization_enabled
            && (inputs.grant_consume_url.is_none() || inputs.rate_limit_consume_url.is_none())) {
        return Err("native encrypted service endpoint selection is incomplete".to_owned());
    }
    Ok(())
}

fn token_values(inputs: &GateStateInputs, lease: &Option<String>, grant: &Option<String>,
    rate: &Option<String>, release: &Option<String>, management: &Option<String>) -> Result<(), String> {
    endpoints(inputs)?;
    if lease.is_none() || management.is_none()
        || inputs.grant_consume_url.is_some() != grant.is_some()
        || inputs.rate_limit_consume_url.is_some() != rate.is_some()
        || inputs.release_authorization_base_url.is_some() != release.is_some() {
        return Err("native encrypted service tokens differ from the exact endpoint selection".to_owned());
    }
    let values = [("credential lease token", lease), ("grant consume token", grant),
        ("rate-limit consume token", rate), ("release authorization token", release),
        ("management token", management)];
    for (_, value) in &values {
        if let Some(value) = value {
            if value.is_empty() || value.len() as u64 > MAX_INTERNAL_SERVICE_TOKEN_FILE_BYTES
                || value.chars().any(|item| item.is_whitespace() || item.is_control())
                || reqwest::header::HeaderValue::from_str(value).is_err() {
                return Err("native encrypted service token is outside its bounded header grammar".to_owned());
            }
        }
    }
    validate_configured_internal_service_tokens(true, &values)
}

/// Pure cold validation permits absent bearers only for this exact pending
/// envelope, never for legacy input or an already consumed/failed transition.
pub(super) fn pending(inputs: &GateStateInputs) -> Result<bool, String> {
    match &inputs.service_tokens {
        Source::Legacy => Ok(false),
        Source::Pending(envelope) => {
            endpoints(inputs)?;
            if inputs.measured_audit.is_none()
                || inputs.credential_lease_token.is_some() || inputs.grant_consume_token.is_some()
                || inputs.rate_limit_consume_token.is_some() || inputs.release_authorization_token.is_some()
                || inputs.management_token.is_some() {
                return Err("native encrypted startup requires its cold measured profile and null bearer slots".to_owned());
            }
            envelope.validate(&binding(inputs, &inputs.binary_digest, &inputs.policy_high_water.policy_hash)?)?;
            Ok(true)
        },
        Source::Installed => { ready(inputs)?; Ok(false) },
        Source::Failed => Err("native service token transition is no longer usable".to_owned()),
    }
}

pub(super) fn ready(inputs: &GateStateInputs) -> Result<(), String> {
    match &inputs.service_tokens {
        Source::Legacy => Ok(()),
        Source::Installed => {
            inputs.native_serving_privileges.as_ref()
                .ok_or("native service tokens lost their actual serving owner")?.check()?;
            token_values(inputs, &inputs.credential_lease_token, &inputs.grant_consume_token,
                &inputs.rate_limit_consume_token, &inputs.release_authorization_token, &inputs.management_token)
        },
        Source::Pending(_) | Source::Failed => Err("native state cannot publish pending or failed service tokens".to_owned()),
    }
}

/// Called after actual binary/policy/identity joins and broker bind, before
/// state construction. The library owns the one-shot recipient and deadline.
pub(super) fn install(inputs: &mut GateStateInputs, broker: &mut Owner,
    identity: &mut EnclaveRuntimeIdentityV1, binary: &str, policy: &str, deadline: u64) -> Result<(), String> {
    if !pending(inputs)? { return Ok(()); }
    if binary != inputs.binary_digest || policy != inputs.policy_high_water.policy_hash {
        return Err("native service token binding differs from the actual executable or admitted policy".to_owned());
    }
    let expected = binding(inputs, binary, policy)?;
    let Source::Pending(envelope) = std::mem::replace(&mut inputs.service_tokens, Source::Failed) else {
        return Err("native service token pending owner was lost".to_owned());
    };
    envelope.validate(&expected)?;
    let mut tokens: Tokens = broker.open_service_tokens(identity, envelope, &expected, deadline)?;
    tokens.validate(&expected)?;
    // Keep failure cleanup with Tokens::drop until every value passes the
    // existing strength/distinctness checks and the exact new URL/null rules.
    token_values(inputs, &tokens.credential_lease_token, &tokens.grant_consume_token,
        &tokens.rate_limit_consume_token, &tokens.release_authorization_token, &tokens.management_token)?;
    inputs.credential_lease_token = tokens.credential_lease_token.take();
    inputs.grant_consume_token = tokens.grant_consume_token.take();
    inputs.rate_limit_consume_token = tokens.rate_limit_consume_token.take();
    inputs.release_authorization_token = tokens.release_authorization_token.take();
    inputs.management_token = tokens.management_token.take();
    inputs.service_tokens = Source::Installed;
    ready(inputs)
}
