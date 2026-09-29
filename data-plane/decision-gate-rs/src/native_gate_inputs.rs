//! Fail-closed configuration checks before cold native state assembly.
//!
//! These checks neither load resources nor admit their provenance. The native
//! bootstrap separately acquires and compiles the original signed policy, joins
//! its proof signer and checkpoint, and consumes the actual runtime cohort.
//! No supplied snapshot or caller-selected MITM authority enters this path.

use super::gate_state_init::GateStateInputs;
use super::{
    canonical_spiffe_id, validate_configured_control_plane_urls,
    validate_configured_internal_service_tokens, validate_internal_service_tokens,
    verifying_key_from_spki_pem_text, PolicyTrustRootSource, ResponseProofSigner,
    ResponseProofSigningMaterial,
    AUDIT_INGEST_PATH, CREDENTIAL_LEASE_PATH, GRANT_CONSUME_PATH,
    POLICY_TRUST_ROOT_ATTESTATION_PATH, RATE_LIMIT_CONSUME_PATH,
    RELEASE_AUTHORIZATION_BASE_PATH,
};
use std::time::Duration;

pub(super) fn validate_native_gate_inputs(inputs: &GateStateInputs,
    proof: &ResponseProofSigningMaterial) -> Result<(), String> {
    validate_native_gate_static_inputs(inputs)?;
    if inputs.measured_audit.is_some() {
        inputs.native_serving_privileges.as_ref()
            .ok_or("native v5 requires actual permanent serving privileges")?.check()?;
        if inputs.secret_broker.is_some() || inputs.prepared_secret_broker.is_none() {
            return Err("native v5 bootstrap requires its actual pre-drop broker preparation".to_owned());
        }
    }
    let shadow = inputs.policy_shadow_generation_control.as_ref()
        .ok_or("native bootstrap requires actual production shadow control")?;
    if !shadow.is_production() {
        return Err("native bootstrap rejects development shadow control".to_owned());
    }
    if shadow.startup_request().is_some() {
        return Err("native bootstrap does not install pending shadow startup generations".to_owned());
    }
    let ResponseProofSigner::Custody(signer) = &proof.signer else {
        return Err("native production requires an actual custody response proof signer".to_owned());
    };
    // Native custody is an actual retained owner in this address space, not a
    // host UDS peer or UID-isolated process. Legacy UDS startup still enforces
    // its separate UID. Neither construction supplies independent admission.
    signer.transport.require_native()?;
    if let Some(currentness) = &inputs.credential_currentness { currentness.validate()?; }
    if signer.public_key_pem != proof.public_key_pem || signer.key_id != proof.key_id {
        return Err("native custody signer metadata does not match the supplied proof configuration".to_owned());
    }
    let (key, key_id) = verifying_key_from_spki_pem_text(
        &signer.public_key_pem, "native custody response proof",
    )?;
    if key.as_bytes() != signer.verifying_key.as_bytes() || key_id != signer.key_id {
        return Err("native custody signer key does not match its actual verifying key and ID".to_owned());
    }
    // The startup composition constructs this through the actual production
    // hello. Presence alone in this lower-level preparation is not admission.
    if inputs.response_observation_v2_client.is_none() {
        return Err("native production requires the response-observation v2 client".to_owned());
    }
    Ok(())
}

/// Pure preflight for cold configuration, usable before opening NSM, generating
/// keys or contacting startup services. Actual-owner checks remain separate.
pub(super) fn validate_native_gate_static_inputs(inputs: &GateStateInputs) -> Result<(), String> {
    let measured = inputs.measured_audit.is_some();
    let configured = inputs.secret_broker.is_some();
    let prepared = inputs.prepared_secret_broker.is_some();
    if (configured && prepared) || measured != (configured || prepared)
        || prepared != inputs.native_serving_privileges.is_some() {
        return Err("native measured audit and secret broker must share the explicit v5 cold profile".to_owned());
    }
    if let Some(config) = &inputs.secret_broker { config.validate()?; }
    let pending_tokens = super::native_service_tokens::pending(inputs)?;
    if !inputs.is_production {
        return Err("native bootstrap requires production configuration".to_owned());
    }
    if !inputs.policy_path.is_empty()
        || inputs.policy_high_water_path.is_some()
        || inputs.release_provenance_path.is_some()
        || inputs.image_signatures_path.is_some()
        || inputs.initial_policy_mtime.is_some()
        || inputs.initial_release_evidence_mtimes.0.is_some()
        || inputs.initial_release_evidence_mtimes.1.is_some()
    {
        return Err("native raw-input bootstrap rejects policy, checkpoint and release-evidence filesystem inputs".to_owned());
    }
    if inputs.credential_lease_recipient_attestation_command.is_some() {
        return Err("native bootstrap rejects an external recipient attestation command".to_owned());
    }

    let trust_url = match &inputs.policy_trust_root_source {
        PolicyTrustRootSource::AttestedControlPlane { url, .. } => url.as_str(),
        PolicyTrustRootSource::File(_) => {
            return Err("native bootstrap requires an attested control-plane trust source".to_owned());
        }
    };
    let mut endpoints = vec![(
        "policy trust root", trust_url, POLICY_TRUST_ROOT_ATTESTATION_PATH,
    )];
    for (label, url, path) in [
        ("credential lease", inputs.credential_lease_url.as_deref(), CREDENTIAL_LEASE_PATH),
        ("audit", inputs.audit_url.as_deref(), AUDIT_INGEST_PATH),
        ("grant consume", inputs.grant_consume_url.as_deref(), GRANT_CONSUME_PATH),
        ("rate-limit consume", inputs.rate_limit_consume_url.as_deref(), RATE_LIMIT_CONSUME_PATH),
        ("release authorization", inputs.release_authorization_base_url.as_deref(), RELEASE_AUTHORIZATION_BASE_PATH),
    ] {
        if let Some(url) = url {
            endpoints.push((label, url, path));
        }
    }
    // The fixed native service-relay table uses this same per-URL ceiling.
    if endpoints.iter().any(|(_, url, _)| url.len() > 4096) {
        return Err("native control-plane URL exceeds 4096 bytes".to_owned());
    }
    validate_configured_control_plane_urls(true, false, &endpoints)?;

    let configured_tokens = [
        ("credential lease token", &inputs.credential_lease_token),
        ("audit token", &inputs.audit_token),
        ("grant consume token", &inputs.grant_consume_token),
        ("rate-limit consume token", &inputs.rate_limit_consume_token),
        ("release authorization token", &inputs.release_authorization_token),
        ("management token", &inputs.management_token),
    ];
    validate_configured_internal_service_tokens(true, &configured_tokens)?;
    let mut required_tokens = vec![
        ("credential lease token", &inputs.credential_lease_token),
        ("management token", &inputs.management_token),
    ];
    if !measured { required_tokens.push(("audit token", &inputs.audit_token)); }
    if inputs.atomic_release_authorization_enabled {
        required_tokens.push(("release authorization token", &inputs.release_authorization_token));
        if inputs.release_authorization_base_url.is_none() {
            return Err("native atomic release authorization requires its base URL".to_owned());
        }
    } else {
        required_tokens.extend([
            ("grant consume token", &inputs.grant_consume_token),
            ("rate-limit consume token", &inputs.rate_limit_consume_token),
        ]);
        if inputs.grant_consume_url.is_none() {
            return Err("native production requires a grant consume URL without atomic release authorization".to_owned());
        }
    }
    if !pending_tokens { validate_internal_service_tokens(true, &required_tokens)?; }
    if measured && (inputs.audit_url.is_none() || inputs.audit_token.is_some()) {
        return Err("native v5 measured audit requires its URL and forbids a bearer token".to_owned());
    }
    if !measured && inputs.audit_url.is_some() != inputs.audit_token.is_some() {
        return Err("native audit URL and token must be supplied together".to_owned());
    }
    if inputs.credential_lease_url.is_none() {
        return Err("native bootstrap requires a credential broker URL".to_owned());
    }
    for (label, url, token) in [
        ("credential lease", &inputs.credential_lease_url, &inputs.credential_lease_token),
        ("grant consume", &inputs.grant_consume_url, &inputs.grant_consume_token),
        ("rate-limit consume", &inputs.rate_limit_consume_url, &inputs.rate_limit_consume_token),
        ("release authorization", &inputs.release_authorization_base_url, &inputs.release_authorization_token),
    ] {
        if !pending_tokens && url.is_some() && token.is_none() {
            return Err(format!("native {label} URL requires its service token"));
        }
    }

    if inputs.response_proof_attestation_command.is_some() {
        return Err("native bootstrap rejects an external response proof attestation command".to_owned());
    }
    let instance = inputs.server_instance_id.as_deref()
        .ok_or("native production requires a SPIFFE instance ID")?;
    if !canonical_spiffe_id(instance) {
        return Err("native production instance ID must be a canonical SPIFFE ID".to_owned());
    }
    for (name, value, minimum, maximum) in [
        ("grant cache", inputs.grant_cache_max, 1, 1_000_000),
        ("credential lease cache", inputs.credential_lease_cache_max, 1, 1_000_000),
        ("credential renewal workers", inputs.credential_lease_renewal_workers, 1, 32),
        ("credential renewal queue", inputs.credential_lease_renewal_queue_capacity, 1, 65_536),
        ("audit batch", inputs.audit_batch_max, 1, 200),
    ] {
        if !(minimum..=maximum).contains(&value) {
            return Err(format!("native {name} must be between {minimum} and {maximum}"));
        }
    }
    // Legacy main supplies positive sizes but defines no upper policy for these.
    if inputs.audit_queue_max == 0 || inputs.gmail_proof_cache_max == 0 {
        return Err("native audit queue and Gmail proof cache must be positive".to_owned());
    }
    for (name, value, minimum_ms, maximum_ms) in [
        ("credential renewal interval", inputs.credential_lease_renewal_interval, 50, 1_000),
        ("request head deadline", inputs.request_head_deadline, 100, 30_000),
        ("request body deadline", inputs.request_body_deadline, 1_000, 600_000),
        ("response write deadline", inputs.response_write_deadline, 1_000, 600_000),
    ] {
        if value < Duration::from_millis(minimum_ms)
            || value > Duration::from_millis(maximum_ms)
        {
            return Err(format!("native {name} must be between {minimum_ms} and {maximum_ms} milliseconds"));
        }
    }
    Ok(())
}
