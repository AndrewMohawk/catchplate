//! Closed, ordinary configuration for a cold production gate, not admission.
//!
//! The wire uses camelCase, with required `policyHighWater` and `policyTrust`
//! objects; the latter contains an explicit pinned `verifier`. Cache/queue
//! sizes are integer counts, and all four interval/deadline fields end in `Ms`.
//! Service URLs/tokens use the matching GateStateInputs names. Required service
//! strings are `credentialLeaseUrl`, `credentialLeaseToken`, `managementToken`
//! and `instanceId`. Conditional service URL/token fields and both TLS-root
//! lists may be omitted/null; no other configuration values have defaults.
//! V6's separate outer parser requires every bearer slot explicitly null and
//! supplies the actual encrypted-envelope state. The common internal shape
//! accepts those nulls only under that mode; v1-v5 retain their strings.
//!
//! `controlPlaneTlsRootsPem` replaces built-in roots when supplied, whereas
//! `upstreamTlsRootsPem` adds roots, preserving the existing client contracts.
//! Each supplied list is nonempty and bounded. Neither a supplied root nor
//! `expectedBinarySha256` proves its provenance or actual runtime measurement.
//! Filesystem policy/checkpoint/evidence inputs, imported keys, external proof
//! commands, runtime owners and development mode cannot be represented here.
//! Conversion performs only in-memory checks, including the existing native
//! production validator; actual startup performs the remaining owner joins.

use super::PinnedVerifierConfigV1;
use super::super::{
    is_sha256_digest, pem_certificates, ControlPlaneAttestationVerifier,
    ControlPlaneClientConfig, GateStateInputs, PolicyHighWater,
    PolicyTrustRootSource, UpstreamClientConfig,
    MAX_INTERNAL_SERVICE_TOKEN_FILE_BYTES,
};
use super::super::native_gate_inputs::validate_native_gate_static_inputs;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::time::Duration;

const MAX_TLS_ROOTS: usize = 32;
const MAX_TLS_ROOT_BYTES: usize = 64 * 1024;
const MAX_TLS_ROOT_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_POLICY_ID_BYTES: usize = 256;
const MAX_INSTANCE_ID_BYTES: usize = 4096;
const MAX_COLD_CACHE_ENTRIES: usize = 1_000_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GateConfigV1 {
    policy_high_water: PolicyHighWaterConfigV1,
    policy_trust: PolicyTrustConfigV1,
    expected_binary_sha256: String,
    instance_id: String,
    grant_cache_max: usize,
    gmail_proof_cache_max: usize,
    credential_lease_url: String,
    #[serde(deserialize_with = "required_token")]
    credential_lease_token: Option<String>,
    credential_lease_renewal_interval_ms: u64,
    credential_lease_renewal_workers: usize,
    credential_lease_renewal_queue_capacity: usize,
    credential_lease_cache_max: usize,
    control_plane_tls_roots_pem: Option<Vec<String>>,
    upstream_tls_roots_pem: Option<Vec<String>>,
    audit_url: Option<String>,
    audit_token: Option<String>,
    grant_consume_url: Option<String>,
    grant_consume_token: Option<String>,
    rate_limit_consume_url: Option<String>,
    rate_limit_consume_token: Option<String>,
    atomic_release_authorization_enabled: bool,
    release_authorization_base_url: Option<String>,
    release_authorization_token: Option<String>,
    #[serde(deserialize_with = "required_token")]
    management_token: Option<String>,
    audit_queue_max: usize,
    audit_batch_max: usize,
    request_head_deadline_ms: u64,
    request_body_deadline_ms: u64,
    response_write_deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyHighWaterConfigV1 {
    api_version: String,
    policy_id: String,
    sequence: u64,
    rollback_epoch: u64,
    policy_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyTrustConfigV1 {
    url: String,
    expected_quote_key_id: Option<String>,
    verifier: PinnedVerifierConfigV1,
}

impl GateConfigV1 {
    pub(super) fn into_inputs(self,
        secret_broker: Option<serverware_decision_gate::native_secret_broker_v1::Configuration>,
        measured_audit: Option<super::super::native_audit_transport::Configuration>,
        measured_refresh: Option<serverware_decision_gate::native_oauth_refresh_v1::Configuration>,
        service_tokens: super::super::native_service_tokens::Source)
        -> Result<(GateStateInputs, ControlPlaneClientConfig), String>
    {
        // The common in-memory shape permits null only after the separate
        // closed v6 parser selected a real encrypted envelope. Legacy wire
        // versions still require both original non-null strings.
        if matches!(&service_tokens, super::super::native_service_tokens::Source::Legacy)
            && (self.credential_lease_token.is_none() || self.management_token.is_none()) {
            return Err("legacy native startup requires its plaintext service token strings".to_owned());
        }
        if !is_sha256_digest(&self.expected_binary_sha256)
            || self.instance_id.is_empty() || self.instance_id.len() > MAX_INSTANCE_ID_BYTES
            || !(1..=MAX_COLD_CACHE_ENTRIES).contains(&self.gmail_proof_cache_max)
            || !(1..=MAX_COLD_CACHE_ENTRIES).contains(&self.audit_queue_max)
        {
            return Err("native gate binary pin, instance or cache bounds are invalid".to_owned());
        }
        for token in [
            self.credential_lease_token.as_deref(),
            self.audit_token.as_deref(),
            self.grant_consume_token.as_deref(),
            self.rate_limit_consume_token.as_deref(),
            self.release_authorization_token.as_deref(),
            self.management_token.as_deref(),
        ].into_iter().flatten() {
            if token.is_empty() || token.len() as u64 > MAX_INTERNAL_SERVICE_TOKEN_FILE_BYTES
                || token.chars().any(|value| value.is_whitespace() || value.is_control())
            {
                return Err("native gate service token exceeds its bound or contains whitespace/control characters".to_owned());
            }
        }
        let high_water = self.policy_high_water;
        if high_water.api_version != "serverware.policyHighWater/v1"
            || high_water.policy_id.is_empty()
            || high_water.policy_id.len() > MAX_POLICY_ID_BYTES
            || high_water.policy_id.trim() != high_water.policy_id
            || high_water.policy_id.chars().any(char::is_control)
            || high_water.sequence == 0 || high_water.rollback_epoch == 0
            || !is_sha256_digest(&high_water.policy_hash)
        {
            return Err("native gate supplied policy checkpoint is malformed".to_owned());
        }
        if self.policy_trust.expected_quote_key_id.as_deref()
            .is_some_and(|value| !is_sha256_digest(value))
        {
            return Err("native gate control-plane quote key pin is malformed".to_owned());
        }
        let control_plane_config = match tls_roots(
            self.control_plane_tls_roots_pem, "control-plane",
        )? {
            None => ControlPlaneClientConfig::builtin(),
            Some((text, _)) => ControlPlaneClientConfig::from_pem(&text)?,
        };
        let root_certificates = match tls_roots(self.upstream_tls_roots_pem, "upstream")? {
            None => Vec::new(),
            Some((_, certificates)) => certificates,
        };
        let inputs = GateStateInputs {
            service_tokens,
            native_serving_privileges: None,
            prepared_secret_broker: None,
            secret_broker,
            measured_refresh,
            measured_audit,
            credential_currentness: None,
            policy_shadow_generation_control: None,
            policy_path: String::new(),
            policy_trust_root_source: PolicyTrustRootSource::AttestedControlPlane {
                url: self.policy_trust.url,
                expected_quote_key_id: self.policy_trust.expected_quote_key_id,
                verifier: Some(ControlPlaneAttestationVerifier::Pinned(
                    self.policy_trust.verifier.into_command()?,
                )),
                native_transport: None,
            },
            initial_policy_mtime: None,
            initial_release_evidence_mtimes: (None, None),
            policy_high_water_path: None,
            policy_high_water: PolicyHighWater {
                api_version: high_water.api_version,
                policy_id: high_water.policy_id,
                sequence: high_water.sequence,
                rollback_epoch: high_water.rollback_epoch,
                policy_hash: high_water.policy_hash,
            },
            grant_cache_max: self.grant_cache_max,
            gmail_proof_cache_max: self.gmail_proof_cache_max,
            credential_lease_url: Some(self.credential_lease_url),
            credential_lease_recipient_attestation_command: None,
            credential_lease_renewal_interval:
                Duration::from_millis(self.credential_lease_renewal_interval_ms),
            credential_lease_renewal_workers: self.credential_lease_renewal_workers,
            credential_lease_renewal_queue_capacity: self.credential_lease_renewal_queue_capacity,
            credential_lease_cache_max: self.credential_lease_cache_max,
            upstream_client_config: UpstreamClientConfig { root_certificates },
            audit_url: self.audit_url,
            credential_lease_token: self.credential_lease_token,
            audit_token: self.audit_token,
            grant_consume_url: self.grant_consume_url,
            grant_consume_token: self.grant_consume_token,
            rate_limit_consume_url: self.rate_limit_consume_url,
            rate_limit_consume_token: self.rate_limit_consume_token,
            is_production: true,
            atomic_release_authorization_enabled: self.atomic_release_authorization_enabled,
            release_authorization_base_url: self.release_authorization_base_url,
            release_authorization_token: self.release_authorization_token,
            management_token: self.management_token,
            audit_queue_max: self.audit_queue_max,
            audit_batch_max: self.audit_batch_max,
            request_head_deadline: Duration::from_millis(self.request_head_deadline_ms),
            request_body_deadline: Duration::from_millis(self.request_body_deadline_ms),
            response_write_deadline: Duration::from_millis(self.response_write_deadline_ms),
            binary_digest: self.expected_binary_sha256,
            release_provenance_path: None,
            image_signatures_path: None,
            response_proof_attestation_command: None,
            server_instance_id: Some(self.instance_id),
            response_observation_v2_client: None,
        };
        validate_native_gate_static_inputs(&inputs)?;
        Ok((inputs, control_plane_config))
    }
}

fn required_token<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

fn tls_roots(originals: Option<Vec<String>>, label: &str)
    -> Result<Option<(String, Vec<reqwest::Certificate>)>, String>
{
    let Some(originals) = originals else { return Ok(None); };
    if originals.is_empty() || originals.len() > MAX_TLS_ROOTS {
        return Err(format!("native {label} roots must contain 1..32 PEM certificates"));
    }
    let mut total = 0usize;
    let mut distinct = BTreeSet::new();
    let mut text = String::new();
    let mut certificates = Vec::with_capacity(originals.len());
    for original in originals {
        total = total.checked_add(original.len())
            .ok_or("native TLS root size overflow")?;
        if original.is_empty() || original.len() > MAX_TLS_ROOT_BYTES
            || total > MAX_TLS_ROOT_TOTAL_BYTES || !original.is_ascii()
        {
            return Err(format!("native {label} PEM root inventory exceeds its bounds"));
        }
        let extracted = pem_certificates(&original);
        // Accept only one explicit certificate and surrounding ASCII whitespace,
        // not PEM keys, ignored text, nested blocks or an unfinished second root.
        let normalized = original.replace("\r\n", "\n");
        if extracted.len() != 1
            || normalized.trim() != std::str::from_utf8(&extracted[0])
                .map_err(|_| "native PEM certificate is not ASCII")?.trim()
            || !distinct.insert(extracted[0].clone())
        {
            return Err(format!("native {label} root is not one distinct complete PEM certificate"));
        }
        certificates.push(reqwest::Certificate::from_pem(&extracted[0])
            .map_err(|_| format!("native {label} root certificate cannot be parsed"))?);
        text.push_str(std::str::from_utf8(&extracted[0])
            .map_err(|_| "native PEM certificate is not ASCII")?);
    }
    Ok(Some((text, certificates)))
}
