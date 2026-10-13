//! Stable native settings and separately pinned per-launch originals.

use super::{bounded_absolute_path, ensure};
use super::super::*;
use super::super::native_startup::NativeStartupParametersV1;
use serverware_decision_gate::enclave_runtime_identity_v1::RuntimeScopeCommitmentsV1;
use serverware_decision_gate::native_upstream_relays_v1::NativeRelayAssignmentV1;
use base64::Engine as _;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LaunchV1 {
    api_version: String,
    release_record_sha256: String,
    configuration_sha256: String,
    pub(super) deadline_boottime_ns: u64,
    ca_not_before_unix_seconds: i64,
    ca_not_after_unix_seconds: i64,
    ingress_not_before_unix_seconds: i64,
    ingress_not_after_unix_seconds: i64,
    ingress_nonce_base64url: String,
    proof_nonce_base64url: String,
}

impl LaunchV1 {
    pub(super) fn validate(&self, configuration_pin: &str) -> Result<(), String> {
        ensure(self.api_version == "serverware.nativeStartupLaunch/v1"
            && self.configuration_sha256 == configuration_pin
            && is_sha256_digest(&self.release_record_sha256),
            "native launch version, configuration join or release reference differs")?;
        // Genuine runtime/device checks still enforce these times and original
        // lifetime. A caller's nonce/time/hash is not independent authority.
        nonce(&self.ingress_nonce_base64url)?;
        nonce(&self.proof_nonce_base64url)?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RelayV1 { host: String, endpoint: SocketAddr, parent_port: u32 }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkersV1 {
    proxy_workers: usize,
    proxy_queue_capacity: usize,
    policy_interval_ms: u64,
    audit_interval_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NativeSettingsV1 {
    ingress_host: String,
    ingress_client_roots_der_base64url: Vec<String>,
    control_plane_response_public_key_pem: String,
    control_plane_response_key_id: String,
    attempt_ledger_directory: PathBuf,
    relay_assignments: Vec<RelayV1>,
    listener_port: u32,
    expected_policy_signing_key_id: String,
    runtime: WorkersV1,
}

fn nonce(text: &str) -> Result<[u8; 32], String> {
    ensure(text.len() == 43, "native launch nonce must encode 32 bytes")?;
    let bytes = decode_canonical_base64url_exact(text, 32, "native launch nonce")?;
    let result: [u8; 32] = bytes.try_into().map_err(|_| "native launch nonce size differs")?;
    ensure(result != [0; 32], "native launch nonce must be nonzero")?;
    Ok(result)
}

fn timestamp(seconds: i64) -> Result<OffsetDateTime, String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| "native launch certificate time exceeds its range".to_owned())
}

impl NativeSettingsV1 {
    pub(super) fn listener_port(&self) -> u32 { self.listener_port }
    pub(super) fn into_parameters(self, launch: LaunchV1, configuration_pin: &str,
        checkpoint: &PolicyHighWater, control_plane_tls: ControlPlaneClientConfig,
        policy_bytes: Vec<u8>, enrollment: Option<super::EnrollmentParts>)
        -> Result<NativeStartupParametersV1, String>
    {
        ensure((1..=32).contains(&self.ingress_client_roots_der_base64url.len())
            && (1..=32).contains(&self.relay_assignments.len()),
            "native startup root or relay inventory exceeds its bound")?;
        let mut client_roots = Vec::new();
        let mut total = 0usize;
        for encoded in self.ingress_client_roots_der_base64url {
            ensure(!encoded.is_empty() && encoded.len() <= 87_382,
                "native ingress certificate encoding exceeds its bound")?;
            let der = general_purpose::URL_SAFE_NO_PAD.decode(&encoded)
                .map_err(|_| "native ingress certificate is not base64url")?;
            total = total.checked_add(der.len()).ok_or("native ingress root size overflow")?;
            ensure(!der.is_empty() && der.len() <= 64 * 1024 && total <= 1024 * 1024
                && general_purpose::URL_SAFE_NO_PAD.encode(&der) == encoded,
                "native ingress certificate encoding or size is invalid")?;
            client_roots.push(der);
        }
        ensure(!self.control_plane_response_public_key_pem.is_empty()
            && self.control_plane_response_public_key_pem.len() <= 4096,
            "native control-plane response public key exceeds its bound")?;
        let (response_key, response_key_id) = verifying_key_from_spki_pem_text(
            &self.control_plane_response_public_key_pem, "native startup control-plane response")?;
        ensure(response_key_id == self.control_plane_response_key_id,
            "native startup response public key differs from its key ID")?;
        let enrollment_authorizer = match enrollment {
            None => None,
            Some(super::EnrollmentParts { authorizer: original, endpoint, setup_authorizer }) => {
                ensure(original.api_version == "serverware.nativeEnrollmentAuthorizer/v1",
                    "native enrollment authorizer version differs")?;
                let authorizer = native_enrollment_authorizer::NativeEnrollmentAuthorizer::from_original(
                    original.public_key_pem.as_bytes(), &original.public_key_pem_sha256, &endpoint,
                    self.listener_port, &response_key, &self.expected_policy_signing_key_id,
                    launch.deadline_boottime_ns)?;
                Some(match setup_authorizer {
                    None => authorizer,
                    Some(setup) => {
                        ensure(setup.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                            "native enrollment setup authorizer version differs")?;
                        authorizer.with_setup_original(setup.public_key_pem.as_bytes(),
                            &setup.public_key_pem_sha256)?
                    },
                })
            },
        };
        bounded_absolute_path(&self.attempt_ledger_directory)?;
        let scope = RuntimeScopeCommitmentsV1::new(
            native_lease_digest_bytes(&launch.release_record_sha256)?,
            native_lease_digest_bytes(&checkpoint.policy_hash)?,
            native_lease_digest_bytes(configuration_pin)?)?;
        let runtime = NativeRuntimeSettingsV1::new(self.runtime.proxy_workers,
            self.runtime.proxy_queue_capacity, Duration::from_millis(self.runtime.policy_interval_ms),
            Duration::from_millis(self.runtime.audit_interval_ms))?;
        Ok(NativeStartupParametersV1 {
            scope, ca_not_before: timestamp(launch.ca_not_before_unix_seconds)?,
            ca_not_after: timestamp(launch.ca_not_after_unix_seconds)?,
            ingress_not_before: timestamp(launch.ingress_not_before_unix_seconds)?,
            ingress_not_after: timestamp(launch.ingress_not_after_unix_seconds)?,
            ingress_host: self.ingress_host, ingress_client_roots: client_roots,
            ingress_nonce: nonce(&launch.ingress_nonce_base64url)?,
            proof_nonce: nonce(&launch.proof_nonce_base64url)?,
            control_plane_response_key: response_key,
            control_plane_response_key_id: response_key_id,
            enrollment_authorizer,
            workload_trust: None,
            postboot_audit_port: None,
            postboot_jit_review_port: None,
            attempt_ledger_directory: self.attempt_ledger_directory,
            relay_assignments: self.relay_assignments.into_iter().map(|relay|
                NativeRelayAssignmentV1 { host: relay.host, endpoint: relay.endpoint,
                    parent_port: relay.parent_port }).collect(),
            listener_port: self.listener_port, policy_bytes,
            expected_policy_signing_key_id: self.expected_policy_signing_key_id,
            minimum_sequence: checkpoint.sequence, minimum_rollback_epoch: checkpoint.rollback_epoch,
            control_plane_tls, runtime, deadline_boottime_ns: launch.deadline_boottime_ns,
        })
    }
}
