//! Closed configuration data for explicit native response-v2 startup.
//!
//! JSON fields: apiVersion (serverware.nativeResponseObservationV2Config/v1),
//! socketPath, expectedUid, startupTimeoutMs, signerKeySha256,
//! roleIdentityRootSha256, proofPinsRootSha256, teeVerifier,
//! transparencyTrustPin, roleKeys (an array), generationId,
//! expectedSourceCommitSha256, expectedSourceTreeSha256,
//! expectedProviderGeneration, expectedTrustRootSha256,
//! expectedTrustCheckpointSha256, and minimumRevocationEpoch. The three
//! expected provider/trust fields are optional; the remaining fields are
//! required. Nested objects retain their existing closed schemas.
//!
//! The enclosing original parser must reject duplicate keys, floats, excess
//! bytes/depth/nodes before serde. Conversion forces hardware/local-1-of-1
//! configuration; it does not open files, contact services, invoke NSM, create
//! threads or manufacture a client. Actual peer custody and authenticated
//! hello/TEE/release/trust admission remain in the later startup constructor.
//! Additive v2 requires guestListener and the fixed guest socket path; only an
//! actual cold Pending encrypted-service-token source permits it. Old v1 forbids the new field,
//! including explicit null, and never falls back after guest admission fails.

use super::{
    validate_response_observation_v2_client_config,
    ReleaseTransparencyTrustPinV2, ResponseObservationV2ClientConfig,
    ResponseObservationV2TeeTopologyProfile, ResponseV2PinnedTeeVerifier,
    V2AttestationMode, V2PinnedRoleKeyV1,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = "serverware.nativeResponseObservationV2Config/v1";
const MAX_ROLES: usize = 256;
const MAX_OPERATIONS_PER_ROLE: usize = 256;
const MAX_ROLE_TEXT_BYTES: usize = 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NativeResponseObservationV2ConfigV1 {
    api_version: String,
    #[serde(default, deserialize_with = "guest_profile")]
    guest_listener: Option<serverware_decision_gate::GuestResponseV2ListenerProfile>,
    socket_path: PathBuf,
    expected_uid: libc::uid_t,
    startup_timeout_ms: u64,
    signer_key_sha256: String,
    role_identity_root_sha256: String,
    proof_pins_root_sha256: String,
    tee_verifier: ResponseV2PinnedTeeVerifier,
    transparency_trust_pin: ReleaseTransparencyTrustPinV2,
    role_keys: Vec<V2PinnedRoleKeyV1>,
    generation_id: String,
    expected_source_commit_sha256: String,
    expected_source_tree_sha256: String,
    expected_provider_generation: Option<u64>,
    expected_trust_root_sha256: Option<String>,
    expected_trust_checkpoint_sha256: Option<String>,
    minimum_revocation_epoch: u64,
}

impl NativeResponseObservationV2ConfigV1 {
    pub(super) fn into_config(self, allow_guest: bool) -> Result<ResponseObservationV2ClientConfig, String> {
        let selected = match self.api_version.as_str() {
            VERSION => self.guest_listener.is_none(),
            "serverware.nativeResponseObservationV2Config/v2" => allow_guest && self.guest_listener.is_some(),
            _ => false,
        };
        if !selected
            || self.role_keys.is_empty()
            || self.role_keys.len() > MAX_ROLES
        {
            return Err("native response-v2 config version or role count is invalid".to_owned());
        }
        // Bound the typed collection before shared validation clones/sorts
        // operation lists or decodes public keys. These are resource ceilings,
        // not an alternate role or signature admission path.
        let mut remaining = MAX_ROLE_TEXT_BYTES;
        let mut role_keys = BTreeMap::new();
        for pin in self.role_keys {
            for value in [&pin.role, &pin.generation_id, &pin.provider_id] {
                account_text(value, MAX_IDENTIFIER_BYTES, &mut remaining)?;
            }
            for value in [
                &pin.key_id, &pin.key_material_sha256, &pin.key_material_path,
                &pin.executable_measurement_sha256, &pin.executable_path,
                &pin.provider_config_sha256, &pin.provider_config_path,
                &pin.tee_measurement_sha256, &pin.public_key_base64,
                &pin.public_key_sha256,
            ] {
                account_text(value, MAX_FIELD_BYTES, &mut remaining)?;
            }
            if pin.allowed_operations.len() > MAX_OPERATIONS_PER_ROLE {
                return Err("native response-v2 role operation count exceeds its bound".to_owned());
            }
            for operation in &pin.allowed_operations {
                account_text(operation, MAX_IDENTIFIER_BYTES, &mut remaining)?;
            }
            if role_keys.insert(pin.role.clone(), pin).is_some() {
                return Err("native response-v2 config repeats an authority role".to_owned());
            }
        }
        // Existing typed transparency and verifier validators retain all of
        // their semantic checks; cap their variable inputs before decoding.
        let pin = &self.transparency_trust_pin;
        for value in [
            &pin.api_version, &pin.kind, &pin.schema_version, &pin.generation_id,
            &pin.proof_pins_root_sha256, &pin.log_id, &pin.log_key_id,
            &pin.log_key_spki_base64, &pin.log_key_spki_sha256,
            &pin.anchor_root_sha256, &pin.trust_checkpoint_sha256,
        ] {
            if value.len() > MAX_FIELD_BYTES {
                return Err("native response-v2 transparency field exceeds its bound".to_owned());
            }
        }
        if self.tee_verifier.executable.as_os_str().len() > MAX_FIELD_BYTES {
            return Err("native response-v2 verifier path exceeds its bound".to_owned());
        }
        for input in [
            self.tee_verifier.verifier_module.as_ref(),
            Some(&self.tee_verifier.expectations),
            Some(&self.tee_verifier.trust_roots),
        ].into_iter().flatten() {
            if input.path.as_os_str().len() > MAX_FIELD_BYTES {
                return Err("native response-v2 verifier input path exceeds its bound".to_owned());
            }
        }
        let config = ResponseObservationV2ClientConfig {
            socket_path: self.socket_path,
            guest_listener: self.guest_listener,
            expected_uid: self.expected_uid,
            startup_timeout: Duration::from_millis(self.startup_timeout_ms),
            attestation_mode: V2AttestationMode::TeeHardware,
            signer_key_sha256: self.signer_key_sha256,
            role_identity_root_sha256: self.role_identity_root_sha256,
            proof_pins_root_sha256: self.proof_pins_root_sha256,
            tee_verifier: Some(self.tee_verifier),
            tee_topology_profile: Some(
                ResponseObservationV2TeeTopologyProfile::LocalSingleNodeOneOfOne,
            ),
            transparency_trust_pin: Arc::new(self.transparency_trust_pin),
            role_keys: Arc::new(role_keys),
            generation_id: self.generation_id,
            expected_source_commit_sha256: self.expected_source_commit_sha256,
            expected_source_tree_sha256: self.expected_source_tree_sha256,
            expected_provider_generation: self.expected_provider_generation,
            expected_trust_root_sha256: self.expected_trust_root_sha256,
            expected_trust_checkpoint_sha256: self.expected_trust_checkpoint_sha256,
            minimum_revocation_epoch: self.minimum_revocation_epoch,
        };
        if config.guest_listener.is_some() {
            super::validate_response_observation_v2_client_config_for_native_serving(&config)?;
        } else { validate_response_observation_v2_client_config(&config)?; }
        Ok(config)
    }
}

fn guest_profile<'de, D: serde::Deserializer<'de>>(deserializer: D)
    -> Result<Option<serverware_decision_gate::GuestResponseV2ListenerProfile>, D::Error> {
    // Absence selects old v1; explicit null never widens that closed profile.
    serverware_decision_gate::GuestResponseV2ListenerProfile::deserialize(deserializer).map(Some)
}

fn account_text(value: &str, maximum: usize, remaining: &mut usize) -> Result<(), String> {
    if value.len() > maximum || value.len() > *remaining {
        return Err("native response-v2 role text exceeds its bound".to_owned());
    }
    *remaining -= value.len();
    Ok(())
}
