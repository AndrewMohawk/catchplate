//! Explicit native launch configuration, not independent configuration admission.
//!
//! The static original is separately pinned from launch-specific nonces, times
//! and the release-record reference. Its actual byte hash is the configuration
//! scope commitment, avoiding a self-referential embedded configuration hash.

mod cli;
mod gate;
mod originals;
mod parameters;
mod shadow;
// Reuse the exact bounded duplicate-rejecting integer-only parser, not a
// second permissive configuration parser. It calls this module's ensure.
#[path = "../native_verifier/json.rs"]
mod json;

use super::*;
use originals::{ArtifactV1, HeldOriginal};
use std::os::unix::ffi::OsStrExt;
use std::path::Component;

const MAX_CONFIGURATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_LAUNCH_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 8 * 1024 * 1024;

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

fn bounded_absolute_path(path: &Path) -> Result<(), String> {
    let bytes = path.as_os_str().as_bytes();
    ensure(!bytes.is_empty() && bytes.len() <= 4096 && !bytes.contains(&0)
        && path.is_absolute() && path.file_name().is_some()
        && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "native configuration path must be bounded and absolute without traversal")?;
    // Component iteration normalizes dot/repeated separators; reject those
    // original spellings without consulting the filesystem here.
    let rebuilt: PathBuf = path.components().collect();
    ensure(rebuilt.as_os_str().as_bytes() == bytes,
        "native configuration path spelling is not canonical")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PinnedVerifierConfigV1 {
    executable: PathBuf,
    arguments: Vec<String>,
    sha256: String,
}

impl PinnedVerifierConfigV1 {
    fn into_command(self) -> Result<PinnedVerifierCommand, String> {
        bounded_absolute_path(&self.executable)?;
        ensure(is_sha256_digest(&self.sha256) && self.arguments.is_empty(),
            "native verifier requires a canonical pin and no command arguments")?;
        // Actual executable measurement/use remains with the existing owner.
        Ok(PinnedVerifierCommand { executable: self.executable,
            arguments: self.arguments, expected_sha256: self.sha256 })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV1 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentAuthorizerV1 {
    api_version: String,
    public_key_pem: String,
    public_key_pem_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV2 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV3 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
}

struct EnrollmentParts {
    authorizer: EnrollmentAuthorizerV1,
    endpoint: String,
    setup_authorizer: Option<EnrollmentAuthorizerV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV4 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV5 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::native_audit_transport::Configuration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV6 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV7 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_refresh: serverware_decision_gate::native_oauth_refresh_v1::Configuration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV8 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_refresh: serverware_decision_gate::native_oauth_refresh_v1::Configuration,
    guest_inspector: serverware_decision_gate::GuestInspectorConfiguration,
}

// This is only a source-local decomposition after exact version-specific
// decoding. It is never accepted as configuration or verification authority.
struct ConfigurationParts {
    guest_inspector: Option<serverware_decision_gate::GuestInspectorConfiguration>,
    measured_refresh: Option<serverware_decision_gate::native_oauth_refresh_v1::Configuration>,
    service_tokens: super::native_service_tokens::Source,
    secret_broker: Option<serverware_decision_gate::native_secret_broker_v1::Configuration>,
    measured_audit: Option<super::native_audit_transport::Configuration>,
    credential_currentness: Option<serverware_decision_gate::native_currentness_v1::Configuration>,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV1,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment: Option<EnrollmentParts>,
}

fn configuration(raw: &[u8], mode: cli::Mode) -> Result<ConfigurationParts, String> {
    let value = json::parse(raw, MAX_CONFIGURATION_BYTES)?;
    let version = value.get("apiVersion").and_then(Value::as_str);
    ensure(match mode {
        cli::Mode::Legacy => !matches!(version, Some("serverware.nativeStartupConfiguration/v6" | "serverware.nativeStartupConfiguration/v7" | "serverware.nativeStartupConfiguration/v8")),
        cli::Mode::EnclaveV5 => version == Some("serverware.nativeStartupConfiguration/v5"),
        cli::Mode::EncryptedV6 => version == Some("serverware.nativeStartupConfiguration/v6"),
        cli::Mode::MeasuredRefreshV7 => version == Some("serverware.nativeStartupConfiguration/v7"),
        cli::Mode::GuestInspectorV8 => version == Some("serverware.nativeStartupConfiguration/v8"),
    }, "native startup mode does not admit this configuration version")?;
    match value.get("apiVersion").and_then(Value::as_str) {
        Some("serverware.nativeStartupConfiguration/v1") => {
            let original: ConfigurationV1 = serde_json::from_value(value)
                .map_err(|_| "native v1 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v1",
                "native startup v1 configuration version differs")?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: None, service_tokens: super::native_service_tokens::Source::Legacy,
                secret_broker: None, measured_audit: None, credential_currentness: None, gate: original.gate, native: original.native,
                shadow: original.shadow, response_observation_v2: original.response_observation_v2,
                policy: original.policy, enrollment: None })
        },
        Some("serverware.nativeStartupConfiguration/v2") => {
            let original: ConfigurationV2 = serde_json::from_value(value)
                .map_err(|_| "native v2 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v2"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1",
                "native startup v2 authorizer version differs")?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: None, service_tokens: super::native_service_tokens::Source::Legacy,
                secret_broker: None, measured_audit: None, credential_currentness: None, gate: original.gate, native: original.native,
                shadow: original.shadow, response_observation_v2: original.response_observation_v2,
                policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint, setup_authorizer: None }) })
        },
        Some("serverware.nativeStartupConfiguration/v3") => {
            let original: ConfigurationV3 = serde_json::from_value(value)
                .map_err(|_| "native v3 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v3"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native startup v3 authorizer version differs")?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: None, service_tokens: super::native_service_tokens::Source::Legacy,
                secret_broker: None, measured_audit: None, credential_currentness: None, gate: original.gate, native: original.native,
                shadow: original.shadow, response_observation_v2: original.response_observation_v2,
                policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint,
                    setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        Some("serverware.nativeStartupConfiguration/v4") => {
            let original: ConfigurationV4 = serde_json::from_value(value)
                .map_err(|_| "native v4 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v4"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native startup v4 authorizer version differs")?;
            original.credential_currentness.validate()?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: None, service_tokens: super::native_service_tokens::Source::Legacy,
                secret_broker: None, measured_audit: None, credential_currentness: Some(original.credential_currentness),
                gate: original.gate, native: original.native, shadow: original.shadow,
                response_observation_v2: original.response_observation_v2, policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint,
                    setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        Some("serverware.nativeStartupConfiguration/v5") => {
            let original: ConfigurationV5 = serde_json::from_value(value)
                .map_err(|_| "native v5 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v5"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native startup v5 authorizer version differs")?;
            original.credential_currentness.validate()?;
            original.secret_broker.validate()?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: None, service_tokens: super::native_service_tokens::Source::Legacy,
                secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
                credential_currentness: Some(original.credential_currentness),
                gate: original.gate, native: original.native, shadow: original.shadow,
                response_observation_v2: original.response_observation_v2, policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint,
                    setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        Some("serverware.nativeStartupConfiguration/v8") => {
            let gate = value.get("gate").and_then(Value::as_object).ok_or("native v8 gate must be closed")?;
            for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
                "releaseAuthorizationToken", "managementToken", "auditToken"] {
                ensure(gate.get(name) == Some(&Value::Null), "native v8 requires explicit null plaintext bearer slots")?;
            }
            let original: ConfigurationV8 = serde_json::from_value(value)
                .map_err(|_| "native v8 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v8"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native v8 authorizer version differs")?;
            original.credential_currentness.validate()?;
            original.secret_broker.validate()?;
            original.measured_refresh.validate()?;
            original.guest_inspector.validate()?;
            Ok(ConfigurationParts { guest_inspector: Some(original.guest_inspector),
                measured_refresh: Some(original.measured_refresh),
                service_tokens: super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
                secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
                credential_currentness: Some(original.credential_currentness), gate: original.gate, native: original.native,
                shadow: original.shadow, response_observation_v2: original.response_observation_v2, policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint, setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        Some("serverware.nativeStartupConfiguration/v7") => {
            let gate = value.get("gate").and_then(Value::as_object).ok_or("native v7 gate must be closed")?;
            for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
                "releaseAuthorizationToken", "managementToken", "auditToken"] {
                ensure(gate.get(name) == Some(&Value::Null), "native v7 requires explicit null plaintext bearer slots")?;
            }
            let original: ConfigurationV7 = serde_json::from_value(value).map_err(|_|"native v7 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v7"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native v7 authorizer version differs")?;
            original.credential_currentness.validate()?; original.secret_broker.validate()?; original.measured_refresh.validate()?;
            Ok(ConfigurationParts { guest_inspector: None, measured_refresh: Some(original.measured_refresh),
                service_tokens: super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
                secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
                credential_currentness: Some(original.credential_currentness), gate: original.gate, native: original.native,
                shadow: original.shadow, response_observation_v2: original.response_observation_v2, policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint, setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        Some("serverware.nativeStartupConfiguration/v6") => {
            let gate = value.get("gate").and_then(Value::as_object)
                .ok_or("native v6 gate must be a closed object")?;
            for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
                "releaseAuthorizationToken", "managementToken", "auditToken"] {
                ensure(gate.get(name) == Some(&Value::Null),
                    "native v6 requires every plaintext bearer slot explicitly null")?;
            }
            let original: ConfigurationV6 = serde_json::from_value(value)
                .map_err(|_| "native v6 configuration violates its closed contract")?;
            ensure(original.api_version == "serverware.nativeStartupConfiguration/v6"
                && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
                && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
                "native startup v6 authorizer version differs")?;
            original.credential_currentness.validate()?;
            original.secret_broker.validate()?;
            Ok(ConfigurationParts {
                guest_inspector: None,
                measured_refresh: None,
                service_tokens: super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
                secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
                credential_currentness: Some(original.credential_currentness),
                gate: original.gate, native: original.native, shadow: original.shadow,
                response_observation_v2: original.response_observation_v2, policy: original.policy,
                enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
                    endpoint: original.enrollment_proxy_endpoint,
                    setup_authorizer: Some(original.enrollment_setup_authorizer) }) })
        },
        _ => Err("native startup configuration version differs".to_owned()),
    }
}

fn decode<T: DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T, String> {
    let value = json::parse(raw, maximum)?;
    // Never include serde's input-value diagnostics: configuration can contain
    // service tokens. Field names and the closed contract are documented.
    serde_json::from_value(value)
        .map_err(|_| "native configuration does not match its closed JSON contract".to_owned())
}

fn run(configuration: ArtifactV1, launch: ArtifactV1, public_identity_stdout: bool, mode: cli::Mode) -> Result<(), String> {
    let configuration_pin = configuration.sha256.clone();
    let (mut configuration_original, raw_configuration) =
        HeldOriginal::read(configuration, MAX_CONFIGURATION_BYTES)?;
    let raw_configuration = zeroize::Zeroizing::new(raw_configuration);
    configuration_original.require_private()?;
    let configuration = self::configuration(&raw_configuration, mode)?;
    let (mut launch_original, raw_launch) = HeldOriginal::read(launch, MAX_LAUNCH_BYTES)?;
    let launch: parameters::LaunchV1 = decode(&raw_launch, MAX_LAUNCH_BYTES)?;
    launch.validate(&configuration_pin)?;
    let lifetime = NativeRuntimeLifetimeV1::new(launch.deadline_boottime_ns)?;
    let allow_guest_listener = matches!(&configuration.service_tokens, super::native_service_tokens::Source::Pending(_));
    let (mut inputs, control_plane_tls) = configuration.gate.into_inputs(configuration.secret_broker,
        configuration.measured_audit, configuration.measured_refresh, configuration.service_tokens)?;
    inputs.credential_currentness = configuration.credential_currentness;
    let v2 = configuration.response_observation_v2.into_config(allow_guest_listener)?;
    let shadow = configuration.shadow.into_config()?;
    lifetime.check()?;
    let (mut policy_original, policy_bytes) = HeldOriginal::read(configuration.policy, MAX_POLICY_BYTES)?;
    let parameters = configuration.native.into_parameters(launch, &configuration_pin,
        &inputs.policy_high_water, control_plane_tls, policy_bytes, configuration.enrollment)?;
    // Parsing consumes exact retained originals. Recheck the three names and
    // held byte hashes immediately before handing off to actual startup; this
    // is local input integrity, not signed/current release admission.
    configuration_original.recheck()?;
    configuration_original.require_private()?;
    launch_original.recheck()?;
    policy_original.recheck()?;
    lifetime.check()?;
    drop(raw_configuration);
    // Owners remain in this frame through serving. Runtime policy uses the
    // retained parsed bytes; it does not periodically reopen the policy path.
    super::native_startup::run(inputs, parameters, shadow, v2, configuration.guest_inspector, public_identity_stdout)
}

pub(super) fn run_from_process_arguments() -> Result<Option<()>, String> {
    match cli::arguments(std::env::args_os().skip(1))? {
        None => Ok(None),
        Some((configuration, launch, public_identity_stdout, mode)) =>
            run(configuration, launch, public_identity_stdout, mode).map(Some),
    }
}
