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

fn decode<T: DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T, String> {
    let value = json::parse(raw, maximum)?;
    // Never include serde's input-value diagnostics: configuration can contain
    // service tokens. Field names and the closed contract are documented.
    serde_json::from_value(value)
        .map_err(|_| "native configuration does not match its closed JSON contract".to_owned())
}

fn run(configuration: ArtifactV1, launch: ArtifactV1) -> Result<(), String> {
    let configuration_pin = configuration.sha256.clone();
    let (mut configuration_original, raw_configuration) =
        HeldOriginal::read(configuration, MAX_CONFIGURATION_BYTES)?;
    let raw_configuration = zeroize::Zeroizing::new(raw_configuration);
    configuration_original.require_private()?;
    let configuration: ConfigurationV1 = decode(&raw_configuration, MAX_CONFIGURATION_BYTES)?;
    ensure(configuration.api_version == "serverware.nativeStartupConfiguration/v1",
        "native startup configuration version differs")?;
    let (mut launch_original, raw_launch) = HeldOriginal::read(launch, MAX_LAUNCH_BYTES)?;
    let launch: parameters::LaunchV1 = decode(&raw_launch, MAX_LAUNCH_BYTES)?;
    launch.validate(&configuration_pin)?;
    let lifetime = NativeRuntimeLifetimeV1::new(launch.deadline_boottime_ns)?;
    let (inputs, control_plane_tls) = configuration.gate.into_inputs()?;
    let v2 = configuration.response_observation_v2.into_config()?;
    let shadow = configuration.shadow.into_config()?;
    lifetime.check()?;
    let (mut policy_original, policy_bytes) = HeldOriginal::read(configuration.policy, MAX_POLICY_BYTES)?;
    let parameters = configuration.native.into_parameters(launch, &configuration_pin,
        &inputs.policy_high_water, control_plane_tls, policy_bytes)?;
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
    super::native_startup::run(inputs, parameters, shadow, v2)
}

pub(super) fn run_from_process_arguments() -> Result<Option<()>, String> {
    match cli::arguments(std::env::args_os().skip(1))? {
        None => Ok(None),
        Some((configuration, launch)) => run(configuration, launch).map(Some),
    }
}
