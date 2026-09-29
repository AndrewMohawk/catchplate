//! Closed opt-in native mode; no arguments retains the legacy entrypoint.

use super::originals::ArtifactV1;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) enum Mode { Legacy, EnclaveV5, EncryptedV6, MeasuredRefreshV7, GuestInspectorV8 }

pub(super) fn arguments(mut arguments: impl Iterator<Item = OsString>)
    -> Result<Option<(ArtifactV1, ArtifactV1, bool, Mode)>, String>
{
    let Some(argument) = arguments.next() else { return Ok(None); };
    let mode = if argument == "--native-startup" { Mode::Legacy }
        else if argument == "--native-enclave-startup" { Mode::EnclaveV5 }
        else if argument == "--native-encrypted-startup" { Mode::EncryptedV6 }
        else if argument == "--native-measured-refresh-startup" { Mode::MeasuredRefreshV7 }
        else if argument == "--native-startup-inspector-v8" { Mode::GuestInspectorV8 }
        else { return Err("decision gate accepts no arguments or an explicit native startup mode".to_owned()); };
    let mut configuration = None;
    let mut configuration_pin = None;
    let mut launch = None;
    let mut launch_pin = None;
    let mut public_identity_stdout = false;
    while let Some(flag) = arguments.next() {
        let flag = flag.to_str().ok_or("native startup flag must be UTF-8")?;
        if flag == "--public-identity-stdout" {
            if public_identity_stdout {
                return Err("native startup received an unknown or repeated flag".to_owned());
            }
            public_identity_stdout = true;
            continue;
        }
        let value = arguments.next().ok_or("native startup flag requires a value")?;
        match flag {
            "--configuration" if configuration.is_none() => configuration = Some(PathBuf::from(value)),
            "--configuration-sha256" if configuration_pin.is_none() => {
                configuration_pin = Some(value.into_string().map_err(|_| "native configuration pin must be UTF-8")?);
            }
            "--launch" if launch.is_none() => launch = Some(PathBuf::from(value)),
            "--launch-sha256" if launch_pin.is_none() => {
                launch_pin = Some(value.into_string().map_err(|_| "native launch pin must be UTF-8")?);
            }
            _ => return Err("native startup received an unknown or repeated flag".to_owned()),
        }
    }
    Ok(Some((ArtifactV1 {
        path: configuration.ok_or("native startup requires --configuration")?,
        sha256: configuration_pin.ok_or("native startup requires --configuration-sha256")?,
    }, ArtifactV1 {
        path: launch.ok_or("native startup requires --launch")?,
        sha256: launch_pin.ok_or("native startup requires --launch-sha256")?,
    }, public_identity_stdout, mode)))
}
