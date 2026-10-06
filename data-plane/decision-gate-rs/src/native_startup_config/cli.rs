//! Closed opt-in native mode; no arguments retains the legacy entrypoint.

use super::originals::ArtifactV1;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) enum Mode { Legacy, EnclaveV5, EncryptedV6, MeasuredRefreshV7, GuestInspectorV8, MeasuredIssuanceV9, GuestCohortV10, MeasuredCleanupV11, GuestRoleKeysV12, MeasuredPendingRetirementV13, GateCgroupV14, MeasuredSetupV15, MeasuredCaptureRetirementV16, MeasuredReconnectV17, MeasuredSuccessionV18, MeasuredCanaryDeliveryV19, NativeHeartbeatV20, NativeReadinessV21, WorkloadTrustV22, StaticCredentialV23 }

pub(super) fn arguments(mut arguments: impl Iterator<Item = OsString>)
    -> Result<Option<(ArtifactV1, ArtifactV1, bool, bool, Mode, Option<ArtifactV1>)>, String>
{
    let Some(argument) = arguments.next() else { return Ok(None); };
    let mode = if argument == "--native-startup" { Mode::Legacy }
        else if argument == "--native-enclave-startup" { Mode::EnclaveV5 }
        else if argument == "--native-encrypted-startup" { Mode::EncryptedV6 }
        else if argument == "--native-measured-refresh-startup" { Mode::MeasuredRefreshV7 }
        else if argument == "--native-startup-inspector-v8" { Mode::GuestInspectorV8 }
        else if argument == "--native-measured-issuance-startup-v9" { Mode::MeasuredIssuanceV9 }
        else if argument == "--native-guest-cohort-startup-v10" { Mode::GuestCohortV10 }
        else if argument == "--native-measured-cleanup-startup-v11" { Mode::MeasuredCleanupV11 }
        else if argument == "--native-guest-role-keys-startup-v12" { Mode::GuestRoleKeysV12 }
        else if argument == "--native-measured-pending-retirement-startup-v13" { Mode::MeasuredPendingRetirementV13 }
        else if argument == "--native-gate-cgroup-startup-v14" { Mode::GateCgroupV14 }
        else if argument == "--native-measured-setup-startup-v15" { Mode::MeasuredSetupV15 }
        else if argument == "--native-measured-capture-retirement-startup-v16" { Mode::MeasuredCaptureRetirementV16 }
        else if argument == "--native-measured-reconnect-startup-v17" { Mode::MeasuredReconnectV17 }
        else if argument == "--native-measured-succession-startup-v18" { Mode::MeasuredSuccessionV18 }
        else if argument == "--native-measured-canary-delivery-startup-v19" { Mode::MeasuredCanaryDeliveryV19 }
        else if argument == "--native-canary-heartbeat-startup-v20" { Mode::NativeHeartbeatV20 }
        else if argument == "--native-canary-readiness-startup-v21" { Mode::NativeReadinessV21 }
        else if argument == "--native-workload-trust-startup-v22" { Mode::WorkloadTrustV22 }
        else if argument == "--native-static-credential-startup-v23" { Mode::StaticCredentialV23 }
        else { return Err("decision gate accepts no arguments or an explicit native startup mode".to_owned()); };
    let mut configuration = None;
    let mut configuration_pin = None;
    let mut launch = None;
    let mut launch_pin = None;
    let mut public_identity_stdout = false;
    let mut response_proof_identity_stdout = false;
    let mut trust_authorization = None;
    let mut trust_pin = None;
    while let Some(flag) = arguments.next() {
        let flag = flag.to_str().ok_or("native startup flag must be UTF-8")?;
        if flag == "--public-identity-stdout" {
            if public_identity_stdout {
                return Err("native startup received an unknown or repeated flag".to_owned());
            }
            public_identity_stdout = true;
            continue;
        }
        if flag == "--response-proof-identity-stdout" {
            if response_proof_identity_stdout {
                return Err("native startup received an unknown or repeated flag".to_owned());
            }
            response_proof_identity_stdout = true;
            continue;
        }
        let value = arguments.next().ok_or("native startup flag requires a value")?;
        match flag {
            "--workload-trust-authorization" if matches!(&mode, Mode::WorkloadTrustV22)
                && trust_authorization.is_none() => trust_authorization = Some(PathBuf::from(value)),
            "--workload-trust-authorization-sha256" if matches!(&mode, Mode::WorkloadTrustV22)
                && trust_pin.is_none() => trust_pin = Some(value.into_string()
                    .map_err(|_| "native workload trust pin must be UTF-8")?),
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
    let trust = if matches!(&mode, Mode::WorkloadTrustV22) {
        Some(ArtifactV1 {
            path: trust_authorization.ok_or("native v22 requires --workload-trust-authorization")?,
            sha256: trust_pin.ok_or("native v22 requires --workload-trust-authorization-sha256")?,
        })
    } else { None };
    Ok(Some((ArtifactV1 {
        path: configuration.ok_or("native startup requires --configuration")?,
        sha256: configuration_pin.ok_or("native startup requires --configuration-sha256")?,
    }, ArtifactV1 {
        path: launch.ok_or("native startup requires --launch")?,
        sha256: launch_pin.ok_or("native startup requires --launch-sha256")?,
    }, public_identity_stdout, response_proof_identity_stdout, mode, trust)))
}
