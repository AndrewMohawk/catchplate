//! Closed opt-in native mode; no arguments retains the legacy entrypoint.

use super::originals::ArtifactV1;
use crate::native_public_identity::ResponseProofIdentityExport;
use std::ffi::OsString;
use std::path::PathBuf;

pub(super) enum Mode { Legacy, EnclaveV5, EncryptedV6, MeasuredRefreshV7, GuestInspectorV8, MeasuredIssuanceV9, GuestCohortV10, MeasuredCleanupV11, GuestRoleKeysV12, MeasuredPendingRetirementV13, GateCgroupV14, MeasuredSetupV15, MeasuredCaptureRetirementV16, MeasuredReconnectV17, MeasuredSuccessionV18, MeasuredCanaryDeliveryV19, NativeHeartbeatV20, NativeReadinessV21, WorkloadTrustV22, StaticCredentialV23, PostbootStaticV24, StaticCredentialRotationV25, JitReviewV26, JitReviewOpenV27 }

pub(super) fn arguments(mut arguments: impl Iterator<Item = OsString>)
    -> Result<Option<(ArtifactV1, ArtifactV1, bool, ResponseProofIdentityExport, Mode, Option<ArtifactV1>)>, String>
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
        else if argument == "--native-postboot-static-startup-v24" { Mode::PostbootStaticV24 }
        else if argument == "--native-static-credential-rotation-startup-v25" { Mode::StaticCredentialRotationV25 }
        else if argument == "--native-jit-review-startup-v26" { Mode::JitReviewV26 }
        else if argument == "--native-jit-review-open-startup-v27" { Mode::JitReviewOpenV27 }
        else { return Err("decision gate accepts no arguments or an explicit native startup mode".to_owned()); };
    let mut configuration = None;
    let mut configuration_pin = None;
    let mut launch = None;
    let mut launch_pin = None;
    let mut public_identity_stdout = false;
    let mut response_proof_identity_export = ResponseProofIdentityExport::None;
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
        if matches!(flag, "--response-proof-identity-stdout" | "--response-proof-identity-vsock") {
            if response_proof_identity_export != ResponseProofIdentityExport::None {
                return Err("native startup received an unknown or repeated flag".to_owned());
            }
            response_proof_identity_export = if flag == "--response-proof-identity-stdout" {
                ResponseProofIdentityExport::Stdout
            } else {
                if !matches!(&mode, Mode::PostbootStaticV24 | Mode::StaticCredentialRotationV25 | Mode::JitReviewV26 | Mode::JitReviewOpenV27) {
                    return Err("response-proof identity vsock requires explicit postboot startup".into());
                }
                ResponseProofIdentityExport::Vsock
            };
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
    if matches!(&mode, Mode::PostbootStaticV24 | Mode::StaticCredentialRotationV25 | Mode::JitReviewV26 | Mode::JitReviewOpenV27)
        && response_proof_identity_export == ResponseProofIdentityExport::None {
        return Err("postboot static startup requires a response-proof identity export".into());
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
    }, public_identity_stdout, response_proof_identity_export, mode, trust)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opening_arguments(export: Option<&str>) -> Vec<OsString> {
        let mut values: Vec<OsString> = ["--native-jit-review-open-startup-v27",
            "--configuration", "/fixture/configuration.json", "--configuration-sha256", "fixture-pin",
            "--launch", "/fixture/launch.json", "--launch-sha256", "fixture-pin"]
            .into_iter().map(OsString::from).collect();
        if let Some(flag) = export { values.push(OsString::from(flag)); }
        values
    }

    #[test]
    fn opening_cli_requires_response_proof_identity_export() {
        assert!(arguments(opening_arguments(None).into_iter()).is_err());
        assert!(arguments(opening_arguments(Some("--public-identity-stdout")).into_iter()).is_err());
        for (flag, expected) in [
            ("--response-proof-identity-stdout", ResponseProofIdentityExport::Stdout),
            ("--response-proof-identity-vsock", ResponseProofIdentityExport::Vsock),
        ] {
            let (_, _, _, export, mode, trust) = arguments(opening_arguments(Some(flag)).into_iter())
                .unwrap().unwrap();
            assert!(matches!(mode, Mode::JitReviewOpenV27));
            assert!(export == expected && trust.is_none());
        }
    }

    #[test]
    fn sealing_cli_remains_a_separate_explicit_mode() {
        let mut values = opening_arguments(Some("--response-proof-identity-vsock"));
        values[0] = OsString::from("--native-jit-review-startup-v26");
        let (_, _, _, _, mode, _) = arguments(values.into_iter()).unwrap().unwrap();
        assert!(matches!(mode, Mode::JitReviewV26));
        let mut mixed = opening_arguments(Some("--response-proof-identity-vsock"));
        mixed.push(OsString::from("--native-jit-review-startup-v26"));
        assert!(arguments(mixed.into_iter()).is_err());
    }
}
