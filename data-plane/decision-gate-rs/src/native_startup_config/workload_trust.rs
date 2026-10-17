//! One closed native successor. The grant is a separate launch original;
//! neither its bytes nor its hash enters the self-hashed cold configuration.
use super::*;
use super::super::native_workload_identity_trust::Authorizer;

pub(super) fn configuration(raw: &[u8]) -> Result<(ConfigurationParts, Authorizer), String> {
    let mut value = json::parse(raw, MAX_CONFIGURATION_BYTES)?;
    ensure(value.get("apiVersion").and_then(Value::as_str)
        == Some("catchplate.nativeStartupConfiguration/v22"), "native workload trust requires v22")?;
    let object = value.as_object_mut().ok_or("native workload trust configuration must be closed")?;
    let authorizer: Authorizer = serde_json::from_value(object.remove("workloadTrustAuthorizer")
        .ok_or("native workload trust authorizer is absent")?)
        .map_err(|_| "native workload trust authorizer violates its closed contract")?;
    for name in ["enrollmentAuthorizer", "enrollmentSetupAuthorizer"] {
        let original = object.get(name).and_then(|v| v.get("publicKeyPem")).and_then(Value::as_str)
            .ok_or("native workload trust exclusion original is absent")?;
        authorizer.exclude_original(original)?;
    }
    // Only this source-selected successor delegates its unchanged v21 fields
    // to that exact decoder. Original v22 bytes remain the quoted config pin.
    object.insert("apiVersion".into(), json!("catchplate.nativeStartupConfiguration/v21"));
    let parts = super::configuration(&serde_json::to_vec(&value)
        .map_err(|_| "encode native workload trust predecessor fields")?, cli::Mode::NativeReadinessV21)?;
    Ok((parts, authorizer))
}
