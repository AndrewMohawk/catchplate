//! Explicit normal-credential profile. OAuth purpose owners are not enabled
//! merely to obtain an encrypted native browser or credential broker.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV23 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV15,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_static_credential: serverware_decision_gate::native_static_credential_v1::Configuration,
    guest_inspector: serverware_decision_gate::GuestInspectorConfiguration,
    guest_cohort: serverware_decision_gate::GuestCohortConfiguration,
    guest_role_key_provisioner: serverware_decision_gate::GuestRoleKeyProvisionerConfiguration,
    gate_cgroup: serverware_decision_gate::native_gate_cgroup::Configuration,
}

pub(super) fn configuration(value: Value) -> Result<ConfigurationParts, String> {
    let gate = value.get("gate").and_then(Value::as_object).ok_or("static native gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null), "static native startup refuses plaintext service tokens")?;
    }
    let original: ConfigurationV23 = serde_json::from_value(value)
        .map_err(|_|"static native startup violates its closed contract")?;
    ensure(original.api_version == "serverware.nativeStartupConfiguration/v23"
        && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
        "static native startup authorizer version differs")?;
    original.credential_currentness.validate()?;
    original.secret_broker.validate()?;
    original.measured_static_credential.validate()?;
    original.guest_inspector.validate()?;
    original.guest_cohort.validate()?;
    original.guest_role_key_provisioner.validate()?;
    original.gate_cgroup.validate()?;
    ensure(original.measured_static_credential.deployment_id == original.credential_currentness.deployment_id,
        "static native deployment differs")?;
    Ok(ConfigurationParts {
        measured_static_credential: Some(original.measured_static_credential),
        measured_canary_delivery: None, measured_succession: None, historical_broker: None,
        measured_reconnect: None, measured_setup: None, measured_capture_retirement: None,
        gate_cgroup: Some(original.gate_cgroup), measured_pending_retirement: None,
        guest_role_key_provisioner: Some(original.guest_role_key_provisioner), measured_cleanup: None,
        guest_cohort: Some(original.guest_cohort), guest_inspector: Some(original.guest_inspector),
        measured_issuance: None, measured_refresh: None,
        service_tokens: super::super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
        secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
        credential_currentness: Some(original.credential_currentness),
        gate: original.gate, native: original.native, shadow: original.shadow,
        response_observation_v2: original.response_observation_v2, policy: original.policy,
        enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
            endpoint: original.enrollment_proxy_endpoint, setup_authorizer: Some(original.enrollment_setup_authorizer) }),
    })
}
