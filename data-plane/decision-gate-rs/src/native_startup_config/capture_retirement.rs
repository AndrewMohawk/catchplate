//! Explicit v16 decomposition; cold data never authorizes provider effects.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV16 {
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
    measured_refresh: serverware_decision_gate::native_oauth_refresh_v1::Configuration,
    guest_inspector: serverware_decision_gate::GuestInspectorConfiguration,
    measured_setup: serverware_decision_gate::native_oauth_setup_v1::Configuration,
    guest_cohort: serverware_decision_gate::GuestCohortConfiguration,
    measured_cleanup: serverware_decision_gate::native_oauth_cleanup_v1::Configuration,
    guest_role_key_provisioner: serverware_decision_gate::GuestRoleKeyProvisionerConfiguration,
    measured_pending_retirement: serverware_decision_gate::native_oauth_pending_retirement_v1::Configuration,
    gate_cgroup: serverware_decision_gate::native_gate_cgroup::Configuration,
    measured_capture_retirement: serverware_decision_gate::native_oauth_capture_retirement_v1::Configuration,
}

pub(super) fn configuration(value: Value) -> Result<ConfigurationParts, String> {
    let gate = value.get("gate").and_then(Value::as_object)
        .ok_or("native v16 gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null),
            "native v16 requires explicit null plaintext bearer slots")?;
    }
    let original: ConfigurationV16 = serde_json::from_value(value)
        .map_err(|_| "native v16 configuration violates its closed contract")?;
    ensure(original.api_version == "serverware.nativeStartupConfiguration/v16"
        && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
        "native v16 authorizer version differs")?;
    original.credential_currentness.validate()?;
    original.secret_broker.validate()?;
    original.measured_refresh.validate()?;
    original.guest_inspector.validate()?;
    original.measured_setup.validate()?;
    original.guest_cohort.validate()?;
    original.measured_cleanup.validate()?;
    original.guest_role_key_provisioner.validate()?;
    original.measured_pending_retirement.validate()?;
    original.gate_cgroup.validate()?;
    original.measured_capture_retirement.validate()?;
    Ok(ConfigurationParts {
        measured_capture_retirement: Some(original.measured_capture_retirement),
        measured_setup: Some(original.measured_setup),
        gate_cgroup: Some(original.gate_cgroup),
        measured_pending_retirement: Some(original.measured_pending_retirement),
        guest_role_key_provisioner: Some(original.guest_role_key_provisioner),
        measured_cleanup: Some(original.measured_cleanup),
        guest_cohort: Some(original.guest_cohort),
        guest_inspector: Some(original.guest_inspector),
        measured_issuance: None,
        measured_refresh: Some(original.measured_refresh),
        service_tokens: super::super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
        secret_broker: Some(original.secret_broker),
        measured_audit: Some(original.measured_audit),
        credential_currentness: Some(original.credential_currentness),
        gate: original.gate,
        native: original.native,
        shadow: original.shadow,
        response_observation_v2: original.response_observation_v2,
        policy: original.policy,
        enrollment: Some(EnrollmentParts {
            authorizer: original.enrollment_authorizer,
            endpoint: original.enrollment_proxy_endpoint,
            setup_authorizer: Some(original.enrollment_setup_authorizer),
        }),
    })
}
