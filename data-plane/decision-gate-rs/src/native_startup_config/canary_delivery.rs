//! Explicit v19 succession plus independently admitted durable canary delivery.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV19 {
    api_version: String,
    measured_canary_delivery: serverware_decision_gate::native_canary_delivery_v1::Configuration,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV15,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::history::ConfigurationV2,
    measured_audit: super::super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_refresh: serverware_decision_gate::native_oauth_refresh_v1::Configuration,
    guest_inspector: serverware_decision_gate::GuestInspectorConfiguration,
    measured_succession: serverware_decision_gate::native_oauth_succession_v1::Configuration,
    guest_cohort: serverware_decision_gate::GuestCohortConfiguration,
    measured_cleanup: serverware_decision_gate::native_oauth_cleanup_v1::Configuration,
    guest_role_key_provisioner: serverware_decision_gate::GuestRoleKeyProvisionerConfiguration,
    measured_pending_retirement: serverware_decision_gate::native_oauth_pending_retirement_v1::Configuration,
    gate_cgroup: serverware_decision_gate::native_gate_cgroup::Configuration,
    measured_capture_retirement: serverware_decision_gate::native_oauth_capture_retirement_v1::Configuration,
}

pub(super) fn configuration(value: Value) -> Result<ConfigurationParts, String> {
    let gate = value.get("gate").and_then(Value::as_object)
        .ok_or("native v19 gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null),
            "native v19 requires explicit null plaintext bearer slots")?;
    }
    let original: ConfigurationV19 = serde_json::from_value(value)
        .map_err(|_| "native v19 configuration violates its closed contract")?;
    ensure(original.api_version == "serverware.nativeStartupConfiguration/v19"
        && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
        "native v19 authorizer version differs")?;
    ensure(original.measured_canary_delivery.api_version == "serverware.nativeCanaryDurableDelivery/v1",
        "native v19 retains exactly the original interval-only delivery profile")?;
    original.measured_canary_delivery.validate()?;
    ensure(original.measured_canary_delivery.instance_id == original.measured_succession.instance_id
        && original.measured_canary_delivery.deployment_id == original.measured_succession.deployment_id
        && original.measured_canary_delivery.deployment_id == original.credential_currentness.deployment_id,
        "native v19 canary delivery must retain the same deployment and instance")?;
    original.credential_currentness.validate()?;
    original.secret_broker.validate()?;
    original.measured_refresh.validate()?;
    original.guest_inspector.validate()?;
    original.measured_succession.validate()?;
    original.guest_cohort.validate()?;
    original.measured_cleanup.validate()?;
    original.guest_role_key_provisioner.validate()?;
    original.measured_pending_retirement.validate()?;
    original.gate_cgroup.validate()?;
    original.measured_capture_retirement.validate()?;
    let (primary_broker, historical_broker) = original.secret_broker.into_parts()?;
    Ok(ConfigurationParts {
        measured_canary_delivery: Some(original.measured_canary_delivery),
        measured_reconnect: None,
        historical_broker: Some(historical_broker),
        measured_static_credential: None, measured_setup: None,
        measured_capture_retirement: Some(original.measured_capture_retirement),
        measured_succession: Some(original.measured_succession),
        gate_cgroup: Some(original.gate_cgroup),
        measured_pending_retirement: Some(original.measured_pending_retirement),
        guest_role_key_provisioner: Some(original.guest_role_key_provisioner),
        measured_cleanup: Some(original.measured_cleanup),
        guest_cohort: Some(original.guest_cohort),
        guest_inspector: Some(original.guest_inspector),
        measured_issuance: None,
        measured_refresh: Some(original.measured_refresh),
        service_tokens: super::super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
        secret_broker: Some(primary_broker),
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
