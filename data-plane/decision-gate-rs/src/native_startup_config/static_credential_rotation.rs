//! Explicit postboot N+1 rotation selection. No creation or OAuth purpose is
//! implicitly enabled, and the caller retains the complete v25 original.
use super::*;
use catchplate_decision_gate::native_static_credential_rotation_v1::Configuration as RotationConfiguration;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV25 {
    api_version: String,
    gate: gate::GateConfigV1,
    native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV15,
    response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1,
    enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1,
    enrollment_proxy_endpoint: String,
    credential_currentness: catchplate_decision_gate::native_currentness_v1::Configuration,
    secret_broker: catchplate_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::super::native_audit_transport::Configuration,
    encrypted_service_tokens: catchplate_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_static_credential_rotation: RotationConfiguration,
    guest_inspector: catchplate_decision_gate::GuestInspectorConfiguration,
    guest_cohort: catchplate_decision_gate::GuestCohortConfiguration,
    guest_role_key_provisioner: catchplate_decision_gate::GuestRoleKeyProvisionerConfiguration,
    gate_cgroup: catchplate_decision_gate::native_gate_cgroup::Configuration,
    postboot_audit_vsock_port: u32,
}

pub(super) fn configuration(raw: &[u8])
    -> Result<(ConfigurationParts, u32, RotationConfiguration), String> {
    let value = json::parse(raw, MAX_CONFIGURATION_BYTES)?;
    let gate = value.get("gate").and_then(Value::as_object)
        .ok_or("rotation native gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null),
            "rotation native startup refuses plaintext service tokens")?;
    }
    let original: ConfigurationV25 = serde_json::from_value(value)
        .map_err(|_| "rotation native startup violates its closed contract")?;
    ensure(original.api_version == "catchplate.nativeStartupConfiguration/v25"
        && original.enrollment_authorizer.api_version == "catchplate.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "catchplate.nativeEnrollmentSetupAuthorizer/v1",
        "rotation native startup authorizer version differs")?;
    original.credential_currentness.validate()?;
    original.secret_broker.validate()?;
    original.measured_static_credential_rotation.validate()?;
    original.guest_inspector.validate()?;
    original.guest_cohort.validate()?;
    original.guest_role_key_provisioner.validate()?;
    original.gate_cgroup.validate()?;
    ensure(original.measured_audit.requires_postboot_assignment(),
        "rotation startup requires postboot audit admission")?;
    ensure(original.measured_static_credential_rotation.deployment_id == original.credential_currentness.deployment_id,
        "rotation native deployment differs")?;
    let port = original.postboot_audit_vsock_port;
    let browser = original.measured_static_credential_rotation.browser_vsock_port;
    ensure((1024..u32::MAX).contains(&port) && port != original.native.listener_port()
        && port != browser && browser != original.native.listener_port(),
        "rotation audit, browser and ingress listeners must be distinct")?;
    Ok((ConfigurationParts {
        measured_static_credential: None,
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
    }, port, original.measured_static_credential_rotation))
}
