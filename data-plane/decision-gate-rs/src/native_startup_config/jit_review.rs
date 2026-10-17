//! Explicit JIT-only v26. Static creation/rotation and OAuth are not enabled.
use super::*;
use catchplate_decision_gate::native_jit_review_v1::Configuration as JitConfiguration;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV26 {
    api_version: String, gate: gate::GateConfigV1, native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV15, response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1, enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1, enrollment_proxy_endpoint: String,
    credential_currentness: catchplate_decision_gate::native_currentness_v1::Configuration,
    secret_broker: catchplate_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::super::native_audit_transport::Configuration,
    encrypted_service_tokens: catchplate_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_jit_review: JitConfiguration,
    guest_inspector: catchplate_decision_gate::GuestInspectorConfiguration,
    guest_cohort: catchplate_decision_gate::GuestCohortConfiguration,
    guest_role_key_provisioner: catchplate_decision_gate::GuestRoleKeyProvisionerConfiguration,
    gate_cgroup: catchplate_decision_gate::native_gate_cgroup::Configuration,
    postboot_audit_vsock_port: u32, postboot_jit_review_vsock_port: u32,
}

pub(super) fn configuration(raw: &[u8]) -> Result<(ConfigurationParts, u32, u32, JitConfiguration), String> {
    let value = json::parse(raw, MAX_CONFIGURATION_BYTES)?;
    let gate = value.get("gate").and_then(Value::as_object).ok_or("JIT native gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null), "JIT startup refuses plaintext service tokens")?;
    }
    let original: ConfigurationV26 = serde_json::from_value(value).map_err(|_| "JIT startup violates its closed contract")?;
    ensure(original.api_version == "catchplate.nativeStartupConfiguration/v26"
        && original.enrollment_authorizer.api_version == "catchplate.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "catchplate.nativeEnrollmentSetupAuthorizer/v1",
        "JIT startup authorizer version differs")?;
    original.credential_currentness.validate()?; original.secret_broker.validate()?;
    original.measured_jit_review.validate()?; original.guest_inspector.validate()?;
    original.guest_cohort.validate()?; original.guest_role_key_provisioner.validate()?; original.gate_cgroup.validate()?;
    ensure(original.measured_audit.requires_postboot_assignment()
        && original.measured_jit_review.deployment_id() == original.credential_currentness.deployment_id,
        "JIT startup requires its exact encrypted/currentness/postboot audit profile")?;
    let audit = original.postboot_audit_vsock_port; let jit = original.postboot_jit_review_vsock_port;
    ensure((1024..u32::MAX).contains(&audit) && (1024..u32::MAX).contains(&jit) && audit != jit
        && audit != original.native.listener_port() && jit != original.native.listener_port(),
        "JIT audit, assignment and ingress listeners must be distinct")?;
    Ok((ConfigurationParts {
        measured_static_credential: None, measured_canary_delivery: None, measured_succession: None,
        historical_broker: None, measured_reconnect: None, measured_setup: None, measured_capture_retirement: None,
        gate_cgroup: Some(original.gate_cgroup), measured_pending_retirement: None,
        guest_role_key_provisioner: Some(original.guest_role_key_provisioner), measured_cleanup: None,
        guest_cohort: Some(original.guest_cohort), guest_inspector: Some(original.guest_inspector),
        measured_issuance: None, measured_refresh: None,
        service_tokens: super::super::native_service_tokens::Source::Pending(original.encrypted_service_tokens),
        secret_broker: Some(original.secret_broker), measured_audit: Some(original.measured_audit),
        credential_currentness: Some(original.credential_currentness), gate: original.gate, native: original.native,
        shadow: original.shadow, response_observation_v2: original.response_observation_v2, policy: original.policy,
        enrollment: Some(EnrollmentParts { authorizer: original.enrollment_authorizer,
            endpoint: original.enrollment_proxy_endpoint, setup_authorizer: Some(original.enrollment_setup_authorizer) }),
    }, audit, jit, original.measured_jit_review))
}
