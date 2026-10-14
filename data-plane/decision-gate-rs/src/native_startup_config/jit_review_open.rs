//! Explicit combined JIT v27. Sealing and opening retain separate policies and
//! postboot assignments on one broker; static and OAuth purposes remain absent.
use super::*;
use serverware_decision_gate::native_jit_review_v1::Configuration as JitConfiguration;
use serverware_decision_gate::native_jit_review_open_v1::Configuration as OpeningConfiguration;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationV27 {
    api_version: String, gate: gate::GateConfigV1, native: parameters::NativeSettingsV1,
    shadow: shadow::ShadowConfigV15, response_observation_v2: NativeResponseObservationV2ConfigV1,
    policy: ArtifactV1, enrollment_authorizer: EnrollmentAuthorizerV1,
    enrollment_setup_authorizer: EnrollmentAuthorizerV1, enrollment_proxy_endpoint: String,
    credential_currentness: serverware_decision_gate::native_currentness_v1::Configuration,
    secret_broker: serverware_decision_gate::native_secret_broker_v1::Configuration,
    measured_audit: super::super::native_audit_transport::Configuration,
    encrypted_service_tokens: serverware_decision_gate::native_secret_broker_v1::service_tokens::Envelope,
    measured_jit_review: JitConfiguration,
    measured_jit_review_open: OpeningConfiguration,
    guest_inspector: serverware_decision_gate::GuestInspectorConfiguration,
    guest_cohort: serverware_decision_gate::GuestCohortConfiguration,
    guest_role_key_provisioner: serverware_decision_gate::GuestRoleKeyProvisionerConfiguration,
    gate_cgroup: serverware_decision_gate::native_gate_cgroup::Configuration,
    postboot_audit_vsock_port: u32, postboot_jit_review_vsock_port: u32,
    postboot_jit_review_open_vsock_port: u32,
}

fn distinct_ports(ports: [u32; 6]) -> Result<(), String> {
    ensure(ports.iter().enumerate().all(|(index, port)|
        (1024..u32::MAX).contains(port) && !ports[..index].contains(port)),
        "JIT audit, sealing assignment, opening assignment, browser, ingress and identity listeners must be distinct")
}

pub(super) fn configuration(raw: &[u8])
    -> Result<(ConfigurationParts, u32, u32, JitConfiguration, u32, OpeningConfiguration), String> {
    let value = json::parse(raw, MAX_CONFIGURATION_BYTES)?;
    let gate = value.get("gate").and_then(Value::as_object)
        .ok_or("JIT opening native gate must be closed")?;
    for name in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(gate.get(name) == Some(&Value::Null), "JIT opening startup refuses plaintext service tokens")?;
    }
    let original: ConfigurationV27 = serde_json::from_value(value)
        .map_err(|_| "JIT opening startup violates its closed contract")?;
    ensure(original.api_version == "serverware.nativeStartupConfiguration/v27"
        && original.enrollment_authorizer.api_version == "serverware.nativeEnrollmentAuthorizer/v1"
        && original.enrollment_setup_authorizer.api_version == "serverware.nativeEnrollmentSetupAuthorizer/v1",
        "JIT opening startup authorizer version differs")?;
    original.credential_currentness.validate()?; original.secret_broker.validate()?;
    original.measured_jit_review.validate()?; original.measured_jit_review_open.validate()?;
    original.guest_inspector.validate()?;
    original.guest_cohort.validate()?; original.guest_role_key_provisioner.validate()?; original.gate_cgroup.validate()?;
    ensure(original.measured_audit.requires_postboot_assignment()
        && original.measured_jit_review.deployment_id() == original.credential_currentness.deployment_id
        && original.measured_jit_review_open.deployment_id() == original.credential_currentness.deployment_id
        && original.measured_jit_review.instance_id() == original.measured_jit_review_open.instance_id(),
        "combined JIT startup requires exact instance/deployment and encrypted/currentness/postboot audit profile")?;
    let audit = original.postboot_audit_vsock_port;
    let sealing = original.postboot_jit_review_vsock_port;
    let opening = original.postboot_jit_review_open_vsock_port;
    distinct_ports([audit, sealing, opening, original.measured_jit_review_open.browser_vsock_port(),
        original.native.listener_port(), super::super::native_public_identity_transport::PORT])?;
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
    }, audit, sealing, original.measured_jit_review, opening, original.measured_jit_review_open))
}

#[cfg(test)]
mod tests {
    use super::distinct_ports;

    #[test]
    fn opening_ports_are_pairwise_distinct_and_bounded() {
        let ports = [9201, 9202, 9203, 9204, 9205, 9101];
        assert!(distinct_ports(ports).is_ok());
        for index in 0..ports.len() {
            for invalid in [0, 1023, u32::MAX] {
                let mut changed = ports; changed[index] = invalid;
                assert!(distinct_ports(changed).is_err());
            }
            for other in 0..ports.len() {
                if index != other {
                    let mut changed = ports; changed[index] = ports[other];
                    assert!(distinct_ports(changed).is_err());
                }
            }
        }
    }
}
