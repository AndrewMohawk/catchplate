//! Cold native startup called by the explicit native CLI, not an admission token.
//!
//! All configuration, trust pins, clocks/nonces and the existing attempt ledger
//! still require independent admission. This sequence generates the real keys,
//! obtains original NSM quotes, constructs the existing checked service owners,
//! loads the signed policy and only then binds the fixed-parent listener. It
//! neither imports private keys nor invokes legacy environment-driven startup.

use super::*;
use super::policy_shadow_generation::PolicyShadowGenerationConfig;
use serverware_decision_gate::enclave_runtime_identity_v1::RuntimeScopeCommitmentsV1;
use serverware_decision_gate::native_upstream_relays_v1::NativeRelayAssignmentV1;
use std::os::unix::ffi::OsStrExt;
use std::path::Component;

const MAX_POLICY_BYTES: usize = 8 * 1024 * 1024;
const MAX_CLIENT_ROOTS: usize = 32;
const MAX_CLIENT_ROOT_BYTES: usize = 64 * 1024;
const MAX_CLIENT_TRUST_BYTES: usize = 1024 * 1024;
const MAX_RELAY_ASSIGNMENTS: usize = 32;
const NITRO_PARENT_CID: u32 = 3;

/// Supplied values, not a verified configuration or a hardware-attestation
/// result. The instance SPIFFE identity comes only from the cold GateStateInputs.
/// Private-key material, a prebuilt proof signer and an imported GateState are
/// deliberately absent. Runtime settings already have a bounded constructor.
pub(super) struct NativeStartupParametersV1 {
    pub(super) scope: RuntimeScopeCommitmentsV1,
    pub(super) ca_not_before: OffsetDateTime,
    pub(super) ca_not_after: OffsetDateTime,
    pub(super) ingress_not_before: OffsetDateTime,
    pub(super) ingress_not_after: OffsetDateTime,
    pub(super) ingress_host: String,
    pub(super) ingress_client_roots: Vec<Vec<u8>>,
    pub(super) ingress_nonce: [u8; 32],
    pub(super) proof_nonce: [u8; 32],
    pub(super) control_plane_response_key: VerifyingKey,
    pub(super) control_plane_response_key_id: String,
    pub(super) attempt_ledger_directory: PathBuf,
    pub(super) relay_assignments: Vec<NativeRelayAssignmentV1>,
    pub(super) listener_port: u32,
    pub(super) policy_bytes: Vec<u8>,
    pub(super) expected_policy_signing_key_id: String,
    pub(super) minimum_sequence: u64,
    pub(super) minimum_rollback_epoch: u64,
    pub(super) control_plane_tls: ControlPlaneClientConfig,
    pub(super) runtime: NativeRuntimeSettingsV1,
    pub(super) deadline_boottime_ns: u64,
}

fn validate_parameters(parameters: &NativeStartupParametersV1) -> Result<(), String> {
    if parameters.policy_bytes.is_empty() || parameters.policy_bytes.len() > MAX_POLICY_BYTES
        || !is_sha256_digest(&parameters.expected_policy_signing_key_id)
        || parameters.minimum_sequence == 0 || parameters.minimum_rollback_epoch == 0
        || parameters.listener_port <= 1023 || parameters.listener_port == u32::MAX
        || parameters.ingress_nonce == [0; 32] || parameters.proof_nonce == [0; 32]
    {
        return Err("native startup policy, floors, listener port or quote nonces are invalid".to_owned());
    }
    let now = OffsetDateTime::now_utc();
    if parameters.ca_not_after <= parameters.ca_not_before
        || parameters.ca_not_after - parameters.ca_not_before > TimeDuration::hours(24)
        || parameters.ingress_not_after <= parameters.ingress_not_before
        || parameters.ingress_not_before < parameters.ca_not_before
        || parameters.ingress_not_after > parameters.ca_not_after
        || now < parameters.ingress_not_before || now >= parameters.ingress_not_after
    {
        return Err("native startup TLS intervals must be live and within one original CA day".to_owned());
    }
    if parameters.ingress_host.is_empty() || parameters.ingress_host.len() > 253
        || !parameters.ingress_host.is_ascii()
        || rustls::pki_types::ServerName::try_from(parameters.ingress_host.as_str()).is_err()
    {
        return Err("native startup ingress host must be a bounded DNS name or IP address".to_owned());
    }
    if parameters.ingress_client_roots.is_empty()
        || parameters.ingress_client_roots.len() > MAX_CLIENT_ROOTS
    {
        return Err("native startup requires 1..32 client trust certificates".to_owned());
    }
    let mut root_bytes = 0usize;
    let mut distinct_roots = HashSet::new();
    for root in &parameters.ingress_client_roots {
        root_bytes = root_bytes.checked_add(root.len())
            .ok_or("native startup client trust size overflow")?;
        if root.is_empty() || root.len() > MAX_CLIENT_ROOT_BYTES
            || root_bytes > MAX_CLIENT_TRUST_BYTES || !distinct_roots.insert(root.as_slice())
        {
            return Err("native startup client trust inventory exceeds its bounds or repeats".to_owned());
        }
    }
    // The custody constructor independently repeats this actual-key join. Do
    // it before NSM access as well, without reading a PEM file or environment.
    let mut control_plane_spki = Vec::with_capacity(44);
    control_plane_spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    control_plane_spki.extend_from_slice(parameters.control_plane_response_key.as_bytes());
    if parameters.control_plane_response_key.is_weak()
        || !is_sha256_digest(&parameters.control_plane_response_key_id)
        || parameters.control_plane_response_key_id != sha256_prefixed(&control_plane_spki)
    {
        return Err("native startup control-plane key differs from its independent key ID".to_owned());
    }
    let ledger_path = &parameters.attempt_ledger_directory;
    if !ledger_path.is_absolute() || ledger_path.as_os_str().as_bytes().len() > 4096
        || ledger_path.as_os_str().as_bytes().contains(&0)
        || ledger_path.file_name().is_none()
        || ledger_path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("native startup attempt ledger requires a bounded absolute directory path".to_owned());
    }
    // Cheap shape limits precede key generation. The retained relay constructor
    // later performs its complete canonical-host, endpoint and table joins;
    // these checks neither contact a parent nor admit a route or destination.
    if parameters.relay_assignments.is_empty()
        || parameters.relay_assignments.len() > MAX_RELAY_ASSIGNMENTS
    {
        return Err("native startup requires 1..32 literal relay assignments".to_owned());
    }
    for relay in &parameters.relay_assignments {
        if relay.host.is_empty() || relay.host.len() > 253 || !relay.host.is_ascii()
            || relay.host.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || relay.endpoint.port() == 0 || relay.endpoint.ip().is_unspecified()
            || relay.endpoint.ip().is_multicast()
            || relay.parent_port <= 1023 || relay.parent_port == u32::MAX
        {
            return Err("native startup relay assignment exceeds its basic bounds".to_owned());
        }
    }
    Ok(())
}

pub(super) fn run(
    mut inputs: GateStateInputs,
    parameters: NativeStartupParametersV1,
    shadow_config: PolicyShadowGenerationConfig,
    v2_config: ResponseObservationV2ClientConfig,
    public_identity_stdout: bool,
) -> Result<(), String> {
    // This guard starts no tasks and grants no new interval. Runtime serving
    // later installs its own cancellation owner with this SAME absolute bound.
    let startup = NativeRuntimeLifetimeV1::new(parameters.deadline_boottime_ns)?;
    if inputs.policy_shadow_generation_control.is_some()
        || inputs.response_observation_v2_client.is_some()
    {
        return Err("native startup requires cold inputs without shadow or observation owners".to_owned());
    }
    super::native_gate_inputs::validate_native_gate_static_inputs(&inputs)?;
    validate_parameters(&parameters)?;
    validate_response_observation_v2_client_config(&v2_config)?;
    if !matches!(&inputs.policy_trust_root_source,
        PolicyTrustRootSource::AttestedControlPlane {
            verifier: Some(ControlPlaneAttestationVerifier::Pinned(_)), native_transport: None, ..
        })
    {
        return Err("native startup requires an unused independently pinned attested trust source".to_owned());
    }
    if shadow_config.startup_generation_path.is_some()
        || shadow_config.startup_generation_sha256.is_some()
    {
        return Err("native startup cannot install a pending shadow generation".to_owned());
    }
    startup.check()?;
    // These are real constructors, not caller-provided healthy flags. The
    // attested-trust classification above is required; true is not quote proof.
    let shadow = PolicyShadowGenerationControl::from_config(true, true, shadow_config)?;
    if !shadow.is_production() || shadow.startup_request().is_some() {
        return Err("native startup shadow owner is not configured for production startup".to_owned());
    }
    inputs.policy_shadow_generation_control = Some(shadow);
    startup.check()?;
    inputs.response_observation_v2_client = Some(
        initialize_response_observation_v2_client_from_config(
            v2_config, parameters.deadline_boottime_ns)?,
    );
    startup.check()?;

    let mut identity = EnclaveRuntimeIdentityV1::open(parameters.scope,
        parameters.ca_not_before, parameters.ca_not_after, parameters.deadline_boottime_ns)?;
    startup.check()?;
    let custody = CustodyRuntime::generate_native_with_control_plane_response_public_key(
        &mut identity, parameters.control_plane_response_key,
        &parameters.control_plane_response_key_id, parameters.proof_nonce,
        &parameters.attempt_ledger_directory, parameters.deadline_boottime_ns,
    ).map_err(|_| "native startup custody key and ledger construction failed".to_owned())?;
    startup.check()?;
    let proof = super::native_proof_signer::initialize_native_response_proof_signer(custody)?;
    startup.check()?;
    let instance = inputs.server_instance_id.as_deref()
        .ok_or("native startup lost its canonical instance identity")?;
    let ingress = identity.quote_mutual_tls_ingress(&parameters.ingress_host, Some(instance),
        &parameters.ingress_client_roots, parameters.ingress_not_before,
        parameters.ingress_not_after, parameters.ingress_nonce, parameters.deadline_boottime_ns)?;
    startup.check()?;
    let bootstrap = EnclaveBootstrapV1::new(identity, ingress, parameters.relay_assignments,
        OffsetDateTime::now_utc(), parameters.deadline_boottime_ns)?;
    startup.check()?;
    let prepared = prepare_native_tls_gate_state(inputs, proof, bootstrap,
        &parameters.policy_bytes, &parameters.expected_policy_signing_key_id,
        &parameters.control_plane_tls, parameters.minimum_sequence,
        parameters.minimum_rollback_epoch)?;
    startup.check()?;
    if prepared.deadline != parameters.deadline_boottime_ns {
        return Err("native startup preparation changed its original lifetime".to_owned());
    }
    // This opt-in writes public originals only. Publication is not independent
    // attestation verification, CA installation permission or service readiness.
    startup.check()?;
    if public_identity_stdout {
        super::native_public_identity::write_startup_public_identity(&prepared)?;
    }
    startup.check()?;
    // No external vsock ingress is bound before genuine preparation succeeds.
    // Preparation can create its private outbound loopback bridges. Peer CID
    // is routing scope, not authentication; the actual quoted TLS config still
    // requires mandatory client authentication inside the enclave.
    let listener = VsockListenerV1::bind(parameters.listener_port, NITRO_PARENT_CID,
        parameters.deadline_boottime_ns)
        .map_err(|_| "native startup fixed-parent listener bind failed".to_owned())?;
    startup.check()?;
    serve_native_vsock_proxy(listener, prepared, parameters.runtime)
}
