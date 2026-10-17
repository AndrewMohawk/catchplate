//! Explicit v10 bridge admission of the existing authenticated INITIAL wrapper.
//!
//! Ordinary runtimes and generation grants are selected by the bridge's genuine
//! C9-bound runtime, not inferred from wrapper claims. This admits public history
//! keyrings only. It does not measure remote directories or certify generation
//! installation; the actual request path retains its separate live scope guards.

use super::*;
use super::super::{generation_service::RemoteGrant, RuntimeConfigHeaderV3};
use crate::policy_shadow::{AuthorityRole, ProductionCustodyConfiguration, Sha256Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Member {
    pub(super) runtime_original: String,
    pub(super) generation_grant_original: String,
    #[serde(default, skip_serializing_if="Option::is_none", deserialize_with="history_original")]
    pub(super) history_original: Option<String>,
}

fn history_original<'de,D:serde::Deserializer<'de>>(decoder:D)->Result<Option<String>,D::Error>{
    // Missing is legacy-only; explicit null is never an original.
    String::deserialize(decoder).map(Some)
}

pub(super) type Members = BTreeMap<TrustedHostServiceRoleV3, Member>;

pub(super) fn ordinary_header(role: TrustedHostServiceRoleV3, raw: &[u8]) -> Result<RuntimeConfigHeaderV3, ServiceRunnerError> {
    // Literal ordinary originals are flat {runtime, ...role-specific fields}.
    // Decode the actual closed consumer type; never invent a `service` wrapper.
    use super::super::*;
    let header = match role {
        TrustedHostServiceRoleV3::DurableRecoveryStore => decode_canonical_frame::<DurableRecoveryStoreRuntimeConfigV3>(raw)?.runtime,
        TrustedHostServiceRoleV3::CleanupAuthorizationConsumer => decode_canonical_frame::<CleanupAuthorizationConsumerRuntimeConfigV3>(raw)?.runtime,
        TrustedHostServiceRoleV3::RecoveryTargetProvider => decode_canonical_frame::<RecoveryTargetProviderRuntimeConfigV3>(raw)?.runtime,
        TrustedHostServiceRoleV3::CurrentSignatureAuthority => decode_canonical_frame::<CurrentSignatureAuthorityRuntimeConfigV3>(raw)?.runtime,
        TrustedHostServiceRoleV3::BoundedCleanupHelper => {
            let value: BoundedCleanupHelperRuntimeConfigV3 = decode_canonical_frame(raw)?;
            require(if value.runtime.api_version == helper_initial::RUNTIME {
                value.initial_endpoint_histories.is_some() && value.initial_endpoint_pins.is_some()
            } else { value.initial_endpoint_histories.is_none() && value.initial_endpoint_pins.is_none() })?;
            value.runtime
        }
    };
    require(header.api_version != helper_initial::RUNTIME || role == TrustedHostServiceRoleV3::BoundedCleanupHelper)?;
    Ok(header)
}

pub(super) fn validate_helper(runtime: &ProductionRpcRuntimeConfigV4) -> Result<(), ServiceRunnerError> {
    require(runtime.helper_initial_selected() == runtime.helper_bootstrap.is_some())?;
    let Some(manifest) = &runtime.helper_bootstrap else { return Ok(()); };
    manifest.validate()?;
    let member = runtime.ordinary_initial_histories.as_ref()
        .and_then(|members| members.get(&TrustedHostServiceRoleV3::BoundedCleanupHelper))
        .ok_or_else(|| error("initial helper runtime member absent"))?;
    let helper: super::super::BoundedCleanupHelperRuntimeConfigV3 = decode_canonical_frame(member.runtime_original.as_bytes())?;
    helper.runtime.validate()?;
    let members = helper.initial_endpoint_histories.as_ref().ok_or_else(|| error("initial helper role histories absent"))?;
    let pins = helper.initial_endpoint_pins.as_ref().ok_or_else(|| error("initial helper role pins absent"))?;
    require(helper.runtime.api_version == super::super::helper_initial::RUNTIME
        && pins.keys().copied().collect::<Vec<_>>() == super::super::helper_initial::ROLES
        && manifest.service_configuration_sha256 == Sha256Digest::compute(member.runtime_original.as_bytes())
        && manifest.operation_generation == helper.runtime.operation_generation
        && manifest.shared_configuration_sha256 == helper.runtime.shared_configuration_sha256
        && manifest.initial_endpoint_history_sha256 == super::super::helper_initial::history_pins(members)?
        && runtime.expected_helper_endpoint_roles.iter().copied().collect::<Vec<_>>() == super::super::helper_initial::ROLES)?;
    let session = runtime.service_sessions.iter().find(|session| session.service_role == TrustedHostServiceRoleV3::BoundedCleanupHelper)
        .ok_or_else(|| error("initial helper session absent"))?;
    require(session.expected_socket_path == helper.runtime.listener_socket_path
        && session.handshakes.iter().map(|h| h.endpoint_role).collect::<Vec<_>>() == super::super::helper_initial::ROLES
        && session.handshakes.iter().all(|h| h.request.deadline == manifest.deadline))
}

fn require(value: bool) -> Result<(), ServiceRunnerError> {
    if value { Ok(()) } else {
        Err(ServiceRunnerError::invalid("initial bridge history association refused"))
    }
}

fn error(value: impl std::fmt::Display) -> ServiceRunnerError {
    ServiceRunnerError::invalid(value.to_string())
}

pub(super) fn validate(runtime: &ProductionRpcRuntimeConfigV4) -> Result<(), ServiceRunnerError> {
    require(runtime.initial_history_selected() == runtime.ordinary_initial_histories.is_some())?;
    let Some(members) = &runtime.ordinary_initial_histories else { return Ok(()); };
    let roles = super::super::generation_service_client::roles();
    require(members.keys().copied().collect::<BTreeSet<_>>() == roles
        && runtime.expected_service_configuration_sha256.keys().copied().collect::<BTreeSet<_>>() == roles
        && runtime.expected_service_restart_epoch.keys().copied().collect::<BTreeSet<_>>() == roles
        && runtime.expected_service_readiness_epoch.keys().copied().collect::<BTreeSet<_>>() == roles
        && runtime.expected_service_authority_history_manifest_sha256.keys().copied().collect::<BTreeSet<_>>() == roles
        && encode_canonical_frame(runtime)?.len() <= super::super::MAX_CONFIG_BYTES)?;
    for member in members.values() {
        require(runtime.native_terminal_selected() == member.history_original.is_some())?;
        if let Some(raw)=&member.history_original {
            require(raw.is_ascii() && !raw.is_empty() && raw.len()<=1024*1024)?;
        }
        for (raw, bound) in [(&member.runtime_original, super::super::MAX_CONFIG_BYTES),
            (&member.generation_grant_original, 65536)] {
            require(raw.is_ascii() && !raw.is_empty() && raw.len() <= bound)?;
        }
    }
    Ok(())
}

fn equal(value: &serde_json::Value, name: &str, expected: &impl Serialize)
    -> Result<(), ServiceRunnerError> {
    require(value.get(name) == Some(&serde_json::to_value(expected).map_err(error)?))
}

pub(super) fn scope_binding(scope: &serde_json::Value, configuration: &ProductionCustodyConfiguration)
    -> Result<(), ServiceRunnerError> {
    require(scope.as_object().is_some_and(|value| value.len() == 18)
        && scope.get("previousConfigurationBindingSha256") == Some(&serde_json::Value::Null))?;
    equal(scope, "successorConfigurationBindingSha256", configuration.production_configuration_binding_sha256())?;
    equal(scope, "kernelDriverIdentitySha256", configuration.kernel_retained_driver_identity_sha256())?;
    equal(scope, "assignmentId", configuration.assignment_id())?;
    equal(scope, "assignmentPayloadSha256", configuration.assignment_payload_sha256())?;
    equal(scope, "assignmentRevision", &configuration.assignment_revision())?;
    equal(scope, "operationCoverageRootSha256", configuration.operation_coverage_root_sha256())?;
    equal(scope, "fiveServiceProtocolSetSha256", configuration.dispatcher_protocol_set_sha256())?;
    let key = configuration.authority_binding(AuthorityRole::CustodyResultEnvelope).map_err(error)?;
    equal(scope, "envelopeAuthorityKeyId", key.key_id())?;
    equal(scope, "envelopeAuthorityKeySpkiSha256", key.key_spki_sha256())?;
    let checkpoint = configuration.authority_trust_checkpoint();
    equal(scope, "trustedTimeCheckpointSha256", &checkpoint.checkpoint_id)?;
    equal(scope, "trustedTimeRevocationGeneration", &checkpoint.revocation_generation)?;
    equal(scope, "trustedTimeRevocationRootSha256", &checkpoint.revocation_root_sha256)?;
    let issued = scope.get("installationIssuedAtUnixNanos").and_then(serde_json::Value::as_i64)
        .ok_or_else(|| error("initial bridge installation interval missing"))?;
    let expires = scope.get("installationExpiresAtUnixNanos").and_then(serde_json::Value::as_i64)
        .ok_or_else(|| error("initial bridge installation interval missing"))?;
    let assignment = configuration.retained_verified_assignment.payload();
    require(issued > 0 && issued < expires
        && expires - issued <= configuration.maximum_authority_evidence_age_nanos()
        && assignment.issued_at_unix_nanos <= issued && expires <= assignment.expires_at_unix_nanos
        && checkpoint.as_of_unix_nanos <= issued
        && expires.checked_sub(checkpoint.as_of_unix_nanos).is_some_and(|age| age <= 300_000_000_000))?;
    // All eighteen fields are also identical across the five authenticated,
    // independently pinned grants below. Descriptor-set, bootstrap-receipt and
    // dispatch-manifest associations remain the real generation request/factory
    // guards; current trusted-time request admission is not manufactured here.
    Ok(())
}

pub(super) fn load(runtime: &ProductionRpcRuntimeConfigV4,
    credentials: &super::super::CredentialDirectory, bootstrap: &super::super::Bootstrap)
    -> Result<ProductionServiceHistoricalKeyringsV4, ServiceRunnerError> {
    runtime.validate()?;
    let super::super::Bootstrap::NativeRetrieval(owner) = bootstrap else {
        return Err(error("initial bridge history requires the actual native bridge owner"));
    };
    let super::super::CredentialDirectory::Guest(retained) = credentials else {
        return Err(error("initial bridge history requires retained guest credentials"));
    };
    require(Arc::ptr_eq(retained, owner.delivery()))?;
    owner.check().map_err(error)?;
    let guest = owner.guest_binding();
    require(guest.service_role == "production-bridge"
        && guest.runtime_configuration_sha256 == Sha256Digest::compute(&encode_canonical_frame(runtime)?))?;
    let configuration = owner.active_native_configuration().map_err(error)?
        .ok_or_else(|| error("initial bridge history requires activated native configuration"))?;
    let members = runtime.ordinary_initial_histories.as_ref()
        .ok_or_else(|| error("initial bridge history members missing"))?;
    let selection = serde_json::to_value(runtime.generation_admission.as_ref()
        .ok_or_else(|| error("initial bridge generation selection missing"))?).map_err(error)?;
    let selected_grants: BTreeMap<TrustedHostServiceRoleV3, Sha256Digest> = serde_json::from_value(
        selection.get("grants").ok_or_else(|| error("initial bridge grant pins missing"))?.clone()).map_err(error)?;
    let mut histories = BTreeMap::new();
    let mut common_scope = None;
    let mut uids = BTreeSet::from([guest.uid]);
    let mut gids = BTreeSet::from([guest.gid]);
    for configured in &runtime.histories {
        let role = trusted_service_role(configured.service_role);
        let member = members.get(&role).ok_or_else(|| error("initial bridge role missing"))?;
        let header = ordinary_header(role, member.runtime_original.as_bytes())?;
        let header = &header;
        header.validate()?;
        if role == TrustedHostServiceRoleV3::BoundedCleanupHelper {
            require(runtime.helper_initial_selected() == (header.api_version == super::super::helper_initial::RUNTIME))?;
        }
        require(runtime.expected_service_configuration_sha256.get(&role)
                == Some(&Sha256Digest::compute(member.runtime_original.as_bytes()))
            && header.authority_history_manifest_sha256 == configured.manifest_sha256
            && header.authority_history_root_key_id == configured.root_key_id
            && header.authority_history_root_key_spki_sha256 == configured.root_key_spki_sha256
            && expected_history_manifest_sha256(runtime, configured.service_role) == Some(&configured.manifest_sha256)
            && runtime.expected_service_restart_epoch.get(&role) == Some(&header.service_restart_epoch)
            && runtime.expected_service_readiness_epoch.get(&role) == Some(&header.readiness_epoch)
            && header.operation_generation == runtime.expected_operation_generation
            && header.shared_configuration_sha256 == runtime.expected_shared_configuration_sha256
            && header.production_dispatch_protocol_set_sha256 == runtime.expected_production_dispatch_protocol_set_sha256
            && header.production_dispatch_protocol_set_sha256 == *configuration.dispatcher_protocol_set_sha256()
            && header.maximum_durability_worker_nanos == runtime.expected_maximum_durability_worker_nanos
            && header.expected_peer.uid == guest.uid && header.expected_peer.gid == guest.gid
            && header.expected_peer.pid == std::process::id() as i32)?;
        let exact = credentials.read(&configured.manifest_credential, super::super::MAX_CONFIG_BYTES)?;
        if let Some(original)=&member.history_original {require(original.as_bytes()==exact.as_slice())?;}
        require(super::super::initial_history::selected(&exact)?)?;
        let history = header.history_from_original(&exact, role)?;
        let grant = RemoteGrant::admit(member.generation_grant_original.as_bytes(), history, role, &guest)?;
        require(selected_grants.get(&role) == Some(grant.digest())
            && grant.guest().runtime_configuration_sha256 == Sha256Digest::compute(member.runtime_original.as_bytes())
            && uids.insert(grant.guest().uid) && gids.insert(grant.guest().gid))?;
        super::super::initial_history::require_remote_guest(&exact, header, role, &grant)?;
        let (scope_raw, issued, expires) = grant.history_scope_original()?;
        if role == TrustedHostServiceRoleV3::BoundedCleanupHelper {
            if let Some(manifest) = &runtime.helper_bootstrap {
                require(manifest.deadline.absolute_boottime_nanos() <= expires)?;
            }
        }
        let scope: serde_json::Value = decode_canonical_frame(&scope_raw)?;
        scope_binding(&scope, configuration)?;
        if let Some(previous) = &common_scope { require(previous == &scope_raw)?; }
        else { common_scope = Some(scope_raw); }
        let now = boottime_now_nanos().map_err(error)?;
        require(issued <= now && now < expires
            && now < native_guest::decimal(&guest.startup_deadline_boottime_ns).map_err(error)?)?;
        require(histories.insert(configured.service_role, grant.into_history()).is_none())?;
    }
    owner.check().map_err(error)?;
    ProductionServiceHistoricalKeyringsV4::new(
        take_history(&mut histories, HistoricalServiceRoleV3::DurableRecoveryStore)?,
        take_history(&mut histories, HistoricalServiceRoleV3::CleanupAuthorizationConsumer)?,
        take_history(&mut histories, HistoricalServiceRoleV3::RecoveryTargetProvider)?,
        take_history(&mut histories, HistoricalServiceRoleV3::CurrentSignatureAuthority)?,
        take_history(&mut histories, HistoricalServiceRoleV3::BoundedCleanupHelper)?,
    )
}

#[cfg(test)]
mod flat_runtime_tests {
    use super::*;

    #[test]
    fn actual_flat_helper_runtime_is_decoded_without_synthetic_service_wrapper() {
        // Syntactic public fixture only, not authenticated runtime admission.
        let pin = Sha256Digest::compute(b"SYNTHETIC flat ordinary runtime");
        let peer = serde_json::json!({"uid":1,"gid":2,"pid":3,"processIdentitySha256":pin,
            "startTimeTicks":4,"executableDevice":5,"executableInode":6,"executableLength":7,
            "executableSha256":pin,"cgroupPathSha256":pin,"cgroupMountId":8,"cgroupInode":9,
            "securityLabelSha256":pin,"configurationGenerationSha256":pin});
        let header = serde_json::json!({"apiVersion":"catchplate.policyCustodyServiceRuntimeConfig/v5",
            "startupTimeoutMillis":10,"operationGeneration":1,"serviceRestartEpoch":1,"readinessEpoch":1,
            "durabilityWorkerQueueDepth":8,"maximumDurabilityWorkerNanos":100,
            "authorityHistoryManifestSha256":pin,"authorityHistoryManifestCredential":"synthetic-history",
            "authorityHistoryRootKeyId":pin,"authorityHistoryRootKeySpkiSha256":pin,
            "productionDispatchProtocolSetSha256":pin,"deploymentGenerationSha256":pin,
            "sharedConfigurationSha256":pin,"listenerSocketPath":"/run/synthetic/helper.sock",
            "expectedPeer":peer,"activationDirectoryIdentities":{}});
        let flat = serde_json::json!({"runtime":header,"signingKeyCredential":"synthetic-signing",
            "currentHeadAuthorityVerifyingKeyCredential":"synthetic-public","currentHeadAuthorityKeyId":pin,
            "endpointProcessIdentitySha256":pin,"endpointGeneration":1,"helperGeneration":1,
            "signingKeyId":pin,"checkpointSequence":1,"currentKeyAuthorizationCheckpointSha256":pin,
            "revocationGeneration":1,"revocationRootSha256":pin});
        let raw = encode_canonical_frame(&flat).unwrap();
        assert!(ordinary_header(TrustedHostServiceRoleV3::BoundedCleanupHelper,&raw).is_ok());
        let mut service = flat.clone(); service.as_object_mut().unwrap().remove("runtime");
        let wrapped = encode_canonical_frame(&serde_json::json!({"runtime":header,"service":service})).unwrap();
        assert!(ordinary_header(TrustedHostServiceRoleV3::BoundedCleanupHelper,&wrapped).is_err());
    }
}
