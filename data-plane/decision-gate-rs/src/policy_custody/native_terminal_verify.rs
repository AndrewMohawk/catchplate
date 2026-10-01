//! Gate-side successful-invocation evidence. This is a child of production so
//! it reuses the exact existing endpoint/commit grammars. No process-death or
//! global business-effect retirement assertion is constructed here.
use super::*;
use crate::policy_shadow::*;
use crate::policy_shadow::policy_custody::{native_terminal as wire, native_remote_factory::Factory};
use crate::policy_shadow::policy_custody::production_dispatch::ProductionDispatchBindingV4;
use crate::policy_shadow::policy_custody::services::guest::native_keys::admission::persistence;

fn ensure(value: bool) -> Result<(), ShadowError> {
    if value { Ok(()) } else { Err(ShadowError::BindingDrift) }
}
fn exact<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T, ShadowError> {
    ensure(!raw.is_empty() && raw.len() <= MAX_SERVICE_FRAME_BYTES && raw.is_ascii())?;
    let value: T = serde_json::from_slice(raw).map_err(|_| ShadowError::BindingDrift)?;
    ensure(canonical_json_bytes(&value)? == raw)?;
    Ok(value)
}
fn encoded<T: serde::de::DeserializeOwned + Serialize>(value: &str) -> Result<(T, Vec<u8>), ShadowError> {
    ensure(!value.is_empty() && value.len() <= MAX_SERVICE_FRAME_BYTES)?;
    let raw = URL_SAFE_NO_PAD.decode(value).map_err(|_| ShadowError::BindingDrift)?;
    ensure(URL_SAFE_NO_PAD.encode(&raw) == value)?;
    Ok((exact(&raw)?, raw))
}
fn signature(value: &str) -> Result<Signature, ShadowError> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ShadowError::SignatureInvalid)?;
    ensure(URL_SAFE_NO_PAD.encode(&bytes) == value && bytes.len() == 64)?;
    Signature::from_slice(&bytes).map_err(|_| ShadowError::SignatureInvalid)
}
fn key(configuration: &ProductionCustodyConfiguration, trust: &dyn EnvelopeKeyTrust,
    checkpoint: &AtomicTrustCheckpoint, role: AuthorityRole, id: &Sha256Digest, spki: &Sha256Digest,
    domain: &str) -> Result<VerifyingKey, ShadowError> {
    let assigned = configuration.authority_binding(role)?;
    ensure(assigned.key_id() == id && assigned.key_spki_sha256() == spki)?;
    let key = trust.resolve_ed25519_key(checkpoint, domain, id, spki)?;
    ensure(&ed25519_public_key_material_sha256(&key) == assigned.key_material_sha256()
        && trust.current_checkpoint()? == *checkpoint)?;
    Ok(key)
}
fn endpoint_reply(request: &ProductionAuthorityEndpointRequestV4, reply: &ProductionAuthorityEndpointReplyV4,
    role: AuthorityRole, domain: &str, configuration: &ProductionCustodyConfiguration,
    trust: &dyn EnvelopeKeyTrust, checkpoint: &AtomicTrustCheckpoint,
    opened: u64, now: u64) -> Result<VerifyingKey, ShadowError> {
    ensure(request.api_version == PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
        && request.request_sha256 == request.computed_request_sha256().map_err(|_| ShadowError::BindingDrift)?
        && reply.api_version == request.api_version && reply.endpoint == request.endpoint
        && reply.request_sha256 == request.request_sha256 && reply.replay_id_sha256 == request.replay_id_sha256
        && reply.completed_at_boottime_nanos >= opened && reply.completed_at_boottime_nanos <= now
        && reply.completed_at_boottime_nanos < request.deadline_boottime_nanos
        && reply.result_sha256 == hash_domain_frames(PRODUCTION_AUTHORITY_ENDPOINT_RESPONSE_DOMAIN,
            &[&canonical_json_bytes(&reply.result)?]))?;
    let key = key(configuration, trust, checkpoint, role, &reply.authority_key_id,
        &reply.authority_key_spki_sha256, domain)?;
    key.verify_strict(&domain_separated_signature_preimage(PRODUCTION_AUTHORITY_ENDPOINT_SIGNATURE_DOMAIN,
        &reply.signature_payload().map_err(|_| ShadowError::BindingDrift)?)
        .map_err(|_| ShadowError::BindingDrift)?, &signature(&reply.signature_base64)?)
        .map_err(|_| ShadowError::SignatureInvalid)?;
    Ok(key)
}

fn histories(factory: &Factory, configuration: &ProductionCustodyConfiguration,
    trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime, now: u64)
    -> Result<(ProductionRpcRuntimeConfigV4, ProductionServiceHistoricalKeyringsV4, u64), ShadowError> {
    let raw = factory.native_terminal_runtime_original(trust, time)?;
    let runtime: ProductionRpcRuntimeConfigV4 = exact(&raw)?;
    runtime.validate().map_err(|_| ShadowError::BindingDrift)?;
    ensure(runtime.native_terminal_selected())?;
    let guest = configuration.remote_native_execution_closure().ok_or(ShadowError::BindingDrift)?.guest();
    ensure(guest.runtime_configuration_sha256 == Sha256Digest::compute(&raw))?;
    let members = runtime.ordinary_initial_histories.as_ref().ok_or(ShadowError::BindingDrift)?;
    let selected = serde_json::to_value(runtime.generation_admission.as_ref().ok_or(ShadowError::BindingDrift)?)
        .map_err(|_| ShadowError::BindingDrift)?;
    let pins: BTreeMap<TrustedHostServiceRoleV3, Sha256Digest> = serde_json::from_value(
        selected.get("grants").ok_or(ShadowError::BindingDrift)?.clone()).map_err(|_| ShadowError::BindingDrift)?;
    let mut histories = BTreeMap::new();
    let mut common_scope = None;
    let mut deadline = u64::MAX;
    let mut uids = BTreeSet::from([guest.uid]);
    let mut gids = BTreeSet::from([guest.gid]);
    for configured in &runtime.histories {
        let role = trusted_service_role(configured.service_role);
        let member = members.get(&role).ok_or(ShadowError::BindingDrift)?;
        let header = initial_history::ordinary_header(role, member.runtime_original.as_bytes())
            .map_err(|_| ShadowError::BindingDrift)?;
        header.validate().map_err(|_| ShadowError::BindingDrift)?;
        ensure(runtime.expected_service_configuration_sha256.get(&role) == Some(&Sha256Digest::compute(member.runtime_original.as_bytes()))
            && configured.manifest_sha256 == header.authority_history_manifest_sha256
            && configured.root_key_id == header.authority_history_root_key_id
            && configured.root_key_spki_sha256 == header.authority_history_root_key_spki_sha256
            && expected_history_manifest_sha256(&runtime, configured.service_role) == Some(&configured.manifest_sha256)
            && runtime.expected_service_restart_epoch.get(&role) == Some(&header.service_restart_epoch)
            && runtime.expected_service_readiness_epoch.get(&role) == Some(&header.readiness_epoch)
            && header.operation_generation == runtime.expected_operation_generation
            && header.shared_configuration_sha256 == runtime.expected_shared_configuration_sha256
            && header.production_dispatch_protocol_set_sha256 == *configuration.dispatcher_protocol_set_sha256()
            && header.production_dispatch_protocol_set_sha256 == runtime.expected_production_dispatch_protocol_set_sha256
            && header.maximum_durability_worker_nanos == runtime.expected_maximum_durability_worker_nanos
            && header.expected_peer.uid == guest.uid && header.expected_peer.gid == guest.gid)?;
        let original = member.history_original.as_ref().ok_or(ShadowError::BindingDrift)?;
        ensure(super::super::initial_history::selected(original.as_bytes()).map_err(|_| ShadowError::BindingDrift)?)?;
        let (history, history_deadline) = super::super::initial_history::load_retained_completed_invocation(original.as_bytes(), &header, role)
            .map_err(|_| ShadowError::BindingDrift)?;
        let grant = super::super::generation_service::RemoteGrant::admit(
            member.generation_grant_original.as_bytes(), history, role, guest).map_err(|_| ShadowError::BindingDrift)?;
        ensure(pins.get(&role) == Some(grant.digest())
            && grant.guest().runtime_configuration_sha256 == Sha256Digest::compute(member.runtime_original.as_bytes())
            && uids.insert(grant.guest().uid) && gids.insert(grant.guest().gid))?;
        super::super::initial_history::require_retained_completed_guest(original.as_bytes(), &header, role, &grant)
            .map_err(|_| ShadowError::BindingDrift)?;
        let (scope_raw, issued, expires) = grant.history_scope_original().map_err(|_| ShadowError::BindingDrift)?;
        deadline = deadline.min(expires).min(history_deadline);
        let scope: serde_json::Value = exact(&scope_raw)?;
        initial_history::scope_binding(&scope, configuration).map_err(|_| ShadowError::BindingDrift)?;
        ensure(scope.get("dispatchManifestSha256") == Some(&serde_json::to_value(factory.manifest.manifest_sha256()).map_err(|_| ShadowError::BindingDrift)?)
            && scope.get("retainedDescriptorSetSha256") == Some(&serde_json::to_value(&factory.driver.retained_descriptor_manifest_sha256).map_err(|_| ShadowError::BindingDrift)?)
            && scope.get("driverGenerationReceiptSha256") == Some(&serde_json::to_value(&factory.prior_admission_sha256).map_err(|_| ShadowError::BindingDrift)?)
            && issued <= now && now < expires)?;
        if let Some(prior) = &common_scope { ensure(prior == &scope_raw)?; }
        else { common_scope = Some(scope_raw); }
        ensure(histories.insert(configured.service_role, grant.into_history()).is_none())?;
    }
    let histories = ProductionServiceHistoricalKeyringsV4::new(
        take_history(&mut histories, HistoricalServiceRoleV3::DurableRecoveryStore).map_err(|_| ShadowError::BindingDrift)?,
        take_history(&mut histories, HistoricalServiceRoleV3::CleanupAuthorizationConsumer).map_err(|_| ShadowError::BindingDrift)?,
        take_history(&mut histories, HistoricalServiceRoleV3::RecoveryTargetProvider).map_err(|_| ShadowError::BindingDrift)?,
        take_history(&mut histories, HistoricalServiceRoleV3::CurrentSignatureAuthority).map_err(|_| ShadowError::BindingDrift)?,
        take_history(&mut histories, HistoricalServiceRoleV3::BoundedCleanupHelper).map_err(|_| ShadowError::BindingDrift)?)
        .map_err(|_| ShadowError::BindingDrift)?;
    Ok((runtime, histories, deadline))
}

/// Constructor is confined to this complete verifier. A caller cannot supply a
/// success boolean, result digest, process proof, or alternate authority roster.
pub(in crate::policy_shadow) struct NativeEvidence {
    factory: Arc<Factory>, binding: ProductionDispatchBindingV4,
    operation: PolicyShadowCustodyOperation, checkpoint: AtomicTrustCheckpoint,
    completed: u64, original_sha256: Sha256Digest, expires_at_boottime_nanos: u64,
}
impl NativeEvidence {
    pub(in crate::policy_shadow) fn finish(self, permit: &ProductionCustodyMutationPermit,
        disposition: ProductionCustodyResultDisposition, configuration: &ProductionCustodyConfiguration,
        history: &ProductionCustodyKeyHistoryState, trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime)
        -> Result<(u64, Sha256Digest), ShadowError> {
        self.factory.check(trust, time)?;
        permit.authorize_cleanup(permit.operation(), permit.operation_id_sha256())?;
        ensure(self.factory.native_terminal_selected() && disposition == ProductionCustodyResultDisposition::ResultCommitted
            && permit.operation() == self.operation && *permit.operation_id_sha256() == self.binding.operation_id_sha256
            && *permit.termination_fence_sha256() == self.binding.termination_fence_sha256
            && *permit.request_sha256() == self.binding.request_sha256
            && *permit.durable_request_sha256() == self.binding.durable_request_sha256
            && permit.operation_deadline().opened_at_boottime_nanos() == self.binding.opened_at_boottime_nanos
            && permit.operation_deadline().operation_deadline_boottime_nanos() == self.binding.operation_deadline_boottime_nanos
            && permit.operation_deadline().cleanup_deadline_boottime_nanos() == self.binding.cleanup_deadline_boottime_nanos
            && *configuration.production_configuration_binding_sha256() == self.binding.production_configuration_binding_sha256
            && *configuration.kernel_retained_driver_identity_sha256() == self.binding.kernel_driver_identity_sha256
            && trust.current_checkpoint()? == self.checkpoint)?;
        history.validate(configuration, &self.checkpoint)?;
        let now = boottime_now_nanos().map_err(|_| ShadowError::CustodyUnavailable)?;
        ensure(self.completed >= self.binding.opened_at_boottime_nanos && self.completed <= now
            && now < self.binding.cleanup_deadline_boottime_nanos && now < self.expires_at_boottime_nanos)?;
        Ok((self.completed, self.original_sha256))
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::policy_shadow) fn verify(value: wire::Wire, request_raw: &[u8], response_raw: &[u8],
    expected: &ProductionDispatchBindingV4, permit: &ProductionCustodyMutationPermit, factory: Arc<Factory>,
    configuration: &ProductionCustodyConfiguration, trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime)
    -> Result<NativeEvidence, ShadowError> {
    factory.check(trust, time)?;
    let publication_selected = factory.publication_terminal_selected();
    ensure(factory.native_terminal_selected() && value.api_version == (if publication_selected {wire::PUBLICATION_WIRE_API}else{wire::WIRE_API})
        && value.dispatch_request_original_sha256 == Sha256Digest::compute(request_raw)
        && value.dispatch_response_original_sha256 == Sha256Digest::compute(response_raw))?;
    configuration.revalidate_active_attestation(trust, time)?;
    let checkpoint = trust.current_checkpoint()?;
    let now = boottime_now_nanos().map_err(|_| ShadowError::CustodyUnavailable)?;
    let rpc_request: ProductionRpcRequestV4 = exact(request_raw)?;
    rpc_request.validate().map_err(|_| ShadowError::BindingDrift)?;
    let rpc_response: ProductionRpcResponseV4 = exact(response_raw)?;
    rpc_response.validate_for_request(&rpc_request).map_err(|_| ShadowError::BindingDrift)?;
    let ProductionRpcRequestBodyV4::Dispatch(dispatch) = &rpc_request.request else { return Err(ShadowError::BindingDrift); };
    let response = match &rpc_response.response {
        ProductionRpcResponseBodyV4::Dispatch(response) => response,
        ProductionRpcResponseBodyV4::NativeCommitRequest { dispatch: response, computation } => {
            crate::policy_shadow::policy_custody::native_request_commitment::verify_computation(
                computation, dispatch, response, configuration, trust, time)?;
            response
        },
        _ => return Err(ShadowError::BindingDrift),
    };
    let binding = dispatch.binding();
    ensure(binding == expected && binding.opened_at_boottime_nanos <= now && now < binding.cleanup_deadline_boottime_nanos)?;
    let (runtime, histories, history_deadline) = histories(&factory, configuration, trust, time, now)?;
    ensure(runtime.publication_selected() == publication_selected)?;
    response.validate(dispatch, &histories.borrowed()).map_err(|_| ShadowError::BindingDrift)?;
    let request: ProductionAuthorityEndpointRequestV4 = exact(value.persistence_request_original.as_bytes())?;
    let reply: ProductionAuthorityEndpointReplyV4 = exact(value.persistence_reply_original.as_bytes())?;
    let ProductionAuthorityEndpointRequestBodyV4::VerifyCompletedInvocation { query } = &request.request
        else { return Err(ShadowError::BindingDrift); };
    query.validate().map_err(|_| ShadowError::BindingDrift)?;
    ensure(query.api_version == wire::Query::api_for_publication(publication_selected)
        && query.dispatch == *dispatch && query.dispatch_response_sha256 == Sha256Digest::compute(&canonical_json_bytes(response)?)
        && request.endpoint == ProductionAuthorityEndpointIdentityV4::Proof(ProductionProofEndpointKindV4::Persistence)
        && request.replay_id_sha256 == binding.replay_id_sha256
        && request.deadline_boottime_nanos == binding.cleanup_deadline_boottime_nanos)?;
    let store_key = endpoint_reply(&request, &reply, AuthorityRole::CustodyStoreResponse,
        authority_role_signature_domain(AuthorityRole::CustodyStoreResponse), configuration, trust,
        &checkpoint, binding.opened_at_boottime_nanos, now)?;
    let ProductionAuthorityEndpointResultV4::CompletedInvocation(proof) = &reply.result
        else { return Err(ShadowError::BindingDrift); };
    ensure(proof.api_version == query.proof_api())?;
    let commit: persistence::Commit = exact(proof.commit_original.as_bytes())?;
    let head: persistence::PersistenceHead = exact(proof.head_original.as_bytes())?;
    let payload = &commit.payload;
    let bridge = configuration.remote_native_execution_closure().ok_or(ShadowError::BindingDrift)?.guest();
    let persistence = runtime.proof_endpoints.iter().find(|endpoint| endpoint.endpoint_kind == ProductionProofEndpointKindV4::Persistence)
        .ok_or(ShadowError::BindingDrift)?;
    let issued = payload.guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| ShadowError::BindingDrift)?;
    let startup = payload.guest.startup_deadline_boottime_ns.parse::<u64>().map_err(|_| ShadowError::BindingDrift)?;
    let lifetime = payload.guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| ShadowError::BindingDrift)?;
    ensure(payload.api_version == "serverware.nativeShadowPersistenceCommit/v1"
        && payload.proof_scope_sha256 == *configuration.proof_scope().binding_sha256()
        && payload.signing_key_id == reply.authority_key_id && payload.signing_key_spki_sha256 == reply.authority_key_spki_sha256
        && payload.guest.service_role == "production-bridge"
        && payload.guest.uid == persistence.expected_peer.uid && payload.guest.gid == persistence.expected_peer.gid
        && persistence.authority_key_id == reply.authority_key_id && persistence.authority_key_spki_sha256 == reply.authority_key_spki_sha256
        && issued > 0 && issued < startup && startup < lifetime && now < lifetime
        && payload.guest.issued_at_boottime_ns == issued.to_string()
        && payload.guest.startup_deadline_boottime_ns == startup.to_string()
        && payload.guest.lifetime_deadline_boottime_ns == lifetime.to_string()
        && issued <= binding.opened_at_boottime_nanos && binding.cleanup_deadline_boottime_nanos <= lifetime
        && payload.guest.uid != bridge.uid && payload.guest.boot_id_base64url == bridge.boot_id_base64url
        && payload.guest.time_namespace_device == bridge.time_namespace_device
        && payload.guest.time_namespace_inode == bridge.time_namespace_inode
        && payload.original_deadline_boottime_nanos == binding.operation_deadline_boottime_nanos
        && payload.stored_at_boottime_nanos >= binding.opened_at_boottime_nanos
        && payload.stored_at_boottime_nanos < binding.operation_deadline_boottime_nanos
        && payload.stored_at_boottime_nanos <= reply.completed_at_boottime_nanos
        && head.api_version == "serverware.nativeShadowPersistenceHead/v1"
        && payload.sequence > 0 && head.sequence == payload.sequence && head.sequence <= proof.current_head_sequence
        && proof.current_head_sequence <= 128 && proof.current_head_sha256 != Sha256Digest::compute(&[])
        && head.previous_head_sha256 == payload.previous_head_sha256
        && head.commit_original_sha256 == Sha256Digest::compute(proof.commit_original.as_bytes())
        && (head.sequence != proof.current_head_sequence || proof.current_head_sha256 == Sha256Digest::compute(proof.head_original.as_bytes())))?;
    store_key.verify_strict(&signature_preimage(persistence::COMMIT_DOMAIN, &canonical_json_bytes(payload)?),
        &Signature::from_bytes(&commit.signature.decode()?)).map_err(|_| ShadowError::SignatureInvalid)?;
    let (final_request, final_raw): (ProductionAuthorityEndpointRequestV4, _) = encoded(&payload.request_original_base64url)?;
    let (final_reply, _): (ProductionAuthorityEndpointReplyV4, _) = encoded(&payload.reply_original_base64url)?;
    ensure(payload.request_original_sha256 == Sha256Digest::compute(&final_raw)
        && persistence::final_dispatch(&final_request)? == dispatch
        && final_request.replay_id_sha256 == binding.replay_id_sha256
        && final_request.deadline_boottime_nanos == binding.operation_deadline_boottime_nanos
        && final_reply.result == ProductionAuthorityEndpointResultV4::Dispatch(response.clone())
        && final_reply.completed_at_boottime_nanos <= payload.stored_at_boottime_nanos)?;
    let role = if let ProductionAuthorityEndpointRequestBodyV4::FinishNativeSpool { completion, .. } = &final_request.request {
        completion.payload.prepared.core.validate().map_err(|_| ShadowError::BindingDrift)?;
        completion.payload.prepared.core.role()
    } else { production_signer_role(dispatch).map_err(|_| ShadowError::BindingDrift)? };
    ensure(final_request.endpoint == ProductionAuthorityEndpointIdentityV4::ParentSigner(role))?;
    let signer = endpoint_reply(&final_request, &final_reply, authority_role_for_custody_signer(role),
        role.signature_domain(), configuration, trust, &checkpoint, binding.opened_at_boottime_nanos, now)?;
    verify_final_request(&final_request, response, &signer, &final_reply, publication_selected)?;
    let publication_deadline = if let ProductionAuthorityEndpointRequestBodyV4::FinishNativePublication { proposal, .. } = &final_request.request {
        verify_publication_admission(&runtime, &histories, configuration, trust, time, &checkpoint, proposal, now)?
    } else { u64::MAX };
    factory.check(trust, time)?;
    ensure(trust.current_checkpoint()? == checkpoint)?;
    let completed = reply.completed_at_boottime_nanos;
    let original_sha256 = Sha256Digest::compute(&canonical_json_bytes(&value)?);
    // Authentication can consume time. Preserve every authenticated original
    // bound through both this return and the caller's final capability check.
    let expires_at_boottime_nanos = history_deadline.min(lifetime).min(binding.cleanup_deadline_boottime_nanos).min(publication_deadline);
    let final_now = boottime_now_nanos().map_err(|_| ShadowError::CustodyUnavailable)?;
    ensure(final_now >= now && final_now >= completed && final_now < expires_at_boottime_nanos)?;
    Ok(NativeEvidence { factory, binding: binding.clone(), operation: permit.operation(), checkpoint,
        completed, original_sha256, expires_at_boottime_nanos })
}

fn verify_final_request(request: &ProductionAuthorityEndpointRequestV4, response: &ClosedProductionDispatchResponseV4,
    key: &VerifyingKey, reply: &ProductionAuthorityEndpointReplyV4, publication_selected: bool) -> Result<(), ShadowError> {
    use ProductionAuthorityEndpointRequestBodyV4 as Body;
    match &request.request {
        // v12's admitted operation set uses genuine native completion paths;
        // an old final Dispatch signature cannot stand in for that execution.
        Body::Dispatch(_) => Err(ShadowError::BindingDrift),
        Body::FinishNativePublication { proposal, result, service_transitions } => {
            ensure(publication_selected
                && request.endpoint == ProductionAuthorityEndpointIdentityV4::ParentSigner(PolicyShadowCustodySignerRole::PublicationReconciliation))?;
            persistence::verify_publication_final(proposal, result, service_transitions, response, key,
                &reply.authority_key_id, &reply.authority_key_spki_sha256)
        },
        Body::FinishCommitRequest { computation, service_transitions } => {
            ensure(matches!(computation.request, ClosedProductionDispatchRequestV4::CommitRequest { .. })
                && request.endpoint == ProductionAuthorityEndpointIdentityV4::ParentSigner(PolicyShadowCustodySignerRole::LedgerAppend)
                && response.result == computation.result && response.service_transitions == *service_transitions
                && computation.api_version == "serverware.nativeShadowCommitRequestComputation/v1"
                && computation.result_sha256 == response.result_sha256
                && computation.computed_at_boottime_nanos >= computation.request.binding().opened_at_boottime_nanos
                && computation.computed_at_boottime_nanos < request.deadline_boottime_nanos)?;
            key.verify_strict(&computation.preimage().map_err(|_| ShadowError::BindingDrift)?,
                &signature(&computation.signature_base64url)?).map_err(|_| ShadowError::SignatureInvalid)
        },
        Body::FinishNativeSpool { completion, result, service_transitions } => {
            let core = &completion.payload.prepared.core;
            ensure(matches!(core.request, ClosedProductionDispatchRequestV4::BeginIngress { .. }
                    | ClosedProductionDispatchRequestV4::ReserveSpoolAppend { .. }
                    | ClosedProductionDispatchRequestV4::AppendSpoolEvent { .. }
                    | ClosedProductionDispatchRequestV4::AppendTerminal { .. })
                && *result == response.result && *service_transitions == response.service_transitions
                && completion.payload.claim.request == core.request
                && core.signing_key_id == reply.authority_key_id && core.signing_key_spki_sha256 == reply.authority_key_spki_sha256
                && final_artifact(result)? == &completion.payload.artifact)?;
            key.verify_strict(&signature_preimage(super::super::spool_head_values::COMPLETE_DOMAIN,
                &canonical_json_bytes(&completion.payload)?), &Signature::from_bytes(&completion.signature.decode()?))
                .map_err(|_| ShadowError::SignatureInvalid)
        },
        Body::FinishNativeActiveEffect { completion, result, service_transitions } => {
            let core = &completion.prepared.core;
            core.validate().map_err(|_| ShadowError::BindingDrift)?;
            ensure(matches!(core.request, ClosedProductionDispatchRequestV4::AppendActiveEffectBarrier { .. }
                    | ClosedProductionDispatchRequestV4::CommitActiveEffect { .. }
                    | ClosedProductionDispatchRequestV4::ReconcileActiveEffect { .. })
                && *result == response.result && *service_transitions == response.service_transitions
                && request.endpoint == ProductionAuthorityEndpointIdentityV4::ParentSigner(core.role())
                && core.signing_key_id == reply.authority_key_id && core.signing_key_spki_sha256 == reply.authority_key_spki_sha256
                && final_artifact(result)? == &completion.artifact)?;
            key.verify_strict(&completion.preimage().map_err(|_| ShadowError::BindingDrift)?,
                &Signature::from_bytes(&completion.signature.decode()?)).map_err(|_| ShadowError::SignatureInvalid)
        },
        _ => Err(ShadowError::BindingDrift),
    }
}

fn publication_admission(runtime: &ProductionRpcRuntimeConfigV4, histories: &ProductionServiceHistoricalKeyringsV4,
    configuration: &ProductionCustodyConfiguration, trust: &dyn EnvelopeKeyTrust, time: &dyn TrustedTime,
    checkpoint: &AtomicTrustCheckpoint, now: u64) -> Result<(super::super::publication_service::Grant,VerifyingKey), ShadowError> {
    use super::super::publication_service::Grant;
    ensure(runtime.publication_selected())?;
    let selection = runtime.publication.as_ref().ok_or(ShadowError::BindingDrift)?;
    selection.validate().map_err(|_| ShadowError::BindingDrift)?;
    let (durable_raw, current_raw) = selection.originals();
    let durable: Grant = exact(durable_raw.as_bytes())?;
    let current: Grant = exact(current_raw.as_bytes())?;
    let rings = histories.borrowed();
    let drs = rings.history(HistoricalServiceRoleV3::DurableRecoveryStore);
    let csa = rings.history(HistoricalServiceRoleV3::CurrentSignatureAuthority);
    let durable_key = durable.verify(drs).map_err(|_| ShadowError::BindingDrift)?;
    current.verify(csa).map_err(|_| ShadowError::BindingDrift)?;
    let d = &durable.payload;
    let c = &current.payload;
    let bridge = configuration.remote_native_execution_closure().ok_or(ShadowError::BindingDrift)?.guest();
    ensure(d.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore
        && c.service_role == TrustedHostServiceRoleV3::CurrentSignatureAuthority
        && d.admission == c.admission && d.native == c.native && d.retrieval == c.retrieval
        && d.durable_authority_epoch == c.durable_authority_epoch
        && d.durable_public_key_base64url == c.durable_public_key_base64url
        && d.initial_transition_head_sha256 == c.initial_durable_transition_head_sha256
        && d.guest.uid != c.guest.uid && d.guest.gid != c.guest.gid
        && d.admission.proof_scope_original.as_bytes() == canonical_json_bytes(configuration.proof_scope())?.as_slice()
        && d.admission.scope.assignment_payload_sha256 == *configuration.assignment_payload_sha256()
        && d.admission.scope.assignment_revision == configuration.assignment_revision()
        && d.admission.scope.retrieval_namespace_sha256 == *configuration.retrieval_namespace_sha256()
        && d.admission.scope.issued_at_boottime_nanos <= now && now < d.admission.scope.expires_at_boottime_nanos)?;
    for p in [d, c] {
        ensure(runtime.expected_service_configuration_sha256.get(&p.service_role) == Some(&p.runtime_configuration_sha256)
            && p.guest.uid != bridge.uid && p.guest.gid != bridge.gid
            && p.guest.boot_id_base64url == bridge.boot_id_base64url
            && p.guest.time_namespace_device == bridge.time_namespace_device && p.guest.time_namespace_inode == bridge.time_namespace_inode)?;
    }
    for role_key in [&d.native, &d.retrieval] {
        let domain = if role_key.role == AuthorityRole::CustodyPublicationReconciliation {
            PolicyShadowCustodySignerRole::PublicationReconciliation.signature_domain()
        } else { authority_role_signature_domain(AuthorityRole::CustodyRetrievalResponse) };
        let assigned = key(configuration, trust, checkpoint, role_key.role, &role_key.key_id, &role_key.key_spki_sha256, domain)?;
        ensure(assigned == role_key.material().map_err(|_| ShadowError::BindingDrift)?)?;
    }
    ensure(runtime.publication_adoption_selected()==d.admission.adoption.is_some())?;
    if let Some(adoption)=&d.admission.adoption {
        require_adoption_authority(adoption,configuration,trust,time,checkpoint)?;
        adoption.require_guest(bridge).map_err(|_|ShadowError::BindingDrift)?;
        ensure(d.admission.scope.expires_at_boottime_nanos<=adoption.deadline_boottime()?)?;
    }
    Ok((durable,durable_key))
}

fn require_adoption_authority(adoption:&super::super::publication_adoption::Authorization,
    configuration:&ProductionCustodyConfiguration,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
    checkpoint:&AtomicTrustCheckpoint)->Result<(),ShadowError>{
    let binding=configuration.authority_binding(AuthorityRole::CustodySupervisorCapability)?;
    let authority=key(configuration,trust,checkpoint,AuthorityRole::CustodySupervisorCapability,
        binding.key_id(),binding.key_spki_sha256(),authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability))?;
    adoption.require_authority(binding.key_id(),binding.key_spki_sha256(),&authority,checkpoint,time.now_unix_nanos()?)?;
    let scope=String::from_utf8(canonical_json_bytes(configuration.proof_scope())?).map_err(|_|ShadowError::BindingDrift)?;
    adoption.verify_current(configuration.assignment_payload_sha256(),configuration.assignment_revision(),
        configuration.production_configuration_binding_sha256(),&scope)?;
    ensure(boottime_now_nanos().map_err(|_|ShadowError::CustodyUnavailable)?<adoption.deadline_boottime()?)
}

/// Acquire only from the actual retained selected runtime and independently
/// authenticated ordinary grants. An artifact cannot introduce an adoption.
pub(in crate::policy_shadow) fn publication_adoption(factory:&Factory,configuration:&ProductionCustodyConfiguration,
    trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<super::super::publication_adoption::Authorization,ShadowError>{
    factory.check(trust,time)?;ensure(factory.publication_adoption_selected())?;
    let now=boottime_now_nanos().map_err(|_|ShadowError::CustodyUnavailable)?;
    let (runtime,histories,deadline)=histories(factory,configuration,trust,time,now)?;
    ensure(runtime.publication_adoption_selected() && now<deadline)?;
    let checkpoint=trust.current_checkpoint()?;
    let (grant,_)=publication_admission(&runtime,&histories,configuration,trust,time,&checkpoint,now)?;
    let adoption=*grant.payload.admission.adoption.ok_or(ShadowError::BindingDrift)?;
    factory.check(trust,time)?;ensure(trust.current_checkpoint()?==checkpoint)?;
    Ok(adoption)
}

fn verify_publication_admission(runtime: &ProductionRpcRuntimeConfigV4, histories: &ProductionServiceHistoricalKeyringsV4,
    configuration: &ProductionCustodyConfiguration, trust: &dyn EnvelopeKeyTrust, time:&dyn TrustedTime,
    checkpoint: &AtomicTrustCheckpoint, proposal: &super::super::publication::Proposal, now: u64) -> Result<u64, ShadowError> {
    let (durable,durable_key)=publication_admission(runtime,histories,configuration,trust,time,checkpoint,now)?;
    let d=&durable.payload;
    proposal.verify_with_key(&d.admission, &d.native, &d.retrieval, &d.durable_authority_epoch, &durable_key)
        .map_err(|_| ShadowError::BindingDrift)?;
    ensure(proposal.completed_at_boottime_nanos <= now)?;
    Ok(d.admission.scope.expires_at_boottime_nanos)
}
fn final_artifact(result: &crate::policy_shadow::policy_custody::production_dispatch::ClosedProductionDispatchResultV4)
    -> Result<&CanonicalProductionArtifactV4, ShadowError> {
    use crate::policy_shadow::policy_custody::production_dispatch::ClosedProductionDispatchResultV4 as R;
    match result { R::Artifact(value) => Ok(value), R::SealedArtifact { exact_signed_artifact, .. } => Ok(&exact_signed_artifact.artifact),
        _ => Err(ShadowError::BindingDrift) }
}
