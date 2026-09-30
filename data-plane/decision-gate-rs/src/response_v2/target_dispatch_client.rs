//! One retained authenticated session, no target-contact retry or reopen path.
use super::*;
use serverware_decision_gate::native_target_dispatch_v1 as profile;
use serverware_decision_gate::response_observation_v2::custody::target_dispatch::wire;
use serverware_decision_gate::response_observation_v2::state_authority::{canonical,lifecycle,rpc};
use base64::{engine::general_purpose::STANDARD,Engine as _};

fn invalid()->ResponseObservationV2TransactionError {ResponseObservationV2TransactionError::InvalidResponse}

/// Source-owned raw TLS capture retained only after verified persistence and
/// the actual provider-send effect commit. No wire constructor, Clone or
/// Deserialize implementation can turn a completion DTO into this owner.
pub(crate) struct CommittedNativeCapture {
    raw: Zeroizing<Vec<u8>>,
    capture: wire::NativeCaptureEnvelope,
    completion: wire::CompletedCapture,
    method: String,
    hook: policy_core::ShadowResponseHook,
    finished: bool,
    _retention: policy_core::NativeResponseRetention,
}

impl CommittedNativeCapture {
    pub(crate) fn raw(&self) -> &[u8] { &self.raw }
    pub(crate) fn capture(&self) -> &wire::NativeCaptureEnvelope { &self.capture }
    pub(crate) fn completion(&self) -> &wire::CompletedCapture { &self.completion }
    pub(crate) fn method(&self) -> &str { &self.method }
    pub(super) fn detailed_observations_selected(&self) -> bool { self.hook.native_details_selected() }

    // Only the transaction module calls this, after exact release consumption,
    // final-envelope verification, reflection and durable-policy completion.
    pub(super) fn finish(mut self, snapshot: &Arc<Snapshot>, validation: &Value, response: &[u8]) {
        self.hook.finish_native_response(snapshot, &self, validation, response);
        self.finished = true;
    }
}

impl Drop for CommittedNativeCapture {
    fn drop(&mut self) {
        if !self.finished {
            self.hook.record_unavailable(
                policy_core::PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
            );
        }
    }
}
fn same<T:Serialize>(a:&T,b:&T)->Result<bool,ResponseObservationV2TransactionError> {
    Ok(profile::canonical(a).map_err(|_|invalid())?==profile::canonical(b).map_err(|_|invalid())?)
}
pub(super) fn signed<T:Serialize>(client:&ResponseObservationV2Client,role:&str,key:&str,domain:&[u8],value:&T,signature:&str)
    ->Result<(),ResponseObservationV2TransactionError> {
    let pin=client.role_keys.get(role).ok_or_else(invalid)?;
    let public=STANDARD.decode(&pin.public_key_base64).map_err(|_|invalid())?;
    let signature_bytes=STANDARD.decode(signature).map_err(|_|invalid())?;
    if pin.role!=role || pin.generation_id!=client.generation_id || pin.provider_generation!=client.provider_generation
        || pin.key_id!=key || pin.key_id!=pin.public_key_sha256 || pin.key_material_sha256!=pin.public_key_sha256
        || public.len()!=32 || signature_bytes.len()!=64 || STANDARD.encode(&public)!=pin.public_key_base64
        || STANDARD.encode(&signature_bytes)!=signature || profile::sha256(&public)!=pin.public_key_sha256 {
        return Err(invalid());
    }
    let mut original=domain.to_vec();original.extend(custody_canonical_json_bytes(value).map_err(|_|invalid())?);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,public).verify(&original,&signature_bytes).map_err(|_|invalid())
}
pub(super) fn scope(client:&ResponseObservationV2Client,value:&serverware_decision_gate::ProviderAuthorityScopeV2,
    attempt:&str,operation:&str,revision:u64,fence:u64)->Result<(),ResponseObservationV2TransactionError> {
    let pin=client.role_keys.get("linearizable-store").ok_or_else(invalid)?;
    let mut unsigned=value.clone();unsigned.operation_binding_sha256.clear();
    if value.api_version!="serverware.responseObservationV2ProviderAuthorityScope/v2"
        || value.role_identity_root_sha256!=client.role_identity_root_sha256
        || !value.allowed_operations.contains(&ServiceOperationV1::StateCas)
        || value.operation_binding_sha256!=profile::sha256(&custody_canonical_json_bytes(&unsigned).map_err(|_|invalid())?)
        || value.generation_id!=client.generation_id || value.generation!=client.provider_generation
        || value.service_role!=CustodyServiceRole::StateAuthority || value.service_id!=pin.provider_id
        || value.logical_role!="linearizable-store" || value.key_id!=pin.key_id
        || value.key_material_sha256!=pin.key_material_sha256 || value.executable_sha256!=pin.executable_measurement_sha256
        || value.configuration_sha256!=pin.provider_config_sha256 || value.operation!=ServiceOperationV1::StateCas
        || value.attempt_id!=attempt || value.operation_id!=operation || value.attempt_revision!=revision || value.fencing_token!=fence {
        return Err(invalid());
    }
    Ok(())
}
fn receipt(client:&ResponseObservationV2Client,value:&wire::SignedStateMutationReceiptV1,frame:&rpc::RpcRequestFrame,
    original:&wire::DispatchOriginal,revision:u64,state:&str)->Result<(),ResponseObservationV2TransactionError> {
    let digest=canonical::sha256_digest(&canonical::canonical_jcs_bytes(frame).map_err(|_|invalid())?).0;
    if value.api_version!="serverware.responseObservationV2StateMutationReceipt/v1"
        || value.generation_id!=client.generation_id || value.generation!=client.provider_generation
        || value.operation!=ServiceOperationV1::StateCas || value.signer_logical_role!="linearizable-store"
        || value.request_id!=frame.request.request_id.0 || value.operation_id!=frame.request.operation_id.0
        || value.exact_request_sha256!=digest || value.disposition!="APPLIED" || value.authoritative_revision!=revision
        || value.authoritative_state!=state || value.attempt_id!=original.binding.attempt_id
        || value.fencing_token!=original.binding.fencing_token || value.stable_resume_id!=original.stable_resume_id {
        return Err(invalid());
    }
    scope(client,&value.authority_scope,&value.attempt_id,&value.operation_id,revision,value.fencing_token)?;
    let mut unsigned=value.clone();unsigned.signature.clear();
    signed(client,"linearizable-store",&value.signer_key_id,wire::STATE_RECEIPT_DOMAIN,&unsigned,&value.signature)
}
fn observation(client:&ResponseObservationV2Client,value:&wire::SignedAttemptStateObservationV1,
    original:&wire::DispatchOriginal,revision:u64,state:lifecycle::AttemptState)->Result<(),ResponseObservationV2TransactionError> {
    if value.api_version!="serverware.responseObservationV2AttemptStateObservation/v1"
        || !is_sha256_digest(&value.authoritative_state_sha256) || value.proof_material.is_some()
        || value.generation_id!=client.generation_id || value.generation!=client.provider_generation
        || value.operation!=ServiceOperationV1::StateCas || value.signer_logical_role!="linearizable-store"
        || value.attempt_id!=original.binding.attempt_id || value.attempt_revision!=revision
        || value.fencing_token!=original.binding.fencing_token || value.stable_resume_id!=original.stable_resume_id
        || value.authoritative_state!=state || value.deadline_boot_millis.checked_mul(1_000_000)
            !=original.binding.monotonic_deadline.absolute_boottime_ns.parse().ok() {
        return Err(invalid());
    }
    scope(client,&value.authority_scope,&value.attempt_id,&value.operation_id,revision,value.fencing_token)?;
    let mut body=value.clone();body.signature.clear();body.observation_sha256.clear();
    if profile::sha256(&custody_canonical_json_bytes(&body).map_err(|_|invalid())?)!=value.observation_sha256 {return Err(invalid());}
    let mut unsigned=value.clone();unsigned.signature.clear();
    signed(client,"linearizable-store",&value.signer_key_id,wire::STATE_OBSERVATION_DOMAIN,&unsigned,&value.signature)
}

impl ResponseObservationV2Session<'_> {
    fn same_session(&self,reply:&ResponseObservationV2ResponseDataReply)->Result<(),ResponseObservationV2TransactionError> {
        let response:V2ResponseDataControlResponse=decode_canonical_custody_json(&reply.canonical_response).map_err(|_|invalid())?;
        let V2ResponseDataControlResponse::Success {attestation:Some(attestation),..}=response else {return Err(invalid());};
        if !reply.exact_bytes.is_empty() || self.lifecycle_deadline.expired()
            || attestation.authenticated_session_sha256!=self.hello_attestation.authenticated_session_sha256
            || attestation.client_identity_sha256!=self.client.authenticated_client_identity_sha256 {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn begin_target_dispatch(&self,begin:wire::BeginRequest)->Result<AuthenticatedTargetDispatchReply,ResponseObservationV2TransactionError> {
        let request=V2ResponseDataRequest::TargetDispatchBegin {api_version:RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id:begin.original.binding.request_id.clone(),boot_id:self.client.boot_id.clone(),params:begin.clone()};
        let reply=self.execute_response_data(&request,Vec::new())?;
        self.same_session(&reply)?;
        let V2ResponseDataResult::TargetDispatchBegin(permit)=reply.result else {return Err(invalid());};
        let original=&begin.original;
        if !same(original,&permit.original)? || permit.api_version!=wire::PERMIT
            || original.session_sha256!=self.hello_attestation.authenticated_session_sha256 {return Err(invalid());}
        let pin=self.client.role_keys.get("target-transport").ok_or_else(invalid)?;
        if permit.public_key_base64!=pin.public_key_base64 {return Err(invalid());}
        let mut unsigned=permit.clone();unsigned.signature.clear();
        signed(self.client,"target-transport",&pin.key_id,wire::PERMIT_DOMAIN,&unsigned,&permit.signature)?;
        verify_nested_authority_signature(self.client,&permit.credential_use,&FINAL_ARTIFACTS[1],&original.binding.attempt_id,
            original.binding.attempt_revision,original.binding.fencing_token,u64::try_from(now_epoch_ms()).map_err(|_|invalid())?)?;
        let frame=&permit.dispatch_request;
        let rpc::MutationPayload::BeginDispatch(intent)=&frame.request.payload else {return Err(invalid());};
        let operation=format!("dispatch:{}",&profile::sha256(&profile::canonical(original).map_err(|_|invalid())?)[7..]);
        if frame.request.generation_id.0!=original.generation_id || frame.request.attempt_id.0!=original.binding.attempt_id
            || frame.request.operation_id.0!=operation || permit.credential_use.body.operation_id.0!=operation
            || permit.credential_use.body.artifact_id.0!=operation
            || frame.request.request_id.0!=original.binding.request_id || frame.request.expected_revision!=original.binding.attempt_revision
            || frame.request.expected_state!=lifecycle::AttemptState::Staged || frame.request.operation!=lifecycle::OperationKind::DispatchBegin
            || frame.request.fence.fence_token.as_ref().map(|v|v.0.as_str())!=Some(original.binding.fencing_token.to_string().as_str())
            || frame.request.deadline.deadline_boot_millis.checked_mul(1_000_000)!=self.monotonic_deadline.absolute_boottime_ns.parse().ok()
            || !same(&intent.request_object,&original.staged_request)? || !same(&intent.transport_authorization,&permit.credential_use)?
            || Some(intent.credential_binding_sha256.0.as_str())!=original.binding.transaction.credential_binding_sha256.as_deref() {
            return Err(invalid());
        }
        let next=original.binding.attempt_revision.checked_add(1).ok_or_else(invalid)?;
        receipt(self.client,&permit.dispatch_receipt,frame,original,next,"DISPATCHING")?;
        observation(self.client,&permit.post_state,original,next,lifecycle::AttemptState::Dispatching)?;
        Ok(AuthenticatedTargetDispatchReply {permit})
    }
    pub(super) fn persist_target_capture(&self,captured:&native_target_dispatch::Captured)
        ->Result<wire::CompletedCapture,ResponseObservationV2TransactionError> {
        let input=response_observation_v2_exact_input(&captured.request.raw_response.object_id,ExactObjectMediaType::Http11Response,
            0,&captured.raw,self.lifecycle_deadline)?;
        if input.descriptor!=captured.request.raw_response {return Err(invalid());}
        let request=V2ResponseDataRequest::CapturePersist {api_version:RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id:captured.request.request_id.clone(),boot_id:self.client.boot_id.clone(),params:captured.request.clone()};
        let reply=self.execute_response_data(&request,vec![input])?;
        self.same_session(&reply)?;
        let V2ResponseDataResult::CapturePersist(completed)=reply.result else {return Err(invalid());};
        let original=&captured.request.permit.original;
        let capture_sha=profile::sha256(&profile::canonical(&captured.request.capture).map_err(|_|invalid())?);
        let next=captured.request.permit.post_state.attempt_revision.checked_add(2).ok_or_else(invalid)?;
        if completed.api_version!="serverware.responseV2.targetCaptureCommitted/v1" || completed.capture_sha256!=capture_sha
            || completed.object.object_sha256!=captured.request.raw_response.sha256
            || completed.object.byte_length!=captured.request.raw_response.byte_length
            || completed.object.object_type!=ImmutableObjectType::UpstreamResponse
            || completed.outcome_request.request.expected_revision!=next-1
            || completed.outcome_request.request.operation!=lifecycle::OperationKind::DispatchRecordOutcome {
            return Err(invalid());
        }
        let rpc::MutationPayload::RecordDispatchOutcome(outcome)=&completed.outcome_request.request.payload else {return Err(invalid());};
        if outcome.outcome!=lifecycle::TargetEffectState::Observed || outcome.uncertainty_code.is_some()
            || outcome.response_object.as_ref().is_none_or(|raw|raw.content_sha256.0!=captured.request.raw_response.sha256
                || raw.content_length!=captured.request.raw_response.byte_length || raw.object_id.0!=captured.request.raw_response.object_id)
            || !same(&outcome.transport_evidence,&completed.target_effect)? {return Err(invalid());}
        verify_nested_authority_signature(self.client,&completed.target_effect,&FINAL_ARTIFACTS[2],&original.binding.attempt_id,
            next-1,original.binding.fencing_token,u64::try_from(now_epoch_ms()).map_err(|_|invalid())?)?;
        receipt(self.client,&completed.outcome_receipt,&completed.outcome_request,original,next,"OBSERVED")?;
        observation(self.client,&completed.post_state,original,next,lifecycle::AttemptState::Observed)?;
        Ok(completed)
    }
}

/// This branch is selected by the actual cold guest client, never by a failed
/// ordinary request. Cursor promotion uses the verified signed successor, not
/// the legacy single-transition +1 recipe or a fabricated state observation.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_native_capture(state:&GateState,snapshot:&Arc<Snapshot>,decision:&Value,
    request:&IncomingRequest,url:&Url,headers:&BTreeMap<String,String>,injection:&Value,
    session:&ResponseObservationV2Session<'_>,cursor:&mut ResponseObservationV2AttemptCursor,
    stable_resume_id:&str,staged:&ImmutableObjectReference,staged_input:&ExactByteObjectDescriptor,
    staged_bytes:&[u8],shadow:Option<&policy_core::ShadowRequestHandle>,barrier_crossed:&mut bool)
    ->Result<(EvidenceReference,ImmutableObjectReference,ResponseSecretGuard,Option<CommittedNativeCapture>),ResponseObservationV2TransactionError> {
    use serverware_decision_gate::response_observation_v2::state_authority::contract::{Digest,Identifier};
    if staged.object_type!=ImmutableObjectType::StagedRequest || staged.object_sha256!=staged_input.sha256
        || staged.byte_length!=staged_input.byte_length || cursor.attempt.state!=V2AttemptState::Staged {
        return Err(invalid());
    }
    let request_id=canonical_custody_request_id().map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    let binding=cursor.operation_binding(&request_id,&session.client.boot_id,&session.client.authenticated_client_identity_sha256);
    // The requested selection comes from our retained exact, credential-free
    // input. The role independently matches it to the actual signed Stage.
    let staged_original=rpc::RawObjectReference {generation_id:Identifier(session.client.generation_id.clone()),
        object_id:Identifier(staged_input.object_id.clone()),object_kind:Identifier("staged-request".to_owned()),
        content_sha256:Digest(staged_input.sha256.clone()),content_length:staged_input.byte_length,media_type:"http11-request".to_owned()};
    let prepared=native_target_dispatch::Prepared::open(state,snapshot,decision,request,url,headers,injection,
        binding,stable_resume_id,staged_original,staged_bytes,session,shadow)
        .map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    let begin=prepared.begin_original().map_err(|_|ResponseObservationV2TransactionError::Unavailable)?;
    let admitted=session.begin_target_dispatch(begin)?;
    let final_request_sha=prepared.request_sha256().to_owned();
    let mut shadow_permit=match shadow {
        Some(owner)=>record_shadow_dispatch_barrier_with_commitment(snapshot,owner,decision,true,final_request_sha.clone())
            .map_err(|_|ResponseObservationV2TransactionError::Unavailable)?,
        None=>None,
    };
    if shadow.is_some() && shadow_permit.as_ref().is_none_or(|permit|!permit.authorizes_credentialed_send(&final_request_sha)) {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    *barrier_crossed=shadow_permit.is_some();
    let result=(|| {
        // The preparation and permit are consumed exactly once. Neither the
        // transport nor the caller reopens a connection after uncertainty.
        let captured=prepared.capture(admitted).map_err(|_|ResponseObservationV2TransactionError::OutcomeUnknown)?;
        let completed=session.persist_target_capture(&captured)?;
        let evidence_sha=profile::sha256(&completed.target_effect.canonical_signed_bytes().map_err(|_|invalid())?);
        let evidence=EvidenceReference {evidence_type:V2EvidenceType::Dispatch,evidence_sha256:evidence_sha,
            retrieval_id:completed.target_effect.body.artifact_id.0.clone()};
        // OBSERVED is the underlying state authority's exact post-capture
        // state; DISPATCHED is this public protocol's existing projection.
        cursor.attempt=AttemptStateReference {attempt_id:completed.post_state.attempt_id.clone(),
            state:V2AttemptState::Dispatched,state_sha256:completed.post_state.authoritative_state_sha256.clone(),
            attempt_revision:completed.post_state.attempt_revision,fencing_token:completed.post_state.fencing_token};
        let object = completed.object.clone();
        let retained = match shadow {
            Some(owner) => {
                let originals_bytes = profile::canonical(&captured.request.capture).map_err(|_|invalid())?.len()
                    .checked_add(profile::canonical(&completed).map_err(|_|invalid())?.len())
                    .ok_or_else(invalid)?;
                match owner.reserve_native_response_retention(captured.raw.len(), originals_bytes) {
                    Ok(retention) => Some(CommittedNativeCapture {
                        raw: captured.raw, capture: captured.request.capture, completion: completed,
                        method: request.method.clone(), hook: owner.response_hook(), finished: false,
                        _retention: retention,
                    }),
                    Err(_) => {
                        owner.response_hook().record_unavailable(
                            policy_core::PolicyShadowTerminalReason::ActiveResponseValidationUnavailable,
                        );
                        None
                    },
                }
            },
            None => None,
        };
        Ok((evidence,object,captured.response_guard,retained))
    })();
    if let Some(permit)=shadow_permit.take() {
        let (effect,outcome)=match &result {
            Ok((evidence,object,_,_))=>(digest_json_ensure_ascii(&json!({
                "domain":"serverware.policyShadowNativeCapture/v1","requestSha256":final_request_sha,
                "dispatchEvidenceSha256":evidence.evidence_sha256,"upstreamResponseSha256":object.object_sha256,
                "outcome":"response-observed"})),ActiveEffectCommitState::Committed),
            Err(_)=>(digest_json_ensure_ascii(&json!({"domain":"serverware.policyShadowNativeCapture/v1",
                "requestSha256":final_request_sha,"outcome":"capture-outcome-unknown"})),ActiveEffectCommitState::OutcomeUnknown),
        };
        permit.commit_provider_send(outcome,&effect).map_err(|_|ResponseObservationV2TransactionError::OutcomeUnknown)?;
    }
    result
}
