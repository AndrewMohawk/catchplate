//! Companion-original Stage selection. The legacy AttemptStage artifact
//! contract is not widened: only this measured-purpose entrypoint consumes
//! exact authenticated Authorize + immutable-object predecessor originals.
use super::*;
use crate::response_observation_v2::custody::staging::VerifiedRequest;
use super::super::sequence_originals::refused;

pub(super) struct StageCompanion<'a> {
    value:&'a VerifiedRequest,
    authorize:&'a CommittedRequestOriginalV1,
    persisted:&'a CommittedRequestOriginalV1,
}

impl<B,S,O,C,G> StateAuthority<B,S,O,C,G>
where B:PostgresBackend,S:AuthorityResultSigner,O:ImmutableObjectStore,C:BootClock,G:CgroupObserver {
    pub(crate) fn execute_native_staging_stage(&self,value:&VerifiedRequest,frame:&RpcRequestFrame,
        authorize:&CommittedRequestOriginalV1,persisted:&CommittedRequestOriginalV1)->AuthorityResult<ExactSignedResultBytes> {
        if value.phase()!="STAGE"||frame.request.operation!=OperationKind::AttemptStage {
            return Err(refused("companion owner only executes the selected native Stage"));
        }
        let companion=StageCompanion {value,authorize,persisted};
        self.execute_mutation_profile(frame,true,Some(&companion))
    }

    pub(super) fn require_native_stage_predecessor(&self,transaction:&mut dyn PostgresTransaction,
        generation:&ProviderGeneration,request:&RpcRequest,stage:&StageMutation,companion:&StageCompanion<'_>)
        ->AuthorityResult<Vec<Identifier>> {
        use native_staging_journal::{CLAIM,parameters,require_claim,require_positive};
        if super::super::sequence_originals::profile(&generation.migration_sha256)?
            !=super::super::sequence_originals::Profile::NativeStagingV3 {
            return Err(refused("companion Stage requires exact native v3 profile"));
        }
        let value=companion.value;
        let row=transaction.query_optional(CLAIM,&parameters(value,"STAGE"))?
            .ok_or_else(||refused("companion Stage has no actual durable public claim"))?;
        require_claim(&row,value)?;
        require_positive(transaction,generation,companion.authorize)?;
        require_positive(transaction,generation,companion.persisted)?;
        let previous=transaction.query_optional(native_staging_journal::RESULT,&parameters(value,"AUTHORIZE"))?
            .ok_or_else(||refused("companion Stage has no completed original Authorize phase"))?;
        let previous_bytes=previous.require_bytes("canonical_result")?;
        let previous_result:crate::response_observation_v2::custody::staging::wire::SignedStagingResult=
            serde_json::from_slice(&previous_bytes).map_err(|_|refused("companion Authorize terminal shape"))?;
        if value.original().predecessor_result_sha256.as_deref()!=Some(sha256_digest(&previous_bytes).0.as_str())
            ||previous.require_text("result_sha256")?!=sha256_digest(&previous_bytes).0
            ||previous_result.body.state_originals.len()!=1
            ||canonical_jcs_bytes(&previous_result.body.state_originals[0])?!=canonical_jcs_bytes(companion.authorize)? {
            return Err(refused("companion Stage does not consume the exact retained Authorize terminal"));
        }
        let authorization=&companion.authorize.frame.request;
        let persisted=&companion.persisted.frame.request;
        let MutationPayload::Authorize(authorize)=&authorization.payload else {return Err(refused("companion is not Authorize"));};
        let MutationPayload::CommitRawObject(object)=&persisted.payload else {return Err(refused("companion persistence payload differs"));};
        let public=match &value.original().request {
            crate::response_observation_v2_api::V2OperationRequest::Stage {params,..}=>params,
            _=>return Err(refused("companion public Stage absent")),
        };
        let authorized=&companion.authorize.result.body;
        let committed=&companion.persisted.result.body;
        let persisted_id=format!("staged-put:{}",&value.original_sha256()[7..]);
        if authorization.operation!=OperationKind::AttemptAuthorize||persisted.operation!=OperationKind::ObjectCommitRaw
            ||authorized.authoritative_state!=AttemptState::Authorized||committed.authoritative_state!=AttemptState::Authorized
            ||authorization.attempt_id!=request.attempt_id||persisted.attempt_id!=request.attempt_id
            ||persisted.request_id.0!=persisted_id||persisted.operation_id.0!=persisted_id
            ||request.request_id.0!=value.binding().request_id
            ||request.attempt_id.0!=value.binding().attempt_id||request.deadline!=*value.deadline()
            ||authorization.deadline!=request.deadline||persisted.deadline!=request.deadline
            ||authorized.authoritative_revision!=value.binding().attempt_revision
            ||persisted.expected_revision!=authorized.authoritative_revision||persisted.expected_state!=AttemptState::Authorized
            ||request.expected_revision!=committed.authoritative_revision||request.expected_state!=AttemptState::Authorized
            ||authorized.fence_token.0!=value.binding().fencing_token.to_string()||committed.fence_token!=authorized.fence_token
            ||request.fence.fence_token.as_ref()!=Some(&authorized.fence_token)
            ||authorized.stable_resume_id!=committed.stable_resume_id
            ||stage.transition_artifacts!=authorize.authorization_artifacts||stage.transition_artifacts.len()!=1
            ||stage.credential_binding_sha256.0!=value.binding().transaction.credential_binding_sha256.clone().unwrap_or_default()
            ||stage.staged_request_object.object_kind.0!="staged-request"
            ||stage.staged_request_object.object_id!=object.object_id||stage.staged_request_object.object_kind!=object.object_kind
            ||stage.staged_request_object.content_sha256!=object.expected_content_sha256
            ||stage.staged_request_object.content_length!=object.expected_content_length
            ||stage.staged_request_object.media_type!=object.media_type||object.media_type!="http11-request"
            ||object.object_id.0!=public.credential_free_request.object_id
            ||stage.staged_request_object.generation_id!=request.generation_id
            ||object.expected_content_sha256.0!=public.credential_free_request.sha256
            ||object.expected_content_length!=public.credential_free_request.byte_length {
            return Err(refused("companion Stage is not the exact admitted Authorize/storage successor"));
        }
        // The nested authorization is still verified with its ORIGINAL
        // AttemptAuthorize purpose/revision, never relabelled as AttemptStage.
        let trusted=self.lock_trusted_time(transaction,generation,OperationKind::AttemptStage)?;
        for artifact in &authorize.authorization_artifacts {
            self.verify_nested(generation,artifact,OperationKind::AttemptAuthorize,authorization,trusted)?;
        }
        self.staging_current(transaction,value,request.expected_revision,AttemptState::Authorized,value.binding().fencing_token)?;
        Ok(stage.transition_artifacts.iter().map(|artifact|artifact.body.artifact_id.clone()).collect())
    }
}
