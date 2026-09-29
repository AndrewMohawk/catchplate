//! Same-transaction authenticated request selection, not an object inventory guess.
use super::*;
use super::super::sequence_originals as profile;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CommittedRequestOriginalV1 {
    pub frame:RpcRequestFrame,
    pub exact_request_sha256:String,
    pub result:SignedOperationResult,
    pub exact_result_sha256:String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct StagedAttemptOriginalV1 {
    pub attempt_id:String,pub stable_resume_id:String,pub revision:u64,pub fencing_token:u64,
    pub state:AttemptState,pub original_deadline:BootDeadline,
    pub reserve:CommittedRequestOriginalV1,pub stage:CommittedRequestOriginalV1,
    #[serde(deserialize_with="required_option")]
    pub dispatch:Option<CommittedRequestOriginalV1>,
}
fn required_option<'de,D,T>(d:D)->Result<Option<T>,D::Error>
where D:serde::Deserializer<'de>,T:Deserialize<'de>{Option::<T>::deserialize(d)}

const CURRENT_SQL:&str=r#"
SELECT attempt.revision, attempt.state, attempt.fence_token, attempt.stable_resume_id,
       attempt.owner_process_id,attempt.owner_pid,attempt.owner_start_time_ticks,attempt.owner_cgroup_id,
       attempt.deadline_clock,attempt.deadline_boot_id,attempt.deadline_boot_millis,
       attempt.request_sha256,attempt.route_sha256,attempt.credential_scope_sha256,
       fence.allocation_sequence,fence.state AS fence_state,fence.fence_token AS allocated_fence,
       fence.owner_process_id AS fence_owner,fence.owner_pid AS fence_pid,
       fence.owner_start_time_ticks AS fence_start,fence.owner_cgroup_id AS fence_cgroup
FROM response_v2_state_authority.attempts AS attempt
JOIN response_v2_state_authority.fences AS fence
  ON fence.generation_id=attempt.generation_id AND fence.attempt_id=attempt.attempt_id
WHERE attempt.generation_id=$1 AND attempt.attempt_id=$2
FOR SHARE OF attempt,fence
"#;

fn kind(operation:OperationKind)->Option<(&'static str,AttemptState)> {
    match operation {
        OperationKind::AttemptReserve=>Some(("RESERVE",AttemptState::Reserved)),
        OperationKind::AttemptStage=>Some(("STAGE",AttemptState::Staged)),
        OperationKind::DispatchBegin=>Some(("DISPATCH_BEGIN",AttemptState::Dispatching)),
        _=>None,
    }
}

fn read_original(transaction:&mut dyn PostgresTransaction,generation:&ProviderGeneration,
    attempt:&Identifier,operation:OperationKind)->AuthorityResult<CommittedRequestOriginalV1>{
    let (kind,state)=kind(operation).ok_or_else(||profile::refused("unsupported original purpose"))?;
    let row=transaction.query_optional(profile::SELECT_ORIGINAL_SQL,
        &profile::parameters(&generation.generation_id.0,&attempt.0,kind))?
        .ok_or_else(||profile::refused("exact committed request original is absent; no reconstruction/backfill"))?;
    let frame_bytes=row.require_bytes("canonical_request_frame")?;
    let result_bytes=row.require_bytes("canonical_signed_result")?;
    if frame_bytes.is_empty()||frame_bytes.len()>profile::MAX_ORIGINAL_BYTES||result_bytes.is_empty()
        ||result_bytes.len()>profile::MAX_ORIGINAL_BYTES {return Err(profile::refused("original frame/result bound"));}
    let frame:RpcRequestFrame=serde_json::from_slice(&frame_bytes)
        .map_err(|_|profile::refused("retained request original shape"))?;
    let result:SignedOperationResult=serde_json::from_slice(&result_bytes)
        .map_err(|_|profile::refused("retained committed result shape"))?;
    let request_digest=sha256_digest(&frame_bytes).0;
    let result_digest=sha256_digest(&result_bytes).0;
    if canonical_jcs_bytes(&frame)?!=frame_bytes||canonical_jcs_bytes(&result)?!=result_bytes
        ||row.require_text("status")?!="COMMITTED"
        ||row.require_text("exact_request_sha256")?!=request_digest
        ||row.require_text("replay_request_sha256")?!=request_digest
        ||row.require_text("canonical_signed_result_sha256")?!=result_digest
        ||row.require_text("replay_result_sha256")?!=result_digest||row.require_bytes("replay_result")?!=result_bytes {
        return Err(profile::refused("operation/replay/full authenticated original commitments differ"));
    }
    let caller=generation.topology.roles.iter().find(|role|role.role_id==frame.request.caller_role_id)
        .ok_or_else(||profile::refused("original caller absent from independently pinned generation"))?;
    verify_request_frame(&frame,generation,caller)?;
    verify_signed_operation_result(&result,generation)?;
    let request=&frame.request;let body=&result.body;
    if request.generation_id!=generation.generation_id||request.attempt_id!=*attempt||request.operation!=operation
        ||body.generation_id!=request.generation_id||body.attempt_id!=request.attempt_id
        ||body.request_id!=request.request_id||body.operation_id!=request.operation_id||body.operation!=operation
        ||body.exact_request_sha256.0!=request_digest||body.disposition!=ResultDisposition::Applied
        ||body.authoritative_state!=state||body.authoritative_revision!=request.expected_revision.checked_add(1)
            .ok_or_else(||profile::refused("original revision overflow"))?
        ||body.conflict_code.is_some()||body.response_data_result.is_some()||body.retrieved_immutable_raw.is_some()
        ||body.immutable_inspection.is_some()
        ||request.fence.fence_token.as_ref().is_some_and(|fence|fence!=&body.fence_token) {
        return Err(profile::refused("committed result is not the exact successful request transition"));
    }
    Ok(CommittedRequestOriginalV1{frame,exact_request_sha256:request_digest,result,exact_result_sha256:result_digest})
}

impl<B,S,O,C,G> StateAuthority<B,S,O,C,G>
where B:PostgresBackend,S:AuthorityResultSigner,O:ImmutableObjectStore,C:BootClock,G:CgroupObserver {
    /// Same owned SQL transaction and independently pinned generation as the writer.
    pub fn require_sequence_database(&self,transaction:&mut dyn PostgresTransaction)->AuthorityResult<()> {
        let (generation,status)=self.lock_generation(transaction)?;
        self.enforce_generation_status(status,OperationKind::DispatchBegin)?;
        self.verify_local_signer(&generation)?;
        if !profile::profile(&generation.migration_sha256)?.retains_originals() {
            return Err(profile::refused("numeric custody observation requires the explicit sequence profile; no legacy migration"));
        }
        Ok(())
    }

    pub(super) fn require_original_reserve_scope(&self,transaction:&mut dyn PostgresTransaction,
        generation:&ProviderGeneration,request:&RpcRequest,stage:&StageMutation)->AuthorityResult<()> {
        if profile::profile(&generation.migration_sha256)?==profile::Profile::LegacyV1{return Ok(());}
        let selected=read_original(transaction,generation,&request.attempt_id,OperationKind::AttemptReserve)?;
        let MutationPayload::Reserve(reserve)=&selected.frame.request.payload else{return Err(profile::refused("Reserve original payload differs"));};
        stage.credential_binding_sha256.validate("stage.credentialBindingSha256")?;
        if stage.staged_request_object.object_kind.0!="staged-request"
            ||stage.credential_binding_sha256!=reserve.credential_scope_sha256
            ||request.deadline.clock!=reserve.attempt_deadline.clock
            ||request.deadline.boot_id!=reserve.attempt_deadline.boot_id
            ||request.deadline.deadline_boot_millis>reserve.attempt_deadline.deadline_boot_millis {
            return Err(profile::refused("Stage must select the credential-free template and exact reserved credential scope/original deadline"));
        }
        Ok(())
    }
    pub(super) fn retain_attempt_request_original(&self,transaction:&mut dyn PostgresTransaction,
        generation:&ProviderGeneration,frame:&RpcRequestFrame,digest:&Digest,applied:&AppliedMutation)->AuthorityResult<()> {
        if profile::profile(&generation.migration_sha256)?==profile::Profile::LegacyV1{return Ok(());}
        let Some((kind,state))=kind(frame.request.operation) else{return Ok(());};
        if applied.disposition!=ResultDisposition::Applied||applied.state!=state {
            return Err(profile::refused("selected original requires actual successful transition"));
        }
        let original=canonical_jcs_bytes(frame)?;
        if original.len()>profile::MAX_ORIGINAL_BYTES||sha256_digest(&original)!=*digest {
            return Err(profile::refused("full authenticated request exceeds the exact original bound"));
        }
        let changed=transaction.execute(profile::INSERT_ORIGINAL_SQL,&[
            text(&frame.request.generation_id),text(&frame.request.attempt_id),PgValue::Text(kind.into()),
            text(&frame.request.operation_id),text_digest(digest),PgValue::Bytes(original)])?;
        if changed!=1{return Err(profile::refused("request original was not retained exactly once"));}Ok(())
    }

    pub(super) fn require_original_stage_selection(&self,transaction:&mut dyn PostgresTransaction,
        generation:&ProviderGeneration,request:&RpcRequest,mutation:&BeginDispatchMutation)->AuthorityResult<()> {
        if profile::profile(&generation.migration_sha256)?==profile::Profile::LegacyV1{return Ok(());}
        let selected=read_original(transaction,generation,&request.attempt_id,OperationKind::AttemptStage)?;
        let MutationPayload::Stage(stage)=&selected.frame.request.payload else{return Err(profile::refused("original Stage payload differs"));};
        if request.expected_state!=AttemptState::Staged
            ||request.expected_revision!=selected.result.body.authoritative_revision
            ||request.fence.fence_token.as_ref()!=Some(&selected.result.body.fence_token)
            ||mutation.request_object!=stage.staged_request_object
            ||mutation.credential_binding_sha256!=stage.credential_binding_sha256
            ||request.deadline.clock!=selected.frame.request.deadline.clock
            ||request.deadline.boot_id!=selected.frame.request.deadline.boot_id
            ||request.deadline.deadline_boot_millis>selected.frame.request.deadline.deadline_boot_millis {
            return Err(profile::refused("DispatchBegin changed the exact credential-free Stage selection"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn query_staged_original(&self,attempt_id:&Identifier,resume:&str,revision:u64,fence:u64,
        expected_state:AttemptState,expected_dispatch:Option<&str>,deadline:&BootDeadline)
        ->AuthorityResult<StagedAttemptOriginalV1>{
        attempt_id.validate("stagedOriginal.attemptId",128)?;self.assert_deadline(deadline)?;
        if !matches!(expected_state,AttemptState::Staged|AttemptState::Dispatching)
            ||(expected_state==AttemptState::Dispatching)!=expected_dispatch.is_some() {
            return Err(profile::refused("pre-stage and exact post-dispatch purposes differ"));
        }
        let mut transaction=self.backend.begin_serializable(deadline)?;
        self.configure_transaction(transaction.as_mut())?;
        let (generation,status)=self.lock_generation(transaction.as_mut())?;
        self.enforce_generation_status(status,OperationKind::DispatchBegin)?;
        if !profile::profile(&generation.migration_sha256)?.retains_originals() {
            return Err(profile::refused("legacy attempts have no authenticated staged-original profile; migration is separate"));
        }
        self.verify_local_signer(&generation)?;
        let row=transaction.query_optional(CURRENT_SQL,&[text(&generation.generation_id),text(attempt_id)])?
            .ok_or_else(||profile::refused("current attempt/fence missing"))?;
        let token=row.require_text("fence_token")?;
        let current_fence=profile::canonical_fence(&token,row.require_u64("allocation_sequence")?)?;
        let original_deadline=BootDeadline{clock:row.require_text("deadline_clock")?,
            boot_id:Identifier(row.require_text("deadline_boot_id")?),deadline_boot_millis:row.require_u64("deadline_boot_millis")?};
        self.assert_deadline(&original_deadline)?;
        if current_fence!=fence||row.require_u64("revision")?!=revision||row.require_text("state")?!=expected_state.as_str()
            ||row.require_text("stable_resume_id")?!=resume||row.require_text("fence_state")?!="ACTIVE"
            ||row.require_text("allocated_fence")?!=token||deadline.boot_id!=original_deadline.boot_id
            ||deadline.clock!=original_deadline.clock||deadline.deadline_boot_millis>original_deadline.deadline_boot_millis
            ||row.require_text("fence_owner")?!=row.require_text("owner_process_id")?
            ||row.require_u64("fence_pid")?!=row.require_u64("owner_pid")?
            ||row.require_u64("fence_start")?!=row.require_u64("owner_start_time_ticks")?
            ||row.require_text("fence_cgroup")?!=row.require_text("owner_cgroup_id")? {
            return Err(profile::refused("current state/revision/fence/owner/original interval differs"));
        }
        let reserve=read_original(transaction.as_mut(),&generation,attempt_id,OperationKind::AttemptReserve)?;
        let stage=read_original(transaction.as_mut(),&generation,attempt_id,OperationKind::AttemptStage)?;
        let MutationPayload::Reserve(reserved)=&reserve.frame.request.payload else{return Err(profile::refused("Reserve original payload differs"));};
        let MutationPayload::Stage(staged)=&stage.frame.request.payload else{return Err(profile::refused("Stage original payload differs"));};
        if reserved.stable_resume_id.0!=resume||reserved.owner_process_id.0!=row.require_text("owner_process_id")?
            ||u64::from(reserved.owner_pid)!=row.require_u64("owner_pid")?
            ||reserved.owner_start_time_ticks!=row.require_u64("owner_start_time_ticks")?
            ||reserved.owner_cgroup_id.0!=row.require_text("owner_cgroup_id")?||reserved.attempt_deadline!=original_deadline
            ||reserved.request_sha256.0!=row.require_text("request_sha256")?
            ||reserved.route_sha256.0!=row.require_text("route_sha256")?
            ||reserved.credential_scope_sha256.0!=row.require_text("credential_scope_sha256")?
            ||staged.credential_binding_sha256!=reserved.credential_scope_sha256
            ||staged.staged_request_object.object_kind.0!="staged-request"
            ||reserve.result.body.fence_token.0!=token||stage.result.body.fence_token.0!=token
            ||reserve.result.body.stable_resume_id.0!=resume||stage.result.body.stable_resume_id.0!=resume
            ||stage.frame.request.deadline.boot_id!=original_deadline.boot_id
            ||stage.frame.request.deadline.deadline_boot_millis>original_deadline.deadline_boot_millis {
            return Err(profile::refused("original Reserve/Stage scope no longer matches the authoritative head"));
        }
        staged.credential_binding_sha256.validate("stage.credentialBindingSha256")?;
        self.ensure_object(transaction.as_mut(),&stage.frame.request,&staged.staged_request_object)?;
        let dispatch=if let Some(expected)=expected_dispatch {
            let original=read_original(transaction.as_mut(),&generation,attempt_id,OperationKind::DispatchBegin)?;
            let MutationPayload::BeginDispatch(begun)=&original.frame.request.payload else{return Err(profile::refused("DispatchBegin original payload differs"));};
            if original.exact_request_sha256!=expected||original.result.body.authoritative_revision!=revision
                ||original.frame.request.expected_revision!=stage.result.body.authoritative_revision
                ||original.frame.request.expected_state!=AttemptState::Staged||original.result.body.fence_token.0!=token
                ||original.result.body.stable_resume_id.0!=resume
                ||begun.request_object!=staged.staged_request_object||begun.credential_binding_sha256!=staged.credential_binding_sha256
                ||original.frame.request.deadline.boot_id!=original_deadline.boot_id
                ||original.frame.request.deadline.deadline_boot_millis>original_deadline.deadline_boot_millis {
                return Err(profile::refused("post-begin observation is not the exact consumed Stage successor"));
            }Some(original)
        } else {
            if stage.result.body.authoritative_revision!=revision{return Err(profile::refused("Stage original is not current"));}None
        };
        self.assert_deadline(deadline)?;
        transaction.commit(deadline)?;
        Ok(StagedAttemptOriginalV1{attempt_id:attempt_id.0.clone(),stable_resume_id:resume.into(),revision,
            fencing_token:fence,state:expected_state,original_deadline,reserve,stage,dispatch})
    }
}
