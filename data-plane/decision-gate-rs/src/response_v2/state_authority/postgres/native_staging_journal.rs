//! Irreversible public-phase claims. A missing result is uncertainty, never
//! permission to repeat an external policy/storage call or a state mutation.
use super::*;
use crate::response_observation_v2::custody::staging::{VerifiedRequest,wire};
use super::super::sequence_originals::{self as profile,refused};

pub(super) const CLAIM:&str=r#"SELECT original_sha256,session_sha256,canonical_request,canonical_inputs
FROM response_v2_state_authority.native_staging_claims
WHERE generation_id=$1 AND attempt_id=$2 AND phase=$3 FOR UPDATE"#;
pub(super) const RESULT:&str=r#"SELECT original_sha256,result_sha256,canonical_result
FROM response_v2_state_authority.native_staging_results
WHERE generation_id=$1 AND attempt_id=$2 AND phase=$3 FOR SHARE"#;
const INSERT_CLAIM:&str=r#"INSERT INTO response_v2_state_authority.native_staging_claims
(generation_id,attempt_id,phase,original_sha256,session_sha256,canonical_request,canonical_inputs)
VALUES ($1,$2,$3,$4,$5,$6,$7)"#;
const INSERT_RESULT:&str=r#"INSERT INTO response_v2_state_authority.native_staging_results
(generation_id,attempt_id,phase,original_sha256,result_sha256,canonical_result)
VALUES ($1,$2,$3,$4,$5,$6)"#;
const POSITIVE:&str=r#"SELECT operation.status,operation.exact_request_sha256,
operation.canonical_signed_result,operation.canonical_signed_result_sha256,
replay.exact_request_sha256 AS replay_request_sha256,
replay.canonical_signed_result AS replay_result,replay.canonical_signed_result_sha256 AS replay_result_sha256
FROM response_v2_state_authority.operations operation
JOIN response_v2_state_authority.replay_ledger replay
ON replay.generation_id=operation.generation_id AND replay.operation_id=operation.operation_id
AND replay.replay_id=operation.request_id
WHERE operation.generation_id=$1 AND operation.attempt_id=$2 AND operation.operation_id=$3
FOR SHARE OF operation,replay"#;

pub(crate) struct NativeStagingClaim {
    original_sha256:String,
    phase:&'static str,
    previous:Option<wire::SignedStagingResult>,
    previous_request:Option<wire::StagingRequest>,
    previous_inputs:Option<Vec<u8>>,
}
impl NativeStagingClaim {
    pub(crate) fn previous(&self)->Option<&wire::SignedStagingResult> { self.previous.as_ref() }
    pub(crate) fn previous_request(&self)->Option<&wire::StagingRequest> {self.previous_request.as_ref()}
    pub(crate) fn previous_inputs(&self)->Option<&[u8]> {self.previous_inputs.as_deref()}
}
pub(crate) enum NativeStagingClaimResult { Replay(Vec<u8>), Claimed(NativeStagingClaim) }

pub(super) fn parameters(value:&VerifiedRequest,phase:&str)->[PgValue;3] {
    [PgValue::Text(value.original().generation_id.clone()),PgValue::Text(value.binding().attempt_id.clone()),
        PgValue::Text(phase.into())]
}
fn result_bytes(row:&PgRow,original:&str)->AuthorityResult<Vec<u8>> {
    let bytes=row.require_bytes("canonical_result")?;
    let result:wire::SignedStagingResult=serde_json::from_slice(&bytes).map_err(|_|refused("staging terminal shape differs"))?;
    if bytes.is_empty()||bytes.len()>wire::MAX_METADATA||canonical_jcs_bytes(&result)?!=bytes
        ||row.require_text("original_sha256")?!=original||result.original_sha256!=original
        ||row.require_text("result_sha256")?!=sha256_digest(&bytes).0 {
        return Err(refused("staging exact terminal original differs"));
    }
    Ok(bytes)
}
pub(super) fn require_claim(row:&PgRow,value:&VerifiedRequest)->AuthorityResult<()> {
    if row.require_text("original_sha256")?!=value.original_sha256()
        ||row.require_text("session_sha256")?!=value.original().session_sha256
        ||row.require_bytes("canonical_request")?!=value.exact_request() {
        return Err(refused("staging claim differs from retained native/session original"));
    }
    Ok(())
}

/// Positive operation AND replay originals, with full signed-frame hashes.
/// This deliberately does not accept an unsigned request hash or a receipt
/// saying only that an operation probably committed.
pub(super) fn require_positive(transaction:&mut dyn PostgresTransaction,generation:&ProviderGeneration,
    value:&CommittedRequestOriginalV1)->AuthorityResult<()> {
    let frame=&value.frame; let body=&value.result.body;
    let frame_bytes=canonical_jcs_bytes(frame)?; let result_bytes=canonical_jcs_bytes(&value.result)?;
    if frame_bytes.len()>profile::MAX_ORIGINAL_BYTES||result_bytes.len()>profile::MAX_ORIGINAL_BYTES
        ||sha256_digest(&frame_bytes).0!=value.exact_request_sha256
        ||sha256_digest(&result_bytes).0!=value.exact_result_sha256 {
        return Err(refused("staging state original bounds/full-frame digests differ"));
    }
    let caller=generation.topology.roles.iter().find(|role|role.role_id==frame.request.caller_role_id)
        .ok_or_else(||refused("staging original role is not independently assigned"))?;
    verify_request_frame(frame,generation,caller)?; verify_signed_operation_result(&value.result,generation)?;
    let row=transaction.query_optional(POSITIVE,&[text(&generation.generation_id),text(&frame.request.attempt_id),
        text(&frame.request.operation_id)])?.ok_or_else(||refused("staging positive operation/replay original absent"))?;
    if frame.request.generation_id!=generation.generation_id||body.generation_id!=generation.generation_id
        ||body.request_id!=frame.request.request_id||body.operation_id!=frame.request.operation_id
        ||body.attempt_id!=frame.request.attempt_id||body.operation!=frame.request.operation
        ||body.disposition!=ResultDisposition::Applied||body.conflict_code.is_some()
        ||body.response_data_result.is_some()||body.immutable_inspection.is_some()||body.retrieved_immutable_raw.is_some()
        ||body.exact_request_sha256.0!=value.exact_request_sha256
        ||body.authoritative_revision!=frame.request.expected_revision.checked_add(1).ok_or_else(||refused("revision overflow"))?
        ||frame.request.fence.fence_token.as_ref().is_some_and(|fence|fence!=&body.fence_token)
        ||row.require_text("status")?!="COMMITTED"
        ||row.require_text("exact_request_sha256")?!=value.exact_request_sha256
        ||row.require_text("replay_request_sha256")?!=value.exact_request_sha256
        ||row.require_text("canonical_signed_result_sha256")?!=value.exact_result_sha256
        ||row.require_text("replay_result_sha256")?!=value.exact_result_sha256
        ||row.require_bytes("canonical_signed_result")?!=result_bytes||row.require_bytes("replay_result")?!=result_bytes {
        return Err(refused("staging requires the exact committed successful operation and replay original"));
    }
    Ok(())
}

impl<B,S,O,C,G> StateAuthority<B,S,O,C,G>
where B:PostgresBackend,S:AuthorityResultSigner,O:ImmutableObjectStore,C:BootClock,G:CgroupObserver {
    pub(super) fn staging_generation(&self,transaction:&mut dyn PostgresTransaction)->AuthorityResult<ProviderGeneration> {
        let (generation,status)=self.lock_generation(transaction)?;
        self.verify_local_signer(&generation)?;
        self.enforce_generation_status(status,OperationKind::AttemptStage)?;
        if profile::profile(&generation.migration_sha256)?!=profile::Profile::NativeStagingV3 {
            return Err(refused("public staging requires independently pinned fresh v3 database; no migration/fallback"));
        }
        Ok(generation)
    }
    pub(super) fn staging_current(&self,transaction:&mut dyn PostgresTransaction,value:&VerifiedRequest,
        revision:u64,state:AttemptState,fence:u64)->AuthorityResult<()> {
        let row=transaction.query_optional(statements::LOCK_ATTEMPT_SQL,&[
            PgValue::Text(value.original().generation_id.clone()),PgValue::Text(value.binding().attempt_id.clone())])?;
        if value.phase()=="RESERVE"&&revision==0 {
            if row.is_some() {return Err(refused("native Reserve cannot adopt an existing attempt"));}
            return Ok(());
        }
        let row=row.ok_or_else(||refused("native staging current attempt absent"))?;
        let owner=&value.original().owner;
        if row.require_u64("revision")?!=revision||row.require_text("state")?!=state.as_str()
            ||row.require_text("fence_token")?!=fence.to_string()
            ||row.require_text("owner_process_id")?!=owner.process_id||row.require_u64("owner_pid")?!=u64::from(owner.pid)
            ||row.require_u64("owner_start_time_ticks")?!=owner.start_time_ticks
            ||row.require_text("owner_cgroup_id")?!=owner.cgroup_id
            ||row.require_text("deadline_boot_id")?!=value.deadline().boot_id.0
            ||row.require_u64("deadline_boot_millis")?!=value.deadline().deadline_boot_millis {
            return Err(refused("native staging current state/fence/actual owner/original deadline differs"));
        }
        self.assert_deadline(value.deadline())?; Ok(())
    }
    pub(crate) fn claim_native_staging(&self,value:&VerifiedRequest,
        inputs:&crate::response_observation_v2::custody::staging::inputs::Inputs)->AuthorityResult<NativeStagingClaimResult> {
        self.assert_deadline(value.deadline())?;
        let mut transaction=self.backend.begin_serializable(value.deadline())?;
        self.configure_transaction(transaction.as_mut())?;
        let generation=self.staging_generation(transaction.as_mut())?;
        if generation.generation_id.0!=value.original().generation_id {return Err(refused("native staging generation differs"));}
        let params=parameters(value,value.phase());
        if let Some(row)=transaction.query_optional(CLAIM,&params)? {
            require_claim(&row,value)?;
            if row.require_bytes("canonical_inputs")?!=inputs.retained() {return Err(refused("staging original inputs changed"));}
            let result=transaction.query_optional(RESULT,&params)?
                .ok_or_else(||refused("native staging was claimed without a known terminal; effects cannot retry"))?;
            let bytes=result_bytes(&result,value.original_sha256())?;
            self.assert_deadline(value.deadline())?; transaction.commit(value.deadline())?;
            return Ok(NativeStagingClaimResult::Replay(bytes));
        }
        let mut previous_request=None;let mut previous_inputs=None;
        let previous=if let Some(expected)=&value.original().predecessor_result_sha256 {
            let phase=if value.phase()=="AUTHORIZE" {"RESERVE"} else {"AUTHORIZE"};
            let params=parameters(value,phase);
            let original=transaction.query_optional(CLAIM,&params)?.ok_or_else(||refused("native predecessor claim absent"))?;
            let row=transaction.query_optional(RESULT,&params)?.ok_or_else(||refused("native predecessor terminal absent"))?;
            let bytes=result_bytes(&row,&original.require_text("original_sha256")?)?;
            let previous:wire::SignedStagingResult=serde_json::from_slice(&bytes).map_err(|_|refused("native predecessor shape"))?;
            let predecessor:wire::StagingRequest=serde_json::from_slice(&original.require_bytes("canonical_request")?)
                .map_err(|_|refused("native predecessor request shape"))?;
            let old=&predecessor.evidence.statement.original;
            if sha256_digest(&bytes).0!=*expected||previous.session_sha256!=value.original().session_sha256
                ||old.owner!=value.original().owner||old.gate_key_id!=value.original().gate_key_id
                ||old.generation_id!=value.original().generation_id||old.generation!=value.original().generation
                ||crate::native_staging_v1::binding(old).map_err(|_|refused("native predecessor phase"))?.transaction
                    !=value.binding().transaction
                ||crate::native_staging_v1::deadline(old).map_err(|_|refused("native predecessor deadline"))?
                    !=value.deadline().deadline_boot_millis*1_000_000 {
                return Err(refused("native predecessor is not the same actual transaction/session/owner/original allowance"));
            }
            use crate::response_observation_v2_api::{V2OperationResult,V2ReserveResult,V2AuthorityResult};
            let attempt=match &previous.body.result {
                V2OperationResult::Reserve(V2ReserveResult::Reserved {attempt,..}) if value.phase()=="AUTHORIZE"=>attempt,
                V2OperationResult::Authority(V2AuthorityResult::Ready {attempt,..}) if value.phase()=="STAGE"=>attempt,
                _=>return Err(refused("native predecessor is not the exact successful public phase")),
            };
            if attempt.attempt_id!=value.binding().attempt_id||attempt.attempt_revision!=value.binding().attempt_revision
                ||attempt.fencing_token!=value.binding().fencing_token||attempt.state!=value.binding().predecessor_lifecycle_state
                ||attempt.state_sha256!=value.binding().predecessor_state_sha256 {
                return Err(refused("native public predecessor differs from the retained exact terminal"));
            }
            previous_inputs=Some(original.require_bytes("canonical_inputs")?);previous_request=Some(predecessor);
            Some(previous)
        } else {None};
        let expected_state=if value.phase()=="AUTHORIZE" {AttemptState::Reserved} else {AttemptState::Authorized};
        self.staging_current(transaction.as_mut(),value,value.binding().attempt_revision,expected_state,value.binding().fencing_token)?;
        let inserted=transaction.execute(INSERT_CLAIM,&[params[0].clone(),params[1].clone(),params[2].clone(),
            PgValue::Text(value.original_sha256().into()),PgValue::Text(value.original().session_sha256.clone()),
            PgValue::Bytes(value.exact_request().to_vec()),PgValue::Bytes(inputs.retained().to_vec())])?;
        if inserted!=1 {return Err(refused("native staging claim was not inserted exactly once"));}
        self.assert_deadline(value.deadline())?; transaction.commit(value.deadline())?;
        Ok(NativeStagingClaimResult::Claimed(NativeStagingClaim {
            original_sha256:value.original_sha256().into(),phase:value.phase(),previous,previous_request,previous_inputs}))
    }
    pub(crate) fn complete_native_staging(&self,claim:NativeStagingClaim,value:&VerifiedRequest,
        result:&wire::SignedStagingResult)->AuthorityResult<Vec<u8>> {
        self.assert_deadline(value.deadline())?;
        let bytes=canonical_jcs_bytes(result)?;
        if bytes.is_empty()||bytes.len()>wire::MAX_METADATA||claim.phase!=value.phase()
            ||claim.original_sha256!=value.original_sha256()||result.api_version!=wire::RESULT
            ||result.original_sha256!=value.original_sha256()||result.session_sha256!=value.original().session_sha256
            ||result.generation_id!=value.original().generation_id||result.generation!=value.original().generation
            ||result.body.predecessor_result_sha256!=value.original().predecessor_result_sha256
            ||result.signer_key_id!=self.signer.key_id().0 {
            return Err(refused("native terminal is not the actual claimed owner result"));
        }
        let count=if value.phase()=="STAGE" {2} else {1};
        if result.body.state_originals.len()!=count {return Err(refused("native terminal state chain length differs"));}
        let mut transaction=self.backend.begin_serializable(value.deadline())?;
        self.configure_transaction(transaction.as_mut())?;
        let generation=self.staging_generation(transaction.as_mut())?;
        let params=parameters(value,value.phase());
        let row=transaction.query_optional(CLAIM,&params)?.ok_or_else(||refused("native terminal claim absent"))?;
        require_claim(&row,value)?;
        if transaction.query_optional(RESULT,&params)?.is_some() {return Err(refused("native terminal cannot be replaced/recompleted"));}
        for (index,original) in result.body.state_originals.iter().enumerate() {
            require_positive(transaction.as_mut(),&generation,original)?;
            let expected_operation=match (value.phase(),index) {
                ("RESERVE",0)=>OperationKind::AttemptReserve,("AUTHORIZE",0)=>OperationKind::AttemptAuthorize,
                ("STAGE",0)=>OperationKind::ObjectCommitRaw,("STAGE",1)=>OperationKind::AttemptStage,
                _=>return Err(refused("native terminal operation sequence differs")),
            };
            let expected_state=match expected_operation {
                OperationKind::AttemptReserve=>AttemptState::Reserved,OperationKind::AttemptStage=>AttemptState::Staged,
                _=>AttemptState::Authorized,
            };
            if original.frame.request.attempt_id.0!=value.binding().attempt_id
                ||original.frame.request.deadline!=*value.deadline()||original.frame.request.operation!=expected_operation
                ||original.result.body.authoritative_state!=expected_state
                ||original.frame.request.expected_revision!=value.binding().attempt_revision.checked_add(index as u64)
                    .ok_or_else(||refused("native terminal revision overflow"))? {
                return Err(refused("native terminal state original names another attempt/allowance"));
            }
        }
        let last=&result.body.state_originals.last().ok_or_else(||refused("terminal state missing"))?.result.body;
        let fence=last.fence_token.0.parse::<u64>().map_err(|_|refused("terminal sequence fence invalid"))?;
        profile::canonical_fence(&last.fence_token.0,fence)?;
        self.staging_current(transaction.as_mut(),value,last.authoritative_revision,last.authoritative_state,fence)?;
        let inserted=transaction.execute(INSERT_RESULT,&[params[0].clone(),params[1].clone(),params[2].clone(),
            PgValue::Text(value.original_sha256().into()),PgValue::Text(sha256_digest(&bytes).0),PgValue::Bytes(bytes.clone())])?;
        if inserted!=1 {return Err(refused("native terminal did not append exactly once"));}
        self.assert_deadline(value.deadline())?; transaction.commit(value.deadline())?; Ok(bytes)
    }
}
