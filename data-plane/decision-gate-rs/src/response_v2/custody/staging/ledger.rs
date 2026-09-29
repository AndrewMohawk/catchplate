//! Credential-free staged-object publication. The ledger returns its real signed
//! ObjectCommitRaw frame, never calls back into the waiting state owner.
#[path="ledger_store.rs"] mod store;
#[path="ledger_wire.rs"] mod receipt_wire;
use super::*;
use std::{collections::BTreeMap,fs::File,os::fd::OwnedFd};
use super::super::{attestation::RoleSigningKey,config::{CustodyServiceRole as Role,ScopedCustodyServiceConfig},
    protocol::{ServiceRpcEnvelopeV1,ServiceOperationV1,UnsignedStateAuthorityIntentV1},services::{self,engine},
    state::{immutable_cas_locator,MAX_EXACT_OBJECT_BYTES}};
use super::super::super::state_authority::{contract::{Identifier,Digest as AuthorityDigest},
    lifecycle::{AttemptState,OperationKind},rpc::{SignedAuthorityArtifact,ArtifactCommitArtifact,
        CommitRawObjectMutation,MutationPayload,NestedAuthorityPayload}};
use crate::response_observation_v2_api::{ExactByteObjectDescriptor,ExactObjectMediaType,
    ImmutableObjectReference,ImmutableObjectType,V2OperationRequest};
use receipt_wire::{original,StorageReceipt,PutResult};

fn deadline(value:u64)->Result<(),V2RuntimeError> {
    if value==0||super::super::recovery::boottime_ns()?>=value {return Err(fail("original staged storage deadline passed"));}Ok(())
}
fn current(config:&Config,value:u64)->Result<(),V2RuntimeError> {
    validate_configuration(config)?;
    if config.native_staging.is_none()||value%1_000_000!=0
        ||super::super::guest_delivery::bound_deadline_ns(config,value)?!=value {return Err(fail("staged storage has no exact original allowance"));}
    config.guest_delivery.as_ref().ok_or_else(||fail("actual guest storage owner absent"))?.check()?;deadline(value)
}
pub(crate) fn preserve(value:serde_json::Value)->Result<(),V2RuntimeError>{
    let value:PutResult=serde_json::from_value(value).map_err(|_|fail("actual staged persistence result shape"))?;
    original(&value)?;Ok(())
}
struct VerifiedStaged<'a> {config:&'a Config,request:VerifiedRequest,file:File,bytes:Vec<u8>,descriptor:ExactByteObjectDescriptor}
impl VerifiedStaged<'_> {
    fn check(&self)->Result<(),V2RuntimeError> {self.request.check(self.config)?;
        let mut descriptor=self.descriptor.clone();descriptor.fd_index=0;
        super::super::validate_exact_object_files(&[descriptor],vec![self.file.try_clone().map_err(|_|fail("retain staged descriptor"))?],None)?;
        current(self.config,self.deadline_boottime_ns())}
    fn bytes(&self)->Result<Vec<u8>,V2RuntimeError> {self.check()?;Ok(self.bytes.clone())}
    fn descriptor(&self)->&ExactByteObjectDescriptor {&self.descriptor}
    fn deadline_boottime_ns(&self)->u64 {self.request.deadline().deadline_boot_millis*1_000_000}
    fn generation_id(&self)->&str {&self.request.original().generation_id}
    fn attempt_id(&self)->&str {&self.request.binding().attempt_id}
    fn fencing_token(&self)->u64 {self.request.binding().fencing_token}
}
fn admit_staged<'a>(config:&'a Config,request:&wire::StagedPutRequest,file:File)->Result<VerifiedStaged<'a>,V2RuntimeError> {
    use std::os::unix::fs::FileExt;
    let value=admit(config,request.request.clone())?;
    verification::claim(config,&value,&request.claim,&request.authority_result)?;
    if request.api_version!="serverware.responseV2.nativeStagedPut/v1"||value.phase()!="STAGE" {return Err(fail("closed staged storage purpose differs"));}
    let V2OperationRequest::Stage{params,..}=&value.original().request else{return Err(fail("staged object original missing"));};
    let descriptor=params.credential_free_request.clone();
    if descriptor.media_type!=ExactObjectMediaType::Http11Request||descriptor.byte_length>wire::MAX_INPUT
        ||descriptor.byte_length==0||descriptor.fd_index!=1 {return Err(fail("staged object is not the exact credential-free HTTP descriptor"));}
    let mut transferred=descriptor.clone();transferred.fd_index=0;
    super::super::validate_exact_object_files(&[transferred],vec![file.try_clone().map_err(|_|fail("retain staged input"))?],None)?;
    let mut bytes=vec![0;descriptor.byte_length as usize];file.read_exact_at(&mut bytes,0).map_err(|_|fail("read sealed staged original"))?;
    if native::sha256(&bytes)!=descriptor.sha256 {return Err(fail("sealed staged input differs"));}
    let result=VerifiedStaged{config,request:value,file,bytes,descriptor};result.check()?;Ok(result)
}

pub(crate) fn put(config:&Config,request:&wire::StagedPutRequest,file:File)->Result<PutResult,V2RuntimeError> {
    let staged=admit_staged(config,request,file.try_clone().map_err(|_|fail("retain actual staged input"))?)?;
    let (reply,fds)=services::invoke_service_wire(config,Role::ImmutableArtifactLedger,ServiceOperationV1::ImmutablePut,
        &staged.request.binding().request_id,request,staged.deadline_boottime_ns(),&[file],false)?;
    if !fds.is_empty(){return Err(fail("staged publication returns no plaintext"));}
    let result:PutResult=serde_json::from_value(reply.result).map_err(|_|fail("closed staged put result"))?;
    result.verify(config,&staged)?;Ok(result)
}
pub(crate) fn execute(config:&Config,scoped:&ScopedCustodyServiceConfig,envelope:&ServiceRpcEnvelopeV1,
    keys:&BTreeMap<String,RoleSigningKey>,mut fds:Vec<OwnedFd>)->Result<engine::EngineResult,V2RuntimeError> {
    if scoped.role!=Role::ImmutableArtifactLedger||envelope.operation!=ServiceOperationV1::ImmutablePut||fds.len()!=1 {
        return Err(fail("staged storage needs actual ledger and one credential-free descriptor"));}
    let request:wire::StagedPutRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("staged storage closed request"))?;
    let staged=admit_staged(config,&request,File::from(fds.pop().ok_or_else(||fail("staged descriptor missing"))?))?;
    if envelope.request_id!=staged.request.binding().request_id||envelope.deadline_boottime_ns!=staged.deadline_boottime_ns() {
        return Err(fail("staged publication transport differs from its original"));}
    let key=keys.get("persistence").ok_or_else(||fail("actual ledger key missing"))?;
    let receipt=StorageReceipt::candidate(config,&staged,key)?;
    let mut stored=store::Stored::put(config,&staged,&request,&receipt)?;
    let binding=staged.request.binding();let operation_id=format!("staged-put:{}",&staged.request.original_sha256()[7..]);
    let artifact=engine::sign_nested_artifact(config,Role::ImmutableArtifactLedger,key,OperationKind::ObjectCommitRaw,
        &operation_id,&binding.attempt_id,binding.attempt_revision,binding.fencing_token,binding.deadline_at_epoch_ms,
        NestedAuthorityPayload::ArtifactCommit(ArtifactCommitArtifact{object_id:Identifier(receipt.body.object_id.clone()),
            object_kind:Identifier(receipt_wire::KIND.into()),content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()),
            content_length:receipt.body.content_length,immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?)}),
        None,staged.deadline_boottime_ns())?;
    stored.record(config,store::RecordKind::Artifact,&original(&artifact)?)?;
    let intent=UnsignedStateAuthorityIntentV1{expected_state:AttemptState::Authorized,
        payload:MutationPayload::CommitRawObject(CommitRawObjectMutation{object_id:Identifier(receipt.body.object_id.clone()),
            object_kind:Identifier(receipt_wire::KIND.into()),media_type:receipt_wire::MEDIA.into(),
            expected_content_length:receipt.body.content_length,expected_content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()),
            storage_locator:receipt.locator()?,immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?),artifact_commit:artifact.clone()})};
    // The protected replay ID is generation-wide. This internal commit has
    // its own fixed ID; the following Stage retains the public request ID.
    let frame=engine::signed_state_authority_frame(config,scoped,&operation_id,&operation_id,&binding.attempt_id,
        binding.attempt_revision,binding.fencing_token,staged.deadline_boottime_ns(),&intent,keys)?;
    stored.record(config,store::RecordKind::StateRequest,&original(&frame)?)?;
    let result=PutResult{api_version:receipt_wire::RESULT.into(),original_sha256:staged.request.original_sha256().into(),
        object:ImmutableObjectReference{object_type:ImmutableObjectType::StagedRequest,object_sha256:receipt.body.content_sha256.clone(),
            byte_length:receipt.body.content_length,retrieval_id:receipt.body.object_id.clone(),persistence_receipt_sha256:receipt.sha256()?},
        storage_receipt:receipt,artifact_commit:artifact,state_request:frame};
    result.verify(config,&staged)?;stored.record(config,store::RecordKind::Result,&original(&result)?)?;
    stored.check(config)?;staged.check()?;
    Ok(engine::EngineResult{result:serde_json::to_value(result).map_err(|_|fail("staged result encoding"))?,exact_object_fds:Vec::new()})
}
