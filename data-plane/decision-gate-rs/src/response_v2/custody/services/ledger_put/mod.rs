//! Selected, authenticated raw-response publication. No caller-selected path,
//! generic byte upload, repair, or repeat attempt is exposed.
mod store;
mod validation;
mod wire;

use std::{collections::BTreeMap, fs::File, os::fd::OwnedFd};
use serde::{Deserialize, Deserializer};
use super::super::{RootOwnedResponseObservationV2Config as Config, V2RuntimeError,
    attestation::RoleSigningKey, config::{CustodyServiceRole as Role, ScopedCustodyServiceConfig},
    guest_delivery, recovery, protocol::{AttemptStateQueryRequestV1, ServiceOperationV1,
        ServiceRpcEnvelopeV1, SignedAttemptStateObservationV1, StateMutationExecutionRequestV1, StateMutationExecutionResultV1,
        UnsignedStateAuthorityIntentV1, ATTEMPT_STATE_OBSERVATION_API_VERSION},
    state::{immutable_cas_locator, MAX_EXACT_OBJECT_BYTES},
    target_dispatch::{self, VerifiedCapture, wire::CapturePersistRequest}};
use super::super::super::state_authority::{contract::{Identifier, Digest as AuthorityDigest},
    lifecycle::{AttemptState, OperationKind}, rpc::{ArtifactCommitArtifact,
        CommitRawObjectMutation, MutationPayload, NestedAuthorityPayload, SignedAuthorityArtifact}};
use crate::response_observation_v2_api::{ExactByteObjectDescriptor, ExactObjectMediaType,
    ImmutableObjectReference, ImmutableObjectType};
use wire::original;
pub(crate) use wire::{PutResult, StorageReceipt};

const PROFILE: &str = "serverware.responseV2.ledgerRawPersistence/v1";
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile { api_version:String }
pub(crate) fn configuration_profile<'de,D:Deserializer<'de>>(input:D)->Result<Option<Profile>,D::Error> {
    Profile::deserialize(input).map(Some)
}
impl Profile {
    pub(crate) fn validate(&self, config:&Config)->Result<(),V2RuntimeError> {
        if self.api_version != PROFILE || config.guest_delivery_authority.is_none()
            || config.target_dispatch.is_none() || config.ledger_exact_read.is_none() {
            return Err(fail("explicit guest persistence needs separate target-dispatch assignment and private exact read"));
        }
        Ok(())
    }
}
fn fail(reason:&str)->V2RuntimeError { V2RuntimeError::new("ledger_raw_persistence_refused",reason) }
fn deadline(value:u64)->Result<(),V2RuntimeError> {
    if value == 0 || recovery::boottime_ns()? >= value { return Err(fail("original persistence deadline passed")); }
    Ok(())
}
fn current(config:&Config,value:u64)->Result<(),V2RuntimeError> {
    config.ledger_raw_persistence.as_ref().ok_or_else(|| fail("cold persistence profile absent"))?.validate(config)?;
    config.guest_delivery.as_ref().ok_or_else(|| fail("actual guest delivery owner absent"))?.check()?;
    if value % 1_000_000 != 0 || guest_delivery::bound_deadline_ns(config,value)? != value {
        return Err(fail("persistence cannot round or renew original authority deadline"));
    }
    deadline(value)
}

/// Private role-to-role transport. Both ends independently admit the exact
/// signed capture and held sealed descriptor; a JSON result is never authority.
pub(crate) fn put(config:&Config, request:&CapturePersistRequest, raw:File, deadline_ns:u64)
    ->Result<PutResult,V2RuntimeError> {
    current(config,deadline_ns)?;
    let captured=target_dispatch::verify_capture(config,request,
        raw.try_clone().map_err(|_| fail("retain capture descriptor for response join"))?,deadline_ns)?;
    let (result,fds)=super::invoke_service_wire(config,Role::ImmutableArtifactLedger,
        ServiceOperationV1::ImmutablePut,&request.request_id,request,deadline_ns,&[raw],false)?;
    if !fds.is_empty() { return Err(fail("persistence returns no plaintext descriptor")); }
    let result:PutResult=serde_json::from_value(result.result).map_err(|_| fail("closed persistence result differs"))?;
    validation::result(config,&captured,&result)?;
    Ok(result)
}

pub(super) fn execute(config:&Config,scoped:&ScopedCustodyServiceConfig,envelope:&ServiceRpcEnvelopeV1,
    keys:&BTreeMap<String,RoleSigningKey>,mut fds:Vec<OwnedFd>)->Result<super::engine::EngineResult,V2RuntimeError> {
    current(config,envelope.deadline_boottime_ns)?;
    if scoped.role != Role::ImmutableArtifactLedger || envelope.operation != ServiceOperationV1::ImmutablePut
        || fds.len() != 1 { return Err(fail("fixed ledger operation requires exactly one sealed capture")); }
    let request:CapturePersistRequest=serde_json::from_value(envelope.payload.clone())
        .map_err(|_| fail("closed capture persistence request differs"))?;
    if envelope.request_id != request.request_id || envelope.generation_id != config.custody_topology().generation_id
        || envelope.generation != config.custody_topology().generation { return Err(fail("capture RPC scope differs")); }
    let captured=target_dispatch::verify_capture(config,&request,
        File::from(fds.pop().ok_or_else(|| fail("capture descriptor missing"))?),envelope.deadline_boottime_ns)?;
    let before=observe(config,&captured,false)?;
    validation::observation(config,&captured,&before,captured.attempt_revision(),false)?;
    let key=keys.get("persistence").ok_or_else(|| fail("held persistence signer absent"))?;
    let receipt=StorageReceipt::candidate(config,&captured,key)?;
    let mut stored=store::Stored::put(config,&captured,&request,&receipt)?;
    captured.check()?;
    // Only after exact blob + content-scoped receipt durability may this
    // attempt-scoped artifact attest persistence to the protected state owner.
    let artifact=super::engine::sign_nested_artifact(config,Role::ImmutableArtifactLedger,key,
        OperationKind::ObjectCommitRaw,captured.operation_id(),captured.attempt_id(),
        captured.attempt_revision(),captured.fencing_token(),captured.expires_at_epoch_ms(),
        NestedAuthorityPayload::ArtifactCommit(ArtifactCommitArtifact {
            object_id:Identifier(receipt.body.object_id.clone()), object_kind:Identifier(wire::KIND.to_owned()),
            content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()), content_length:receipt.body.content_length,
            immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?),
        }),None,captured.deadline_boottime_ns())?;
    stored.record(config,store::RecordKind::Artifact,&original(&artifact)?)?;
    let intent=intent(&receipt,&artifact)?;
    let frame=super::engine::signed_state_authority_frame(config,scoped,captured.request_id(),
        captured.operation_id(),captured.attempt_id(),captured.attempt_revision(),captured.fencing_token(),
        captured.deadline_boottime_ns(),&intent,keys)?;
    let execution=super::engine::state_execution_request(captured.request_id(),captured.operation_id(),
        captured.attempt_id(),captured.stable_resume_id(),captured.attempt_revision(),captured.fencing_token(),
        captured.deadline_boottime_ns(),frame);
    stored.record(config,store::RecordKind::StateRequest,&original(&execution)?)?;
    captured.check()?;
    // One call only. Missing acknowledgement never leads back to this call.
    let (state_result,exact)=super::execute_state_mutation(config,&execution,false)?;
    if exact.is_some() { return Err(fail("raw commit unexpectedly returned plaintext")); }
    stored.record(config,store::RecordKind::StateResult,&original(&state_result)?)?;
    validation::state_result(config,&captured,&receipt,&artifact,&execution,&state_result)?;
    let post_state=observe(config,&captured,true)?;
    let result=PutResult { api_version:wire::RESULT.to_owned(),capture_sha256:captured.capture_sha256().to_owned(),
        object:ImmutableObjectReference { object_type:ImmutableObjectType::UpstreamResponse,
            object_sha256:receipt.body.content_sha256.clone(),byte_length:receipt.body.content_length,
            retrieval_id:receipt.body.object_id.clone(),persistence_receipt_sha256:receipt.sha256()? },
        storage_receipt:receipt,artifact_commit:artifact,state_request:execution,state_result,post_state };
    validation::result(config,&captured,&result)?;
    stored.record(config,store::RecordKind::Result,&original(&result)?)?;
    stored.check(config)?; captured.check()?;
    Ok(super::engine::EngineResult { result:serde_json::to_value(result).map_err(|_| fail("encode persistence result"))?,
        exact_object_fds:Vec::new() })
}

fn intent(receipt:&StorageReceipt,artifact:&SignedAuthorityArtifact)->Result<UnsignedStateAuthorityIntentV1,V2RuntimeError> {
    Ok(UnsignedStateAuthorityIntentV1 { expected_state:AttemptState::Dispatching,
        payload:MutationPayload::CommitRawObject(CommitRawObjectMutation {
            object_id:Identifier(receipt.body.object_id.clone()),object_kind:Identifier(wire::KIND.to_owned()),
            media_type:wire::MEDIA.to_owned(),expected_content_length:receipt.body.content_length,
            expected_content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()),storage_locator:receipt.locator()?,
            immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?),artifact_commit:artifact.clone(),
        }) })
}
fn observe(config:&Config,captured:&VerifiedCapture,post:bool)->Result<SignedAttemptStateObservationV1,V2RuntimeError> {
    captured.check()?;
    super::query_attempt_state(config,&AttemptStateQueryRequestV1 {
        api_version:ATTEMPT_STATE_OBSERVATION_API_VERSION.to_owned(),generation_id:captured.generation_id().to_owned(),
        generation:captured.generation(),request_id:format!("{}:{}",captured.request_id(),if post {"post"} else {"pre"}),
        operation_id:captured.operation_id().to_owned(),attempt_id:captured.attempt_id().to_owned(),
        expected_stable_resume_id:captured.stable_resume_id().to_owned(),raw_response_object_id:None,
        include_proof_material:false,deadline_boottime_ns:captured.deadline_boottime_ns(),
    })
}

/// The engine produced and verified these signatures itself. The outer RPC
/// layer may preserve them but must not synthesize a persistence result.
pub(super) fn preserve_result(value:serde_json::Value)->Result<serde_json::Value,V2RuntimeError> {
    let result:PutResult=serde_json::from_value(value).map_err(|_| fail("backend persistence result shape"))?;
    original(&result)?;
    serde_json::to_value(result).map_err(|_| fail("backend persistence result encoding"))
}
