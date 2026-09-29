use super::*;
use super::super::super::attestation::{verify_attempt_state_observation,verify_state_mutation_receipt};
use super::super::super::super::state_authority::{canonical::{canonical_jcs_bytes,sha256_digest},
    contract::{BootDeadline,STATE_AUTHORITY_API_VERSION,STATE_AUTHORITY_RPC_KIND,STATE_AUTHORITY_SCHEMA_VERSION},
    rpc::{RpcRequest,FenceExpectation,FenceExpectationMode}};

pub(super) fn observation(config:&Config,captured:&VerifiedCapture,value:&SignedAttemptStateObservationV1,
    revision:u64,post:bool)->Result<(),V2RuntimeError> {
    captured.check()?;
    verify_attempt_state_observation(config.custody_topology(),value)?;
    if value.request_id != format!("{}:{}",captured.request_id(),if post {"post"} else {"pre"})
        || value.operation_id != captured.operation_id() || value.attempt_id != captured.attempt_id()
        || value.stable_resume_id != captured.stable_resume_id() || value.attempt_revision != revision
        || value.fencing_token != captured.fencing_token() || value.authoritative_state != AttemptState::Dispatching
        || value.deadline_boot_id != recovery::kernel_boot_id()?
        || value.deadline_boot_millis.checked_mul(1_000_000) != Some(captured.deadline_boottime_ns())
        || value.proof_material.is_some() { return Err(fail("persistence state observation differs from retained attempt")); }
    Ok(())
}

pub(super) fn state_result(config:&Config,captured:&VerifiedCapture,receipt:&StorageReceipt,
    artifact:&SignedAuthorityArtifact,execution:&StateMutationExecutionRequestV1,
    value:&StateMutationExecutionResultV1)->Result<(),V2RuntimeError> {
    captured.check()?;
    let topology=config.custody_topology();
    super::super::engine::verify_pinned_authority_artifact(topology,artifact,captured.attempt_id(),captured.fencing_token())?;
    let body=&artifact.body;
    let expected=ArtifactCommitArtifact { object_id:Identifier(receipt.body.object_id.clone()),
        object_kind:Identifier(wire::KIND.to_owned()),content_sha256:AuthorityDigest(receipt.body.content_sha256.clone()),
        content_length:receipt.body.content_length,immutable_storage_receipt_sha256:AuthorityDigest(receipt.sha256()?) };
    if body.artifact_id.0 != captured.operation_id() || body.operation_id.0 != captured.operation_id()
        || body.operation != OperationKind::ObjectCommitRaw || body.attempt_revision != captured.attempt_revision()
        || body.producing_logical_role.as_ref().map(|v|v.0.as_str()) != Some("persistence")
        || body.payload != NestedAuthorityPayload::ArtifactCommit(expected)
        || body.expires_at_epoch_millis != captured.expires_at_epoch_ms() {
        return Err(fail("artifact does not attest this exact attempt's persisted content"));
    }
    let scoped=config.scoped_service_config(Role::ImmutableArtifactLedger)?;
    let unsigned=RpcRequest { api_version:STATE_AUTHORITY_API_VERSION.to_owned(),kind:STATE_AUTHORITY_RPC_KIND.to_owned(),
        schema_version:STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),generation_id:Identifier(captured.generation_id().to_owned()),
        request_id:Identifier(captured.request_id().to_owned()),operation_id:Identifier(captured.operation_id().to_owned()),
        caller_role_id:Identifier(scoped.process.service_id),operation:OperationKind::ObjectCommitRaw,
        attempt_id:Identifier(captured.attempt_id().to_owned()),expected_revision:captured.attempt_revision(),
        expected_state:AttemptState::Dispatching,
        fence:FenceExpectation { mode:FenceExpectationMode::Exact,fence_token:Some(Identifier(captured.fencing_token().to_string())) },
        deadline:BootDeadline { clock:"CLOCK_BOOTTIME".to_owned(),boot_id:Identifier(recovery::kernel_boot_id()?),
            deadline_boot_millis:captured.deadline_boottime_ns()/1_000_000 },payload:intent(receipt,artifact)?.payload };
    if execution.api_version != super::super::super::protocol::STATE_AUTHORITY_API_VERSION
        || execution.request_id != captured.request_id() || execution.operation_id != captured.operation_id()
        || execution.attempt_id != captured.attempt_id() || execution.stable_resume_id != captured.stable_resume_id()
        || execution.attempt_revision != captured.attempt_revision() || execution.fencing_token != captured.fencing_token()
        || execution.deadline_boottime_ns != captured.deadline_boottime_ns()
        || canonical_jcs_bytes(&execution.frame.request).map_err(|_| fail("retained frame request"))?
            != canonical_jcs_bytes(&unsigned).map_err(|_| fail("expected frame request"))? {
        return Err(fail("signed raw commit frame does not carry exact retained authority"));
    }
    // The protected result commits the entire actual authenticated frame, not
    // a reconstructed unsigned request or a caller supplied success digest.
    let digest=sha256_digest(&canonical_jcs_bytes(&execution.frame).map_err(|_| fail("raw commit canonical frame"))?);
    let receipt=&value.receipt;
    verify_state_mutation_receipt(topology,receipt)?;
    if receipt.request_id != captured.request_id() || receipt.operation_id != captured.operation_id()
        || receipt.attempt_id != captured.attempt_id() || receipt.stable_resume_id != captured.stable_resume_id()
        || receipt.fencing_token != captured.fencing_token() || receipt.disposition != "APPLIED"
        || receipt.authoritative_revision != captured.attempt_revision().checked_add(1).ok_or_else(|| fail("revision overflow"))?
        || receipt.authoritative_state != "DISPATCHING" || receipt.exact_request_sha256 != digest.0
        || value.response_data_result.is_some() || value.exact_object.is_some() {
        return Err(fail("raw commit acknowledgement is not exact applied successor; attempt remains consumed"));
    }
    Ok(())
}

pub(super) fn result(config:&Config,captured:&VerifiedCapture,value:&PutResult)->Result<(),V2RuntimeError> {
    current(config,captured.deadline_boottime_ns())?; captured.check()?;
    original(value)?;
    value.storage_receipt.verify(config,captured.descriptor())?;
    if value.api_version != wire::RESULT || value.capture_sha256 != captured.capture_sha256()
        || value.object.object_type != ImmutableObjectType::UpstreamResponse
        || value.object.object_sha256 != captured.descriptor().sha256
        || value.object.byte_length != captured.descriptor().byte_length
        || value.object.retrieval_id != value.storage_receipt.body.object_id
        || value.object.persistence_receipt_sha256 != value.storage_receipt.sha256()? {
        return Err(fail("persistence result content/receipt/capture binding differs"));
    }
    state_result(config,captured,&value.storage_receipt,&value.artifact_commit,&value.state_request,&value.state_result)?;
    observation(config,captured,&value.post_state,captured.attempt_revision().checked_add(1)
        .ok_or_else(|| fail("post-state revision overflow"))?,true)
}
