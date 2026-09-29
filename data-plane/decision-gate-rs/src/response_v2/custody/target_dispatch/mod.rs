//! Separately admitted native execution, not an attested-router shortcut.
//! Wire values alone never construct an execution or persistence capability.
pub mod wire;
mod role;
pub(crate) use role::execute;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::fs::File;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
use super::{RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use super::config::{CustodyAttestationProfile, CustodyServiceRole};
use super::super::state_authority::{canonical, contract, lifecycle, rpc};
use crate::native_target_dispatch_v1 as native;
use wire::{CapturePersistRequest, DispatchOriginal, SignedTargetDispatchPermit};

fn fail(message: impl Into<String>) -> V2RuntimeError {
    V2RuntimeError::new("native_target_dispatch_refused", message)
}
fn same<T: serde::Serialize>(a: &T, b: &T) -> Result<bool,V2RuntimeError> {
    Ok(native::canonical(a).map_err(fail)? == native::canonical(b).map_err(fail)?)
}
fn now_ns() -> Result<u64,V2RuntimeError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| fail("epoch clock invalid"))?
        .as_nanos().try_into().map_err(|_| fail("epoch nanoseconds overflow"))
}
pub(crate) fn configuration_profile<'de,D>(d:D) -> Result<Option<native::Configuration>,D::Error>
where D:serde::Deserializer<'de> {
    native::Configuration::deserialize(d).map(Some)
}

pub(crate) fn validate_configuration(config:&Config) -> Result<(),V2RuntimeError> {
    let Some(selected)=&config.target_dispatch else {return Ok(())};
    selected.validate().map_err(fail)?;
    if config.guest_delivery_authority.is_none() || config.guest_listener.is_none()
        || config.custody_topology.attestation_mode != CustodyAttestationProfile::TeeHardware
        || selected.generation_id != config.custody_topology.generation_id
        || selected.generation != config.custody_topology.generation
        || selected.assignment.expected_binary_digest != config.expected_client_executable_measurement_sha256
        || config.expected_client_uid != 65534 {
        return Err(fail("target dispatch requires the exact independently assigned guest gate and generation"));
    }
    Ok(())
}

fn selected<'a>(config:&'a Config,deadline:u64) -> Result<&'a native::Configuration,V2RuntimeError> {
    validate_configuration(config)?;
    let selected=config.target_dispatch.as_ref().ok_or_else(||fail("native target-dispatch purpose is not assigned"))?;
    config.guest_delivery.as_ref().ok_or_else(||fail("no actual retained guest delivery"))?.check()?;
    let now=now_ns()?;
    if super::recovery::boottime_ns()? >= deadline
        || super::recovery::kernel_boot_id()? != selected.assignment.kernel_boot_id
        || now/1_000_000 < selected.valid_from_epoch_ms
        || now/1_000_000 >= selected.valid_until_epoch_ms {
        return Err(fail("target-dispatch original boot, assignment or operation allowance expired"));
    }
    Ok(selected)
}

pub(crate) fn require_session(config:&Config,request:&crate::response_observation_v2_api::V2ResponseDataRequest,
    client:&super::AuthenticatedClientIdentity,session:&super::AuthenticatedSessionIdentity)->Result<(),V2RuntimeError> {
    use crate::response_observation_v2_api::V2ResponseDataRequest as Request;
    let original=match request {
        Request::TargetDispatchBegin {request_id,params,..}=>{
            if request_id!=&params.original.binding.request_id {return Err(fail("begin request identity differs"));}
            &params.original
        },
        Request::CapturePersist {request_id,params,..}=>{
            if request_id!=&params.request_id {return Err(fail("capture request identity differs"));}
            &params.permit.original
        },
        _=>return Ok(()),
    };
    selected(config,original_deadline(original)?)?;
    if client.identity_sha256()!=original.binding.client_identity_sha256
        || session.client_identity_sha256!=original.binding.client_identity_sha256
        || session.session_sha256()!=original.session_sha256 {
        return Err(fail("target dispatch is not on the actual admitted gate session"));
    }
    Ok(())
}

pub(crate) fn original_deadline(original:&DispatchOriginal) -> Result<u64,V2RuntimeError> {
    let value=&original.binding.monotonic_deadline.absolute_boottime_ns;
    let result=value.parse::<u64>().map_err(|_|fail("invalid original deadline"))?;
    if result==0 || result%1_000_000!=0 || result.to_string()!=*value {
        return Err(fail("original deadline must already be canonical and exactly millisecond-aligned"));
    }
    Ok(result)
}
pub(crate) fn original_sha256(original:&DispatchOriginal) -> Result<String,V2RuntimeError> {
    Ok(native::sha256(&native::canonical(original).map_err(fail)?))
}
pub(crate) fn begin_operation_id(original:&DispatchOriginal) -> Result<String,V2RuntimeError> {
    Ok(format!("dispatch:{}",&original_sha256(original)?[7..]))
}
pub(crate) fn permit_sha256(permit:&SignedTargetDispatchPermit) -> Result<String,V2RuntimeError> {
    Ok(native::sha256(&native::canonical(permit).map_err(fail)?))
}

/// Reconstruct the exact state request whose canonical digest the state
/// authority signed. No receipt for another StateCas operation is accepted.
pub(crate) fn begin_request(config:&Config,original:&DispatchOriginal,
    credential_use:&rpc::SignedAuthorityArtifact) -> Result<rpc::RpcRequest,V2RuntimeError> {
    let binding=&original.binding;
    let rpc::NestedAuthorityPayload::CredentialUse(use_original)=&credential_use.body.payload
        else {return Err(fail("dispatch permit lacks its credential-use original"));};
    let digest=original_sha256(original)?;
    let credential=binding.transaction.credential_binding_sha256.as_ref()
        .ok_or_else(||fail("credential dispatch lacks its actual credential binding"))?;
    if use_original.credential_binding_sha256.0 != *credential
        || use_original.target_effect_id.0 != format!("effect:{}",&digest[7..])
        || use_original.credential_use_id.0 != format!("credential-use:{}",&digest[7..])
        || use_original.one_use_nonce_sha256.0 != digest {
        return Err(fail("credential-use artifact differs from original one-use dispatch"));
    }
    let role=config.custody_topology.process(CustodyServiceRole::CredentialTransport)
        .ok_or_else(||fail("credential transport is unassigned"))?;
    let request=rpc::RpcRequest {
        api_version:contract::STATE_AUTHORITY_API_VERSION.to_owned(),
        kind:contract::STATE_AUTHORITY_RPC_KIND.to_owned(),
        schema_version:contract::STATE_AUTHORITY_SCHEMA_VERSION.to_owned(),
        generation_id:contract::Identifier(original.generation_id.clone()),
        request_id:contract::Identifier(binding.request_id.clone()),
        operation_id:contract::Identifier(begin_operation_id(original)?),
        caller_role_id:contract::Identifier(role.service_id.clone()),
        operation:lifecycle::OperationKind::DispatchBegin,
        attempt_id:contract::Identifier(binding.attempt_id.clone()),
        expected_revision:binding.attempt_revision,
        expected_state:lifecycle::AttemptState::Staged,
        fence:rpc::FenceExpectation {mode:rpc::FenceExpectationMode::Exact,
            fence_token:Some(contract::Identifier(binding.fencing_token.to_string()))},
        deadline:contract::BootDeadline {clock:"CLOCK_BOOTTIME".to_owned(),
            boot_id:contract::Identifier(config.target_dispatch.as_ref().ok_or_else(||fail("target assignment absent"))?
                .assignment.kernel_boot_id.clone()),deadline_boot_millis:original_deadline(original)?/1_000_000},
        payload:rpc::MutationPayload::BeginDispatch(rpc::BeginDispatchMutation {
            target_effect_id:use_original.target_effect_id.clone(),credential_use_id:use_original.credential_use_id.clone(),
            credential_binding_sha256:use_original.credential_binding_sha256.clone(),
            idempotency_key_sha256:contract::Digest(digest),request_object:original.staged_request.clone(),
            transport_authorization:credential_use.clone()}),
    };
    request.validate().map_err(|error|fail(error.to_string()))?;
    Ok(request)
}

pub(crate) fn verify_permit(config:&Config,permit:&SignedTargetDispatchPermit,deadline:u64)
    -> Result<(),V2RuntimeError> {
    let assignment=selected(config,deadline)?;
    let original=&permit.original;
    let binding=&original.binding;
    if permit.api_version!=wire::PERMIT || original.generation_id!=assignment.generation_id
        || original.generation!=assignment.generation || original.gate_key_id!=assignment.assignment.key_id
        || deadline>original_deadline(original)? || now_ns()?/1_000_000>=binding.deadline_at_epoch_ms {
        return Err(fail("permit differs from current assignment or original allowance"));
    }
    let topology=&config.custody_topology;
    let role=topology.logical_role("target-transport").filter(|role|role.service_role==CustodyServiceRole::CredentialTransport)
        .ok_or_else(||fail("target-transport signer not independently assigned"))?;
    let key: [u8;32]=STANDARD.decode(&permit.public_key_base64).map_err(|_|fail("permit key encoding invalid"))?
        .try_into().map_err(|_|fail("permit public key length invalid"))?;
    let signature:[u8;64]=STANDARD.decode(&permit.signature).map_err(|_|fail("permit signature encoding invalid"))?
        .try_into().map_err(|_|fail("permit signature length invalid"))?;
    if STANDARD.encode(key)!=permit.public_key_base64 || STANDARD.encode(signature)!=permit.signature
        || native::sha256(&key)!=role.public_key_sha256 || role.key_id!=role.public_key_sha256 {
        return Err(fail("permit key differs from actual admitted role identity"));
    }
    let mut message=wire::PERMIT_DOMAIN.to_vec();
    message.extend(crate::canonical_json_bytes(&permit.unsigned()).map_err(|_|fail("permit canonicalization failed"))?);
    VerifyingKey::from_bytes(&key).map_err(|_|fail("permit public key invalid"))?
        .verify(&message,&Signature::from_bytes(&signature)).map_err(|_|fail("permit role signature failed"))?;
    super::services::engine::verify_pinned_authority_artifact(topology,&permit.credential_use,
        &binding.attempt_id,binding.fencing_token)?;
    let artifact=&permit.credential_use.body;
    if artifact.producing_logical_role.as_ref().map(|value|value.0.as_str())!=Some("credential-authority")
        || artifact.operation!=lifecycle::OperationKind::DispatchBegin
        || artifact.attempt_revision!=binding.attempt_revision
        || artifact.expires_at_epoch_millis!=binding.deadline_at_epoch_ms
        || now_ns()?/1_000_000>=artifact.expires_at_epoch_millis {
        return Err(fail("credential-use scope differs from original dispatch"));
    }
    let exact_request=begin_request(config,original,&permit.credential_use)?;
    if !same(&permit.dispatch_request.request,&exact_request)? {
        return Err(fail("original signed DispatchBegin frame differs from exact reconstructed request"));
    }
    let exact_request_sha256=canonical::sha256_digest(&canonical::canonical_jcs_bytes(&permit.dispatch_request)
        .map_err(|error|fail(error.to_string()))?).0;
    let receipt=&permit.dispatch_receipt;
    super::attestation::verify_state_mutation_receipt(topology,receipt)?;
    let next=binding.attempt_revision.checked_add(1).ok_or_else(||fail("dispatch revision overflow"))?;
    if receipt.request_id!=binding.request_id || receipt.operation_id!=exact_request.operation_id.0
        || receipt.attempt_id!=binding.attempt_id || receipt.stable_resume_id!=original.stable_resume_id
        || receipt.exact_request_sha256!=exact_request_sha256 || receipt.disposition!="APPLIED"
        || receipt.authoritative_revision!=next || receipt.authoritative_state!="DISPATCHING"
        || receipt.fencing_token!=binding.fencing_token {
        return Err(fail("state receipt does not admit this exact irreversible DispatchBegin"));
    }
    let post=&permit.post_state;
    super::attestation::verify_attempt_state_observation(topology,post)?;
    if post.attempt_id!=binding.attempt_id || post.attempt_revision!=next
        || post.authoritative_state!=lifecycle::AttemptState::Dispatching
        || post.stable_resume_id!=original.stable_resume_id || post.fencing_token!=binding.fencing_token
        || post.deadline_boot_id!=exact_request.deadline.boot_id.0
        || post.deadline_boot_millis!=exact_request.deadline.deadline_boot_millis {
        return Err(fail("post-dispatch state does not preserve the exact attempt, fence and deadline"));
    }
    selected(config,deadline)?;
    Ok(())
}

/// Opaque, non-Clone proof owner. The raw file was checked for exact size,
/// digest, descriptor inventory and all immutable memfd seals before custody.
pub(crate) struct VerifiedCapture {
    original:CapturePersistRequest,
    raw:super::ValidatedExactObject,
    delivery:Arc<super::guest_delivery::Delivery>,
    configuration:native::Configuration,
    pid:libc::pid_t,
    deadline:u64,
    capture_sha256:String,
}
impl VerifiedCapture {
    pub(crate) fn check(&self)->Result<(),V2RuntimeError> {
        self.delivery.check()?;
        let now=now_ns()?;
        if unsafe {libc::getpid()}!=self.pid || super::recovery::kernel_boot_id()?!=self.configuration.assignment.kernel_boot_id
            || super::recovery::boottime_ns()?>=self.deadline
            || now>=self.original.capture.statement.expires_at_epoch_ns
            || now/1_000_000>=self.configuration.valid_until_epoch_ms {
            return Err(fail("verified capture owner lost its original process, boot or allowance"));
        }
        Ok(())
    }
    pub(crate) fn request_id(&self)->&str {&self.original.request_id}
    pub(crate) fn operation_id(&self)->&str {&self.original.operation_id}
    pub(crate) fn stable_resume_id(&self)->&str {&self.original.stable_resume_id}
    pub(crate) fn generation_id(&self)->&str {&self.original.permit.original.generation_id}
    pub(crate) fn generation(&self)->u64 {self.original.permit.original.generation}
    pub(crate) fn attempt_id(&self)->&str {&self.original.permit.original.binding.attempt_id}
    pub(crate) fn attempt_revision(&self)->u64 {self.original.permit.post_state.attempt_revision}
    pub(crate) fn fencing_token(&self)->u64 {self.original.permit.original.binding.fencing_token}
    pub(crate) fn expires_at_epoch_ms(&self)->u64 {self.original.permit.original.binding.deadline_at_epoch_ms}
    pub(crate) fn deadline_boottime_ns(&self)->u64 {self.deadline}
    pub(crate) fn descriptor(&self)->&crate::response_observation_v2_api::ExactByteObjectDescriptor {self.raw.descriptor()}
    pub(crate) fn capture_sha256(&self)->&str {&self.capture_sha256}
    pub(crate) fn permit(&self)->&SignedTargetDispatchPermit {&self.original.permit}
    pub(crate) fn bytes(&self)->Result<Zeroizing<Vec<u8>>,V2RuntimeError> {
        self.check()?;
        let mut result=Zeroizing::new(vec![0;self.descriptor().byte_length as usize]);
        let mut offset=0;
        while offset<result.len() {
            self.check()?;
            let count=self.raw.read_at(&mut result[offset..],offset as u64)?;
            if count==0 {return Err(fail("retained exact capture truncated"));}
            offset+=count;
        }
        if native::sha256(&result)!=self.descriptor().sha256 {return Err(fail("retained raw capture digest changed"));}
        self.check()?;
        Ok(result)
    }
}

pub(crate) fn verify_capture(config:&Config,request:&CapturePersistRequest,file:File,deadline:u64)
    ->Result<VerifiedCapture,V2RuntimeError> {
    let assignment=selected(config,deadline)?;
    // selected() already checked the genuine delivered process. Only the two
    // actual receiving roles may construct the retained raw-byte owner.
    if ![CustodyServiceRole::CredentialTransport,CustodyServiceRole::ImmutableArtifactLedger].iter().any(|role|
        config.custody_topology.process(*role).is_some_and(|process|
            process.uid==unsafe {libc::geteuid()} && process.gid==unsafe {libc::getegid()})) {
        return Err(fail("capture owner requires the actual delivered transport or ledger process"));
    }
    verify_permit(config,&request.permit,deadline)?;
    native::verify(assignment,&request.capture,now_ns()?).map_err(fail)?;
    let statement=&request.capture.statement;
    let capture_sha256=native::sha256(&native::canonical(&request.capture).map_err(fail)?);
    if request.api_version!=wire::PERSIST || statement.phase!="capture"
        || !same(&statement.original,&request.permit.original)?
        || statement.permit_sha256.as_deref()!=Some(permit_sha256(&request.permit)?.as_str())
        || statement.raw_response.as_ref()!=Some(&request.raw_response)
        || request.stable_resume_id!=statement.original.stable_resume_id
        || request.request_id!=format!("capture:{}",&capture_sha256[7..])
        || request.operation_id!=format!("persist:{}",&capture_sha256[7..]) {
        return Err(fail("native capture, transport permission, exact response and persistence context differ"));
    }
    let raw=super::validate_exact_object_files(std::slice::from_ref(&request.raw_response),vec![file],None)?.into_single()?;
    let owner=VerifiedCapture {original:request.clone(),raw,
        delivery:Arc::clone(config.guest_delivery.as_ref().ok_or_else(||fail("guest delivery disappeared"))?),
        configuration:assignment.clone(),pid:unsafe {libc::getpid()},deadline,capture_sha256};
    owner.check()?;
    Ok(owner)
}
