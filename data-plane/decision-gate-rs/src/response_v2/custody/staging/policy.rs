//! The independently keyed policy role admits exact measured gate evaluation
//! originals. It does not accept a caller verdict or call back into the state
//! owner while that owner is waiting for this transition artifact.
use super::*;
use std::{collections::BTreeMap,fs::File,os::fd::OwnedFd};
use serde_json::Value;
use super::super::{attestation::RoleSigningKey,config::{CustodyServiceRole as Role,ScopedCustodyServiceConfig},
    protocol::{ServiceRpcEnvelopeV1,ServiceOperationV1},services::engine};
use super::super::super::state_authority::{contract::{Identifier,Digest},lifecycle::{AttemptState,OperationKind},
    rpc::{NestedAuthorityPayload,TransitionAuthorizationArtifact,SignedAuthorityArtifact}};

fn json(raw:&[u8])->Result<Value,V2RuntimeError> {
    let value:Value=serde_json::from_slice(raw).map_err(|_|fail("staging metadata is not JSON"))?;
    if !value.is_object()||crate::canonical_json_bytes(&value).map_err(|_|fail("staging metadata encoding"))?!=raw {
        return Err(fail("staging metadata must be the exact canonical original"));
    }
    Ok(value)
}
fn text(value:&Value,key:&str,expected:&str)->Result<(),V2RuntimeError> {
    if value.get(key).and_then(Value::as_str)!=Some(expected) {return Err(fail(format!("staging metadata {key} differs")));}
    Ok(())
}

pub(crate) fn execute(config:&Config,scoped:&ScopedCustodyServiceConfig,envelope:&ServiceRpcEnvelopeV1,
    keys:&BTreeMap<String,RoleSigningKey>,fds:Vec<OwnedFd>)->Result<engine::EngineResult,V2RuntimeError> {
    if scoped.role!=Role::PolicyProofVerifier||envelope.operation!=ServiceOperationV1::TransitionAuthorize||fds.len()!=5 {
        return Err(fail("staging policy needs its actual role and five retained exact metadata inputs"));
    }
    let request:wire::PolicyRequest=serde_json::from_value(envelope.payload.clone()).map_err(|_|fail("closed staging policy request"))?;
    let current=admit(config,request.request.clone())?;
    verification::reserve_pair(config,&current,&request)?;
    if envelope.request_id!=current.binding().request_id||envelope.deadline_boottime_ns!=native::deadline(current.original()).map_err(fail)? {
        return Err(fail("staging policy envelope differs from original request allowance"));
    }
    let reserved=admit(config,request.reserve_request.clone())?;
    let mut files:Vec<File>=fds.into_iter().map(File::from).collect();
    let authority=inputs::Inputs::admit(config,&current,files.split_off(3))?;
    let originals=inputs::Inputs::admit(config,&reserved,files)?;
    let route=json(originals.bytes(0)?)?;let decision=json(originals.bytes(1)?)?;
    let runtime=json(originals.bytes(2)?)?;let plan=json(authority.bytes(0)?)?;let evidence=json(authority.bytes(1)?)?;
    let tx=&current.binding().transaction;
    text(&route,"apiVersion","serverware.responseObservationV2RouteSemantics/v1")?;
    text(&route,"principalId",&tx.principal_id)?;text(&route,"routeId",&tx.route_id)?;
    text(&route,"policySha256",&tx.policy_sha256)?;text(&route,"clientRequestSha256",&tx.client_request_sha256)?;
    text(&route,"decisionRequestSha256",&tx.decision_request_sha256)?;
    text(&route,"connectionIdentitySha256",&tx.connection_identity_sha256)?;text(&route,"tlsSessionSha256",&tx.tls_session_sha256)?;
    text(&route,"observationSessionId",&tx.observation_session_id)?;
    if native::sha256(originals.bytes(0)?)!=tx.route_semantics_sha256
        ||route.get("credentialBindingSha256").and_then(Value::as_str)!=tx.credential_binding_sha256.as_deref()
        ||decision.get("allowed").and_then(Value::as_bool)!=Some(true) {
        return Err(fail("admitted exact policy evaluation does not allow this route/credential scope"));
    }
    text(&decision,"principal_id",&tx.principal_id)?;text(&decision,"route_id",&tx.route_id)?;
    text(&decision,"client_request_digest",&tx.client_request_sha256)?;text(&decision,"request_digest",&tx.decision_request_sha256)?;
    let credential=decision.get("credential_ref").and_then(Value::as_str).filter(|v|!v.is_empty())
        .ok_or_else(||fail("native staging requires the actual credentialed decision"))?;
    let version=decision.get("credential_version").and_then(Value::as_u64).filter(|v|*v>0)
        .ok_or_else(||fail("native staging credential generation missing"))?;
    text(&runtime,"apiVersion","serverware.responseObservationV2GateRuntimeEvidence/v1")?;
    if runtime.get("transaction")!=Some(&serde_json::to_value(tx).map_err(|_|fail("transaction original encoding"))?)
        ||runtime.pointer("/helloAttestation/authenticatedSessionSha256").and_then(Value::as_str)
            !=Some(current.original().session_sha256.as_str()) {
        return Err(fail("policy evaluation is not from the retained authenticated gate session"));
    }
    text(&plan,"apiVersion","serverware.responseObservationV2AuthorityPlan/v1")?;
    let required=plan.get("required").and_then(Value::as_bool).ok_or_else(||fail("authority requirement missing"))?;
    let jit=decision.pointer("/jit/required").and_then(Value::as_bool).ok_or_else(||fail("actual JIT policy missing"))?;
    if plan.get("jit")!=decision.get("jit")||jit&&!required {
        return Err(fail("authority plan cannot remove the original JIT requirement"));
    }
    if required {
        let reservation=plan.get("reservation").filter(|v|v.is_object()).ok_or_else(||fail("held release reservation absent"))?;
        text(reservation,"attemptId",&current.binding().attempt_id)?;text(reservation,"principalId",&tx.principal_id)?;
        text(reservation,"routeId",&tx.route_id)?;text(reservation,"credentialId",credential)?;
        text(reservation,"policySha256",&tx.policy_sha256)?;text(reservation,"requestSha256",&tx.decision_request_sha256)?;
        if reservation.get("credentialGeneration").and_then(Value::as_u64)!=Some(version)
            ||reservation.get("operationSha256")!=decision.get("operation_digest")
            ||!reservation.get("bindingSha256").and_then(Value::as_str).is_some_and(crate::native_currentness_v1::digest)
            ||reservation.get("expiresAtEpochMs").and_then(Value::as_u64).is_none_or(|v|v<=epoch_ns().unwrap_or(u64::MAX)/1_000_000) {
            return Err(fail("held release reservation does not bind this actual current decision"));
        }
    } else if plan.get("reservation")!=Some(&Value::Null) {
        return Err(fail("nonrequired authority plan carries an unselected reservation"));
    }
    text(&evidence,"apiVersion","serverware.responseObservationV2ReservedAuthorityEvidence/v1")?;
    text(&evidence,"requestSha256",&tx.client_request_sha256)?;text(&evidence,"policySha256",&tx.policy_sha256)?;
    text(&evidence,"authorityPlanSha256",&native::sha256(authority.bytes(0)?))?;
    text(&evidence,"gateRuntimeAttestationSha256",&native::sha256(originals.bytes(2)?))?;
    current.check(config)?;originals.check(config,&reserved)?;authority.check(config,&current)?;
    let key=keys.get("evidence-trust").ok_or_else(||fail("actual policy role key absent"))?;
    let artifact=engine::sign_nested_artifact(config,Role::PolicyProofVerifier,key,OperationKind::AttemptAuthorize,
        &format!("staging-authorize:{}",&current.original_sha256()[7..]),&current.binding().attempt_id,
        current.binding().attempt_revision,current.binding().fencing_token,current.binding().deadline_at_epoch_ms,
        NestedAuthorityPayload::TransitionAuthorization(TransitionAuthorizationArtifact {
            policy_decision_id:Identifier(format!("decision:{}",&native::sha256(originals.bytes(1)?)[7..])),
            policy_generation_sha256:Digest(tx.policy_sha256.clone()),expected_revision:current.binding().attempt_revision,
            expected_state:AttemptState::Reserved,successor_revision:current.binding().attempt_revision.checked_add(1)
                .ok_or_else(||fail("authorization revision overflow"))?,successor_state:AttemptState::Authorized,passed:true,
        }),None,native::deadline(current.original()).map_err(fail)?)?;
    current.check(config)?;
    Ok(engine::EngineResult {result:serde_json::to_value(artifact).map_err(|_|fail("policy artifact encoding"))?,exact_object_fds:Vec::new()})
}

pub(crate) fn decode_artifact(value:Value)->Result<SignedAuthorityArtifact,V2RuntimeError> {
    serde_json::from_value(value).map_err(|_|fail("actual staging transition artifact missing"))
}
