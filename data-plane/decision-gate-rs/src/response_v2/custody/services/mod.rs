mod cleanup_watchdog;
mod common;
mod credential_transport;
mod immutable_artifact_ledger;
pub(super) mod ledger_exact_read;
pub(super) mod ledger_put;
pub(super) mod engine;
mod policy_proof_verifier;
mod release_attestor_publisher;
pub(super) mod router;
mod state_authority;

pub(crate) use policy_proof_verifier::verify_final_envelope;
pub(crate) use state_authority::{
    execute_generation_postgres,
    generation_reconciliation_checkpoint_postgres,
    generation_reconciliation_cursor_postgres,
};

use sha2::{Digest, Sha256};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::os::fd::OwnedFd;

use super::attestation::{
    verify_attempt_state_observation, verify_custody_error,
    verify_immutable_raw_inspection,
    verify_release_consumption, verify_service_rpc_result,
};
use super::config::CustodyServiceRole;
use super::generation::topology_sha256;
use super::protocol::{
    AttemptStateQueryRequestV1,
    ConsumeReleaseAndRetrieveExactRequestV1,
    InspectImmutableRawRequestV1, ServiceHelloResultV1, ServiceHelloV1,
    ServiceOperationV1, ServiceRpcResultV1,
    SignedImmutableRawInspectionV1, SignedReleaseConsumptionV2,
    SignedAttemptStateObservationV1,
    ReleaseConsumptionResultV2,
    StateMutationExecutionRequestV1,
    StateMutationExecutionResultV1,
    SERVICE_RPC_API_VERSION,
};

pub(super) fn query_attempt_state(
    config: &RootOwnedResponseObservationV2Config,
    request: &AttemptStateQueryRequestV1,
) -> Result<SignedAttemptStateObservationV1, V2RuntimeError> {
    let observation: SignedAttemptStateObservationV1 = invoke_service(
        config,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,
        &request.request_id,
        request,
        request.deadline_boottime_ns,
    )?;
    verify_attempt_state_observation(
        config.custody_topology(),
        &observation,
    )?;
    if observation.request_id != request.request_id
        || observation.operation_id != request.operation_id
        || observation.attempt_id != request.attempt_id
        || observation.stable_resume_id
            != request.expected_stable_resume_id
        || observation.proof_material.is_some()
            != request.include_proof_material
    {
        return Err(V2RuntimeError::new(
            "attempt_state_observation_mismatch",
            "state observation does not answer the exact query",
        ));
    }
    Ok(observation)
}

pub(super) fn query_staged_original(
    config: &RootOwnedResponseObservationV2Config,
    request: &super::protocol::StagedOriginalQueryV1,
) -> Result<super::protocol::SignedStagedOriginalV1, V2RuntimeError> {
    let signed: super::protocol::SignedStagedOriginalV1 = invoke_service(
        config, CustodyServiceRole::StateAuthority, ServiceOperationV1::StateCas,
        &request.request_id, request, request.deadline_boottime_ns)?;
    super::attestation::verify_staged_original(config.custody_topology(), &signed)?;
    let body = &signed.body;
    if request.api_version != super::protocol::STAGED_ORIGINAL_QUERY_API_VERSION
        || signed.generation_id != request.generation_id || signed.generation != request.generation
        || signed.request_id != request.request_id || signed.operation_id != request.operation_id
        || body.attempt_id != request.attempt_id || body.stable_resume_id != request.expected_stable_resume_id
        || body.revision != request.expected_revision || body.fencing_token != request.expected_fencing_token
        || body.state != request.expected_state
        || body.dispatch.as_ref().map(|v| &v.exact_request_sha256) != request.expected_dispatch_request_sha256.as_ref()
        || request.deadline_boottime_ns / 1_000_000 > body.original_deadline.deadline_boot_millis
        || boottime_ns()? >= request.deadline_boottime_ns {
        return Err(V2RuntimeError::new("staged_original_query_mismatch",
            "authenticated original does not answer the exact current-state purpose and original deadline"));
    }
    Ok(signed)
}
use super::recovery::{
    boottime_ns, random_challenge_nonce, BootDeadline,
    ServiceConnection,
};
use super::{
    RootOwnedResponseObservationV2Config, V2RuntimeError,
};

pub(crate) fn run_service(
    config: RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
) -> Result<(), V2RuntimeError> {
    match role {
        CustodyServiceRole::CustodyRouter => {
            router::run(&config)
        }
        CustodyServiceRole::StateAuthority => {
            state_authority::run(&config)
        }
        CustodyServiceRole::CredentialTransport => {
            credential_transport::run(&config)
        }
        CustodyServiceRole::PolicyProofVerifier => {
            policy_proof_verifier::run(&config)
        }
        CustodyServiceRole::ImmutableArtifactLedger => {
            immutable_artifact_ledger::run(&config)
        }
        CustodyServiceRole::ReleaseAttestorPublisher => {
            release_attestor_publisher::run(&config)
        }
        CustodyServiceRole::CleanupWatchdog => {
            cleanup_watchdog::run(&config)
        }
    }
}

pub(crate) fn start_router_readiness(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<router::RouterReadinessGuard, V2RuntimeError> {
    router::start(config)
}

pub(crate) fn check_readiness(
    config: &RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
) -> Result<(), V2RuntimeError> {
    super::guest_delivery::check(config)?;
    let topology = config.custody_topology();
    let scoped = config.scoped_service_config(role)?;
    let record = common::read_readiness_record(
        &scoped.process.readiness_record_path,
    )?;
    common::verify_readiness_record(
        config,
        &scoped,
        &record,
    )?;
    let timeout_ns = scoped
        .process
        .request_timeout_ms
        .checked_mul(1_000_000)
        .and_then(|duration| {
            boottime_ns()
                .ok()
                .and_then(|now| now.checked_add(duration))
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_readiness_deadline_overflow",
                "readiness deadline overflowed",
            )
        })?;
    let deadline = BootDeadline::new(super::guest_delivery::bound_deadline_ns(config, timeout_ns)?)?;
    let mut connection = ServiceConnection::connect(
        &scoped.process.readiness_socket_path,
        deadline,
        scoped.process.max_frame_bytes,
    )?;
    let challenge_nonce = random_challenge_nonce()?;
    let request_id = format!(
        "sha256:{:x}",
        Sha256::digest(format!(
            "{}:{}:{}:{}",
            scoped.role.as_str(),
            scoped.generation_id,
            scoped.generation,
            challenge_nonce,
        ))
    );
    connection.send(&ServiceHelloV1 {
        api_version: SERVICE_RPC_API_VERSION.to_owned(),
        request_id: request_id.clone(),
        expected_service_role: role,
        generation_id: scoped.generation_id.clone(),
        generation: scoped.generation,
        topology_sha256: topology_sha256(topology)?,
        challenge_nonce: challenge_nonce.clone(),
        deadline_boottime_ns: deadline.absolute_ns(),
    })?;
    let response: ServiceHelloResultV1 =
        connection.receive()?;
    if response.api_version != SERVICE_RPC_API_VERSION
        || response.request_id != request_id
        || response.challenge_nonce != challenge_nonce
    {
        return Err(V2RuntimeError::new(
            "custody_readiness_handshake_mismatch",
            "readiness UDS did not answer the exact challenge",
        ));
    }
    if role == CustodyServiceRole::CustodyRouter {
        if response.handshake.is_some()
            || response.dependency_handshakes.len() != 6
        {
            return Err(V2RuntimeError::new(
                "custody_router_readiness_handshake_mismatch",
                "router readiness UDS did not return exactly six fresh signed dependency handshakes",
            ));
        }
        for dependency_role in CustodyServiceRole::ALL {
            if dependency_role == CustodyServiceRole::CustodyRouter {
                continue;
            }
            let baseline = record
                .dependency_handshakes
                .get(&dependency_role)
                .ok_or_else(|| {
                    V2RuntimeError::new(
                        "custody_router_readiness_baseline_missing",
                        "router readiness record omits a dependency baseline",
                    )
                })?;
            let live = response
                .dependency_handshakes
                .get(&dependency_role)
                .ok_or_else(|| {
                    V2RuntimeError::new(
                        "custody_router_readiness_dependency_missing",
                        "router live readiness omits a dependency handshake",
                    )
                })?;
            common::verify_live_handshake_against_record(
                config,
                baseline,
                live,
                &request_id,
                &challenge_nonce,
            )?;
        }
    } else {
        if !response.dependency_handshakes.is_empty() {
            return Err(V2RuntimeError::new(
                "custody_readiness_dependencies_unexpected",
                "non-router readiness returned dependency handshakes",
            ));
        }
        let live = response.handshake.as_ref().ok_or_else(|| {
            V2RuntimeError::new(
                "custody_readiness_handshake_missing",
                "readiness UDS returned no signed role handshake",
            )
        })?;
        let expected =
            record.service_handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_readiness_handshake_missing",
                    "readiness record has no service handshake",
                )
            })?;
        common::verify_live_handshake_against_record(
            config,
            expected,
            live,
            &request_id,
            &challenge_nonce,
        )?;
    }
    super::guest_delivery::check(config)?;
    Ok(())
}

pub(crate) fn invoke_service<P, R>(
    config: &RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
    operation: super::protocol::ServiceOperationV1,
    request_id: &str,
    payload: &P,
    deadline_boottime_ns: u64,
) -> Result<R, V2RuntimeError>
where
    P: Serialize,
    R: DeserializeOwned,
{
    let (result, exact_object_fds) = invoke_service_wire(
        config,
        role,
        operation,
        request_id,
        payload,
        deadline_boottime_ns,
        &[],
        false,
    )?;
    if !exact_object_fds.is_empty() {
        return Err(V2RuntimeError::new(
            "custody_service_exact_object_unexpected",
            "ordinary service invocation returned an exact-object descriptor",
        ));
    }
    serde_json::from_value(result.result).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_result_invalid",
            "service result does not satisfy the expected closed DTO",
        )
    })
}

pub(crate) fn inspect_immutable_raw(
    config: &RootOwnedResponseObservationV2Config,
    request_id: &str,
    payload: &InspectImmutableRawRequestV1,
    deadline_boottime_ns: u64,
) -> Result<
    (SignedImmutableRawInspectionV1, super::ValidatedExactObject),
    V2RuntimeError,
> {
    let (result, mut exact_object_fds) = invoke_service_wire(
        config,
        CustodyServiceRole::ImmutableArtifactLedger,
        ServiceOperationV1::InspectImmutableRaw,
        request_id,
        payload,
        deadline_boottime_ns,
        &[],
        true,
    )?;
    let inspection: SignedImmutableRawInspectionV1 =
        serde_json::from_value(result.result).map_err(|_| {
            V2RuntimeError::new(
                "immutable_raw_inspection_result_invalid",
                "inspection service result is not the closed signed DTO",
            )
        })?;
    verify_immutable_raw_inspection(
        config.custody_topology(),
        &inspection,
    )?;
    if inspection.request_id != request_id
        || inspection.request_sha256 != payload.request_sha256
        || inspection.attempt_id != payload.attempt_id
        || inspection.stable_resume_id != payload.stable_resume_id
        || inspection.raw_object_id != payload.raw_object_id
        || inspection.raw_object_sha256 != payload.raw_object_sha256
        || inspection.raw_object_byte_length
            != payload.raw_object_byte_length
    {
        return Err(V2RuntimeError::new(
            "immutable_raw_inspection_result_mismatch",
            "inspection result is not bound to the exact requested object and stable attempt",
        ));
    }
    let exact_object = validate_exact_service_object(
        &inspection.exact_object,
        exact_object_fds.remove(0),
    )?;
    Ok((inspection, exact_object))
}

pub(crate) fn consume_release_and_retrieve_exact(
    config: &RootOwnedResponseObservationV2Config,
    request_id: &str,
    payload: &ConsumeReleaseAndRetrieveExactRequestV1,
    deadline_boottime_ns: u64,
) -> Result<
    (
        ReleaseConsumptionResultV2,
        Option<super::ValidatedExactObject>,
    ),
    V2RuntimeError,
> {
    let retrieve = matches!(
        payload,
        ConsumeReleaseAndRetrieveExactRequestV1::Retrieve(_)
    );
    let (result, mut exact_object_fds) = invoke_service_wire(
        config,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        request_id,
        payload,
        deadline_boottime_ns,
        &[],
        retrieve,
    )?;
    let consumption: ReleaseConsumptionResultV2 =
        serde_json::from_value(result.result).map_err(|_| {
            V2RuntimeError::new(
                "release_consumption_result_invalid",
                "consume-and-retrieve service result is not the closed signed DTO",
            )
        })?;
    let exact_object = match &consumption {
        ReleaseConsumptionResultV2::Prepare(preparation) => {
            super::attestation::verify_release_preparation_receipt(
                config.custody_topology(),
                preparation,
            )?;
            if retrieve || !exact_object_fds.is_empty() {
                return Err(V2RuntimeError::new(
                    "release_preparation_exact_object_forbidden",
                    "PREPARE must not return an exact object or file descriptor",
                ));
            }
            None
        }
        ReleaseConsumptionResultV2::Retrieve(consumption) => {
            verify_release_consumption(
                config.custody_topology(),
                consumption,
            )?;
            if !retrieve || exact_object_fds.len() != 1 {
                return Err(V2RuntimeError::new(
                    "release_retrieval_exact_object_missing",
                    "RETRIEVE must return exactly one sealed exact object",
                ));
            }
            Some(validate_exact_service_object(
                &consumption.exact_object,
                exact_object_fds.remove(0),
            )?)
        }
    };
    Ok((consumption, exact_object))
}

pub(super) fn execute_state_mutation(
    config: &RootOwnedResponseObservationV2Config,
    request: &StateMutationExecutionRequestV1,
    expects_exact_object: bool,
) -> Result<
    (
        StateMutationExecutionResultV1,
        Option<super::ValidatedExactObject>,
    ),
    V2RuntimeError,
> {
    let (result, mut exact_object_fds) = invoke_service_wire(
        config,
        CustodyServiceRole::StateAuthority,
        ServiceOperationV1::StateCas,
        &request.request_id,
        request,
        request.deadline_boottime_ns,
        &[],
        expects_exact_object,
    )?;
    let execution: StateMutationExecutionResultV1 =
        serde_json::from_value(result.result).map_err(|_| {
            V2RuntimeError::new(
                "state_authority_execution_result_invalid",
                "state authority did not return the closed execution receipt",
            )
        })?;
    let exact = match (
        execution.exact_object.as_ref(),
        exact_object_fds.pop(),
    ) {
        (Some(descriptor), Some(fd)) => {
            Some(validate_exact_service_object(descriptor, fd)?)
        }
        (None, None) => None,
        _ => {
            return Err(V2RuntimeError::new(
                "state_authority_exact_object_mismatch",
                "state authority descriptor and sealed descriptor transfer disagree",
            ))
        }
    };
    Ok((execution, exact))
}

fn validate_exact_service_object(
    descriptor: &crate::response_observation_v2_api::
        ExactByteObjectDescriptor,
    fd: OwnedFd,
) -> Result<super::ValidatedExactObject, V2RuntimeError> {
    super::validate_exact_object_files(
        std::slice::from_ref(descriptor),
        vec![File::from(fd)],
        None,
    )?
    .into_single()
}

pub(crate) fn invoke_response_data_service(
    config: &RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
    operation: ServiceOperationV1,
    request: &crate::response_observation_v2_api::V2ResponseDataRequest,
    request_exact_objects: &[File],
    deadline_boottime_ns: u64,
) -> Result<
    (
        crate::response_observation_v2_api::V2ResponseDataResult,
        Vec<super::ValidatedExactObject>,
    ),
    V2RuntimeError,
> {
    let expects_exact_object = matches!(
        request,
        crate::response_observation_v2_api::
            V2ResponseDataRequest::ConsumeAndRetrieveExact {
                params:
                    crate::response_observation_v2_api::
                        V2ConsumeAndRetrieveExactParams::Retrieve {
                            ..
                        },
                ..
            }
    );
    let (result, exact_object_fds) = invoke_service_wire(
        config,
        role,
        operation,
        request.request_id(),
        request,
        deadline_boottime_ns,
        request_exact_objects,
        expects_exact_object,
    )?;
    let result:
        crate::response_observation_v2_api::V2ResponseDataResult =
        serde_json::from_value(result.result).map_err(|_| {
            V2RuntimeError::new(
                "response_data_service_result_invalid",
                "service result does not satisfy the canonical response-data DTO",
            )
        })?;
    if result.operation() != request.operation() {
        return Err(V2RuntimeError::new(
            "response_data_service_result_mismatch",
            "service response-data result does not bind the requested operation",
        ));
    }
    let descriptors =
        crate::response_observation_v2_api::
            response_data_result_exact_object_descriptors(&result);
    if descriptors.len() != exact_object_fds.len() {
        return Err(V2RuntimeError::new(
            "response_data_service_exact_object_mismatch",
            "response-data descriptor count does not match the service descriptor transfer",
        ));
    }
    let mut validated = Vec::with_capacity(descriptors.len());
    for (descriptor, fd) in
        descriptors.iter().zip(exact_object_fds)
    {
        validated.push(validate_exact_service_object(
            descriptor,
            fd,
        )?);
    }
    Ok((result, validated))
}

fn invoke_service_wire<P>(
    config: &RootOwnedResponseObservationV2Config,
    role: CustodyServiceRole,
    operation: ServiceOperationV1,
    request_id: &str,
    payload: &P,
    deadline_boottime_ns: u64,
    request_exact_objects: &[File],
    expects_exact_object: bool,
) -> Result<(ServiceRpcResultV1, Vec<OwnedFd>), V2RuntimeError>
where
    P: Serialize,
{
    let topology = config.custody_topology();
    let scoped = config.scoped_service_config(role)?;
    if !super::generation::selected_service_operations(config,role)
        .contains(&operation)
        || operation == super::protocol::ServiceOperationV1::Readiness
    {
        return Err(V2RuntimeError::new(
            "custody_service_operation_unassigned",
            "operation is not assigned to the selected custody service",
        ));
    }
    let readiness_record = common::read_readiness_record(
        &scoped.process.readiness_record_path,
    )?;
    common::verify_readiness_record(
        config,
        &scoped,
        &readiness_record,
    )?;
    let deadline = BootDeadline::new(deadline_boottime_ns)?;
    let mut connection = ServiceConnection::connect(
        &scoped.process.socket_path,
        deadline,
        scoped.process.max_frame_bytes,
    )?;
    let challenge_nonce = random_challenge_nonce()?;
    connection.send(&ServiceHelloV1 {
        api_version: SERVICE_RPC_API_VERSION.to_owned(),
        request_id: request_id.to_owned(),
        expected_service_role: role,
        generation_id: topology.generation_id.clone(),
        generation: topology.generation,
        topology_sha256: topology_sha256(topology)?,
        challenge_nonce: challenge_nonce.clone(),
        deadline_boottime_ns,
    })?;
    let hello: ServiceHelloResultV1 =
        connection.receive()?;
    if hello.request_id != request_id
        || hello.challenge_nonce != challenge_nonce
        || !hello.dependency_handshakes.is_empty()
    {
        return Err(V2RuntimeError::new(
            "custody_service_hello_mismatch",
            "service did not answer the exact reconnect challenge",
        ));
    }
    let live_handshake =
        hello.handshake.as_ref().ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_hello_handshake_missing",
                "service reconnect did not return a signed role handshake",
            )
        })?;
    let baseline = readiness_record
        .service_handshake
        .as_ref()
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_readiness_handshake_missing",
                "service readiness record has no handshake baseline",
            )
        })?;
    common::verify_live_handshake_against_record(
        config,
        baseline,
        live_handshake,
        request_id,
        &challenge_nonce,
    )?;
    let payload =
        serde_json::to_value(payload).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_payload_invalid",
                "service payload cannot be represented",
            )
        })?;
    let payload_bytes =
        crate::canonical_json_bytes(&payload).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_payload_invalid",
                "service payload cannot be canonicalized",
            )
        })?;
    let payload_sha256 =
        format!("sha256:{:x}", Sha256::digest(payload_bytes));
    let envelope = super::protocol::ServiceRpcEnvelopeV1 {
        api_version: SERVICE_RPC_API_VERSION.to_owned(),
        request_id: request_id.to_owned(),
        generation_id: topology.generation_id.clone(),
        generation: topology.generation,
        deadline_boottime_ns,
        operation,
        payload_sha256,
        payload,
    };
    if request_exact_objects.is_empty() {
        connection.send(&envelope)?;
    } else {
        if request_exact_objects.len() != 1 {
            return Err(V2RuntimeError::new(
                "custody_service_request_exact_object_count_invalid",
                "service request may carry only its one declared sealed input descriptor",
            ));
        }
        let raw_fds = request_exact_objects
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        connection.send_with_fds(&envelope, &raw_fds)?;
    }
    let (result, exact_object_fds):
        (ServiceRpcResultV1, Vec<OwnedFd>) =
        connection.receive_with_fds(1)?;
    if result.request_id != request_id
        || result.operation != operation
        || result.service_role != role
    {
        return Err(V2RuntimeError::new(
            "custody_service_result_mismatch",
            "service result does not bind the exact request, role, and operation",
        ));
    }
    verify_service_rpc_result(topology, &result)?;
    if (!result.succeeded && !exact_object_fds.is_empty())
        || (result.succeeded
            && expects_exact_object
            && exact_object_fds.len() != 1)
        || (result.succeeded
            && !expects_exact_object
            && !exact_object_fds.is_empty())
    {
        return Err(V2RuntimeError::new(
            "custody_service_exact_object_mismatch",
            "service descriptor count does not match the signed operation outcome",
        ));
    }
    if !result.succeeded {
        let error: super::protocol::SignedCustodyErrorV1 =
            serde_json::from_value(result.result).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_authenticated_error_invalid",
                    "service error does not satisfy the closed signed terminal DTO",
                )
            })?;
        verify_custody_error(topology, role, &error)?;
        return Err(V2RuntimeError::new(
            "custody_service_authenticated_error",
            format!(
                "{}; stableResumeId={}; terminalState={}; reconciliationId={}",
                error.error_code,
                error.stable_resume_id,
                error.terminal_state,
                error.reconciliation_id,
            ),
        ));
    }
    Ok((result, exact_object_fds))
}
