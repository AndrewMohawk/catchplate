use sha2::{Digest, Sha256};

use super::{
    AuthorityResultV1, StateAuthorityCommandV1,
};
use crate::response_observation_v2::custody::attestation::{
    verify_custody_error, verify_service_handshake, verify_service_rpc_result,
    verify_transition_authorization,
};
use crate::response_observation_v2::custody::config::{
    CustodyServiceRole, SignedCustodyTopologyV1,
};
use crate::response_observation_v2::custody::generation::topology_sha256;
use crate::response_observation_v2::custody::protocol::{
    ServiceHelloResultV1, ServiceHelloV1, ServiceOperationV1,
    ServiceRpcEnvelopeV1, ServiceRpcResultV1,
    SignedCustodyErrorV1,
    SignedTransitionAuthorizationV1,
    TransitionAuthorizationRequestV1,
    SERVICE_RPC_API_VERSION,
};
use crate::response_observation_v2::custody::recovery::{
    random_challenge_nonce, BootDeadline, ServiceConnection,
};
use crate::response_observation_v2::custody::V2RuntimeError;

pub(crate) struct StateAuthorityClient<'a> {
    topology: &'a SignedCustodyTopologyV1,
}

impl<'a> StateAuthorityClient<'a> {
    pub(crate) fn new(
        topology: &'a SignedCustodyTopologyV1,
    ) -> Self {
        Self { topology }
    }

    pub(crate) fn execute(
        &self,
        command: &StateAuthorityCommandV1,
    ) -> Result<AuthorityResultV1, V2RuntimeError> {
        let deadline = command_deadline(command)?;
        let process = self
            .topology
            .process(CustodyServiceRole::StateAuthority)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "state_authority_unconfigured",
                    "signed topology has no state-authority process",
                )
            })?;
        let mut connection = ServiceConnection::connect(
            &process.socket_path,
            deadline,
            process.max_frame_bytes,
        )?;
        let command_bytes =
            crate::canonical_json_bytes(command).map_err(|_| {
                V2RuntimeError::new(
                    "state_authority_command_invalid",
                    "state command cannot be canonicalized",
                )
            })?;
        let request_id =
            format!("sha256:{:x}", Sha256::digest(&command_bytes));
        let challenge_nonce = random_challenge_nonce()?;
        let hello = ServiceHelloV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            expected_service_role:
                CustodyServiceRole::StateAuthority,
            generation_id: self.topology.generation_id.clone(),
            generation: self.topology.generation,
            topology_sha256: topology_sha256(self.topology)?,
            challenge_nonce: challenge_nonce.clone(),
            deadline_boottime_ns: deadline.absolute_ns(),
        };
        connection.send(&hello)?;
        let hello_result: ServiceHelloResultV1 =
            connection.receive()?;
        if hello_result.api_version != SERVICE_RPC_API_VERSION
            || hello_result.request_id != request_id
            || hello_result.challenge_nonce != challenge_nonce
            || !hello_result.dependency_handshakes.is_empty()
        {
            return Err(V2RuntimeError::new(
                "state_authority_hello_mismatch",
                "state authority did not answer the exact reconnect challenge",
            ));
        }
        let signed_handshake =
            hello_result.handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "state_authority_handshake_missing",
                    "state authority returned no signed reconnect handshake",
                )
            })?;
        verify_service_handshake(
            self.topology,
            signed_handshake,
        )?;
        if signed_handshake.request_id != request_id
            || signed_handshake.challenge_nonce
                != challenge_nonce
        {
            return Err(V2RuntimeError::new(
                "state_authority_handshake_challenge_mismatch",
                "state authority handshake does not sign the exact reconnect challenge",
            ));
        }
        let payload = serde_json::to_value(command).map_err(|_| {
            V2RuntimeError::new(
                "state_authority_command_invalid",
                "state command cannot be represented as a closed service payload",
            )
        })?;
        let operation = command_operation(command);
        connection.send(&ServiceRpcEnvelopeV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            generation_id: self.topology.generation_id.clone(),
            generation: self.topology.generation,
            deadline_boottime_ns: deadline.absolute_ns(),
            operation,
            payload_sha256: request_id.clone(),
            payload,
        })?;
        let response: ServiceRpcResultV1 =
            connection.receive()?;
        if response.request_id != request_id
            || response.operation != operation
            || response.result_sha256
                != format!(
                    "sha256:{:x}",
                    Sha256::digest(
                        crate::canonical_json_bytes(&response.result)
                            .map_err(|_| {
                                V2RuntimeError::new(
                                    "state_authority_response_invalid",
                                    "state result cannot be canonicalized",
                                )
                            })?
                    )
                )
            || response.signer_logical_role
                != command_signer_role(command)
        {
            return Err(V2RuntimeError::new(
                "state_authority_response_mismatch",
                "state authority response is not bound to the exact canonical command",
            ));
        }
        verify_service_rpc_result(
            self.topology,
            &response,
        )?;
        if !response.succeeded {
            return authenticated_error(
                self.topology,
                response.result,
            );
        }
        let result: AuthorityResultV1 =
            serde_json::from_value(response.result).map_err(|_| {
            V2RuntimeError::new(
                "state_authority_response_invalid",
                "state result does not satisfy the closed authority result DTO",
            )
        })?;
        super::validate_authority_result(command, &result)?;
        Ok(result)
    }

    pub(crate) fn authorize_transition(
        &self,
        request: &TransitionAuthorizationRequestV1,
    ) -> Result<SignedTransitionAuthorizationV1, V2RuntimeError> {
        let deadline =
            BootDeadline::new(request.deadline_boottime_ns)?;
        let process = self
            .topology
            .process(CustodyServiceRole::StateAuthority)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "state_authority_unconfigured",
                    "signed topology has no state-authority process",
                )
            })?;
        let mut connection = ServiceConnection::connect(
            &process.socket_path,
            deadline,
            process.max_frame_bytes,
        )?;
        let request_bytes =
            crate::canonical_json_bytes(request).map_err(|_| {
                V2RuntimeError::new(
                    "transition_authorization_request_invalid",
                    "transition authorization request cannot be canonicalized",
                )
            })?;
        let request_id =
            format!("sha256:{:x}", Sha256::digest(&request_bytes));
        let challenge_nonce = random_challenge_nonce()?;
        connection.send(&ServiceHelloV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            expected_service_role:
                CustodyServiceRole::StateAuthority,
            generation_id: self.topology.generation_id.clone(),
            generation: self.topology.generation,
            topology_sha256: topology_sha256(self.topology)?,
            challenge_nonce: challenge_nonce.clone(),
            deadline_boottime_ns: deadline.absolute_ns(),
        })?;
        let hello: ServiceHelloResultV1 =
            connection.receive()?;
        if hello.request_id != request_id
            || hello.challenge_nonce != challenge_nonce
            || !hello.dependency_handshakes.is_empty()
        {
            return Err(V2RuntimeError::new(
                "transition_authority_hello_mismatch",
                "transition authority did not answer the exact reconnect challenge",
            ));
        }
        let signed_handshake =
            hello.handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "transition_authority_handshake_missing",
                    "transition authority returned no signed reconnect handshake",
                )
            })?;
        verify_service_handshake(self.topology, signed_handshake)?;
        if signed_handshake.request_id != request_id
            || signed_handshake.challenge_nonce
                != challenge_nonce
        {
            return Err(V2RuntimeError::new(
                "transition_authority_handshake_challenge_mismatch",
                "transition authority handshake does not sign the exact reconnect challenge",
            ));
        }
        let payload =
            serde_json::to_value(request).map_err(|_| {
                V2RuntimeError::new(
                    "transition_authorization_request_invalid",
                    "transition authorization request cannot be represented",
                )
            })?;
        connection.send(&ServiceRpcEnvelopeV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            generation_id: self.topology.generation_id.clone(),
            generation: self.topology.generation,
            deadline_boottime_ns: deadline.absolute_ns(),
            operation:
                ServiceOperationV1::TransitionAuthorize,
            payload_sha256: request_id.clone(),
            payload,
        })?;
        let result: ServiceRpcResultV1 =
            connection.receive()?;
        if result.request_id != request_id
            || result.operation
                != ServiceOperationV1::TransitionAuthorize
            || result.signer_logical_role != "linearizable-store"
        {
            return Err(V2RuntimeError::new(
                "transition_authorization_response_mismatch",
                "transition authority response is not bound to the exact request and role",
            ));
        }
        verify_service_rpc_result(self.topology, &result)?;
        if !result.succeeded {
            return authenticated_error(
                self.topology,
                result.result,
            );
        }
        let authorization:
            SignedTransitionAuthorizationV1 =
            serde_json::from_value(result.result).map_err(|_| {
                V2RuntimeError::new(
                    "transition_authorization_response_invalid",
                    "transition authority result is not the closed signed DTO",
                )
            })?;
        verify_transition_authorization(
            self.topology,
            &authorization,
        )?;
        if authorization.request_id != request.request_id
            || authorization.request_sha256
                != request.request_sha256
            || authorization.attempt_id != request.attempt_id
            || authorization.stable_resume_id
                != request.stable_resume_id
            || authorization.authorized_revision
                != request.expected_revision.saturating_add(1)
            || authorization.predecessor_state_sha256
                != request.expected_state_sha256
            || authorization.transition != request.transition
            || authorization.transition_input_sha256
                != request.transition_input_sha256
            || authorization.policy_decision_sha256
                != request.policy_decision_sha256
            || authorization.fencing_token
                != request.fencing_token
        {
            return Err(V2RuntimeError::new(
                "transition_authorization_binding_mismatch",
                "signed transition authorization does not bind the exact CAS predecessor, transition, input, and fence",
            ));
        }
        Ok(authorization)
    }
}

fn authenticated_error<T>(
    topology: &SignedCustodyTopologyV1,
    value: serde_json::Value,
) -> Result<T, V2RuntimeError> {
    let error: SignedCustodyErrorV1 =
        serde_json::from_value(value).map_err(|_| {
            V2RuntimeError::new(
                "state_authority_authenticated_error_invalid",
                "state authority error is not the closed signed terminal DTO",
            )
        })?;
    verify_custody_error(
        topology,
        CustodyServiceRole::StateAuthority,
        &error,
    )?;
    Err(V2RuntimeError::new(
        "state_authority_authenticated_error",
        format!(
            "{}; stableResumeId={}; terminalState={}; reconciliationId={}",
            error.error_code,
            error.stable_resume_id,
            error.terminal_state,
            error.reconciliation_id,
        ),
    ))
}

fn command_operation(
    command: &StateAuthorityCommandV1,
) -> ServiceOperationV1 {
    match command {
        StateAuthorityCommandV1::Mutate(_)
        | StateAuthorityCommandV1::Query { .. } => {
            ServiceOperationV1::StateCas
        }
        StateAuthorityCommandV1::AllocateFence(_) => {
            ServiceOperationV1::FenceAllocate
        }
        StateAuthorityCommandV1::RevokeFence(_) => {
            ServiceOperationV1::FenceRevoke
        }
        StateAuthorityCommandV1::ObserveQuiescence(_) => {
            ServiceOperationV1::QuiescenceObserve
        }
        StateAuthorityCommandV1::ResolveReplay { .. } => {
            ServiceOperationV1::ReplayResolve
        }
        StateAuthorityCommandV1::Reconcile { .. } => {
            ServiceOperationV1::Reconcile
        }
    }
}

fn command_signer_role(
    command: &StateAuthorityCommandV1,
) -> &'static str {
    match command {
        StateAuthorityCommandV1::ConsumeRelease(_) => {
            "public-release-consumption"
        }
        StateAuthorityCommandV1::ResolveReplay { .. } => {
            "outcome-reconciliation"
        }
        StateAuthorityCommandV1::RevokeFence(_)
        | StateAuthorityCommandV1::ObserveQuiescence(_) => {
            "emergency-fence-revoker"
        }
        _ => "linearizable-store",
    }
}

fn command_deadline(
    command: &StateAuthorityCommandV1,
) -> Result<BootDeadline, V2RuntimeError> {
    let deadline = match command {
        StateAuthorityCommandV1::Mutate(value) => &value.deadline,
        StateAuthorityCommandV1::Query { deadline, .. }
        | StateAuthorityCommandV1::ResolveReplay {
            deadline,
            ..
        }
        | StateAuthorityCommandV1::Reconcile {
            deadline,
            ..
        } => deadline,
        StateAuthorityCommandV1::AllocateFence(value) => &value.deadline,
        StateAuthorityCommandV1::RevokeFence(value) => &value.deadline,
        StateAuthorityCommandV1::ObserveQuiescence(value) => {
            &value.deadline
        }
        StateAuthorityCommandV1::ConsumeRelease(value) => {
            &value.deadline
        }
    };
    if deadline.api_version
            != crate::response_observation_v2_api::V2_MONOTONIC_DEADLINE_VERSION
        || deadline.clock_id
            != crate::response_observation_v2_api::V2MonotonicClockId::ClockBoottime
    {
        return Err(V2RuntimeError::new(
            "state_authority_deadline_invalid",
            "state command must carry the original CLOCK_BOOTTIME deadline",
        ));
    }
    let absolute_ns = deadline
        .absolute_boottime_ns
        .parse::<u64>()
        .map_err(|_| {
            V2RuntimeError::new(
                "state_authority_deadline_invalid",
                "state command deadline is not canonical u64 nanoseconds",
            )
        })?;
    BootDeadline::new(absolute_ns)
}
