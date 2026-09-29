use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{
    FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::attestation::{
    expected_operation_signer, sign_service_handshake,
    verify_final_envelope_verification,
    verify_immutable_raw_inspection, verify_release_authorization,
    verify_release_metadata, verify_service_handshake, RoleSigningKey,
    CUSTODY_ATTESTATION_SIGNATURE_DOMAIN,
    CUSTODY_ERROR_SIGNATURE_DOMAIN,
    CUSTODY_RECOVERY_SIGNATURE_DOMAIN,
    FINAL_ENVELOPE_SIGNATURE_DOMAIN,
    IMMUTABLE_RAW_INSPECTION_SIGNATURE_DOMAIN,
    RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
    RELEASE_CONSUMPTION_SIGNATURE_DOMAIN,
    RELEASE_METADATA_SIGNATURE_DOMAIN,
    PUBLICATION_SIGNATURE_DOMAIN, SETTLEMENT_SIGNATURE_DOMAIN,
    SERVICE_RESULT_SIGNATURE_DOMAIN,
    STATE_MUTATION_RECEIPT_SIGNATURE_DOMAIN,
    TRANSITION_AUTHORIZATION_SIGNATURE_DOMAIN,
};
use super::super::config::{
    CustodyServiceRole, ScopedCustodyServiceConfig,
    SignedCustodyTopologyV1,
};
use super::super::generation::{
    logical_role_key_root_sha256, required_service_operations,
    role_identity_root_sha256, topology_sha256,
};
use super::super::protocol::{
    CommitReleaseMetadataRequestV1,
    ConsumeReleaseAndRetrieveExactRequestV1,
    CustodyAttestationRequestV1, CustodyReadinessRecordV1,
    CustodyRecoveryRequestV1, InspectImmutableRawRequestV1,
    PublishRequestV1, ReleaseAuthorizationRequestV2,
    ServiceHelloResultV1, ServiceHelloV1,
    SettlementRequestV1,
    ServiceOperationV1, ServiceRpcEnvelopeV1, ServiceRpcResultV1,
    FinalEnvelopeVerificationRequestV1,
    ProviderAuthorityScopeV2,
    SignedCustodyAttestationV1, SignedCustodyRecoveryV1,
    SignedCustodyErrorV1,
    SignedDurableTerminalReceiptV1,
    SignedFinalEnvelopeVerificationV1,
    SignedImmutableRawInspectionV1, SignedReleaseAuthorizationV2,
    SignedPublicationReceiptV1, SignedReleaseConsumptionV2,
    SignedReleaseMetadataV1,
    SignedServiceHandshakeV1,
    SignedTransitionAuthorizationV1,
    TransitionAuthorizationRequestV1,
    READINESS_RECORD_API_VERSION,
    SERVICE_HANDSHAKE_API_VERSION, SERVICE_RPC_API_VERSION,
};
use super::super::recovery::{
    boottime_ns, random_challenge_nonce, BootDeadline,
    ServiceConnection,
};
use super::super::{
    RootOwnedResponseObservationV2Config, V2RuntimeError,
};

const BACKEND_READINESS_API_VERSION: &str =
    "serverware.responseObservationV2ServiceBackendReadiness/v1";
const SOCKET_MODE: u32 = 0o660;
const READINESS_MODE: u32 = 0o640;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackendReadinessV1 {
    api_version: String,
    service_role: CustodyServiceRole,
    generation_id: String,
    generation: u64,
    executable_sha256: String,
    configuration_sha256: String,
    implemented_operations: Vec<ServiceOperationV1>,
    reconciliation_high_water: u64,
    reconciliation_state_sha256: String,
    ready_after_reconciliation: bool,
    challenge_nonce: String,
}

pub(crate) struct ServiceRuntime {
    config: RootOwnedResponseObservationV2Config,
    topology: SignedCustodyTopologyV1,
    scoped: ScopedCustodyServiceConfig,
    signing_keys: BTreeMap<String, RoleSigningKey>,
    handshake: SignedServiceHandshakeV1,
    readiness_record: CustodyReadinessRecordV1,
}

impl ServiceRuntime {
    pub(crate) fn prepare(
        config: &RootOwnedResponseObservationV2Config,
        role: CustodyServiceRole,
    ) -> Result<Self, V2RuntimeError> {
        let topology = config.custody_topology().clone();
        let scoped = config.scoped_service_config(role)?;
        validate_service_process_identity(&scoped)?;
        validate_service_state_directory(&scoped)?;
        super::super::guest_delivery::check(config)?;
        let signing_keys = load_scoped_signing_keys(config, &scoped)?;
        let readiness =
            in_process_engine_readiness(config, &topology, &scoped)?;
        let signer_role = readiness_signer_role(role).ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_readiness_signer_missing",
                "non-router service has no readiness signing role",
            )
        })?;
        let signer = signing_keys.get(signer_role).ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_readiness_key_missing",
                "service did not load its assigned readiness subkey",
            )
        })?;
        let now = system_time_epoch_ms()?;
        let topology_digest = topology_sha256(&topology)?;
        let mut handshake = SignedServiceHandshakeV1 {
            api_version:
                SERVICE_HANDSHAKE_API_VERSION.to_owned(),
            request_id: format!(
                "readiness-record:{}",
                role.as_str()
            ),
            challenge_nonce: topology_digest.clone(),
            service_role: role,
            service_id: scoped.process.service_id.clone(),
            generation_id: scoped.generation_id.clone(),
            generation: scoped.generation,
            fault_domain_id:
                topology.fault_domain_id.clone(),
            quorum_mode: topology.quorum_mode.clone(),
            fault_domain_count: topology.fault_domain_count,
            external_witness_count:
                topology.external_witness_count,
            hardware_proof: topology.hardware_proof,
            executable_sha256:
                scoped.process.executable_sha256.clone(),
            configuration_sha256:
                scoped.process.configuration_sha256.clone(),
            logical_role_key_root_sha256:
                logical_role_key_root_sha256(&topology, role),
            implemented_operations:
                readiness.implemented_operations.clone(),
            reconciliation_high_water:
                readiness.reconciliation_high_water,
            reconciliation_state_sha256:
                readiness.reconciliation_state_sha256.clone(),
            ready_after_reconciliation:
                readiness.ready_after_reconciliation,
            issued_at_epoch_ms: now,
            expires_at_epoch_ms: MAX_SAFE_INTEGER,
            signer_logical_role: String::new(),
            signer_key_id: String::new(),
            signature: String::new(),
        };
        sign_service_handshake(signer, &mut handshake)?;
        verify_service_handshake(&topology, &handshake)?;
        let readiness_record = CustodyReadinessRecordV1 {
            api_version: READINESS_RECORD_API_VERSION.to_owned(),
            service_role: role,
            service_id: scoped.process.service_id.clone(),
            generation_id: scoped.generation_id.clone(),
            generation: scoped.generation,
            topology_sha256: topology_digest,
            service_handshake: Some(handshake.clone()),
            dependency_handshakes: BTreeMap::new(),
            reconciliation_complete: true,
            reconciliation_high_water:
                readiness.reconciliation_high_water,
            reconciliation_state_sha256:
                readiness.reconciliation_state_sha256,
            socket_identity_sha256:
                pending_socket_identity_sha256(
                    &scoped.process.socket_path,
                ),
            transaction_socket_identity_sha256: None,
            published_at_epoch_ms: now,
        };
        Ok(Self {
            config: config.clone(),
            topology,
            scoped,
            signing_keys,
            handshake,
            readiness_record,
        })
    }

    pub(crate) fn run(mut self) -> Result<(), V2RuntimeError> {
        super::super::guest_delivery::check(&self.config)?;
        let _lease = acquire_service_lease(&self.scoped)?;
        let listener = bind_service_socket(
            &self.scoped.process.socket_path,
            self.scoped.process.gid,
        )?;
        self.readiness_record.socket_identity_sha256 =
            socket_identity_sha256(
                &self.scoped.process.socket_path,
            )?;
        publish_readiness_record(
            &self.scoped.process.readiness_record_path,
            self.scoped.process.uid,
            self.scoped.process.gid,
            &self.readiness_record,
        )?;
        for accepted in listener.incoming() {
            let stream = accepted.map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_accept_failed",
                    "accept service connection",
                )
            })?;
            if let Err(error) = self.handle_connection(stream) {
                if error.suppress_response {
                    continue;
                }
            }
        }
        Err(V2RuntimeError::new(
            "custody_service_listener_stopped",
            "service listener terminated",
        ))
    }

    fn handle_connection(
        &self,
        stream: UnixStream,
    ) -> Result<(), V2RuntimeError> {
        super::super::guest_delivery::check(&self.config)?;
        authenticate_peer(&stream, &self.topology)?;
        let handshake_deadline = BootDeadline::new(
            super::super::guest_delivery::bound_deadline_ns(&self.config, boottime_ns()?
                .checked_add(
                    self.scoped.process.request_timeout_ms
                        * 1_000_000,
                )
                .ok_or_else(|| {
                    V2RuntimeError::new(
                        "custody_service_deadline_overflow",
                        "service handshake deadline overflowed",
                    )
                })?)?,
        )?;
        let mut connection = ServiceConnection::from_accepted(
            stream,
            handshake_deadline,
            self.scoped.process.max_frame_bytes,
        )?;
        let hello: ServiceHelloV1 = connection.receive()?;
        validate_hello(
            &self.topology,
            self.scoped.role,
            &hello,
            handshake_deadline.absolute_ns(),
        )?;
        let live_handshake =
            self.sign_live_handshake(&hello)?;
        connection.send(&ServiceHelloResultV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: hello.request_id.clone(),
            challenge_nonce: hello.challenge_nonce.clone(),
            handshake: Some(live_handshake),
            dependency_handshakes: BTreeMap::new(),
        })?;
        if self.scoped.role == CustodyServiceRole::CustodyRouter {
            return Ok(());
        }
        let stream = connection.into_stream();
        let request_deadline =
            BootDeadline::new(hello.deadline_boottime_ns)?;
        let mut connection = ServiceConnection::from_accepted(
            stream,
            request_deadline,
            self.scoped.process.max_frame_bytes,
        )?;
        let (request, request_exact_object_fds):
            (ServiceRpcEnvelopeV1, Vec<std::os::fd::OwnedFd>) =
            connection.receive_with_fds(1)?;
        validate_service_request(
            &self.topology,
            &self.scoped,
            &request,
            hello.deadline_boottime_ns,
        )?;
        validate_nested_authority_request(
            &self.topology,
            &request,
        )?;
        if (!request_exact_object_fds.is_empty()
            && request.operation
                != ServiceOperationV1::FinalEnvelopeVerify)
            || request_exact_object_fds.len() > 1
        {
            return Err(V2RuntimeError::new(
                "custody_service_request_exact_object_invalid",
                "only final-envelope verification may receive its one declared proof-document descriptor",
            ));
        }
        let signer_role = expected_operation_signer(
            self.scoped.role,
            request.operation,
        )
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_operation_signer_missing",
                "service operation has no assigned logical signer",
            )
        })?;
        let signer =
            self.signing_keys.get(signer_role).ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_service_operation_key_missing",
                    "service did not load the exact operation subkey",
                )
            })?;
        let engine = super::engine::execute(
            &self.config,
            &self.scoped,
            &request,
            &self.signing_keys,
            request_exact_object_fds,
        )?;
        let exact_object_fds = engine.exact_object_fds;
        let signed_result = sign_nested_authority_result(
            &self.topology,
            request.operation,
            &request.payload,
            engine.result,
            signer,
        )?;
        let signed_result_bytes =
            crate::canonical_json_bytes(&signed_result).map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_result_invalid",
                    "signed nested authority result cannot be canonicalized",
                )
            })?;
        let mut result = ServiceRpcResultV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: request.request_id,
            generation_id: self.scoped.generation_id.clone(),
            generation: self.scoped.generation,
            service_role: self.scoped.role,
            operation: request.operation,
            succeeded: true,
            result_sha256: format!(
                "sha256:{:x}",
                Sha256::digest(signed_result_bytes)
            ),
            result: signed_result,
            signer_logical_role: signer.logical_role().to_owned(),
            signer_key_id: signer.key_id().to_owned(),
            signature: String::new(),
        };
        result.signature = signer.sign(
            SERVICE_RESULT_SIGNATURE_DOMAIN,
            &result.without_signature(),
        )?;
        if exact_object_fds.is_empty() {
            connection.send(&result)
        } else {
            connection.send_with_fds(
                &result,
                &[exact_object_fds[0].as_raw_fd()],
            )
        }
    }

    fn sign_live_handshake(
        &self,
        hello: &ServiceHelloV1,
    ) -> Result<SignedServiceHandshakeV1, V2RuntimeError> {
        super::super::guest_delivery::check(&self.config)?;
        let signer_role =
            readiness_signer_role(self.scoped.role).ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_service_readiness_signer_missing",
                    "service has no readiness signing role",
                )
            })?;
        let signer =
            self.signing_keys.get(signer_role).ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_service_readiness_key_missing",
                    "service did not load its readiness subkey",
                )
            })?;
        let mut handshake = self.handshake.clone();
        handshake.request_id = hello.request_id.clone();
        handshake.challenge_nonce =
            hello.challenge_nonce.clone();
        sign_service_handshake(signer, &mut handshake)?;
        verify_service_handshake(&self.topology, &handshake)?;
        Ok(handshake)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StableRequestBindingV1 {
    request_id: String,
    operation_id: String,
    request_sha256: String,
    attempt_id: String,
    attempt_revision: u64,
    stable_resume_id: String,
    fencing_token: u64,
}

pub(super) fn provider_authority_scope(
    topology: &SignedCustodyTopologyV1,
    service_role: CustodyServiceRole,
    signer: &RoleSigningKey,
    operation: ServiceOperationV1,
    operation_id: &str,
    attempt_id: &str,
    attempt_revision: u64,
    fencing_token: u64,
) -> Result<ProviderAuthorityScopeV2, V2RuntimeError> {
    let process = topology.process(service_role).ok_or_else(|| {
        V2RuntimeError::new(
            "custody_authority_scope_process_missing",
            "authority scope service is absent from the signed topology",
        )
    })?;
    let binding = topology
        .logical_role(signer.logical_role())
        .filter(|binding| {
            binding.service_role == service_role
                && binding.key_id == signer.key_id()
        })
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_authority_scope_key_missing",
                "authority scope signer is not assigned to the service",
            )
        })?;
    if operation_id.is_empty()
        || attempt_id.is_empty()
        || attempt_revision == 0
        || fencing_token == 0
    {
        return Err(V2RuntimeError::new(
            "custody_authority_scope_context_invalid",
            "authority scope requires operation, attempt, revision, and state-allocated fence bindings",
        ));
    }
    let mut scope = ProviderAuthorityScopeV2 {
        api_version:
            super::super::protocol::AUTHORITY_SCOPE_API_VERSION
                .to_owned(),
        generation_id: topology.generation_id.clone(),
        generation: topology.generation,
        service_role,
        service_id: process.service_id.clone(),
        logical_role: binding.logical_role.clone(),
        role_identity_root_sha256:
            role_identity_root_sha256(topology),
        key_id: binding.key_id.clone(),
        key_material_sha256: binding.public_key_sha256.clone(),
        operation,
        operation_id: operation_id.to_owned(),
        attempt_id: attempt_id.to_owned(),
        attempt_revision,
        fencing_token,
        executable_sha256: process.executable_sha256.clone(),
        configuration_sha256:
            process.configuration_sha256.clone(),
        allowed_operations: required_service_operations(service_role)
            .into_iter()
            .collect(),
        operation_binding_sha256: String::new(),
    };
    scope.operation_binding_sha256 =
        canonical_sha256(&scope.without_binding_digest())?;
    Ok(scope)
}

fn stable_resume_matches(
    topology: &SignedCustodyTopologyV1,
    request_sha256: &str,
    attempt_id: &str,
    stable_resume_id: &str,
) -> bool {
    stable_resume_id
        == super::super::protocol::stable_resume_id_sha256(
            &topology.generation_id,
            topology.generation,
            request_sha256,
            attempt_id,
    )
}

fn stable_request_binding(
    operation: ServiceOperationV1,
    request: &serde_json::Value,
) -> Result<StableRequestBindingV1, V2RuntimeError> {
    if operation == ServiceOperationV1::FinalEnvelopeVerify {
        let request: FinalEnvelopeVerificationRequestV1 =
            serde_json::from_value(request.clone()).map_err(|_| {
                V2RuntimeError::new(
                    "custody_error_request_binding_missing",
                    "final-envelope error requires the closed verification request",
                )
            })?;
        return Ok(StableRequestBindingV1 {
            request_id: request.envelope.request_id,
            operation_id: request.operation_id,
            request_sha256: request.envelope.request_sha256,
            attempt_id: request.envelope.attempt_id,
            attempt_revision: request.envelope.terminal_revision,
            stable_resume_id:
                request.envelope.stable_resume_id,
            fencing_token: request.envelope.fencing_token,
        });
    }
    serde_json::from_value(request.clone()).map_err(|_| {
        V2RuntimeError::new(
            "custody_error_request_binding_missing",
            "an authenticated error requires request, attempt, and stable resume bindings",
        )
    })
}

fn validate_nested_authority_request(
    topology: &SignedCustodyTopologyV1,
    envelope: &ServiceRpcEnvelopeV1,
) -> Result<(), V2RuntimeError> {
    if envelope.operation == ServiceOperationV1::AuthorizeRelease {
        if let Ok(request) = serde_json::from_value::<
            super::super::protocol::
                ReleaseConsumptionPreauthorizationArtifactRequestV1,
        >(envelope.payload.clone())
        {
            if request.api_version
                    != super::super::protocol::
                        RELEASE_CONSUMPTION_PREAUTHORIZATION_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || request.attempt_revision == 0
                || request.fencing_token == 0
                || request.mutation_binding.expected_state
                    != "OBSERVED"
                || request.mutation_binding.successor_state
                    != "RELEASE_PREPARED"
                || request.mutation_binding.expected_revision
                    != request.attempt_revision
                || request.mutation_binding.successor_revision
                    != request.attempt_revision.saturating_add(1)
                || request.release_object.content_sha256.0
                    != request
                        .mutation_binding
                        .release_object_sha256
            {
                return Err(V2RuntimeError::new(
                    "release_preauthorization_request_invalid",
                    "preauthorization artifact request is not bound to one exact OBSERVED to RELEASE_PREPARED transition",
                ));
            }
            return Ok(());
        }
    }
    match envelope.operation {
        ServiceOperationV1::TransitionAuthorize => {
            let request: TransitionAuthorizationRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "transition_authorization_request_invalid",
                            "transition authorization payload is not the closed state DTO",
                        )
                    })?;
            if request.api_version
                    != super::super::protocol::
                        TRANSITION_AUTHORIZATION_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || request.fencing_token == 0
                || !is_sha256(&request.expected_state_sha256)
                || !is_sha256(&request.transition_input_sha256)
            {
                return Err(V2RuntimeError::new(
                    "transition_authorization_prerequisite_mismatch",
                    "transition authorization is not bound to the generation, stable resume ID, CAS predecessor, transition input, and state-allocated fence",
                ));
            }
        }
        ServiceOperationV1::FinalEnvelopeVerify => {
            let request: FinalEnvelopeVerificationRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "final_envelope_verification_request_invalid",
                            "final-envelope verification payload is not the closed policy DTO",
                        )
                    })?;
            if request.api_version
                    != super::super::protocol::
                        FINAL_ENVELOPE_VERIFICATION_API_VERSION
                || request.envelope.generation_id
                    != topology.generation_id
                || request.envelope.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.envelope.request_sha256,
                    &request.envelope.attempt_id,
                    &request.envelope.stable_resume_id,
                )
                || !request.transition_authorizations.is_empty()
                || !is_sha256(
                    &request.canonical_envelope_bytes_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "final_envelope_verification_prerequisite_mismatch",
                    "final verification accepts only the canonical generation-bound envelope and reconstructs authority transitions independently",
                ));
            }
        }
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact => {
            let request:
                ConsumeReleaseAndRetrieveExactRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "release_consumption_request_invalid",
                            "consume-and-retrieve payload is not the closed two-phase release DTO",
                        )
                    })?;
            match &request {
                ConsumeReleaseAndRetrieveExactRequestV1::Prepare(
                    request,
                ) => {
                    verify_immutable_raw_inspection(
                        topology,
                        &request.inspection,
                    )?;
                    verify_release_authorization(
                        topology,
                        &request.release_authorization,
                    )?;
                    if request.generation_id
                            != topology.generation_id
                        || request.generation != topology.generation
                        || request.attempt_id
                            != request.inspection.attempt_id
                        || request.stable_resume_id
                            != request.inspection.stable_resume_id
                        || request.fencing_token
                            != request
                                .release_authorization
                                .fencing_token
                        || request.exact_replay_key_sha256
                            != request
                                .release_authorization
                                .exact_replay_key_sha256
                    {
                        return Err(V2RuntimeError::new(
                            "release_preparation_prerequisite_mismatch",
                            "PREPARE does not bind one inspection, authorization, replay key, state revision, and fence",
                        ));
                    }
                }
                ConsumeReleaseAndRetrieveExactRequestV1::Retrieve(
                    request,
                ) => {
                    verify_immutable_raw_inspection(
                        topology,
                        &request.inspection,
                    )?;
                    verify_release_authorization(
                        topology,
                        &request.release_authorization,
                    )?;
                    verify_final_envelope_verification(
                        topology,
                        &request.final_envelope_verification,
                    )?;
                    super::super::attestation::
                        verify_release_preparation_receipt(
                            topology,
                            &request.prepared_consumption,
                        )?;
                    if request.generation_id
                            != topology.generation_id
                        || request.generation != topology.generation
                        || request.attempt_id
                            != request
                                .prepared_consumption
                                .attempt_id
                        || request.fencing_token
                            != request
                                .prepared_consumption
                                .fencing_token
                        || request.exact_replay_key_sha256
                            != request
                                .prepared_consumption
                                .exact_replay_key_sha256
                    {
                        return Err(V2RuntimeError::new(
                            "release_retrieval_prerequisite_mismatch",
                            "RETRIEVE does not bind the prepared receipt, final verification, replay key, and fence",
                        ));
                    }
                }
            }
        }
        ServiceOperationV1::AuthorizeRelease => {
            let request: ReleaseAuthorizationRequestV2 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "release_authorization_request_invalid",
                            "release authorization payload is not the closed two-phase DTO",
                        )
                    })?;
            verify_immutable_raw_inspection(
                topology,
                &request.inspection,
            )?;
            request.inspection.authority_proof_seed.validate_integrity()?;
            if request.api_version
                    != super::super::protocol::
                        RELEASE_AUTHORIZATION_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || request.request_id
                    != request.inspection.request_id
                || request.request_sha256
                    != request.inspection.request_sha256
                || request.attempt_id
                    != request.inspection.attempt_id
                || request.stable_resume_id
                    != request.inspection.stable_resume_id
                || request.fencing_token == 0
                || !is_sha256(&request.policy_decision_sha256)
                || !is_sha256(&request.exact_replay_key_sha256)
            {
                return Err(V2RuntimeError::new(
                    "release_authorization_prerequisite_mismatch",
                    "release authorization requires one signed nine-artifact inspection seed for the same stable attempt",
                ));
            }
        }
        ServiceOperationV1::Attest => {
            let request: CustodyAttestationRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "custody_attestation_request_invalid",
                            "attestation payload is not the closed custody DTO",
                        )
                    })?;
            verify_final_envelope_verification(
                topology,
                &request.final_envelope_verification,
            )?;
            if request.api_version
                    != super::super::protocol::
                        CUSTODY_ATTESTATION_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || request.request_id
                    != request.final_envelope_verification.request_id
                || request.attempt_id
                    != request.final_envelope_verification.attempt_id
                || !is_sha256(&request.request_sha256)
                || !is_sha256(&request.stable_resume_id)
            {
                return Err(V2RuntimeError::new(
                    "custody_attestation_prerequisite_mismatch",
                    "attestation requires the independently verified final envelope for the same stable attempt",
                ));
            }
        }
        ServiceOperationV1::CommitReleaseMetadata => {
            let request: CommitReleaseMetadataRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "release_metadata_request_invalid",
                            "release metadata payload is not the closed pre-commit DTO",
                        )
                    })?;
            if request.api_version
                    != super::super::protocol::
                        RELEASE_METADATA_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || !is_sha256(&request.request_sha256)
                || !is_sha256(&request.stable_resume_id)
                || !is_sha256(&request.raw_object_sha256)
                || request.raw_object_byte_length == 0
                || request.expected_attempt_revision == 0
                || request.fencing_token == 0
            {
                return Err(V2RuntimeError::new(
                    "release_metadata_prerequisite_mismatch",
                    "release metadata must bind the stable resume and attempt IDs, state fence, and exact raw-object commitment before object commit",
                ));
            }
        }
        ServiceOperationV1::InspectImmutableRaw => {
            let request: InspectImmutableRawRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "immutable_raw_inspection_request_invalid",
                            "inspection payload is not the closed non-mutating DTO",
                        )
                    })?;
            if request.api_version
                    != super::super::protocol::
                        IMMUTABLE_RAW_INSPECTION_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || !is_sha256(&request.request_sha256)
                || !is_sha256(&request.stable_resume_id)
                || !is_sha256(&request.raw_object_sha256)
                || request.raw_object_byte_length == 0
            {
                return Err(V2RuntimeError::new(
                    "immutable_raw_inspection_prerequisite_mismatch",
                    "inspection request is not bound to an exact immutable raw object and stable attempt",
                ));
            }
        }
        ServiceOperationV1::Recover => {
            let request: CustodyRecoveryRequestV1 =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "custody_recovery_request_invalid",
                            "recovery payload is not the closed custody DTO",
                        )
                    })?;
            if request.api_version
                    != super::super::protocol::
                        CUSTODY_RECOVERY_API_VERSION
                || request.generation_id != topology.generation_id
                || request.generation != topology.generation
                || !stable_resume_matches(
                    topology,
                    &request.request_sha256,
                    &request.attempt_id,
                    &request.stable_resume_id,
                )
                || !is_sha256(&request.request_sha256)
                || !is_sha256(&request.stable_resume_id)
                || !is_sha256(
                    &request.expected_terminal_state_sha256,
                )
                || request.reconciliation_cursor == 0
            {
                return Err(V2RuntimeError::new(
                    "custody_recovery_prerequisite_mismatch",
                    "recovery request is not bound to the stable resume ID, expected terminal state, and reconciliation cursor",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn sign_backend_custody_error(
    topology: &SignedCustodyTopologyV1,
    operation: ServiceOperationV1,
    request: &serde_json::Value,
    result: serde_json::Value,
    signer: &RoleSigningKey,
) -> Result<serde_json::Value, V2RuntimeError> {
    let binding = stable_request_binding(operation, request)?;
    let mut error: SignedCustodyErrorV1 =
        serde_json::from_value(result).map_err(|_| {
            V2RuntimeError::new(
                "custody_error_result_invalid",
                "backend error is not the closed durably terminalized custody DTO",
            )
        })?;
    if error.api_version
            != super::super::protocol::CUSTODY_ERROR_API_VERSION
        || error.generation_id != topology.generation_id
        || error.generation != topology.generation
        || error.operation != operation
        || error.request_id != binding.request_id
        || error.request_sha256 != binding.request_sha256
        || error.attempt_id != binding.attempt_id
        || error.stable_resume_id != binding.stable_resume_id
        || !stable_resume_matches(
            topology,
            &binding.request_sha256,
            &binding.attempt_id,
            &binding.stable_resume_id,
        )
        || error.error_code.is_empty()
        || error.error_code.len() > 128
        || !error
            .error_code
            .bytes()
            .all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'_'
            })
        || !error.durable_terminalized
        || !matches!(
            error.terminal_state.as_str(),
            "FAILED" | "OUTCOME_UNKNOWN"
        )
        || !is_sha256(&error.terminal_state_sha256)
        || error.reconciliation_id.is_empty()
        || error.reconciliation_id.len() > 256
        || !is_sha256(&error.reconciliation_record_sha256)
        || error.authority_sequence == 0
        || !is_sha256(&error.canonical_error_sha256)
    {
        return Err(V2RuntimeError::new(
            "custody_error_not_terminalized",
            "custody refuses to authenticate an error unless the authority durably terminalized or reconciled the stable attempt",
        )
        .suppress_response());
    }
    error.authority_scope = provider_authority_scope(
        topology,
        topology
            .logical_role(signer.logical_role())
            .map(|binding| binding.service_role)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_error_signer_unmapped",
                    "custody error signer is absent from topology",
                )
            })?,
        signer,
        operation,
        &binding.operation_id,
        &binding.attempt_id,
        binding.attempt_revision,
        binding.fencing_token,
    )?;
    error.signer_logical_role =
        signer.logical_role().to_owned();
    error.signer_key_id = signer.key_id().to_owned();
    error.signature = signer.sign(
        CUSTODY_ERROR_SIGNATURE_DOMAIN,
        &error.without_signature(),
    )?;
    serde_json::to_value(error).map_err(|_| {
        V2RuntimeError::new(
            "custody_error_result_invalid",
            "signed custody error cannot be represented",
        )
    })
}

fn sign_nested_authority_result(
    topology: &SignedCustodyTopologyV1,
    operation: ServiceOperationV1,
    request: &serde_json::Value,
    result: serde_json::Value,
    signer: &RoleSigningKey,
) -> Result<serde_json::Value, V2RuntimeError> {
    if serde_json::from_value::<
        crate::response_observation_v2_api::V2ResponseDataRequest,
    >(request.clone())
    .is_ok()
    {
        let public = serde_json::from_value::<
            crate::response_observation_v2_api::V2ResponseDataResult,
        >(result.clone())
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_public_result_invalid",
                "response-data engine did not return its closed public result DTO",
            )
        })?;
        if public.operation()
            != crate::response_observation_v2_api::
                V2ResponseDataRequest::operation(
                    &serde_json::from_value(request.clone()).map_err(
                        |_| {
                            V2RuntimeError::new(
                                "response_data_public_request_invalid",
                                "response-data request cannot be decoded",
                            )
                        },
                    )?,
                )
        {
            return Err(V2RuntimeError::new(
                "response_data_public_result_mismatch",
                "response-data result operation differs from its request",
            ));
        }
        return Ok(result);
    }
    if operation == ServiceOperationV1::AuthorizeRelease
        && serde_json::from_value::<
            super::super::protocol::
                ReleaseConsumptionPreauthorizationArtifactRequestV1,
        >(request.clone())
        .is_ok()
    {
        let artifact = serde_json::from_value::<
            super::super::super::state_authority::rpc::
                SignedAuthorityArtifact,
        >(result.clone())
        .map_err(|_| {
            V2RuntimeError::new(
                "release_preauthorization_artifact_invalid",
                "release service did not return the closed signed authority artifact",
            )
        })?;
        artifact.validate_contract().map_err(|error| {
            V2RuntimeError::new(
                "release_preauthorization_artifact_invalid",
                error.to_string(),
            )
        })?;
        return Ok(result);
    }
    match operation {
        ServiceOperationV1::TransitionAuthorize => {
            let request:
                TransitionAuthorizationRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "transition_authorization_request_invalid",
                        "state service request is not the closed transition authorization DTO",
                    )
                })?;
            let mut authorization:
                SignedTransitionAuthorizationV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "transition_authorization_result_invalid",
                        "state backend did not return the closed transition authorization DTO",
                    )
                })?;
            if authorization.api_version
                    != super::super::protocol::
                        TRANSITION_AUTHORIZATION_API_VERSION
                || authorization.generation_id
                    != request.generation_id
                || authorization.generation != request.generation
                || authorization.operation
                    != ServiceOperationV1::TransitionAuthorize
                || authorization.request_id != request.request_id
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
                || authorization.authority_sequence == 0
                || !is_sha256(
                    &authorization.canonical_result_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "transition_authorization_backend_mismatch",
                    "state backend authorization is not bound to the exact CAS predecessor, request, policy, transition, and state-allocated fence",
                ));
            }
            authorization.signer_logical_role =
                signer.logical_role().to_owned();
            authorization.signer_key_id =
                signer.key_id().to_owned();
            authorization.signature = signer.sign(
                TRANSITION_AUTHORIZATION_SIGNATURE_DOMAIN,
                &authorization.without_signature(),
            )?;
            serde_json::to_value(authorization).map_err(|_| {
                V2RuntimeError::new(
                    "transition_authorization_result_invalid",
                    "signed transition authorization cannot be represented",
                )
            })
        }
        ServiceOperationV1::FinalEnvelopeVerify => {
            let request:
                FinalEnvelopeVerificationRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "final_envelope_verification_request_invalid",
                        "policy service request is not the closed final-envelope verification DTO",
                    )
                })?;
            let mut verification:
                SignedFinalEnvelopeVerificationV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "final_envelope_verification_result_invalid",
                        "policy backend did not return the closed final-envelope verification DTO",
                    )
                })?;
            if verification.api_version
                    != super::super::protocol::
                        FINAL_ENVELOPE_VERIFICATION_API_VERSION
                || verification.generation_id
                    != request.envelope.generation_id
                || verification.generation
                    != request.envelope.generation
                || verification.operation
                    != ServiceOperationV1::FinalEnvelopeVerify
                || verification.request_id
                    != request.envelope.request_id
                || verification.attempt_id
                    != request.envelope.attempt_id
                || verification.stable_resume_id
                    != request.envelope.stable_resume_id
                || verification.final_envelope_sha256
                    != request.envelope.final_envelope_sha256
                || verification.canonical_envelope_bytes_sha256
                    != request.canonical_envelope_bytes_sha256
                || verification.transition_chain_root_sha256
                    != request.envelope.transition_chain_root_sha256
                || !verification.verified
                || verification.verification_sequence == 0
                || !is_sha256(
                    &verification.verification_result_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "final_envelope_verification_backend_mismatch",
                    "policy backend verification is not bound to the only canonical final envelope, its exact bytes, and reconstructed transition root",
                ));
            }
            verification.authority_scope = provider_authority_scope(
                topology,
                CustodyServiceRole::PolicyProofVerifier,
                signer,
                ServiceOperationV1::FinalEnvelopeVerify,
                &request.operation_id,
                &request.envelope.attempt_id,
                request.envelope.terminal_revision,
                request.envelope.fencing_token,
            )?;
            verification.signer_logical_role =
                signer.logical_role().to_owned();
            verification.signer_key_id =
                signer.key_id().to_owned();
            verification.signature = signer.sign(
                FINAL_ENVELOPE_SIGNATURE_DOMAIN,
                &verification.without_signature(),
            )?;
            serde_json::to_value(verification).map_err(|_| {
                V2RuntimeError::new(
                    "final_envelope_verification_result_invalid",
                    "signed final-envelope verification cannot be represented",
                )
            })
        }
        ServiceOperationV1::CommitReleaseMetadata => {
            let request: CommitReleaseMetadataRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "release_metadata_request_invalid",
                        "state service request is not the closed release-metadata commitment DTO",
                    )
                })?;
            let mut metadata: SignedReleaseMetadataV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "release_metadata_result_invalid",
                        "state backend did not return the closed release-metadata DTO",
                    )
                })?;
            if request.api_version
                    != super::super::protocol::
                        RELEASE_METADATA_API_VERSION
                || metadata.api_version
                    != super::super::protocol::
                        RELEASE_METADATA_API_VERSION
                || metadata.generation_id != request.generation_id
                || metadata.generation != request.generation
                || metadata.operation
                    != ServiceOperationV1::CommitReleaseMetadata
                || metadata.request_id != request.request_id
                || metadata.request_sha256 != request.request_sha256
                || metadata.attempt_id != request.attempt_id
                || metadata.stable_resume_id
                    != request.stable_resume_id
                || metadata.raw_object_id != request.raw_object_id
                || metadata.raw_object_sha256
                    != request.raw_object_sha256
                || metadata.raw_object_byte_length
                    != request.raw_object_byte_length
                || !metadata.raw_target_bytes_unchanged
                || !metadata.metadata_is_separate_record
                || !metadata.committed_before_object
                || metadata.metadata_commit_sequence == 0
                || metadata.object_commit_sequence
                    <= metadata.metadata_commit_sequence
                || !is_sha256(&metadata.metadata_record_sha256)
            {
                return Err(V2RuntimeError::new(
                    "release_metadata_backend_mismatch",
                    "state backend did not durably bind the stable resume and attempt identifiers before reserving the immutable raw-object commit sequence",
                ));
            }
            metadata.signer_logical_role =
                signer.logical_role().to_owned();
            metadata.signer_key_id =
                signer.key_id().to_owned();
            metadata.signature = signer.sign(
                RELEASE_METADATA_SIGNATURE_DOMAIN,
                &metadata.without_signature(),
            )?;
            serde_json::to_value(metadata).map_err(|_| {
                V2RuntimeError::new(
                    "release_metadata_result_invalid",
                    "signed release metadata cannot be represented",
                )
            })
        }
        ServiceOperationV1::InspectImmutableRaw => {
            let request: InspectImmutableRawRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "immutable_raw_inspection_request_invalid",
                        "ledger request is not the closed immutable-raw inspection DTO",
                    )
                })?;
            let mut inspection: SignedImmutableRawInspectionV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "immutable_raw_inspection_result_invalid",
                        "ledger backend did not return the closed immutable-raw inspection DTO",
                    )
                })?;
            if request.api_version
                    != super::super::protocol::
                        IMMUTABLE_RAW_INSPECTION_API_VERSION
                || inspection.api_version
                    != super::super::protocol::
                        IMMUTABLE_RAW_INSPECTION_API_VERSION
                || inspection.generation_id
                    != request.generation_id
                || inspection.generation != request.generation
                || inspection.operation
                    != ServiceOperationV1::InspectImmutableRaw
                || inspection.request_id != request.request_id
                || inspection.request_sha256
                    != request.request_sha256
                || inspection.attempt_id != request.attempt_id
                || inspection.stable_resume_id
                    != request.stable_resume_id
                || inspection.raw_object_id
                    != request.raw_object_id
                || inspection.raw_object_sha256
                    != request.raw_object_sha256
                || inspection.raw_object_byte_length
                    != request.raw_object_byte_length
                || !inspection.immutable
                || inspection.consumed
                || inspection.inspection_sequence == 0
                || !is_sha256(
                    &inspection.inspection_receipt_sha256,
                )
                || inspection.exact_object.fd_index != 0
                || inspection.exact_object.media_type
                    != crate::response_observation_v2_api::
                        ExactObjectMediaType::Http11Response
                || inspection.exact_object.required_seals
                    != crate::response_observation_v2_api::
                        MemfdSealProfile::ImmutableV1
                || inspection.exact_object.object_id
                    != inspection.raw_object_id
                || inspection.exact_object.sha256
                    != inspection.raw_object_sha256
                || inspection.exact_object.byte_length
                    != inspection.raw_object_byte_length
            {
                return Err(V2RuntimeError::new(
                    "immutable_raw_inspection_backend_mismatch",
                    "ledger backend inspection is not a non-consuming exact-object view bound to the pre-commit release metadata",
                ));
            }
            inspection.authority_scope = provider_authority_scope(
                topology,
                CustodyServiceRole::ImmutableArtifactLedger,
                signer,
                ServiceOperationV1::InspectImmutableRaw,
                &request.operation_id,
                &request.attempt_id,
                inspection.inspection_sequence,
                request.fencing_token,
            )?;
            inspection.signer_logical_role =
                signer.logical_role().to_owned();
            inspection.signer_key_id =
                signer.key_id().to_owned();
            inspection.signature = signer.sign(
                IMMUTABLE_RAW_INSPECTION_SIGNATURE_DOMAIN,
                &inspection.without_signature(),
            )?;
            serde_json::to_value(inspection).map_err(|_| {
                V2RuntimeError::new(
                    "immutable_raw_inspection_result_invalid",
                    "signed immutable-raw inspection cannot be represented",
                )
            })
        }
        ServiceOperationV1::AuthorizeRelease => {
            let request: ReleaseAuthorizationRequestV2 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "release_authorization_request_invalid",
                        "release service request is not the closed authorization DTO",
                    )
                })?;
            verify_immutable_raw_inspection(
                topology,
                &request.inspection,
            )?;
            request.inspection.authority_proof_seed.validate_integrity()?;
            let mut authorization:
                SignedReleaseAuthorizationV2 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "release_authorization_result_invalid",
                        "release backend did not return the closed authorization DTO",
                    )
                })?;
            if request.api_version
                    != super::super::protocol::
                        RELEASE_AUTHORIZATION_API_VERSION
                || authorization.api_version
                    != super::super::protocol::
                        RELEASE_AUTHORIZATION_API_VERSION
                || authorization.generation_id
                    != request.generation_id
                || authorization.generation != request.generation
                || authorization.operation
                    != ServiceOperationV1::AuthorizeRelease
                || authorization.request_id != request.request_id
                || authorization.request_sha256
                    != request.request_sha256
                || authorization.attempt_id != request.attempt_id
                || authorization.stable_resume_id
                    != request.stable_resume_id
                || authorization.fencing_token
                    != request.fencing_token
                || authorization.inspection_receipt_sha256
                    != request.inspection.inspection_receipt_sha256
                || authorization.authority_proof_seed_sha256
                    != request
                        .inspection
                        .authority_proof_seed
                        .seed_sha256
                || authorization
                    .authority_proof_seed_artifacts_root_sha256
                    != request
                        .inspection
                        .authority_proof_seed
                        .authority_artifacts_root_sha256
                || authorization.raw_object_sha256
                    != request.inspection.raw_object_sha256
                || authorization.policy_decision_sha256
                    != request.policy_decision_sha256
                || authorization.exact_replay_key_sha256
                    != request.exact_replay_key_sha256
                || authorization.expires_at_epoch_ms
                    != request.expires_at_epoch_ms
                || !is_sha256(
                    &authorization.authorization_result_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "release_authorization_backend_mismatch",
                    "release authorization is not bound to the inspected object, signed nine-artifact seed, policy decision, state fence, and exact replay key",
                ));
            }
            authorization.authority_scope = provider_authority_scope(
                topology,
                CustodyServiceRole::ReleaseAttestorPublisher,
                signer,
                ServiceOperationV1::AuthorizeRelease,
                &request.operation_id,
                &request.attempt_id,
                request.attempt_revision,
                request.fencing_token,
            )?;
            authorization.signer_logical_role =
                signer.logical_role().to_owned();
            authorization.signer_key_id =
                signer.key_id().to_owned();
            authorization.signature = signer.sign(
                RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN,
                &authorization.without_signature(),
            )?;
            serde_json::to_value(authorization).map_err(|_| {
                V2RuntimeError::new(
                    "release_authorization_result_invalid",
                    "signed release authorization cannot be represented",
                )
            })
        }
        ServiceOperationV1::ConsumeReleaseAndRetrieveExact => {
            let _: ConsumeReleaseAndRetrieveExactRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "release_consumption_request_invalid",
                        "state service request is not the closed phase-specific DTO",
                    )
                })?;
            Ok(result)
        }
        ServiceOperationV1::Publish => {
            let request: PublishRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "publication_request_invalid",
                        "publication request is not the closed DTO",
                    )
                })?;
            let mut publication: SignedPublicationReceiptV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "publication_result_invalid",
                        "publication engine did not return the closed receipt",
                    )
                })?;
            if publication.api_version
                    != super::super::protocol::PUBLICATION_API_VERSION
                || publication.generation_id != request.generation_id
                || publication.generation != request.generation
                || publication.operation != ServiceOperationV1::Publish
                || publication.request_id != request.request_id
                || publication.request_sha256 != request.request_sha256
                || publication.attempt_id != request.attempt_id
                || publication.stable_resume_id
                    != request.stable_resume_id
                || publication.publication_id != request.publication_id
                || publication.outbox_id != request.outbox_id
                || publication.finalization_id
                    != request.finalization_id
                || publication.payload_object_sha256
                    != request.payload_object_sha256
                || publication.publication_sequence == 0
                || !is_sha256(
                    &publication
                        .durable_publication_receipt_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "publication_result_mismatch",
                    "publication receipt does not bind the exact durable outbox transition",
                ));
            }
            publication.authority_scope = provider_authority_scope(
                topology,
                CustodyServiceRole::ReleaseAttestorPublisher,
                signer,
                ServiceOperationV1::Publish,
                &request.operation_id,
                &request.attempt_id,
                publication.publication_sequence,
                request.fencing_token,
            )?;
            publication.signer_logical_role =
                signer.logical_role().to_owned();
            publication.signer_key_id = signer.key_id().to_owned();
            publication.signature = signer.sign(
                PUBLICATION_SIGNATURE_DOMAIN,
                &publication.without_signature(),
            )?;
            serde_json::to_value(publication).map_err(|_| {
                V2RuntimeError::new(
                    "publication_result_invalid",
                    "signed publication receipt cannot be represented",
                )
            })
        }
        ServiceOperationV1::Reconcile
        | ServiceOperationV1::Cleanup => {
            let request: SettlementRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "settlement_request_invalid",
                        "settlement request is not the closed DTO",
                    )
                })?;
            let mut settlement: SignedDurableTerminalReceiptV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "settlement_result_invalid",
                        "settlement engine did not return the closed receipt",
                    )
                })?;
            let reconciliation_evidence_valid = match (
                settlement.reconciliation_id.as_deref(),
                settlement.reconciliation_artifact.as_ref(),
                settlement.reconciliation_artifact_sha256.as_deref(),
            ) {
                (Some(id), Some(artifact), Some(expected_sha256)) => {
                    !id.is_empty()
                        && is_sha256(expected_sha256)
                        && canonical_sha256(artifact)?
                            == expected_sha256
                }
                (None, None, None) => true,
                _ => false,
            };
            let recovery_evidence_valid = match (
                settlement.recovery_artifact.as_ref(),
                settlement.recovery_artifact_sha256.as_deref(),
            ) {
                (Some(artifact), Some(expected_sha256)) => {
                    is_sha256(expected_sha256)
                        && canonical_sha256(artifact)?
                            == expected_sha256
                }
                (None, None) => true,
                _ => false,
            };
            let operation_evidence_valid = match operation {
                ServiceOperationV1::Reconcile => {
                    settlement.reconciliation_artifact.is_some()
                }
                ServiceOperationV1::Cleanup => {
                    settlement.reconciliation_artifact.is_none()
                        && settlement.recovery_artifact.is_some()
                }
                _ => false,
            };
            if settlement.api_version
                    != super::super::protocol::SETTLEMENT_API_VERSION
                || settlement.generation_id != request.generation_id
                || settlement.generation != request.generation
                || settlement.operation != operation
                || settlement.request_id != request.request_id
                || settlement.request_sha256 != request.request_sha256
                || settlement.attempt_id != request.attempt_id
                || settlement.stable_resume_id
                    != request.stable_resume_id
                || !settlement.durable
                || !settlement.reconciled
                || settlement.authority_sequence == 0
                || settlement.terminal_state_sha256
                    != request.expected_terminal_state_sha256
                || !is_sha256(
                    &settlement.settlement_receipt_sha256,
                )
                || !reconciliation_evidence_valid
                || !recovery_evidence_valid
                || !operation_evidence_valid
            {
                return Err(V2RuntimeError::new(
                    "settlement_result_mismatch",
                    "settlement receipt is not the exact durable terminal result",
                ));
            }
            let service_role = topology
                .logical_role(signer.logical_role())
                .map(|binding| binding.service_role)
                .filter(|role| {
                    *role == CustodyServiceRole::CleanupWatchdog
                })
                .ok_or_else(|| {
                    V2RuntimeError::new(
                        "settlement_signer_role_invalid",
                        "settlement receipts require a cleanup-watchdog reconciliation or cleanup signer",
                    )
                })?;
            settlement.authority_scope = provider_authority_scope(
                topology,
                service_role,
                signer,
                operation,
                &request.operation_id,
                &request.attempt_id,
                settlement.authority_sequence,
                request.fencing_token,
            )?;
            settlement.signer_logical_role =
                signer.logical_role().to_owned();
            settlement.signer_key_id = signer.key_id().to_owned();
            settlement.signature = signer.sign(
                SETTLEMENT_SIGNATURE_DOMAIN,
                &settlement.without_signature(),
            )?;
            serde_json::to_value(settlement).map_err(|_| {
                V2RuntimeError::new(
                    "settlement_result_invalid",
                    "signed settlement receipt cannot be represented",
                )
            })
        }
        ServiceOperationV1::Attest => {
            let request: CustodyAttestationRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "custody_attestation_request_invalid",
                        "attestation request is not the closed custody DTO",
                    )
                })?;
            verify_final_envelope_verification(
                topology,
                &request.final_envelope_verification,
            )?;
            let mut attestation: SignedCustodyAttestationV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "custody_attestation_result_invalid",
                        "attestation backend did not return the closed signed DTO",
                    )
                })?;
            if request.api_version
                    != super::super::protocol::
                        CUSTODY_ATTESTATION_API_VERSION
                || attestation.api_version
                    != super::super::protocol::
                        CUSTODY_ATTESTATION_API_VERSION
                || attestation.generation_id
                    != request.generation_id
                || attestation.generation != request.generation
                || attestation.operation
                    != ServiceOperationV1::Attest
                || attestation.request_id != request.request_id
                || attestation.request_sha256
                    != request.request_sha256
                || attestation.attempt_id != request.attempt_id
                || attestation.stable_resume_id
                    != request.stable_resume_id
                || attestation.final_envelope_sha256
                    != request
                        .final_envelope_verification
                        .final_envelope_sha256
                || attestation.attestation_sequence == 0
                || !is_sha256(
                    &attestation.attestation_evidence_sha256,
                )
                || !is_sha256(
                    &attestation.attestation_result_sha256,
                )
            {
                return Err(V2RuntimeError::new(
                    "custody_attestation_backend_mismatch",
                    "attestation result is not bound to the independently verified final envelope and stable attempt",
                ));
            }
            attestation.signer_logical_role =
                signer.logical_role().to_owned();
            attestation.signer_key_id =
                signer.key_id().to_owned();
            attestation.signature = signer.sign(
                CUSTODY_ATTESTATION_SIGNATURE_DOMAIN,
                &attestation.without_signature(),
            )?;
            serde_json::to_value(attestation).map_err(|_| {
                V2RuntimeError::new(
                    "custody_attestation_result_invalid",
                    "signed custody attestation cannot be represented",
                )
            })
        }
        ServiceOperationV1::Recover => {
            let request: CustodyRecoveryRequestV1 =
                serde_json::from_value(request.clone()).map_err(|_| {
                    V2RuntimeError::new(
                        "custody_recovery_request_invalid",
                        "recovery request is not the closed custody DTO",
                    )
                })?;
            let mut recovery: SignedCustodyRecoveryV1 =
                serde_json::from_value(result).map_err(|_| {
                    V2RuntimeError::new(
                        "custody_recovery_result_invalid",
                        "recovery backend did not return the closed signed DTO",
                    )
                })?;
            if request.api_version
                    != super::super::protocol::
                        CUSTODY_RECOVERY_API_VERSION
                || recovery.api_version
                    != super::super::protocol::
                        CUSTODY_RECOVERY_API_VERSION
                || recovery.generation_id != request.generation_id
                || recovery.generation != request.generation
                || recovery.operation
                    != ServiceOperationV1::Recover
                || recovery.request_id != request.request_id
                || recovery.request_sha256
                    != request.request_sha256
                || recovery.attempt_id != request.attempt_id
                || recovery.stable_resume_id
                    != request.stable_resume_id
                || recovery.recovered_terminal_state_sha256
                    != request.expected_terminal_state_sha256
                || recovery.recovery_sequence == 0
                || recovery.reconciliation_high_water
                    < request.reconciliation_cursor
                || !is_sha256(&recovery.recovered_result_sha256)
            {
                return Err(V2RuntimeError::new(
                    "custody_recovery_backend_mismatch",
                    "recovery result is not bound to the stable resume ID, expected terminal state, and reconciliation cursor",
                ));
            }
            recovery.authority_scope = provider_authority_scope(
                topology,
                CustodyServiceRole::StateAuthority,
                signer,
                ServiceOperationV1::Recover,
                &request.operation_id,
                &request.attempt_id,
                request.attempt_revision,
                request.fencing_token,
            )?;
            recovery.signer_logical_role =
                signer.logical_role().to_owned();
            recovery.signer_key_id =
                signer.key_id().to_owned();
            recovery.signature = signer.sign(
                CUSTODY_RECOVERY_SIGNATURE_DOMAIN,
                &recovery.without_signature(),
            )?;
            serde_json::to_value(recovery).map_err(|_| {
                V2RuntimeError::new(
                    "custody_recovery_result_invalid",
                    "signed custody recovery cannot be represented",
                )
            })
        }
        _ => Ok(result),
    }
}

fn canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(value).map_err(|_| {
        V2RuntimeError::new(
            "custody_nested_authority_value_invalid",
            "nested authority value cannot be canonicalized",
        )
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub(crate) fn read_readiness_record(
    path: &Path,
) -> Result<CustodyReadinessRecordV1, V2RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_readiness_record_unavailable",
            "open service readiness record",
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 256 * 1024
    {
        return Err(V2RuntimeError::new(
            "custody_readiness_record_unsafe",
            "readiness record is not an immutable bounded regular file",
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_readiness_record_unreadable",
            "read service readiness record",
        )
    })?;
    crate::decode_canonical_json(&bytes).map_err(|_| {
        V2RuntimeError::new(
            "custody_readiness_record_invalid",
            "readiness record is not a canonical closed DTO",
        )
    })
}

pub(crate) fn verify_readiness_record(
    topology: &SignedCustodyTopologyV1,
    scoped: &ScopedCustodyServiceConfig,
    record: &CustodyReadinessRecordV1,
) -> Result<(), V2RuntimeError> {
    if record.api_version != READINESS_RECORD_API_VERSION
        || record.service_role != scoped.role
        || record.service_id != scoped.process.service_id
        || record.generation_id != scoped.generation_id
        || record.generation != scoped.generation
        || record.topology_sha256 != topology_sha256(topology)?
        || !record.reconciliation_complete
        || record.reconciliation_high_water == 0
        || !is_sha256(&record.reconciliation_state_sha256)
        || record.socket_identity_sha256
            != socket_identity_sha256(
                &scoped.process.readiness_socket_path,
            )?
        || record.published_at_epoch_ms == 0
    {
        return Err(V2RuntimeError::new(
            "custody_readiness_record_binding_invalid",
            "readiness record does not bind the exact socket, generation, topology, and completed reconciliation",
        ));
    }
    if scoped.role == CustodyServiceRole::CustodyRouter {
        if record.service_handshake.is_some()
            || record.dependency_handshakes.len() != 6
            || record.transaction_socket_identity_sha256.as_ref()
                != Some(&socket_identity_sha256(
                    &scoped.process.socket_path,
                )?)
        {
            return Err(V2RuntimeError::new(
                "custody_router_readiness_invalid",
                "router readiness must bind the live transaction listener, aggregate exactly six signed dependency handshakes, and own no signing key",
            ));
        }
        for role in CustodyServiceRole::ALL {
            if role == CustodyServiceRole::CustodyRouter {
                continue;
            }
            let handshake =
                record.dependency_handshakes.get(&role).ok_or_else(|| {
                    V2RuntimeError::new(
                        "custody_router_dependency_missing",
                        "router readiness omits a required signed dependency handshake",
                    )
                })?;
            verify_service_handshake(topology, handshake)?;
        }
    } else {
        if record.transaction_socket_identity_sha256.is_some() {
            return Err(V2RuntimeError::new(
                "custody_service_transaction_socket_unexpected",
                "only router readiness may bind a public transaction listener",
            ));
        }
        let handshake =
            record.service_handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_service_handshake_missing",
                    "service readiness omits its signed handshake",
                )
            })?;
        verify_service_handshake(topology, handshake)?;
        if !record.dependency_handshakes.is_empty()
            || handshake.reconciliation_high_water
                != record.reconciliation_high_water
            || handshake.reconciliation_state_sha256
                != record.reconciliation_state_sha256
        {
            return Err(V2RuntimeError::new(
                "custody_service_readiness_mismatch",
                "readiness record and signed post-reconciliation handshake differ",
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_live_handshake_against_record(
    topology: &SignedCustodyTopologyV1,
    baseline: &SignedServiceHandshakeV1,
    live: &SignedServiceHandshakeV1,
    request_id: &str,
    challenge_nonce: &str,
) -> Result<(), V2RuntimeError> {
    verify_service_handshake(topology, baseline)?;
    verify_service_handshake(topology, live)?;
    let now = system_time_epoch_ms()?;
    if live.request_id != request_id
        || live.challenge_nonce != challenge_nonce
        || live.issued_at_epoch_ms > now
        || live.expires_at_epoch_ms <= now
    {
        return Err(V2RuntimeError::new(
            "custody_live_handshake_not_fresh",
            "live service handshake does not sign the exact readiness challenge or is outside its signed validity interval",
        ));
    }
    let mut normalized = live.clone();
    normalized.request_id = baseline.request_id.clone();
    normalized.challenge_nonce =
        baseline.challenge_nonce.clone();
    normalized.signature = baseline.signature.clone();
    if crate::canonical_json_bytes(&normalized).ok()
        != crate::canonical_json_bytes(baseline).ok()
    {
        return Err(V2RuntimeError::new(
            "custody_live_handshake_generation_changed",
            "live service handshake differs from the durable generation, role-key, configuration, capability, or reconciliation binding",
        ));
    }
    Ok(())
}

fn in_process_engine_readiness(
    config: &RootOwnedResponseObservationV2Config,
    topology: &SignedCustodyTopologyV1,
    scoped: &ScopedCustodyServiceConfig,
) -> Result<BackendReadinessV1, V2RuntimeError> {
    let (reconciliation_high_water, reconciliation_state_sha256) =
        if scoped.role == CustodyServiceRole::StateAuthority {
            let readiness =
                super::super::generation::
                    load_verified_bootstrap_readiness(config)?;
            (
                readiness.reconciliation_high_water,
                readiness.reconciliation_state_sha256,
            )
        } else {
            let authority =
                config.scoped_service_config(
                    CustodyServiceRole::StateAuthority,
                )?;
            let record = read_readiness_record(
                &authority.process.readiness_record_path,
            )?;
            verify_readiness_record(
                topology,
                &authority,
                &record,
            )?;
            if !record.reconciliation_complete
                || record.reconciliation_high_water == 0
            {
                return Err(V2RuntimeError::new(
                    "custody_state_authority_not_reconciled",
                    "state-authority readiness is not post-reconciliation",
                ));
            }
            let mut hasher = Sha256::new();
            hasher.update(
                b"serverware.response-v2/local-engine-readiness/v1",
            );
            hasher.update(
                record.reconciliation_state_sha256.as_bytes(),
            );
            hasher.update(scoped.role.as_str().as_bytes());
            for operation in required_service_operations(scoped.role) {
                hasher.update(operation.as_str().as_bytes());
            }
            (
                record.reconciliation_high_water,
                format!("sha256:{:x}", hasher.finalize()),
            )
        };
    Ok(BackendReadinessV1 {
        api_version: BACKEND_READINESS_API_VERSION.to_owned(),
        service_role: scoped.role,
        generation_id: topology.generation_id.clone(),
        generation: topology.generation,
        executable_sha256: scoped.process.executable_sha256.clone(),
        configuration_sha256:
            scoped.process.configuration_sha256.clone(),
        implemented_operations:
            required_service_operations(scoped.role)
                .into_iter()
                .collect(),
        reconciliation_high_water,
        reconciliation_state_sha256,
        ready_after_reconciliation: true,
        challenge_nonce: topology_sha256(topology)?,
    })
}

fn validate_service_request(
    topology: &SignedCustodyTopologyV1,
    scoped: &ScopedCustodyServiceConfig,
    request: &ServiceRpcEnvelopeV1,
    expected_deadline_boottime_ns: u64,
) -> Result<(), V2RuntimeError> {
    let canonical =
        crate::canonical_json_bytes(&request.payload).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_request_invalid",
                "service request payload cannot be canonicalized",
            )
        })?;
    if request.api_version != SERVICE_RPC_API_VERSION
        || request.generation_id != topology.generation_id
        || request.generation != topology.generation
        || request.request_id.is_empty()
        || request.request_id.len() > 256
        || request.payload_sha256
            != format!("sha256:{:x}", Sha256::digest(canonical))
        || !required_service_operations(scoped.role)
            .contains(&request.operation)
        || request.operation == ServiceOperationV1::Readiness
        || request.deadline_boottime_ns <= boottime_ns()?
        || request.deadline_boottime_ns
            != expected_deadline_boottime_ns
    {
        return Err(V2RuntimeError::new(
            "custody_service_request_binding_invalid",
            "service request is not canonical, generation-bound, deadline-bound, or assigned to this process",
        ));
    }
    Ok(())
}

pub(crate) fn validate_hello(
    topology: &SignedCustodyTopologyV1,
    role: CustodyServiceRole,
    hello: &ServiceHelloV1,
    maximum_deadline_boottime_ns: u64,
) -> Result<(), V2RuntimeError> {
    if hello.api_version != SERVICE_RPC_API_VERSION
        || hello.expected_service_role != role
        || hello.generation_id != topology.generation_id
        || hello.generation != topology.generation
        || hello.topology_sha256 != topology_sha256(topology)?
        || hello.request_id.is_empty()
        || !is_sha256(&hello.challenge_nonce)
        || hello.deadline_boottime_ns <= boottime_ns()?
        || hello.deadline_boottime_ns
            > maximum_deadline_boottime_ns
    {
        return Err(V2RuntimeError::new(
            "custody_service_hello_invalid",
            "service hello is not a fresh exact-generation challenge",
        ));
    }
    Ok(())
}

pub(super) fn load_scoped_signing_keys(
    config: &RootOwnedResponseObservationV2Config,
    scoped: &ScopedCustodyServiceConfig,
) -> Result<BTreeMap<String, RoleSigningKey>, V2RuntimeError> {
    let mut keys = BTreeMap::new();
    for descriptor in &scoped.process.role_keys {
        let key = super::super::guest_delivery::role_key(config, scoped, descriptor)?;
        if keys.insert(descriptor.logical_role.clone(), key).is_some() {
            return Err(V2RuntimeError::new(
                "custody_service_key_duplicate",
                "service loaded a duplicate logical-role subkey",
            ));
        }
    }
    if keys.len() != scoped.logical_roles.len() {
        return Err(V2RuntimeError::new(
            "custody_service_key_scope_incomplete",
            "service did not load exactly its signed logical-role subkeys",
        ));
    }
    Ok(keys)
}

pub(super) fn readiness_signer_role(
    role: CustodyServiceRole,
) -> Option<&'static str> {
    Some(match role {
        CustodyServiceRole::CustodyRouter => return None,
        CustodyServiceRole::StateAuthority => "linearizable-store",
        CustodyServiceRole::CredentialTransport => "mutation-supervisor",
        CustodyServiceRole::PolicyProofVerifier => "evidence-trust",
        CustodyServiceRole::ImmutableArtifactLedger => "persistence",
        CustodyServiceRole::ReleaseAttestorPublisher => "attester",
        CustodyServiceRole::CleanupWatchdog => {
            "emergency-cleanup-executor"
        }
    })
}

pub(crate) fn validate_service_process_identity(
    scoped: &ScopedCustodyServiceConfig,
) -> Result<(), V2RuntimeError> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid != scoped.process.uid || gid != scoped.process.gid {
        return Err(V2RuntimeError::new(
            "custody_service_process_identity_mismatch",
            "service effective UID/GID does not match the signed topology",
        ));
    }
    Ok(())
}

pub(crate) fn validate_service_state_directory(
    scoped: &ScopedCustodyServiceConfig,
) -> Result<(), V2RuntimeError> {
    let metadata =
        fs::symlink_metadata(&scoped.process.state_directory)
            .map_err(|_| {
                V2RuntimeError::new(
                    "custody_service_state_unavailable",
                    "inspect service state directory",
                )
            })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != scoped.process.uid
        || metadata.gid() != scoped.process.gid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(V2RuntimeError::new(
            "custody_service_state_unsafe",
            "service state directory must be mode 0700 and owned by the exact service UID/GID",
        ));
    }
    Ok(())
}

pub(crate) fn acquire_service_lease(
    scoped: &ScopedCustodyServiceConfig,
) -> Result<File, V2RuntimeError> {
    let path = scoped.process.state_directory.join(".service.lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_service_lease_failed",
                "open service singleton lease",
            )
        })?;
    if unsafe {
        libc::flock(
            file.as_raw_fd(),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } != 0
    {
        return Err(V2RuntimeError::new(
            "custody_service_already_running",
            "another process owns the service singleton lease",
        ));
    }
    Ok(file)
}

pub(crate) fn bind_service_socket(
    path: &Path,
    gid: u32,
) -> Result<UnixListener, V2RuntimeError> {
    if let Ok(existing) = UnixStream::connect(path) {
        drop(existing);
        return Err(V2RuntimeError::new(
            "custody_service_socket_live",
            "refuse to replace a live service socket",
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(V2RuntimeError::new(
                "custody_service_socket_unsafe",
                "stale service path is not an owned socket",
            ));
        }
        fs::remove_file(path).map_err(|_| {
            V2RuntimeError::new(
                "custody_service_socket_remove_failed",
                "remove stale service socket under singleton lease",
            )
        })?;
    }
    let listener = UnixListener::bind(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_socket_bind_failed",
            "bind service socket",
        )
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_service_socket_mode_failed",
                "set service socket mode",
            )
        })?;
    let c_path = std::ffi::CString::new(
        path.as_os_str().as_encoded_bytes(),
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_service_socket_path_invalid",
            "service socket path contains NUL",
        )
    })?;
    if unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) } != 0 {
        return Err(V2RuntimeError::new(
            "custody_service_socket_owner_failed",
            "set service socket group",
        ));
    }
    Ok(listener)
}

pub(crate) fn publish_readiness_record(
    path: &Path,
    uid: u32,
    gid: u32,
    record: &CustodyReadinessRecordV1,
) -> Result<(), V2RuntimeError> {
    let bytes = crate::canonical_json_bytes(record).map_err(|_| {
        V2RuntimeError::new(
            "custody_readiness_record_invalid",
            "readiness record cannot be canonicalized",
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        V2RuntimeError::new(
            "custody_readiness_path_invalid",
            "readiness record has no parent directory",
        )
    })?;
    let temporary = parent.join(format!(
        ".readiness-{}-{}.tmp",
        record.service_role.as_str(),
        unsafe { libc::getpid() },
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(READINESS_MODE)
        .open(&temporary)
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_readiness_record_write_failed",
                "create readiness record staging file",
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_readiness_record_write_failed",
                "write and synchronize readiness record",
            )
        })?;
    if unsafe {
        libc::fchown(file.as_raw_fd(), uid, gid)
    } != 0
    {
        let _ = fs::remove_file(&temporary);
        return Err(V2RuntimeError::new(
            "custody_readiness_record_owner_failed",
            "set readiness record ownership",
        ));
    }
    fs::rename(&temporary, path).map_err(|_| {
        V2RuntimeError::new(
            "custody_readiness_record_publish_failed",
            "atomically publish readiness record",
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_readiness_record_publish_failed",
                "synchronize readiness record directory",
            )
        })
}

pub(crate) fn authenticate_peer(
    stream: &UnixStream,
    topology: &SignedCustodyTopologyV1,
) -> Result<(), V2RuntimeError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length =
        std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred
                as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        return Err(V2RuntimeError::new(
            "custody_service_peer_credentials_failed",
            "read service peer credentials",
        ));
    }
    let allowed = topology.processes.iter().any(|process| {
        process.uid == credentials.uid
    });
    if !allowed {
        return Err(V2RuntimeError::new(
            "custody_service_peer_unauthorized",
            "peer UID is outside the signed custody topology",
        )
        .suppress_response());
    }
    Ok(())
}

pub(crate) fn socket_identity_sha256(
    path: &Path,
) -> Result<String, V2RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        V2RuntimeError::new(
            "custody_service_socket_unavailable",
            "inspect service socket identity",
        )
    })?;
    if !metadata.file_type().is_socket() {
        return Err(V2RuntimeError::new(
            "custody_service_socket_invalid",
            "service path is not a socket",
        ));
    }
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(format!(
            "{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
        ))
    ))
}

fn pending_socket_identity_sha256(path: &Path) -> String {
    format!("sha256:{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()))
}

pub(crate) fn system_time_epoch_ms(
) -> Result<u64, V2RuntimeError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_service_time_invalid",
                "system time is not representable",
            )
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
