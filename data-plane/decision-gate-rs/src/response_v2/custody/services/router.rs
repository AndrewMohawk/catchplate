use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::common::{
    acquire_service_lease, authenticate_peer, bind_service_socket,
    publish_readiness_record, read_readiness_record,
    socket_identity_sha256, validate_hello,
    validate_service_process_identity, validate_service_state_directory,
    verify_live_handshake_against_record, verify_readiness_record,
};
use super::super::config::CustodyServiceRole;
use super::super::generation::topology_sha256;
use super::super::protocol::{
    CustodyReadinessRecordV1, ServiceHelloResultV1, ServiceHelloV1,
    SignedServiceHandshakeV1, READINESS_RECORD_API_VERSION,
    SERVICE_RPC_API_VERSION,
    ServiceOperationV1,
};
use super::super::recovery::{
    boottime_ns, BootDeadline, ServiceConnection,
};
use super::super::{
    RootOwnedResponseObservationV2Config, V2RuntimeError,
};

pub(crate) struct RouterReadinessGuard {
    _lease: File,
    _readiness_thread: JoinHandle<()>,
    _transaction_thread:
        JoinHandle<Result<(), V2RuntimeError>>,
}

pub(crate) struct RoutedResponseData {
    pub result:
        crate::response_observation_v2_api::V2ResponseDataResult,
    pub exact_objects: Vec<File>,
}

pub(crate) fn handle_response_data_request(
    config: &RootOwnedResponseObservationV2Config,
    request:
        crate::response_observation_v2_api::V2ResponseDataRequest,
    request_exact_objects: Vec<File>,
) -> Result<RoutedResponseData, V2RuntimeError> {
    use crate::response_observation_v2_api::
        V2ResponseDataRequest;
    let (role, operation) = match &request {
        V2ResponseDataRequest::TargetDispatchBegin {..}|V2ResponseDataRequest::CapturePersist {..}=>(
            CustodyServiceRole::CredentialTransport,ServiceOperationV1::TargetDispatch),
        V2ResponseDataRequest::AppendReleaseTransparency { .. } => (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::Publish,
        ),
        V2ResponseDataRequest::InspectImmutableResponse { .. } => (
            CustodyServiceRole::ImmutableArtifactLedger,
            ServiceOperationV1::InspectImmutableRaw,
        ),
        V2ResponseDataRequest::ValidateFinalEnvelope { .. } => (
            CustodyServiceRole::PolicyProofVerifier,
            ServiceOperationV1::FinalEnvelopeVerify,
        ),
        V2ResponseDataRequest::AuthorizeExactRelease { .. } => (
            CustodyServiceRole::ReleaseAttestorPublisher,
            ServiceOperationV1::AuthorizeRelease,
        ),
        V2ResponseDataRequest::ConsumeAndRetrieveExact { .. } => (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::ConsumeReleaseAndRetrieveExact,
        ),
        V2ResponseDataRequest::ResolveExactReplay { .. } => (
            CustodyServiceRole::StateAuthority,
            ServiceOperationV1::ReplayResolve,
        ),
        V2ResponseDataRequest::SettleAttempt { .. } => (
            CustodyServiceRole::CleanupWatchdog,
            ServiceOperationV1::Reconcile,
        ),
    };
    let deadline_boottime_ns = request
        .deadline()
        .0
        .absolute_boottime_ns
        .parse::<u64>()
        .map_err(|_| {
            V2RuntimeError::new(
                "response_data_deadline_invalid",
                "response-data request deadline is not canonical CLOCK_BOOTTIME nanoseconds",
            )
        })?;
    let (result, exact_objects) =
        super::invoke_response_data_service(
            config,
            role,
            operation,
            &request,
            &request_exact_objects,
            deadline_boottime_ns,
        )?;
    let expected_outputs = usize::from(matches!(
        request,
        V2ResponseDataRequest::ConsumeAndRetrieveExact {
            params:
                crate::response_observation_v2_api::
                    V2ConsumeAndRetrieveExactParams::Retrieve { .. },
            ..
        }
    ));
    if exact_objects.len() != expected_outputs {
        return Err(V2RuntimeError::new(
            "response_data_exact_object_cardinality_invalid",
            "only ConsumeAndRetrieveExact may return the sole exact response descriptor",
        ));
    }
    Ok(RoutedResponseData {
        result,
        exact_objects: exact_objects
            .into_iter()
            .map(super::super::ValidatedExactObject::into_file)
            .collect(),
    })
}

pub(crate) fn run(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    start(config)?.wait()
}

impl RouterReadinessGuard {
    fn wait(self) -> Result<(), V2RuntimeError> {
        loop {
            if self._transaction_thread.is_finished() {
                return self
                    ._transaction_thread
                    .join()
                    .map_err(|_| {
                        V2RuntimeError::new(
                            "custody_router_transaction_thread_failed",
                            "router transaction worker panicked",
                        )
                    })?
                    .and_then(|_| {
                        Err(V2RuntimeError::new(
                            "custody_router_transaction_stopped",
                            "router transaction listener stopped",
                        ))
                    });
            }
            if self._readiness_thread.is_finished() {
                self._readiness_thread.join().map_err(|_| {
                    V2RuntimeError::new(
                        "custody_router_readiness_thread_failed",
                        "router readiness UDS worker terminated unexpectedly",
                    )
                })?;
                return Err(V2RuntimeError::new(
                    "custody_router_readiness_stopped",
                    "router readiness UDS stopped",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

pub(crate) fn public_reconciliation_snapshot(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(u64, String), V2RuntimeError> {
    let topology = config.custody_topology();
    let mut reconciliation_high_water = u64::MAX;
    let mut reconciliation_hasher = Sha256::new();
    for role in CustodyServiceRole::ALL {
        if role == CustodyServiceRole::CustodyRouter {
            continue;
        }
        let dependency = config.scoped_service_config(role)?;
        let record = read_readiness_record(
            &dependency.process.readiness_record_path,
        )?;
        verify_readiness_record(config, &dependency, &record)?;
        let handshake =
            record.service_handshake.ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_router_dependency_handshake_missing",
                    "dependency readiness omits its signed handshake",
                )
            })?;
        reconciliation_high_water = reconciliation_high_water
            .min(handshake.reconciliation_high_water);
        reconciliation_hasher.update(
            crate::canonical_json_bytes(&handshake).map_err(|_| {
                V2RuntimeError::new(
                    "custody_router_dependency_invalid",
                    "dependency handshake cannot be canonicalized",
                )
            })?,
        );
    }
    if reconciliation_high_water == 0
        || reconciliation_high_water == u64::MAX
    {
        return Err(V2RuntimeError::new(
            "custody_router_reconciliation_invalid",
            "router dependencies have no shared reconciliation high-water",
        ));
    }
    Ok((
        reconciliation_high_water,
        format!(
            "sha256:{:x}",
            reconciliation_hasher.finalize()
        ),
    ))
}

fn transaction_listener_start_timeout(
    timeout_ms: u64,
) -> Duration {
    Duration::from_millis(timeout_ms.max(1))
}

fn join_startup_failure(
    thread: JoinHandle<Result<(), V2RuntimeError>>,
) -> V2RuntimeError {
    match thread.join() {
        Ok(Err(error)) => error,
        Ok(Ok(())) => V2RuntimeError::new(
            "custody_router_transaction_stopped",
            "router transaction listener stopped during startup",
        ),
        Err(_) => V2RuntimeError::new(
            "custody_router_transaction_thread_failed",
            "router transaction worker panicked during startup",
        ),
    }
}

/*
 * The public and legacy transaction families intentionally share the one
 * configured SOCK_SEQPACKET listener. The readiness UDS remains a separate
 * UnixStream endpoint used only for service liveness.
 */
fn start_transaction_listener(
    config: &RootOwnedResponseObservationV2Config,
    timeout_ms: u64,
) -> Result<
    JoinHandle<Result<(), V2RuntimeError>>,
    V2RuntimeError,
> {
    super::super::guest_delivery::check(config)?;
    let transaction_config = config.clone();
    let (ready_tx, ready_rx) = sync_channel(1);
    let thread = thread::Builder::new()
        .name("response-v2-router-transaction".to_owned())
        .spawn(move || {
            super::super::supervisor::
                run_router_transaction_listener(
                    transaction_config,
                    ready_tx,
                )
        })
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_router_transaction_thread_failed",
                "start router transaction listener",
            )
        })?;
    let timeout_ms = super::super::guest_delivery::bounded_timeout_ms(config, timeout_ms)?;
    match ready_rx.recv_timeout(
        transaction_listener_start_timeout(timeout_ms),
    ) {
        Ok(()) => {
            super::super::guest_delivery::check(config)?;
            Ok(thread)
        }
        Err(_) if config.guest_delivery.is_some() => Err(V2RuntimeError::new(
            "guest_router_start_timeout", "guest router failed to start within its original allowance")),
        Err(_) => Err(join_startup_failure(thread)),
    }
}

pub(crate) fn start(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<RouterReadinessGuard, V2RuntimeError> {
    super::super::guest_delivery::check(config)?;
    let topology = config.custody_topology().clone();
    let scoped =
        config.scoped_service_config(CustodyServiceRole::CustodyRouter)?;
    validate_service_process_identity(&scoped)?;
    validate_service_state_directory(&scoped)?;
    if config.socket_path() != scoped.process.socket_path {
        return Err(V2RuntimeError::new(
            "custody_router_transaction_socket_mismatch",
            "legacy and public transaction protocols must share the one signed router socket path",
        ));
    }
    let lease = acquire_service_lease(&scoped)?;
    let transaction_thread = start_transaction_listener(
        config,
        scoped.process.request_timeout_ms,
    )?;
    let mut dependencies = BTreeMap::new();
    let mut reconciliation_high_water = u64::MAX;
    let mut reconciliation_hasher = Sha256::new();
    for role in CustodyServiceRole::ALL {
        if role == CustodyServiceRole::CustodyRouter {
            continue;
        }
        let dependency = config.scoped_service_config(role)?;
        let record = read_readiness_record(
            &dependency.process.readiness_record_path,
        )?;
        verify_readiness_record(
            config,
            &dependency,
            &record,
        )?;
        let handshake =
            record.service_handshake.ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_router_dependency_handshake_missing",
                    "dependency readiness omits its signed handshake",
                )
            })?;
        reconciliation_high_water = reconciliation_high_water
            .min(handshake.reconciliation_high_water);
        reconciliation_hasher.update(
            crate::canonical_json_bytes(&handshake).map_err(|_| {
                V2RuntimeError::new(
                    "custody_router_dependency_invalid",
                    "dependency handshake cannot be canonicalized",
                )
            })?,
        );
        dependencies.insert(role, handshake);
    }
    if reconciliation_high_water == 0
        || reconciliation_high_water == u64::MAX
    {
        return Err(V2RuntimeError::new(
            "custody_router_reconciliation_invalid",
            "router dependencies have no shared reconciliation high-water",
        ));
    }
    let listener = bind_service_socket(
        &scoped.process.readiness_socket_path,
        scoped.process.gid,
    )?;
    let now = system_time_epoch_ms()?;
    let record = CustodyReadinessRecordV1 {
        api_version: READINESS_RECORD_API_VERSION.to_owned(),
        service_role: CustodyServiceRole::CustodyRouter,
        service_id: scoped.process.service_id.clone(),
        generation_id: scoped.generation_id.clone(),
        generation: scoped.generation,
        topology_sha256: topology_sha256(&topology)?,
        service_handshake: None,
        dependency_handshakes: dependencies.clone(),
        reconciliation_complete: true,
        reconciliation_high_water,
        reconciliation_state_sha256: format!(
            "sha256:{:x}",
            reconciliation_hasher.finalize()
        ),
        socket_identity_sha256: socket_identity_sha256(
            &scoped.process.readiness_socket_path,
        )?,
        transaction_socket_identity_sha256: Some(
            socket_identity_sha256(&scoped.process.socket_path)?,
        ),
        published_at_epoch_ms: now,
    };
    publish_readiness_record(
        &scoped.process.readiness_record_path,
        scoped.process.uid,
        scoped.process.gid,
        &record,
    )?;
    let max_frame_bytes = scoped.process.max_frame_bytes;
    let timeout_ms = scoped.process.request_timeout_ms;
    let topology = Arc::new(topology);
    let config = Arc::new(config.clone());
    let readiness_thread = thread::Builder::new()
        .name("response-v2-router-readiness".to_owned())
        .spawn(move || {
            for accepted in listener.incoming() {
                let Ok(stream) = accepted else {
                    return;
                };
                let _ = handle_readiness_connection(
                    stream,
                    &topology,
                    &config,
                    max_frame_bytes,
                    timeout_ms,
                );
            }
        })
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_router_readiness_thread_failed",
                "start router readiness UDS",
            )
        })?;
    Ok(RouterReadinessGuard {
        _lease: lease,
        _readiness_thread: readiness_thread,
        _transaction_thread: transaction_thread,
    })
}

fn handle_readiness_connection(
    stream: UnixStream,
    topology: &super::super::config::SignedCustodyTopologyV1,
    config: &RootOwnedResponseObservationV2Config,
    max_frame_bytes: usize,
    timeout_ms: u64,
) -> Result<(), V2RuntimeError> {
    authenticate_peer(&stream, topology)?;
    let deadline = BootDeadline::new(
        boottime_ns()?
            .checked_add(timeout_ms * 1_000_000)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_router_readiness_deadline_overflow",
                    "router readiness deadline overflowed",
                )
            })?,
    )?;
    let mut connection = ServiceConnection::from_accepted(
        stream,
        deadline,
        max_frame_bytes,
    )?;
    let hello: ServiceHelloV1 = connection.receive()?;
    validate_hello(
        topology,
        CustodyServiceRole::CustodyRouter,
        &hello,
        deadline.absolute_ns(),
    )?;
    let dependency_handshakes =
        query_live_dependencies(config, &hello, deadline)?;
    connection.send(&ServiceHelloResultV1 {
        api_version: SERVICE_RPC_API_VERSION.to_owned(),
        request_id: hello.request_id,
        challenge_nonce: hello.challenge_nonce,
        handshake: None,
        dependency_handshakes,
    })
}

fn query_live_dependencies(
    config: &RootOwnedResponseObservationV2Config,
    hello: &ServiceHelloV1,
    router_deadline: BootDeadline,
) -> Result<
    BTreeMap<CustodyServiceRole, SignedServiceHandshakeV1>,
    V2RuntimeError,
> {
    let topology = config.custody_topology();
    let deadline = BootDeadline::new(
        hello
            .deadline_boottime_ns
            .min(router_deadline.absolute_ns()),
    )?;
    let mut handshakes = BTreeMap::new();
    for role in CustodyServiceRole::ALL {
        if role == CustodyServiceRole::CustodyRouter {
            continue;
        }
        let scoped = config.scoped_service_config(role)?;
        let record = read_readiness_record(
            &scoped.process.readiness_record_path,
        )?;
        verify_readiness_record(config, &scoped, &record)?;
        let baseline =
            record.service_handshake.as_ref().ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_router_dependency_baseline_missing",
                    "dependency readiness record has no signed baseline",
                )
            })?;
        let mut connection = ServiceConnection::connect(
            &scoped.process.readiness_socket_path,
            deadline,
            scoped.process.max_frame_bytes,
        )?;
        connection.send(&ServiceHelloV1 {
            api_version: SERVICE_RPC_API_VERSION.to_owned(),
            request_id: hello.request_id.clone(),
            expected_service_role: role,
            generation_id: topology.generation_id.clone(),
            generation: topology.generation,
            topology_sha256: topology_sha256(topology)?,
            challenge_nonce: hello.challenge_nonce.clone(),
            deadline_boottime_ns: deadline.absolute_ns(),
        })?;
        let result: ServiceHelloResultV1 =
            connection.receive()?;
        if result.api_version != SERVICE_RPC_API_VERSION
            || result.request_id != hello.request_id
            || result.challenge_nonce != hello.challenge_nonce
            || !result.dependency_handshakes.is_empty()
        {
            return Err(V2RuntimeError::new(
                "custody_router_dependency_hello_mismatch",
                "dependency did not answer the router's exact live challenge",
            ));
        }
        let live = result.handshake.ok_or_else(|| {
            V2RuntimeError::new(
                "custody_router_dependency_handshake_missing",
                "dependency returned no signed live handshake",
            )
        })?;
        verify_live_handshake_against_record(
            config,
            baseline,
            &live,
            &hello.request_id,
            &hello.challenge_nonce,
        )?;
        handshakes.insert(role, live);
    }
    Ok(handshakes)
}

fn system_time_epoch_ms() -> Result<u64, V2RuntimeError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or_else(|| {
            V2RuntimeError::new(
                "custody_router_time_invalid",
                "router readiness time is not representable",
            )
        })
}
