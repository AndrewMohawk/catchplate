#[cfg(target_os = "linux")]
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[cfg(target_os = "linux")]
#[path = "../controller_v12.rs"]
mod controller_v12;
#[cfg(target_os = "linux")]
#[path = "../plan_protocol.rs"]
mod plan_protocol;
#[cfg(target_os = "linux")]
#[path = "../readiness.rs"]
mod readiness;
#[cfg(target_os = "linux")]
#[path = "../runtime_evidence.rs"]
mod runtime_evidence;
#[cfg(target_os = "linux")]
#[path = "../source_cas.rs"]
mod source_cas;
#[cfg(target_os = "linux")]
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[cfg(target_os = "linux")]
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;
#[cfg(target_os = "linux")]
#[path = "../controller_runtime_v12.rs"]
mod controller_runtime_v12;
#[cfg(target_os = "linux")]
#[path = "../docker_contract.rs"]
mod docker_contract;
#[cfg(target_os = "linux")]
#[path = "../docker_policy.rs"]
mod docker_policy;
#[cfg(target_os = "linux")]
#[path = "../docker_ledger.rs"]
mod docker_ledger;
#[cfg(target_os = "linux")]
#[path = "../docker_transport.rs"]
mod docker_transport;
#[cfg(target_os = "linux")]
#[path = "../dind_lifecycle.rs"]
mod dind_lifecycle;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("serverware-coder-lifecycle-privileged-v12: Linux is required");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("serverware-coder-lifecycle-privileged-v12: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::coder_controller_v11::{sha256, Digest};
    use super::controller_v12::{
        LifecycleCleanupRequestV12,
        CONTROLLER_LIFECYCLE_PROTOCOL_V12,
    };
    use super::dind_lifecycle::{
        PrivateDindConfigV12, PrivateDindLifecycleV12,
        RootTerminalDestructionReceiptV12,
        ScopedTerminalDestructionV12,
    };
    use super::docker_contract::{
        canonical_plan_bytes, DockerLaneDecodedPayloadV12,
        DockerLaneOperationV12, DockerLanePayloadContentV12,
        PrivateDindOperationRequestV12, ProxyOperation,
        PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12,
    };
    use super::plan_protocol::{ExactBuildTuple, PinnedPull};
    use super::readiness::PinnedReadinessTrustV12;
    use super::docker_policy::{
        GENERATION_LABEL_V12, LANE_LABEL_V12, OWNER_LABEL_V12,
        RESOURCE_LABEL_V12,
    };
    use super::receipt_contract_v12::{
        canonical_json, parse_canonical_json,
        AuthorityFrameHeaderV12, AUTHORITY_FRAME_BYTES,
    };
    use base64::{
        engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
    };
    use ed25519_dalek::pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePublicKey,
    };
    use ed25519_dalek::{
        Signature, Signer, SigningKey, Verifier, VerifyingKey,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::mem;
    use std::os::fd::{
        AsRawFd, FromRawFd, OwnedFd, RawFd,
    };
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
    const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;
    const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
    const MAX_FDS: usize = 2;
    const CLEANUP_SIGNATURE_DOMAIN: &[u8] =
        b"serverware/privileged-lifecycle-cleanup-signature/v12\0";
    const ADMIN_AGGREGATE_SIGNATURE_DOMAIN: &[u8] =
        b"serverware/private-dind-admin-aggregate-terminal/v12\0";
    const PLAN_AGGREGATE_SIGNATURE_DOMAIN: &[u8] =
        b"serverware/private-dind-plan-aggregate-terminal/v12\0";

    struct RootContext {
        lifecycle: Arc<PrivateDindLifecycleV12>,
        signing_key: SigningKey,
        root_signer_spki_sha256: Digest,
        authorized_peer_uid: u32,
        allowed_pinned_pulls: BTreeSet<Vec<u8>>,
        allowed_exact_builds: BTreeSet<Vec<u8>>,
        aggregate_receipt_root: PathBuf,
        policy_binding_sha256: Digest,
        configuration_generation_sha256: Digest,
        controller_signer_spki_sha256: Digest,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CleanupResponse {
        protocol: String,
        operation: String,
        disposition: String,
        request_sha256_canonical: Digest,
        lane_generation_sha256: Digest,
        acceptance_revoked_sha256: Digest,
        cgroup_kill_sha256: Digest,
        cgroup_empty_sha256: Digest,
        dind_destroyed_sha256: Digest,
        network_destroyed_sha256: Digest,
        mounts_destroyed_sha256: Digest,
        sockets_destroyed_sha256: Digest,
        cleanup_terminal_sha256: Digest,
        exact_plan_terminal_aggregate: Vec<u8>,
        plan_terminal_aggregate_sha256: Digest,
        root_signer_spki_sha256: Digest,
        root_signer_public_key_spki_der: Vec<u8>,
        root_signature: Vec<u8>,
        privileged_response_sha256: Digest,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct AdminAggregateTerminalResult {
        protocol: String,
        scope: String,
        disposition: String,
        terminal_observation_sha256: Digest,
        policy_binding_sha256: Digest,
        root_signer_spki_sha256: Digest,
        root_signer_public_key_spki_der: Vec<u8>,
        root_signature: Vec<u8>,
        result_sha256: Digest,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct PlanScopedTerminalAggregateV12 {
        protocol: String,
        plan_id: Digest,
        request_sha256_canonical: Digest,
        idempotency_key_sha256: Digest,
        observed_terminal_sha256: Digest,
        exact_receipt_sha256s: Vec<Digest>,
        exact_terminal_receipts: Vec<Vec<u8>>,
        root_signer_spki_sha256: Digest,
        root_signer_public_key_spki_der: Vec<u8>,
        root_signature: Vec<u8>,
        aggregate_sha256: Digest,
    }

    pub fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("privileged lifecycle helper requires UID 0".into());
        }
        let arguments =
            std::env::args_os().skip(1).collect::<Vec<_>>();
        if arguments.len() == 2 && arguments[0] == "--config" {
            return run_service(Path::new(&arguments[1]));
        }
        run_admin(&arguments)
    }

    fn run_service(config_path: &Path) -> Result<(), String> {
        let context = Arc::new(load_context(config_path)?);
        context
            .lifecycle
            .setup_host_network()
            .map_err(|error| error.to_string())?;
        context
            .lifecycle
            .startup_reconcile_all_nonterminal()
            .map_err(|error| error.to_string())?;
        let listen_pid = std::env::var("LISTEN_PID")
            .map_err(|_| "privileged helper requires LISTEN_PID")?
            .parse::<u32>()
            .map_err(|_| "privileged helper LISTEN_PID is invalid")?;
        let listen_fds = std::env::var("LISTEN_FDS")
            .map_err(|_| "privileged helper requires LISTEN_FDS")?
            .parse::<u32>()
            .map_err(|_| "privileged helper LISTEN_FDS is invalid")?;
        if listen_pid != std::process::id() || listen_fds != 1 {
            return Err(
                "privileged helper requires exactly one socket-activated listener"
                    .into(),
            );
        }
        let listener = unsafe { UnixListener::from_raw_fd(3) };
        super::receipt_contract_v12::notify_systemd_v12(
            "private-DinD v12 root lifecycle authority ready",
        )
        .map_err(|error| error.to_string())?;
        for stream in listener.incoming() {
            let stream =
                stream.map_err(|error| format!("accept lifecycle: {error}"))?;
            let context = Arc::clone(&context);
            std::thread::spawn(move || {
                if let Err(error) = serve_connection(&context, stream) {
                    eprintln!(
                        "serverware-coder-lifecycle-privileged-v12: request rejected: {error}"
                    );
                }
            });
        }
        Err("privileged lifecycle listener terminated".into())
    }

    fn run_admin(arguments: &[std::ffi::OsString]) -> Result<(), String> {
        if arguments.len() == 5
            && arguments[0] == "admin-reconcile-private-dind-v12"
            && arguments[1] == "--config"
            && arguments[3] == "--scope"
        {
            let scope = arguments[4]
                .to_str()
                .ok_or("admin reconcile scope is not UTF-8")?;
            if scope != "destroy-all-nonterminal-lanes"
                && scope != "destroy-all-owned-lanes"
            {
                return Err(
                    "admin reconcile scope is not a closed v12 scope".into(),
                );
            }
            let context = load_context(Path::new(&arguments[2]))?;
            if scope == "destroy-all-nonterminal-lanes" {
                context
                    .lifecycle
                    .setup_host_network()
                    .map_err(|error| error.to_string())?;
                context
                    .lifecycle
                    .startup_reconcile_all_nonterminal()
                    .map_err(|error| error.to_string())?;
            } else {
                context
                    .lifecycle
                    .shutdown_destroy_all_owned()
                    .map_err(|error| error.to_string())?;
            }
            return persist_admin_aggregate_result(&context, scope);
        }
        if arguments.len() != 7
            || arguments[1] != "--config"
            || arguments[3] != "--lane-id"
            || arguments[5] != "--capability-file"
        {
            return Err(
                "usage: serverware-coder-lifecycle-privileged-v12 admin-create-private-dind-v12|admin-destroy-private-dind-v12|admin-reconcile-private-dind-v12 --config ABSOLUTE_PATH --lane-id LANE_ID --capability-file ABSOLUTE_PATH"
                    .into(),
            );
        }
        let mode = arguments[0]
            .to_str()
            .ok_or("admin mode is not UTF-8")?;
        let context = load_context(Path::new(&arguments[2]))?;
        let bytes = secure_read(
            Path::new(&arguments[6]),
            MAX_FRAME_BYTES,
            0,
        )?;
        let request: PrivateDindOperationRequestV12 =
            serde_json::from_slice(&bytes)
                .map_err(|_| "admin capability is not a v12 lifecycle request")?;
        if canonical_plan_bytes(&request)
            .map_err(|error| error.to_string())?
            != bytes
        {
            return Err("admin capability is not canonical JSON".into());
        }
        request.validate().map_err(|error| error.to_string())?;
        let operation = DockerLaneOperationV12::from_proxy_request(
            request.proxy_request.clone(),
            request.attached_fd_roles.len(),
        )
        .map_err(|error| error.to_string())?;
        if operation.lane_id()
            != arguments[4]
                .to_str()
                .ok_or("admin lane ID is not UTF-8")?
        {
            return Err("admin lane ID differs from capability".into());
        }
        let mode_matches = match mode {
            "admin-create-private-dind-v12" => matches!(
                operation.request.operation,
                ProxyOperation::CreateBuildDind
                    | ProxyOperation::CreateNoBuildDind
            ),
            "admin-destroy-private-dind-v12" => matches!(
                operation.request.operation,
                ProxyOperation::DestroyBuildDind
                    | ProxyOperation::DestroyNoBuildDind
            ),
            "admin-reconcile-private-dind-v12" => {
                operation.request.operation
                    == ProxyOperation::QueryAuthoritativeState
            }
            _ => false,
        };
        if !mode_matches {
            return Err(
                "admin mode differs from capability operation".into(),
            );
        }
        let fds = inherited_admin_fds(
            request.attached_fd_roles.len(),
        )?;
        validate_request_policy_assets(&context, &operation)?;
        let (response, returned) = context
            .lifecycle
            .execute_lane_request(&request, fds)
            .map_err(|error| error.to_string())?;
        if !returned.is_empty() {
            return Err(
                "admin operation cannot release capability FDs on stdout"
                    .into(),
            );
        }
        let response = canonical_plan_bytes(&response)
            .map_err(|error| error.to_string())?;
        std::io::stdout()
            .write_all(&response)
            .map_err(|error| error.to_string())
    }

    fn inherited_admin_fds(count: usize) -> Result<Vec<OwnedFd>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let value = std::env::var("SERVERWARE_PRIVATE_DIND_ADMIN_FDS")
            .map_err(|_| {
                "admin create requires SERVERWARE_PRIVATE_DIND_ADMIN_FDS"
            })?;
        let values = value
            .split(',')
            .map(|value| {
                value
                    .parse::<RawFd>()
                    .map_err(|_| "admin inherited FD is invalid".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() != count {
            return Err(
                "admin inherited FD count differs from capability".into(),
            );
        }
        values
            .into_iter()
            .map(|raw| {
                let duplicated = unsafe {
                    libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3)
                };
                if duplicated < 0 {
                    Err(std::io::Error::last_os_error().to_string())
                } else {
                    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
                }
            })
            .collect()
    }

    fn persist_admin_aggregate_result(
        context: &RootContext,
        scope: &str,
    ) -> Result<(), String> {
        let terminal_observation_sha256 = context
            .lifecycle
            .terminal_observation_sha256()
            .map_err(|error| error.to_string())?;
        let public_der = context
            .signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|error| error.to_string())?
            .as_bytes()
            .to_vec();
        let mut result = AdminAggregateTerminalResult {
            protocol:
                "serverware/private-dind-admin-aggregate-terminal/v12"
                    .to_owned(),
            scope: scope.to_owned(),
            disposition: "DESTROYED".to_owned(),
            terminal_observation_sha256,
            policy_binding_sha256: context.policy_binding_sha256,
            root_signer_spki_sha256:
                context.root_signer_spki_sha256,
            root_signer_public_key_spki_der: public_der,
            root_signature: Vec::new(),
            result_sha256: [0; 32],
        };
        let unsigned = canonical_json(&result, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        result.root_signature = context
            .signing_key
            .sign(
                &[
                    ADMIN_AGGREGATE_SIGNATURE_DOMAIN,
                    unsigned.as_slice(),
                ]
                .concat(),
            )
            .to_bytes()
            .to_vec();
        result.result_sha256 = sha256(
            &canonical_json(&result, MAX_FRAME_BYTES)
                .map_err(|error| error.to_string())?,
        );
        let bytes = canonical_json(&result, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        let path = context.aggregate_receipt_root.join(format!(
            "aggregate-{}-{}.json",
            scope,
            hex::encode(terminal_observation_sha256),
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| error.to_string())?;
            }
            Err(error)
                if error.kind()
                    == std::io::ErrorKind::AlreadyExists =>
            {
                if secure_read(&path, MAX_FRAME_BYTES, 0)? != bytes {
                    return Err(
                        "aggregate terminal result path is occupied by different evidence"
                            .into(),
                    );
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| error.to_string())
    }

    fn serve_connection(
        context: &RootContext,
        mut stream: UnixStream,
    ) -> Result<(), String> {
        if peer_uid(stream.as_raw_fd())?
            != context.authorized_peer_uid
        {
            return Err(
                "privileged lifecycle peer UID is unauthorized".into(),
            );
        }
        let (bytes, deadline, fds) =
            read_frame(&mut stream, MAX_FDS)?;
        let value: Value = parse_canonical_json(&bytes, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        if value.get("protocol").and_then(Value::as_str)
            == Some(PRIVATE_DIND_LIFECYCLE_PROTOCOL_V12)
        {
            let request: PrivateDindOperationRequestV12 =
                serde_json::from_value(value).map_err(|_| {
                    "private DinD lifecycle request is invalid".to_owned()
                })?;
            if request.proxy_request.deadline_boottime_ns != deadline {
                return Err(
                    "private DinD frame deadline differs from request"
                        .into(),
                );
            }
            let operation = DockerLaneOperationV12::from_proxy_request(
                request.proxy_request.clone(),
                fds.len(),
            )
            .map_err(|error| error.to_string())?;
            validate_request_policy_assets(context, &operation)?;
            let (response, returned) = context
                .lifecycle
                .execute_lane_request(&request, fds)
                .map_err(|error| error.to_string())?;
            let response = canonical_plan_bytes(&response)
                .map_err(|error| error.to_string())?;
            return write_frame(
                &mut stream,
                &response,
                deadline,
                &returned,
            );
        }
        if !fds.is_empty() {
            return Err("cleanup request carried descriptors".into());
        }
        let request: LifecycleCleanupRequestV12 =
            serde_json::from_value(value)
                .map_err(|_| "cleanup request is invalid")?;
        request.validate().map_err(|error| error.to_string())?;
        if request.cleanup_deadline_boottime_ns != deadline
            || request.boot_id_sha256
                != super::plan_protocol::current_boot_id_sha256()
                    .map_err(|error| error.to_string())?
            || request.configuration_generation_sha256
                != context.configuration_generation_sha256
            || request.controller_signer_spki_sha256
                != context.controller_signer_spki_sha256
            || request.plan_id
                != sha256(
                    &[
                        b"serverware/controller-plan-id/v12\0"
                            .as_slice(),
                        request.request_sha256.as_slice(),
                        request
                            .configuration_generation_sha256
                            .as_slice(),
                    ]
                    .concat(),
                )
        {
            return Err(
                "cleanup frame or exact signed-generation plan authority differs from request"
                    .into(),
            );
        }
        let scoped = context
            .lifecycle
            .destroy_nonterminal_for_plan(
                request.plan_id,
                request.request_sha256_canonical,
                request.cleanup_deadline_boottime_ns,
            )
            .map_err(|error| error.to_string())?;
        if scoped.plan_id != request.plan_id {
            return Err(
                "plan-scoped cleanup crossed request authority".into(),
            );
        }
        let response =
            signed_cleanup_response(context, &request, &scoped)?;
        let bytes = canonical_json(&response, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        write_frame(&mut stream, &bytes, deadline, &[])
    }

    fn signed_cleanup_response(
        context: &RootContext,
        request: &LifecycleCleanupRequestV12,
        scoped: &ScopedTerminalDestructionV12,
    ) -> Result<CleanupResponse, String> {
        let public_der = context
            .signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|error| error.to_string())?
            .as_bytes()
            .to_vec();
        let mut decoded_receipts =
            Vec::with_capacity(scoped.exact_terminal_receipts.len());
        let mut exact_receipt_sha256s =
            Vec::with_capacity(scoped.exact_terminal_receipts.len());
        for exact in &scoped.exact_terminal_receipts {
            let receipt: RootTerminalDestructionReceiptV12 =
                parse_canonical_json(exact, MAX_FRAME_BYTES)
                    .map_err(|error| error.to_string())?;
            if receipt.plan_id != request.plan_id
                || canonical_plan_bytes(&receipt)
                    .map_err(|error| error.to_string())?
                    != *exact
            {
                return Err(
                    "plan-scoped cleanup receipt is noncanonical or crossed plan authority"
                        .into(),
                );
            }
            exact_receipt_sha256s.push(sha256(exact));
            decoded_receipts.push(receipt);
        }
        let mut aggregate = PlanScopedTerminalAggregateV12 {
            protocol:
                "serverware/private-dind-plan-aggregate-terminal/v12"
                    .to_owned(),
            plan_id: request.plan_id,
            request_sha256_canonical:
                request.request_sha256_canonical,
            idempotency_key_sha256:
                request.idempotency_key_sha256,
            observed_terminal_sha256:
                scoped.observed_terminal_sha256,
            exact_receipt_sha256s,
            exact_terminal_receipts:
                scoped.exact_terminal_receipts.clone(),
            root_signer_spki_sha256:
                context.root_signer_spki_sha256,
            root_signer_public_key_spki_der: public_der.clone(),
            root_signature: Vec::new(),
            aggregate_sha256: [0; 32],
        };
        let unsigned = canonical_json(&aggregate, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        aggregate.root_signature = context
            .signing_key
            .sign(
                &[
                    PLAN_AGGREGATE_SIGNATURE_DOMAIN,
                    unsigned.as_slice(),
                ]
                .concat(),
            )
            .to_bytes()
            .to_vec();
        aggregate.aggregate_sha256 = sha256(
            &canonical_json(&aggregate, MAX_FRAME_BYTES)
                .map_err(|error| error.to_string())?,
        );
        let aggregate_bytes =
            canonical_json(&aggregate, MAX_FRAME_BYTES)
                .map_err(|error| error.to_string())?;
        persist_plan_aggregate(context, &aggregate, &aggregate_bytes)?;
        let facts = cleanup_fact_digests(
            request,
            &aggregate,
            &decoded_receipts,
        )?;
        let mut response = CleanupResponse {
            protocol: CONTROLLER_LIFECYCLE_PROTOCOL_V12.to_owned(),
            operation: "DESTROY_AND_RECONCILE".to_owned(),
            disposition: "DESTROYED".to_owned(),
            request_sha256_canonical:
                request.request_sha256_canonical,
            lane_generation_sha256:
                facts["laneGeneration"],
            acceptance_revoked_sha256:
                facts["acceptanceRevoked"],
            cgroup_kill_sha256: facts["cgroupKill"],
            cgroup_empty_sha256: facts["cgroupEmpty"],
            dind_destroyed_sha256: facts["dindDestroyed"],
            network_destroyed_sha256:
                facts["networkDestroyed"],
            mounts_destroyed_sha256:
                facts["mountsDestroyed"],
            sockets_destroyed_sha256:
                facts["socketsDestroyed"],
            cleanup_terminal_sha256:
                aggregate.aggregate_sha256,
            exact_plan_terminal_aggregate:
                aggregate_bytes.clone(),
            plan_terminal_aggregate_sha256:
                sha256(&aggregate_bytes),
            root_signer_spki_sha256:
                context.root_signer_spki_sha256,
            root_signer_public_key_spki_der: public_der,
            root_signature: Vec::new(),
            privileged_response_sha256: [0; 32],
        };
        let projection = canonical_json(&response, MAX_FRAME_BYTES)
            .map_err(|error| error.to_string())?;
        response.root_signature = context
            .signing_key
            .sign(
                &[
                    CLEANUP_SIGNATURE_DOMAIN,
                    projection.as_slice(),
                ]
                .concat(),
            )
            .to_bytes()
            .to_vec();
        response.privileged_response_sha256 = sha256(
            &canonical_json(&response, MAX_FRAME_BYTES)
                .map_err(|error| error.to_string())?,
        );
        Ok(response)
    }

    fn cleanup_fact_digests(
        request: &LifecycleCleanupRequestV12,
        aggregate: &PlanScopedTerminalAggregateV12,
        receipts: &[RootTerminalDestructionReceiptV12],
    ) -> Result<BTreeMap<String, Digest>, String> {
        let generation = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "capabilitySha256": receipt.capability_sha256,
                    "daemonGeneration": receipt.daemon_generation,
                    "networkNamespace": receipt.network_namespace,
                    "ownerNamespace": receipt.owner_namespace,
                    "profile": receipt.profile,
                    "receiptSha256": receipt.receipt_sha256,
                })
            })
            .collect::<Vec<_>>();
        let acceptance = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "ledgerTerminal": receipt.ledger_terminal,
                    "proxyAccepting": receipt.proxy_accepting,
                    "receiptSha256": receipt.receipt_sha256,
                })
            })
            .collect::<Vec<_>>();
        let cgroups = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "cgroupProcesses": receipt.cgroup_processes,
                    "dindReaped": receipt.dind_reaped,
                    "receiptSha256": receipt.receipt_sha256,
                })
            })
            .collect::<Vec<_>>();
        let dind = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "containers": receipt.containers,
                    "dindReaped": receipt.dind_reaped,
                    "drainedContainers": receipt.drained_containers,
                    "drainedImages": receipt.drained_images,
                    "drainedVolumes": receipt.drained_volumes,
                    "dockerAuthorityEstablished":
                        receipt.docker_authority_established,
                    "images": receipt.images,
                    "receiptSha256": receipt.receipt_sha256,
                    "volumes": receipt.volumes,
                })
            })
            .collect::<Vec<_>>();
        let network = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "drainedNetworks": receipt.drained_networks,
                    "netnsAbsent": receipt.netns_absent,
                    "networks": receipt.networks,
                    "receiptSha256": receipt.receipt_sha256,
                })
            })
            .collect::<Vec<_>>();
        let mounts = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "mounts": receipt.mounts,
                    "receiptSha256": receipt.receipt_sha256,
                    "stateRootAbsent": receipt.state_root_absent,
                })
            })
            .collect::<Vec<_>>();
        let sockets = receipts
            .iter()
            .map(|receipt| {
                json!({
                    "receiptSha256": receipt.receipt_sha256,
                    "socketAbsent": receipt.socket_absent,
                })
            })
            .collect::<Vec<_>>();
        let mut facts = BTreeMap::new();
        for (name, evidence) in [
            ("laneGeneration", generation),
            ("acceptanceRevoked", acceptance),
            ("cgroupKill", cgroups.clone()),
            ("cgroupEmpty", cgroups),
            ("dindDestroyed", dind),
            ("networkDestroyed", network),
            ("mountsDestroyed", mounts),
            ("socketsDestroyed", sockets),
        ] {
            let value = json!({
                "aggregateSha256": aggregate.aggregate_sha256,
                "evidence": evidence,
                "fact": name,
                "planId": request.plan_id,
                "requestSha256Canonical":
                    request.request_sha256_canonical,
                "version":
                    "serverware/private-dind-cleanup-fact/v12",
            });
            facts.insert(
                name.to_owned(),
                sha256(
                    &canonical_json(&value, MAX_FRAME_BYTES)
                        .map_err(|error| error.to_string())?,
                ),
            );
        }
        Ok(facts)
    }

    fn persist_plan_aggregate(
        context: &RootContext,
        aggregate: &PlanScopedTerminalAggregateV12,
        exact: &[u8],
    ) -> Result<(), String> {
        let path = context.aggregate_receipt_root.join(format!(
            "plan-{}-request-{}.json",
            hex::encode(aggregate.plan_id),
            hex::encode(aggregate.request_sha256_canonical),
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(exact)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| error.to_string())?;
                File::open(&context.aggregate_receipt_root)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| error.to_string())?;
            }
            Err(error)
                if error.kind()
                    == std::io::ErrorKind::AlreadyExists =>
            {
                if secure_read(&path, MAX_FRAME_BYTES, 0)? != exact {
                    return Err(
                        "plan aggregate path contains different exact evidence"
                            .into(),
                    );
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        Ok(())
    }

    fn load_context(path: &Path) -> Result<RootContext, String> {
        let config_bytes =
            secure_read(path, MAX_CONFIG_BYTES, 0)?;
        let values = parse_kv(&config_bytes)?;
        for (key, expected) in [
            ("contract_version", "12"),
            ("mode", "privileged-helper-v12"),
            ("socket_activation", "systemd-listen-fds"),
            ("startup_reconcile_owned_resources", "true"),
            ("shutdown_destroy_all_owned_resources", "true"),
            ("destroy_on_any_failure", "true"),
            ("host_docker_socket", "forbidden"),
            ("global_docker_daemon", "forbidden"),
            ("legacy_v11_lease", "forbidden"),
            ("terminal_destruction_receipt", "required-signed-v12"),
            (
                "readiness_probe_order",
                "docker-upgrade,service-health,chromium,teardown",
            ),
            (
                "readiness_before_repository_work_every_invocation",
                "true",
            ),
            (
                "docker_top_level_object_count_scope",
                super::docker_contract::DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
            ),
            (
                "docker_internal_storage_absence_proof",
                super::docker_contract::DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
            ),
            ("netns_prefix", "serverware-coder-v12-"),
            ("host_veth_prefix", "swv12h"),
            (
                "network_identity_allocator",
                "root-locked-generation-allocation-v12",
            ),
            ("network_subnet_cidr", "10.64.0.0/10"),
            ("network_subnet_prefix_length", "30"),
            ("network_subnet_probe_bound", "4096"),
        ] {
            if required(&values, key)? != expected {
                return Err(format!(
                    "privileged lifecycle config differs at {key}"
                ));
            }
        }
        let release_key = load_public_key(&path_value(
            &values,
            "release_manifest_public_key",
        )?)?;
        let release_bytes = verify_signed_file(
            &path_value(&values, "release_manifest")?,
            &path_value(&values, "release_manifest_signature")?,
            &release_key,
        )?;
        let release = parse_kv(&release_bytes)?;
        if required(&release, "manifest_version")? != "12"
            || required(&release, "trust_profile")?
                != "trusted-host-userspace-digest-no-ima"
            || digest_value(
                &release,
                "lifecycle_privileged_config_sha256",
            )? != sha256(&config_bytes)
        {
            return Err(
                "privileged lifecycle config is not release-bound".into(),
            );
        }
        let (
            allowed_pinned_pulls,
            allowed_exact_builds,
            policy_binding_sha256,
            configuration_generation_sha256,
        ) = validate_signed_policy_bindings(
            &values,
            &config_bytes,
            &release,
        )?;
        let signing_key = load_signing_key(required(
            &values,
            "private_key_credential",
        )?)?;
        let root_signer_spki_sha256 = digest_value(
            &release,
            "lifecycle_privileged_authority_spki_sha256",
        )?;
        let controller_signer_spki_sha256 = digest_value(
            &release,
            "controller_identity_spki_sha256",
        )?;
        let actual_spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|error| error.to_string())?;
        if sha256(actual_spki.as_bytes())
            != root_signer_spki_sha256
        {
            return Err(
                "privileged lifecycle key differs from release pin".into(),
            );
        }
        let state_root = path_value(&values, "state_root")?;
        let aggregate_receipt_root = path_value(
            &values,
            "terminal_destruction_receipt_root",
        )?;
        let (
            readiness_trust,
            readiness_public_key,
            readiness_manifest,
        ) = load_readiness_root_bindings(&values, &release)?;
        let readiness_fixture_assets_sha256 =
            readiness_trust
                .fixture_assets_digest()
                .map_err(|error| error.to_string())?;
        let lifecycle_config = PrivateDindConfigV12 {
            lane_ledger_root: state_root.join("lane-ledger-v12"),
            network_ownership_ledger: path_value(
                &values,
                "ownership_ledger",
            )?,
            terminal_receipt_root: path_value(
                &values,
                "terminal_destruction_receipt_root",
            )?,
            dind_root: path_value(&values, "dind_root")?,
            cgroup_root: path_value(&values, "cgroup_root")?,
            private_socket_root: path_value(
                &values,
                "private_socket_root",
            )?,
            private_mount_root: path_value(
                &values,
                "private_mount_root",
            )?,
            netns_root: path_value(&values, "netns_root")?,
            netns_prefix: required(&values, "netns_prefix")?.to_owned(),
            network_hook: path_value(&values, "network_hook")?,
            network_hook_sha256: digest_value(
                &release,
                "network_hook_sha256",
            )?,
            host_ruleset: path_value(&values, "host_ruleset")?,
            host_cleanup_ruleset: path_value(
                &values,
                "host_cleanup_ruleset",
            )?,
            build_lane_ruleset: path_value(
                &values,
                "build_lane_ruleset",
            )?,
            no_build_lane_ruleset: path_value(
                &values,
                "no_build_lane_ruleset",
            )?,
            lane_cleanup_ruleset: path_value(
                &values,
                "lane_cleanup_ruleset",
            )?,
            dockerd_binary: path_value(&values, "dockerd_binary")?,
            dockerd_sha256: digest_value(
                &release,
                "dockerd_binary_sha256",
            )?,
            containerd_binary: path_value(
                &values,
                "containerd_binary",
            )?,
            containerd_sha256: digest_value(
                &release,
                "containerd_binary_sha256",
            )?,
            containerd_shim_binary: path_value(
                &values,
                "containerd_shim_binary",
            )?,
            containerd_shim_sha256: digest_value(
                &release,
                "containerd_shim_binary_sha256",
            )?,
            runc_binary: path_value(&values, "runc_binary")?,
            runc_sha256: digest_value(
                &release,
                "runc_binary_sha256",
            )?,
            readiness_fixture_key_id:
                readiness_trust.fixture_key_id,
            readiness_fixture_public_key:
                readiness_public_key.to_bytes(),
            readiness_fixture_assets_sha256:
                readiness_fixture_assets_sha256,
            readiness_fixture_root: path_value(
                &values,
                "readiness_fixture_root",
            )?,
            readiness_docker_client_stream: path_value(
                &values,
                "readiness_docker_client_stream",
            )?,
            readiness_docker_client_stream_sha256: digest_value(
                &readiness_manifest,
                "docker_101_fixture_sha256",
            )?,
            readiness_docker_server_stream: path_value(
                &values,
                "readiness_docker_server_stream",
            )?,
            readiness_docker_server_stream_sha256: digest_value(
                &readiness_manifest,
                "docker_half_close_fixture_sha256",
            )?,
            readiness_service_image_archive: path_value(
                &values,
                "readiness_service_image_archive",
            )?,
            readiness_service_image_archive_sha256: digest_value(
                &release,
                "runner_oci_sha256",
            )?,
            readiness_service_probe: path_value(
                &values,
                "readiness_service_probe",
            )?,
            readiness_service_probe_sha256: digest_value(
                &readiness_manifest,
                "service_health_fixture_sha256",
            )?,
            readiness_browser_image_archive: path_value(
                &values,
                "readiness_browser_image_archive",
            )?,
            readiness_browser_image_archive_sha256: digest_value(
                &release,
                "browser_oci_sha256",
            )?,
            readiness_chromium_page: path_value(
                &values,
                "readiness_chromium_page",
            )?,
            readiness_chromium_page_sha256: digest_value(
                &readiness_manifest,
                "chromium_page_fixture_sha256",
            )?,
            readiness_chromium_script: path_value(
                &values,
                "readiness_chromium_script",
            )?,
            readiness_chromium_script_sha256: digest_value(
                &readiness_manifest,
                "chromium_script_fixture_sha256",
            )?,
            readiness_chromium_probe: path_value(
                &values,
                "readiness_chromium_probe",
            )?,
            readiness_chromium_probe_sha256: digest_value(
                &readiness_manifest,
                "chromium_probe_fixture_sha256",
            )?,
            readiness_chromium_expected_cdp: path_value(
                &values,
                "readiness_chromium_expected_cdp",
            )?,
            readiness_chromium_expected_cdp_sha256: digest_value(
                &readiness_manifest,
                "chromium_expected_cdp_sha256",
            )?,
            readiness_chromium_expected_dom: path_value(
                &values,
                "readiness_chromium_expected_dom",
            )?,
            readiness_chromium_expected_dom_sha256: digest_value(
                &readiness_manifest,
                "chromium_expected_dom_sha256",
            )?,
            readiness_chromium_expected_js: path_value(
                &values,
                "readiness_chromium_expected_js",
            )?,
            readiness_chromium_expected_js_sha256: digest_value(
                &readiness_manifest,
                "chromium_expected_js_sha256",
            )?,
            readiness_chromium_expected_fetch: path_value(
                &values,
                "readiness_chromium_expected_fetch",
            )?,
            readiness_chromium_expected_fetch_sha256: digest_value(
                &readiness_manifest,
                "chromium_expected_fetch_sha256",
            )?,
            readiness_teardown_fixture: path_value(
                &values,
                "readiness_teardown_fixture",
            )?,
            readiness_teardown_fixture_sha256: digest_value(
                &readiness_manifest,
                "teardown_fixture_sha256",
            )?,
            root_signer_spki_sha256,
            state_root,
        };
        for (path, digest_key) in [
            (&lifecycle_config.host_ruleset, "host_nft_sha256"),
            (
                &lifecycle_config.host_cleanup_ruleset,
                "host_cleanup_nft_sha256",
            ),
            (
                &lifecycle_config.build_lane_ruleset,
                "build_lane_nft_sha256",
            ),
            (
                &lifecycle_config.no_build_lane_ruleset,
                "no_build_lane_nft_sha256",
            ),
            (
                &lifecycle_config.lane_cleanup_ruleset,
                "lane_cleanup_nft_sha256",
            ),
        ] {
            if secure_digest(path, 16 * 1024 * 1024)?
                != digest_value(&release, digest_key)?
            {
                return Err(format!(
                    "privileged lifecycle ruleset differs from {digest_key}"
                ));
            }
        }
        let lifecycle = PrivateDindLifecycleV12::open(
            lifecycle_config,
            signing_key.clone(),
        )
        .map_err(|error| error.to_string())?;
        Ok(RootContext {
            lifecycle: Arc::new(lifecycle),
            signing_key,
            root_signer_spki_sha256,
            authorized_peer_uid: required(
                &values,
                "authorized_peer_uid",
            )?
            .parse::<u32>()
            .map_err(|_| "authorized peer UID is invalid")?,
            allowed_pinned_pulls,
            allowed_exact_builds,
            aggregate_receipt_root,
            policy_binding_sha256,
            configuration_generation_sha256,
            controller_signer_spki_sha256,
        })
    }

    fn load_readiness_root_bindings(
        config: &BTreeMap<String, String>,
        release: &BTreeMap<String, String>,
    ) -> Result<
        (
            PinnedReadinessTrustV12,
            VerifyingKey,
            BTreeMap<String, String>,
        ),
        String,
    > {
        let trust_config_path =
            path_value(config, "readiness_trust_config")?;
        let trust_config =
            secure_read(&trust_config_path, MAX_CONFIG_BYTES, 0)?;
        if sha256(&trust_config)
            != digest_value(release, "executor_config_sha256")?
        {
            return Err(
                "readiness trust configuration is not release-bound".into(),
            );
        }
        let trust_document: Value =
            serde_json::from_slice(&trust_config).map_err(|error| {
                format!("parse root-pinned readiness trust: {error}")
            })?;
        let executor_lifecycle_signer = trust_document
            .get("lifecycle_root_signer_spki_sha256")
            .and_then(Value::as_str)
            .ok_or(
                "executor configuration lacks the privileged lifecycle signer pin",
            )?;
        if executor_lifecycle_signer
            != required(
                release,
                "lifecycle_privileged_authority_spki_sha256",
            )?
            || executor_lifecycle_signer
                != required(
                    release,
                    "executor_lifecycle_root_signer_spki_sha256",
                )?
        {
            return Err(
                "executor configuration privileged signer pin differs from signed release"
                    .into(),
            );
        }
        if trust_document
            .get(
                "full_signed_readiness_before_repository_work_every_invocation",
            )
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(
                "executor configuration does not require full per-invocation readiness"
                    .into(),
            );
        }
        let pinned: PinnedReadinessTrustV12 = serde_json::from_value(
            trust_document
                .get("readiness_trust")
                .cloned()
                .ok_or("readiness trust configuration is absent")?,
        )
        .map_err(|error| {
            format!("parse root-pinned readiness binding: {error}")
        })?;
        let runtime = pinned
            .clone()
            .into_runtime()
            .map_err(|error| error.to_string())?;
        let public_key_path =
            path_value(config, "readiness_fixture_public_key")?;
        if secure_digest(&public_key_path, 64 * 1024)?
            != digest_value(
                release,
                "readiness_fixture_public_key_sha256",
            )?
        {
            return Err(
                "readiness public key is not release-bound".into(),
            );
        }
        let public_key = load_public_key(&public_key_path)?;
        if public_key.to_bytes() != runtime.key.to_bytes()
            || runtime.key_id != pinned.fixture_key_id
        {
            return Err(
                "readiness executor trust differs from the root-pinned key"
                    .into(),
            );
        }
        let manifest_path =
            path_value(config, "readiness_fixture_manifest")?;
        let signature_path = path_value(
            config,
            "readiness_fixture_manifest_signature",
        )?;
        let manifest_bytes = verify_signed_file(
            &manifest_path,
            &signature_path,
            &public_key,
        )?;
        if sha256(&manifest_bytes)
                != digest_value(release, "readiness_manifest_sha256")?
            || secure_digest(&signature_path, 4096)?
                != digest_value(
                    release,
                    "readiness_signature_sha256",
                )?
        {
            return Err(
                "signed readiness manifest is not release-bound".into(),
            );
        }
        let manifest = parse_kv(&manifest_bytes)?;
        let derived_fixture_set_id =
            derived_readiness_fixture_set_id_v12(&manifest)?;
        if required(&manifest, "manifest_version")? != "12"
            || required(&manifest, "fixture_set_id")?.is_empty()
            || required_lowerhex_digest_v12(
                &manifest,
                "fixture_set_id",
            )?
                != pinned
                    .fixture_assets_digest()
                    .map_err(|error| error.to_string())?
            || required_lowerhex_digest_v12(
                &manifest,
                "fixture_set_id",
            )?
                != derived_fixture_set_id
            || digest_value(release, "readiness_fixture_set_id")?
                != derived_fixture_set_id
            || required(release, "readiness_probe_order")?
                != "docker-upgrade,service-health,chromium,teardown"
            || required(
                release,
                "readiness_before_repository_work_every_invocation",
            )? != "true"
            || path_value(
                &manifest,
                "fixture_signing_public_key",
            )? != public_key_path
            || path_value(&manifest, "fixture_signature")?
                != signature_path
        {
            return Err(
                "signed readiness manifest header is invalid".into(),
            );
        }
        for requirement in [
            "require_docker_101",
            "require_half_close",
            "require_build_pinned_pull",
            "require_build_unpinned_egress_denied",
            "require_no_build_egress_denied",
            "require_service_start_health_stop",
            "require_chromium_cdp",
            "require_dom_sentinel",
            "require_javascript_sentinel",
            "require_fetch_sentinel",
            "require_teardown_proof",
        ] {
            if required(&manifest, requirement)? != "true" {
                return Err(format!(
                    "signed readiness manifest disables {requirement}"
                ));
            }
        }
        Ok((pinned, public_key, manifest))
    }

    fn derived_readiness_fixture_set_id_v12(
        manifest: &BTreeMap<String, String>,
    ) -> Result<Digest, String> {
        const DIGEST_KEYS: &[&str] = &[
            "docker_101_fixture_sha256",
            "docker_half_close_fixture_sha256",
            "build_pinned_pull_fixture_sha256",
            "build_unpinned_egress_denied_fixture_sha256",
            "no_build_egress_denied_fixture_sha256",
            "service_health_fixture_sha256",
            "chromium_page_fixture_sha256",
            "chromium_script_fixture_sha256",
            "chromium_probe_fixture_sha256",
            "chromium_expected_cdp_sha256",
            "chromium_expected_dom_sha256",
            "chromium_expected_js_sha256",
            "chromium_expected_fetch_sha256",
            "teardown_fixture_sha256",
        ];
        const FIXED_BINDINGS: &[(&str, &str)] = &[
            (
                "fixture_set_digest_contract",
                "serverware/readiness-assets-digest/v12",
            ),
            ("role.docker_101", "upgrade-client-stream"),
            ("role.docker_half_close", "upgrade-server-stream"),
            (
                "role.build_pinned_pull",
                "build-pinned-pull-contract",
            ),
            (
                "role.build_unpinned_egress_denied",
                "build-egress-denial-contract",
            ),
            (
                "role.no_build_egress_denied",
                "no-build-egress-denial-contract",
            ),
            (
                "role.service_health",
                "service-container-probe-contract",
            ),
            ("role.chromium_page", "chromium-document"),
            ("role.chromium_script", "chromium-javascript"),
            (
                "role.chromium_probe",
                "chromium-container-probe-contract",
            ),
            (
                "role.chromium_expected_cdp",
                "chromium-cdp-expectation",
            ),
            (
                "role.chromium_expected_dom",
                "chromium-dom-expectation",
            ),
            (
                "role.chromium_expected_js",
                "chromium-javascript-expectation",
            ),
            (
                "role.chromium_expected_fetch",
                "chromium-fetch-expectation",
            ),
            (
                "role.teardown",
                "terminal-private-dind-absence-contract",
            ),
            ("require_docker_101", "true"),
            ("require_half_close", "true"),
            ("require_build_pinned_pull", "true"),
            ("require_build_unpinned_egress_denied", "true"),
            ("require_no_build_egress_denied", "true"),
            ("require_service_start_health_stop", "true"),
            ("require_chromium_cdp", "true"),
            ("require_dom_sentinel", "true"),
            ("require_javascript_sentinel", "true"),
            ("require_fetch_sentinel", "true"),
            ("require_teardown_proof", "true"),
            (
                "probe_order",
                "docker-upgrade,service-health,chromium,teardown",
            ),
            ("before_repository_work_every_invocation", "true"),
        ];
        for key in DIGEST_KEYS {
            required_lowerhex_digest_v12(manifest, key)?;
        }
        for (key, expected) in FIXED_BINDINGS {
            if required(manifest, key)? != *expected {
                return Err(format!(
                    "signed readiness asset binding differs from closed v12 contract: {key}",
                ));
            }
        }
        let mut descriptor = Vec::new();
        for key in [
            "fixture_set_digest_contract",
            DIGEST_KEYS[0],
            DIGEST_KEYS[1],
            DIGEST_KEYS[2],
            DIGEST_KEYS[3],
            DIGEST_KEYS[4],
            DIGEST_KEYS[5],
            DIGEST_KEYS[6],
            DIGEST_KEYS[7],
            DIGEST_KEYS[8],
            DIGEST_KEYS[9],
            DIGEST_KEYS[10],
            DIGEST_KEYS[11],
            DIGEST_KEYS[12],
            DIGEST_KEYS[13],
            "role.docker_101",
            "role.docker_half_close",
            "role.build_pinned_pull",
            "role.build_unpinned_egress_denied",
            "role.no_build_egress_denied",
            "role.service_health",
            "role.chromium_page",
            "role.chromium_script",
            "role.chromium_probe",
            "role.chromium_expected_cdp",
            "role.chromium_expected_dom",
            "role.chromium_expected_js",
            "role.chromium_expected_fetch",
            "role.teardown",
            "require_docker_101",
            "require_half_close",
            "require_build_pinned_pull",
            "require_build_unpinned_egress_denied",
            "require_no_build_egress_denied",
            "require_service_start_health_stop",
            "require_chromium_cdp",
            "require_dom_sentinel",
            "require_javascript_sentinel",
            "require_fetch_sentinel",
            "require_teardown_proof",
            "probe_order",
            "before_repository_work_every_invocation",
        ] {
            descriptor.extend_from_slice(key.as_bytes());
            descriptor.push(b'=');
            descriptor.extend_from_slice(required(manifest, key)?.as_bytes());
            descriptor.push(b'\n');
        }
        Ok(sha256(&descriptor))
    }

    fn required_lowerhex_digest_v12(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<Digest, String> {
        let value = required(values, key)?;
        if value.len() != 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
        {
            return Err(format!(
                "{key} must be an exact 64-character lowercase sha256",
            ));
        }
        digest_value(values, key)
    }

    fn validate_signed_policy_bindings(
        config: &BTreeMap<String, String>,
        config_bytes: &[u8],
        release: &BTreeMap<String, String>,
    ) -> Result<
        (
            BTreeSet<Vec<u8>>,
            BTreeSet<Vec<u8>>,
            Digest,
            Digest,
        ),
        String,
    > {
        let generation_key = load_public_key(&path_value(
            config,
            "configuration_authority_public_key",
        )?)?;
        let generation_path =
            path_value(config, "configuration_generation")?;
        let generation_signature = path_value(
            config,
            "configuration_generation_signature",
        )?;
        let generation_bytes = verify_signed_file(
            &generation_path,
            &generation_signature,
            &generation_key,
        )?;
        if digest_value(
            release,
            "config_generation_document_sha256",
        )? != sha256(&generation_bytes)
            || digest_value(
                release,
                "config_generation_signature_sha256",
            )? != secure_digest(&generation_signature, MAX_CONFIG_BYTES as u64)?
        {
            return Err(
                "privileged lifecycle generation is not release-bound".into(),
            );
        }
        let generation = parse_kv(&generation_bytes)?;
        let executor_uid = parse_u32(config, "executor_uid")?;
        if executor_uid != parse_u32(release, "identity.executor.uid")?
            || executor_uid
                != parse_u32(release, "private_dind.executor_uid")?
            || executor_uid
                != parse_u32(&generation, "identity.executor.uid")?
            || executor_uid
                != parse_u32(&generation, "private_dind.executor_uid")?
            || parse_u32(config, "authorized_peer_uid")?
                != parse_u32(release, "identity.lifecycle.uid")?
            || parse_u32(config, "docker_proxy_uid")?
                != parse_u32(release, "identity.docker_proxy.uid")?
            || required(config, "ownership_label.namespace")?
                != OWNER_LABEL_V12
            || required(config, "ownership_label.generation")?
                != GENERATION_LABEL_V12
            || required(config, "ownership_label.lane")?
                != LANE_LABEL_V12
            || required(config, "ownership_label.resource")?
                != RESOURCE_LABEL_V12
            || required(config, "ownership_label.required")? != "true"
        {
            return Err(
                "privileged lifecycle identities or ownership labels differ from signed v12 bindings"
                    .into(),
            );
        }
        for key in [
            "private_dind.global_docker_daemon",
            "private_dind.host_docker_socket",
            "private_dind.legacy_v11_lease",
        ] {
            if required(&generation, key)? != "false" {
                return Err(format!(
                    "signed configuration enables forbidden {key}"
                ));
            }
        }

        let policy_path = path_value(config, "docker_policy")?;
        let policy_bytes =
            secure_read(&policy_path, MAX_POLICY_BYTES, 0)?;
        if digest_value(release, "docker_policy_sha256")?
            != sha256(&policy_bytes)
        {
            return Err(
                "privileged Docker policy is not release-bound".into(),
            );
        }
        let policy = parse_kv(&policy_bytes)?;
        for (key, expected) in [
            ("contract", "serverware/controller-lane-capability/v12"),
            (
                "request_contract",
                "serverware/controller-lane-proxy/v12",
            ),
            ("default", "deny"),
            (
                "enforcement",
                "compiled-rust-source-digest-bound-v12",
            ),
            ("ownership_label.namespace", OWNER_LABEL_V12),
            ("ownership_label.generation", GENERATION_LABEL_V12),
            ("ownership_label.lane", LANE_LABEL_V12),
            ("ownership_label.resource", RESOURCE_LABEL_V12),
        ] {
            if required(&policy, key)? != expected {
                return Err(format!(
                    "privileged Docker policy differs from compiled enforcement at {key}"
                ));
            }
        }
        let ruleset = path_value(&policy, "ruleset_path")?;
        let pinned =
            path_value(&policy, "pinned_pull_set_path")?;
        let exact =
            path_value(&policy, "exact_build_tuple_set_path")?;
        for (path, policy_key, release_key) in [
            (
                &ruleset,
                "ruleset_sha256",
                "docker_api_rule_set_sha256",
            ),
            (
                &pinned,
                "pinned_pull_set_sha256",
                "pinned_pull_set_sha256",
            ),
            (
                &exact,
                "exact_build_tuple_set_sha256",
                "exact_build_tuple_set_sha256",
            ),
        ] {
            let actual =
                secure_digest(path, MAX_POLICY_BYTES as u64)?;
            if actual != digest_value(&policy, policy_key)?
                || actual != digest_value(release, release_key)?
            {
                return Err(format!(
                    "privileged Docker asset differs from signed {release_key}"
                ));
            }
        }
        verify_compiled_ruleset(&ruleset)?;
        let policy_sha256 = sha256(&policy_bytes);
        let ruleset_sha256 =
            secure_digest(&ruleset, MAX_POLICY_BYTES as u64)?;
        let pinned_sha256 =
            secure_digest(&pinned, MAX_POLICY_BYTES as u64)?;
        let exact_sha256 =
            secure_digest(&exact, MAX_POLICY_BYTES as u64)?;
        let config_sha256 = sha256(config_bytes);
        let policy_binding_sha256 = sha256(
            &[
                policy_sha256.as_slice(),
                ruleset_sha256.as_slice(),
                pinned_sha256.as_slice(),
                exact_sha256.as_slice(),
                config_sha256.as_slice(),
            ]
            .concat(),
        );
        Ok((
            load_pinned_pull_set(&pinned)?,
            load_exact_build_set(&exact)?,
            policy_binding_sha256,
            sha256(&generation_bytes),
        ))
    }

    fn verify_compiled_ruleset(path: &Path) -> Result<(), String> {
        let bytes = secure_read(path, MAX_POLICY_BYTES, 0)?;
        let actual: Value =
            parse_canonical_json(&bytes, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?;
        let expected = json!({
            "archiveContract": {
                "format": "serverware/docker-image-archive-set/v12",
                "importVerification":
                    "recanonicalize-and-require-byte-identity",
                "outerContainer": "canonical-ustar-v12",
                "producer":
                    "canonicalize_docker_image_archive_v12"
            },
            "compiledSources": {
                "dindLifecycleSha256": hex::encode(sha256(
                    include_bytes!("../dind_lifecycle.rs")
                )),
                "dockerContractSha256": hex::encode(sha256(
                    include_bytes!("../docker_contract.rs")
                )),
                "dockerPolicySha256": hex::encode(sha256(
                    include_bytes!("../docker_policy.rs")
                ))
            },
            "contract": "serverware/docker-api-rules/v12",
            "default": "deny",
            "enforcement": "compiled-rust-source-digest-bound-v12",
            "operationProfiles": {
                "build": [
                    "createBuildDind", "pullPinned", "buildExact",
                    "createRunner", "runRepositoryBody", "stopRunner",
                    "exportOwnedOci", "destroyBuildDind",
                    "queryAuthoritativeState", "readinessProbe"
                ],
                "noBuild": [
                    "createNoBuildDind", "importSealedOci",
                    "createRunner", "createServices",
                    "runRepositoryBody", "stopRunner",
                    "destroyServices", "destroyNoBuildDind",
                    "queryAuthoritativeState", "readinessProbe"
                ]
            },
            "ownershipLabels": {
                "generation": GENERATION_LABEL_V12,
                "lane": LANE_LABEL_V12,
                "namespace": OWNER_LABEL_V12,
                "resource": RESOURCE_LABEL_V12
            },
            "version": 12
        });
        if actual != expected
            || canonical_json(&actual, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?
                != bytes
        {
            return Err(
                "signed Docker API ruleset differs from compiled v12 enforcement"
                    .into(),
            );
        }
        Ok(())
    }

    fn load_pinned_pull_set(
        path: &Path,
    ) -> Result<BTreeSet<Vec<u8>>, String> {
        let value = load_policy_document(
            path,
            "serverware/pinned-pulls/v12",
            "pulls",
        )?;
        let mut result = BTreeSet::new();
        for entry in value["pulls"]
            .as_array()
            .ok_or("pinned pull policy lacks pulls")?
        {
            let pull: PinnedPull =
                serde_json::from_value(entry.clone())
                    .map_err(|_| "pinned pull entry is invalid")?;
            pull.validate().map_err(|error| error.to_string())?;
            if !result.insert(
                canonical_plan_bytes(&pull)
                    .map_err(|error| error.to_string())?,
            ) {
                return Err("pinned pull policy has a duplicate".into());
            }
        }
        if result.is_empty() {
            return Err("pinned pull policy is empty".into());
        }
        Ok(result)
    }

    fn load_exact_build_set(
        path: &Path,
    ) -> Result<BTreeSet<Vec<u8>>, String> {
        let value = load_policy_document(
            path,
            "serverware/exact-build-tuples/v12",
            "builds",
        )?;
        let mut result = BTreeSet::new();
        for entry in value["builds"]
            .as_array()
            .ok_or("exact build policy lacks builds")?
        {
            let exact: ExactBuildTuple =
                serde_json::from_value(entry.clone())
                    .map_err(|_| "exact build entry is invalid")?;
            exact.validate().map_err(|error| error.to_string())?;
            if !result.insert(
                canonical_plan_bytes(&exact)
                    .map_err(|error| error.to_string())?,
            ) {
                return Err("exact build policy has a duplicate".into());
            }
        }
        if result.is_empty() {
            return Err("exact build policy is empty".into());
        }
        Ok(result)
    }

    fn load_policy_document(
        path: &Path,
        contract: &str,
        array_key: &str,
    ) -> Result<Value, String> {
        let bytes = secure_read(path, MAX_POLICY_BYTES, 0)?;
        let value: Value =
            parse_canonical_json(&bytes, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?;
        let object = value
            .as_object()
            .ok_or("Docker policy set is not an object")?;
        if object.len() != 3
            || value.get("contract").and_then(Value::as_str)
                != Some(contract)
            || value.get("version").and_then(Value::as_u64)
                != Some(12)
            || !value.get(array_key).is_some_and(Value::is_array)
            || canonical_json(&value, MAX_POLICY_BYTES)
                .map_err(|error| error.to_string())?
                != bytes
        {
            return Err(
                "Docker policy set is not exact canonical v12".into(),
            );
        }
        Ok(value)
    }

    fn validate_request_policy_assets(
        context: &RootContext,
        operation: &DockerLaneOperationV12,
    ) -> Result<(), String> {
        let DockerLaneDecodedPayloadV12::Operation(payload) =
            &operation.decoded_payload
        else {
            return Ok(());
        };
        let validate_pull = |pull: &PinnedPull| {
            let bytes = canonical_plan_bytes(pull)
                .map_err(|error| error.to_string())?;
            context
                .allowed_pinned_pulls
                .contains(&bytes)
                .then_some(())
                .ok_or_else(|| {
                    "request pull is absent from signed policy".to_owned()
                })
        };
        let validate_build = |exact: &ExactBuildTuple| {
            let bytes = canonical_plan_bytes(exact)
                .map_err(|error| error.to_string())?;
            if !context.allowed_exact_builds.contains(&bytes) {
                return Err(
                    "request build is absent from signed policy".to_owned(),
                );
            }
            for pull in &exact.pinned_pulls {
                validate_pull(pull)?;
            }
            Ok(())
        };
        match &payload.content {
            DockerLanePayloadContentV12::CreateBuildDind {
                exact_build,
                ..
            }
            | DockerLanePayloadContentV12::BuildExact {
                exact_build,
            } => validate_build(exact_build),
            DockerLanePayloadContentV12::PullPinned { pull } => {
                validate_pull(pull)
            }
            _ => Ok(()),
        }
    }

    fn parse_u32(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<u32, String> {
        required(values, key)?
            .parse::<u32>()
            .map_err(|_| format!("{key} is not u32"))
    }

    fn parse_kv(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "manifest is not UTF-8")?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) =
                line.split_once('=').ok_or("manifest line lacks '='")?;
            if key.is_empty()
                || value.is_empty()
                || values
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err("manifest key is empty or duplicated".into());
            }
        }
        Ok(values)
    }

    fn required<'a>(
        values: &'a BTreeMap<String, String>,
        key: &str,
    ) -> Result<&'a str, String> {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("manifest lacks {key}"))
    }

    fn path_value(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<PathBuf, String> {
        let path = PathBuf::from(required(values, key)?);
        if !path.is_absolute() {
            return Err(format!("{key} is not absolute"));
        }
        Ok(path)
    }

    fn digest_value(
        values: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<Digest, String> {
        let bytes =
            hex::decode(required(values, key)?).map_err(|_| {
                format!("{key} is not a hexadecimal digest")
            })?;
        bytes.try_into().map_err(|_| {
            format!("{key} is not a 32-byte digest")
        })
    }

    fn secure_read(
        path: &Path,
        maximum: usize,
        owner: u32,
    ) -> Result<Vec<u8>, String> {
        if !path.is_absolute() {
            return Err("secure path is not absolute".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != owner
            || metadata.mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > maximum as u64
        {
            return Err(format!(
                "secure file metadata rejected: {}",
                path.display()
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != metadata.len() {
            return Err("secure file changed while read".into());
        }
        Ok(bytes)
    }

    fn secure_digest(
        path: &Path,
        maximum: u64,
    ) -> Result<Digest, String> {
        if !path.is_absolute() {
            return Err("digest path is not absolute".into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(format!(
                "digest file metadata rejected: {}",
                path.display()
            ));
        }
        super::coder_controller_v11::sha256_exact_reader(
            &mut file,
            metadata.len(),
        )
        .map_err(|error| error.to_string())
    }

    fn load_public_key(path: &Path) -> Result<VerifyingKey, String> {
        let bytes = secure_read(path, 64 * 1024, 0)?;
        if bytes.len() == 32 {
            return VerifyingKey::from_bytes(
                &bytes
                    .try_into()
                    .map_err(|_| "public key length changed")?,
            )
            .map_err(|error| error.to_string());
        }
        VerifyingKey::from_public_key_pem(
            std::str::from_utf8(&bytes)
                .map_err(|_| "public key is not UTF-8")?,
        )
        .map_err(|error| error.to_string())
    }

    fn verify_signed_file(
        path: &Path,
        signature_path: &Path,
        key: &VerifyingKey,
    ) -> Result<Vec<u8>, String> {
        let bytes = secure_read(path, MAX_CONFIG_BYTES, 0)?;
        let signature = secure_read(signature_path, 4096, 0)?;
        let signature = if signature.len() == 64 {
            signature
        } else {
            URL_SAFE_NO_PAD
                .decode(
                    std::str::from_utf8(&signature)
                        .map_err(|_| "signature is not UTF-8")?
                        .trim(),
                )
                .map_err(|_| "signature is not base64url")?
        };
        key.verify(
            &bytes,
            &Signature::from_slice(&signature)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|_| "release signature is invalid")?;
        Ok(bytes)
    }

    fn load_signing_key(name: &str) -> Result<SigningKey, String> {
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || b"._-".contains(&byte)
            })
        {
            return Err("credential name is invalid".into());
        }
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or("CREDENTIALS_DIRECTORY is absent")?;
        let bytes = secure_read(
            &PathBuf::from(directory).join(name),
            64 * 1024,
            0,
        )?;
        if bytes.len() == 32 {
            return Ok(SigningKey::from_bytes(
                &bytes
                    .try_into()
                    .map_err(|_| "signing key length changed")?,
            ));
        }
        SigningKey::from_pkcs8_pem(
            std::str::from_utf8(&bytes)
                .map_err(|_| "signing key is not UTF-8")?,
        )
        .map_err(|error| error.to_string())
    }

    fn peer_uid(fd: RawFd) -> Result<u32, String> {
        let mut credential: libc::ucred = unsafe { mem::zeroed() };
        let mut length =
            mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credential as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(credential.uid)
    }

    fn read_frame(
        stream: &mut UnixStream,
        maximum_fds: usize,
    ) -> Result<(Vec<u8>, u64, Vec<OwnedFd>), String> {
        let mut header = [0u8; AUTHORITY_FRAME_BYTES];
        let mut iov = libc::iovec {
            iov_base: header.as_mut_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        };
        let control_bytes = unsafe {
            libc::CMSG_SPACE(
                (maximum_fds.max(1) * mem::size_of::<RawFd>())
                    as libc::c_uint,
            ) as usize
        };
        let mut control =
            vec![0usize; control_bytes.div_ceil(mem::size_of::<usize>())];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control =
            control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = control_bytes;
        let count = unsafe {
            libc::recvmsg(
                stream.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count <= 0
            || count as usize > header.len()
            || message.msg_flags
                & (libc::MSG_TRUNC | libc::MSG_CTRUNC)
                != 0
        {
            return Err("lifecycle frame header is truncated".into());
        }
        let mut fds = Vec::new();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !cmsg.is_null() {
            unsafe {
                if (*cmsg).cmsg_level != libc::SOL_SOCKET
                    || (*cmsg).cmsg_type != libc::SCM_RIGHTS
                {
                    return Err(
                        "lifecycle frame control is unsupported".into(),
                    );
                }
                let bytes = (*cmsg)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize);
                let count = bytes / mem::size_of::<RawFd>();
                if bytes % mem::size_of::<RawFd>() != 0
                    || fds.len().saturating_add(count) > maximum_fds
                {
                    return Err(
                        "lifecycle frame descriptor set is invalid".into(),
                    );
                }
                let values = libc::CMSG_DATA(cmsg) as *const RawFd;
                for index in 0..count {
                    fds.push(OwnedFd::from_raw_fd(*values.add(index)));
                }
                cmsg = libc::CMSG_NXTHDR(&message, cmsg);
            }
        }
        if count as usize < header.len() {
            stream
                .read_exact(&mut header[count as usize..])
                .map_err(|error| error.to_string())?;
        }
        let header = AuthorityFrameHeaderV12::decode(
            &header,
            MAX_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let mut bytes = vec![0; header.payload_bytes as usize];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        if sha256(&bytes)
            != header
                .payload_sha256
                .decode()
                .map_err(|error| error.to_string())?
        {
            return Err("lifecycle frame digest differs".into());
        }
        Ok((bytes, header.boottime_deadline_ns, fds))
    }

    fn write_frame(
        stream: &mut UnixStream,
        bytes: &[u8],
        deadline: u64,
        fds: &[OwnedFd],
    ) -> Result<(), String> {
        let header = AuthorityFrameHeaderV12::for_payload(
            bytes,
            deadline,
            MAX_FRAME_BYTES,
        )
        .map_err(|error| error.to_string())?
        .encode(MAX_FRAME_BYTES)
        .map_err(|error| error.to_string())?;
        if fds.is_empty() {
            stream
                .write_all(&header)
                .map_err(|error| error.to_string())?;
        } else {
            let raw =
                fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
            let control_bytes = unsafe {
                libc::CMSG_SPACE(
                    (raw.len() * mem::size_of::<RawFd>())
                        as libc::c_uint,
                ) as usize
            };
            let mut control = vec![
                0usize;
                control_bytes.div_ceil(mem::size_of::<usize>())
            ];
            let mut iov = libc::iovec {
                iov_base: header.as_ptr() as *mut libc::c_void,
                iov_len: header.len(),
            };
            let mut message: libc::msghdr = unsafe { mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control =
                control.as_mut_ptr() as *mut libc::c_void;
            message.msg_controllen = control_bytes;
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&message);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(
                    (raw.len() * mem::size_of::<RawFd>())
                        as libc::c_uint,
                ) as usize;
                std::ptr::copy_nonoverlapping(
                    raw.as_ptr(),
                    libc::CMSG_DATA(cmsg) as *mut RawFd,
                    raw.len(),
                );
            }
            let sent = unsafe {
                libc::sendmsg(
                    stream.as_raw_fd(),
                    &message,
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent <= 0 || sent as usize > header.len() {
                return Err(
                    std::io::Error::last_os_error().to_string(),
                );
            }
            stream
                .write_all(&header[sent as usize..])
                .map_err(|error| error.to_string())?;
        }
        stream
            .write_all(bytes)
            .map_err(|error| error.to_string())
    }
}
