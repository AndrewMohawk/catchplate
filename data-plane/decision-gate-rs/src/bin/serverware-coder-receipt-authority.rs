#![allow(dead_code)]

#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;
#[path = "../receipt_ledger.rs"]
mod receipt_ledger;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use receipt_contract_v12::{
    authority_rpc_v12, build_consistency_proof, build_inclusion_proof,
    canonical_json,
    envelope_digest, extract_request_v11_summary, final_trust_observation_digest,
    finalization_binding_digest, logged_receipt_bundle_digest,
    make_log_leaf, merkle_root, now_utc_rfc3339, parse_canonical_json,
    inspect_activated_listener_v12, notify_systemd_v12,
    peer_uid_v12, read_authority_frame_until_v12, read_authority_frame_v12,
    request_admission_digest,
    requester_replay_identity_digest,
    prepared_binding_digest, receipt_authority_submission_digest,
    receipt_body_digest, replay_identity_digest, sha256_bytes, sign_envelope,
    write_authority_frame_v12,
    AuthorityDeadlineV12, AuthorityRoleV12, CanonicalU64,
    FinalSettlementArtifactV12, FinalSettlementCheckpointV12,
    FinalSettlementRequestV12, FinalSettlementResponseV12,
    FinalVerdictAuthorityRequestV12, FinalVerdictAuthorityResponseV12,
    FinalizedLookupRequestV12, FinalizedLookupResponseV12,
    KeyAuthorizationV12, LogAuthorityRequestV12,
    LogAuthorityResponseV12,
    LedgerHighWaterRequestV12, LedgerHighWaterResponseV12,
    LoggedReceiptBundleV12, ReceiptAuthenticationPayloadV12,
    ReceiptAuthenticationEnvelopeV12, ReceiptAuthorityRequestV12,
    ReceiptAuthorityResponseV12, TrustGenerationResolveRequestV12,
    TrustGenerationResolveResponseV12, WitnessFinalizationRequestV12,
    WitnessFinalizationResponseV12, TreeHeadPayloadV12,
    MAX_AUTHORITY_REQUEST_BYTES,
    MAX_AUTHORITY_RESPONSE_BYTES, RECEIPT_AUTHENTICATION_DOMAIN,
    RECEIPT_CONTRACT_VERSION, REQUEST_CONTRACT_VERSION,
};
use receipt_ledger::{
    BuiltLogAppendV12, LedgerStageV12, PrepareInputV12, ReceiptLedgerV12,
    TransitionDispositionV12,
};
use receipt_verifier_v12::{
    build_final_trust_observation, verify_canonical_request_v11_admission,
    verify_final_settlement_artifact_v12,
    verify_receipt_authentication_envelope_v12, verify_logged_bundle_v12,
    verify_trust_generation_bundle, StrictVerifierPinsV12,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SYSTEMD_LISTEN_FD: i32 = 3;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const FINALIZATION_ABORT_RESERVE_NS: u64 = 2_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptAuthorityConfigV12 {
    config_version: u64,
    ledger_root: PathBuf,
    ledger_owner_uid: u32,
    log_id: String,
    allowed_peer_uids: Vec<u32>,
    controller_uid: u32,
    receipt_authority_uid: u32,
    log_authority_uid: u32,
    final_verdict_authority_uid: u32,
    trust_generation_authority_uid: u32,
    external_witness_authority_uid: u32,
    final_settlement_authority_uid: u32,
    listener_owner_uid: u32,
    listener_mode: u32,
    receipt_authentication_signing_key_path: PathBuf,
    receipt_authentication_authorization: KeyAuthorizationV12,
    log_authority_socket_path: PathBuf,
    final_verdict_authority_socket_path: PathBuf,
    trust_generation_authority_socket_path: PathBuf,
    external_witness_authority_socket_path: PathBuf,
    final_settlement_authority_socket_path: PathBuf,
    external_settlement_anchor_path: PathBuf,
    strict_verifier_pins: StrictVerifierPinsV12,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("receipt authority hard-unready: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::var_os("SERVERWARE_RECEIPT_AUTHORITY_CONFIG")
        .ok_or("SERVERWARE_RECEIPT_AUTHORITY_CONFIG is required")?;
    let config_bytes = read_secure_file(
        Path::new(&config_path),
        MAX_CONFIG_BYTES,
        0,
        false,
    )?;
    let config: ReceiptAuthorityConfigV12 =
        parse_canonical_json(&config_bytes, MAX_CONFIG_BYTES)?;
    validate_config(&config)?;

    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0
        || config.ledger_owner_uid != effective_uid
        || config.receipt_authority_uid != effective_uid
    {
        return Err("receipt authority must be the sole ledger owner UID".into());
    }
    let receipt_key = read_signing_key(
        &config.receipt_authentication_signing_key_path,
        effective_uid,
    )?;
    if receipt_contract_v12::ed25519_spki_sha256(&receipt_key.verifying_key())
        != config
            .strict_verifier_pins
            .receipt_authentication
            .spki_der_sha256
    {
        return Err("receipt-authentication private key does not match current pin".into());
    }

    let ledger = ReceiptLedgerV12::open(
        &config.ledger_root,
        config.ledger_owner_uid,
        config.log_id.clone(),
    )?;
    let anchor_bytes = read_secure_file(
        &config.external_settlement_anchor_path,
        MAX_AUTHORITY_RESPONSE_BYTES,
        0,
        false,
    )?;
    let external_anchor: FinalSettlementCheckpointV12 =
        parse_canonical_json(&anchor_bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
    ledger.startup_recover_verified(
        &config.strict_verifier_pins,
        &external_anchor,
    )?;
    let listener = activated_listener(
        config.listener_owner_uid,
        config.listener_mode,
    )?;
    listener.set_nonblocking(true)?;
    notify_systemd_v12("receipt-authentication-v12 ledger reconciled")?;
    loop {
        if let Err(error) = reconcile_next_finalization(config, &ledger) {
            eprintln!("receipt finalization reconciliation deferred: {error}");
        }
        let (stream, _) = match listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) =
            handle_connection(stream, &config, &ledger, &receipt_key)
        {
            eprintln!("receipt authority rejected request: {error}");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    config: &ReceiptAuthorityConfigV12,
    ledger: &ReceiptLedgerV12,
    receipt_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_uid = peer_uid_v12(&stream)?;
    if !config.allowed_peer_uids.contains(&peer_uid) {
        return Err("peer UID is not authorized".into());
    }
    let (request_bytes, frame) =
        read_authority_frame_v12(&stream, MAX_AUTHORITY_REQUEST_BYTES)?;
    let response = run_killable_worker(frame.boottime_deadline_ns, || {
        process_wire_request(
            &request_bytes,
            config,
            ledger,
            receipt_key,
            frame.boottime_deadline_ns,
        )
    })?;
    write_authority_frame_v12(
        &stream,
        &response,
        MAX_AUTHORITY_RESPONSE_BYTES,
        frame.boottime_deadline_ns,
    )?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerResponseV12 {
    ok: bool,
    payload_base64url: String,
    error_code: String,
}

fn run_killable_worker<F>(
    deadline_ns: u64,
    work: F,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<Vec<u8>, Box<dyn std::error::Error>>,
{
    let (parent, child) = UnixStream::pair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if pid == 0 {
        drop(parent);
        let response = match work() {
            Ok(payload) => WorkerResponseV12 {
                ok: true,
                payload_base64url: URL_SAFE_NO_PAD.encode(payload),
                error_code: String::new(),
            },
            Err(_) => WorkerResponseV12 {
                ok: false,
                payload_base64url: String::new(),
                error_code: "WORKER_REJECTED".to_owned(),
            },
        };
        if let Ok(bytes) = canonical_json(&response, MAX_AUTHORITY_RESPONSE_BYTES) {
            let _ = write_authority_frame_v12(
                &child,
                &bytes,
                MAX_AUTHORITY_RESPONSE_BYTES,
                deadline_ns,
            );
        }
        unsafe { libc::_exit(if response.ok { 0 } else { 1 }) };
    }
    drop(child);
    let received = read_authority_frame_until_v12(
        &parent,
        MAX_AUTHORITY_RESPONSE_BYTES,
        deadline_ns,
    );
    if received.is_err() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err("killable ledger worker exceeded the authority deadline".into());
    }
    let (bytes, frame) = received?;
    if frame.boottime_deadline_ns != deadline_ns {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err("ledger worker changed the authority deadline".into());
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
    {
        return Err("ledger worker did not exit cleanly".into());
    }
    let response: WorkerResponseV12 =
        parse_canonical_json(&bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
    if !response.ok || libc::WEXITSTATUS(status) != 0 {
        return Err(response.error_code.into());
    }
    Ok(URL_SAFE_NO_PAD
        .decode(response.payload_base64url)
        .map_err(|_| "ledger worker payload is not base64url")?)
}

fn process_wire_request(
    exact_request_bytes: &[u8],
    config: &ReceiptAuthorityConfigV12,
    ledger: &ReceiptLedgerV12,
    receipt_key: &SigningKey,
    frame_deadline_ns: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value: Value =
        parse_canonical_json(exact_request_bytes, MAX_AUTHORITY_REQUEST_BYTES)?;
    let operation = value
        .as_object()
        .and_then(|object| object.get("operation"))
        .and_then(Value::as_str)
        .ok_or("authority operation is missing")?;
    match operation {
        "AUTHENTICATE_AND_LOG" => process_authenticate_and_log(
            exact_request_bytes,
            config,
            ledger,
            receipt_key,
            frame_deadline_ns,
        ),
        "GET_HIGH_WATER" => {
            let request: LedgerHighWaterRequestV12 = parse_canonical_json(
                exact_request_bytes,
                MAX_AUTHORITY_REQUEST_BYTES,
            )?;
            if request.request_nonce_sha256 == receipt_contract_v12::DigestHex::zero() {
                return Err("high-water query nonce is empty".into());
            }
            canonical_json(
                &LedgerHighWaterResponseV12 {
                    operation: request.operation,
                    request_nonce_sha256: request.request_nonce_sha256,
                    high_water: ledger.verifier_high_water()?,
                },
                MAX_AUTHORITY_RESPONSE_BYTES,
            )
            .map_err(Into::into)
        }
        "GET_FINALIZED" => {
            let request: FinalizedLookupRequestV12 = parse_canonical_json(
                exact_request_bytes,
                MAX_AUTHORITY_REQUEST_BYTES,
            )?;
            let artifact = ledger
                .finalized_artifact_by_replay(
                    &request.replay_key_sha256,
                    &request.finalization_binding_sha256,
                )?
                .map(|bytes| {
                    parse_canonical_json::<FinalSettlementArtifactV12>(
                        &bytes,
                        MAX_AUTHORITY_RESPONSE_BYTES,
                    )
                })
                .transpose()?;
            canonical_json(
                &FinalizedLookupResponseV12 {
                    operation: request.operation,
                    disposition: if artifact.is_some() {
                        "FOUND".to_owned()
                    } else {
                        "PENDING".to_owned()
                    },
                    replay_key_sha256: request.replay_key_sha256,
                    finalization_binding_sha256: request
                        .finalization_binding_sha256,
                    artifact,
                },
                MAX_AUTHORITY_RESPONSE_BYTES,
            )
            .map_err(Into::into)
        }
        _ => Err("unsupported receipt authority operation".into()),
    }
}

fn process_authenticate_and_log(
    exact_request_bytes: &[u8],
    config: &ReceiptAuthorityConfigV12,
    ledger: &ReceiptLedgerV12,
    receipt_key: &SigningKey,
    frame_deadline_ns: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request: ReceiptAuthorityRequestV12 = parse_canonical_json(
        exact_request_bytes,
        MAX_AUTHORITY_REQUEST_BYTES,
    )?;
    if request.operation != "AUTHENTICATE_AND_LOG" {
        return Err("unsupported receipt authority operation".into());
    }
    receipt_contract_v12::validate_identifier(&request.receipt_id)?;
    receipt_contract_v12::validate_identifier(&request.requester_principal_id)?;
    replay_identity_digest(&request.replay_identity)?;
    if request.deadline.boottime_deadline_ns.get()? != frame_deadline_ns {
        return Err("wire frame and authority request deadlines differ".into());
    }
    let exact_request = URL_SAFE_NO_PAD
        .decode(&request.request_admission.exact_request_base64url)
        .map_err(|_| "exact v11 request is not base64url")?;
    let request_v11 =
        coder_controller_v11::parse_exact_canonical_json_v11(
            &exact_request,
            coder_controller_v11::REQUEST_MAX_BYTES as usize,
        )?;
    let verified_request = verify_canonical_request_v11_admission(
        &request_v11,
        &request.request_admission,
        &config.strict_verifier_pins,
        false,
    )?;
    if verified_request.requester_principal_id
        != request.requester_principal_id
        || request.deadline.request_deadline_unix_ms.get()?
            != verified_request.request_deadline_unix_ms
    {
        return Err("authority request does not join canonical requester or deadline".into());
    }
    let request_summary = verified_request.summary.clone();
    let request_admission_sha256 =
        request_admission_digest(&request.request_admission)?;
    let ledger_identity_sha256 = requester_replay_identity_digest(
        &request.requester_principal_id,
        &request.replay_identity.replay_key_sha256,
    )?;
    if request.receipt_body_template.receipt_id != request.receipt_id
        || request.receipt_body_template.receipt_sequence.get()? != 0
        || request.receipt_body_template.requester_principal_id
            != request.requester_principal_id
        || request.receipt_body_template.replay_key_sha256
            != request.replay_identity.replay_key_sha256
        || request.receipt_body_template.request_v11_sha256
            != request_summary.request_v11_sha256
        || request.receipt_body_template.request_envelope_sha256
            != request_summary.request_envelope_sha256
        || request.receipt_body_template.request_canonical_bytes
            != request_summary.request_canonical_bytes
    {
        return Err("receipt body template does not join submission".into());
    }
    let submission_digest = receipt_authority_submission_digest(
        &request.receipt_id,
        &request.requester_principal_id,
        &request.replay_identity,
        &request_summary,
        &request_admission_sha256,
        &request.receipt_body_template,
    )?;
    if submission_digest != request.submission_binding_sha256 {
        return Err("receipt authority submission digest mismatch".into());
    }
    if ledger
        .prepared_binding(&ledger_identity_sha256)?
        .is_none()
    {
        request.deadline.require_live()?;
        verify_canonical_request_v11_admission(
            &request_v11,
            &request.request_admission,
            &config.strict_verifier_pins,
            true,
        )?;
    }

    let prepared = ledger.prepare_with(
        &ledger_identity_sha256,
        |sequence| {
            let mut body = request.receipt_body_template.clone();
            body.receipt_sequence = sequence;
            let (body_sha256, _) = receipt_body_digest(&body)?;
            let prepared_binding_sha256 = prepared_binding_digest(
                &request.receipt_id,
                &request.requester_principal_id,
                &request.replay_identity,
                &request_summary,
                &request_admission_sha256,
                &body,
            )?;
            Ok(PrepareInputV12 {
                receipt_id: request.receipt_id.clone(),
                requester_principal_id: request.requester_principal_id.clone(),
                replay_key_sha256: request
                    .replay_identity
                    .replay_key_sha256
                    .clone(),
                ledger_identity_sha256: ledger_identity_sha256.clone(),
                prepared_binding_sha256,
                request_v11_sha256: request_summary.request_v11_sha256.clone(),
                request_envelope_sha256: request_summary
                    .request_envelope_sha256
                    .clone(),
                request_canonical_bytes: request_summary
                    .request_canonical_bytes
                    .clone(),
                receipt_body_sha256: body_sha256,
                terminal_evidence_root_sha256: body
                    .terminal_evidence_root_sha256,
                terminal_state_root_sha256: body.terminal_state_root_sha256,
                body_trust_observation_sha256: body
                    .body_trust_observation_sha256,
                exact_prepared_request_bytes: exact_request_bytes.to_vec(),
                committed_at: now_utc_rfc3339()?,
            })
        },
    )?;
    if prepared.disposition == TransitionDispositionV12::ExactRetry {
        if let Some(settled) = ledger.settled_artifact_for_prepared(
            &ledger_identity_sha256,
            LedgerStageV12::Logged,
            &prepared.binding.prepared_binding_sha256,
        )? {
            let bundle: LoggedReceiptBundleV12 = parse_canonical_json(
                &settled.exact_bytes,
                MAX_AUTHORITY_RESPONSE_BYTES,
            )?;
            let final_settlement = ledger
                .settled_artifact_for_prepared(
                    &ledger_identity_sha256,
                    LedgerStageV12::Finalized,
                    &prepared.binding.prepared_binding_sha256,
                )?
                .map(|settled| {
                    parse_canonical_json::<FinalSettlementArtifactV12>(
                        &settled.exact_bytes,
                        MAX_AUTHORITY_RESPONSE_BYTES,
                    )
                })
                .transpose()?;
            return canonical_json(
                &ReceiptAuthorityResponseV12 {
                    operation: "AUTHENTICATE_AND_LOG".to_owned(),
                    disposition: "SETTLED".to_owned(),
                    logged_bundle_sha256: logged_receipt_bundle_digest(&bundle)?,
                    logged_bundle: bundle,
                    final_settlement,
                },
                MAX_AUTHORITY_RESPONSE_BYTES,
            )
            .map_err(Into::into);
        }
    }
    let mut body = request.receipt_body_template.clone();
    body.receipt_sequence = prepared.binding.receipt_sequence.clone();
    let (body_sha256, body_canonical_bytes) = receipt_body_digest(&body)?;
    if body_sha256 != prepared.binding.receipt_body_sha256 {
        return Err("durable PREPARED body differs from rebuilt body".into());
    }
    let authentication_payload = |authenticated_at: String| {
        ReceiptAuthenticationPayloadV12 {
            receipt_id: request.receipt_id.clone(),
            receipt_sequence: prepared.binding.receipt_sequence.clone(),
            requester_principal_id: request.requester_principal_id.clone(),
            replay_key_sha256: request.replay_identity.replay_key_sha256.clone(),
            request_v11_sha256: request_summary.request_v11_sha256.clone(),
            request_envelope_sha256: request_summary
                .request_envelope_sha256
                .clone(),
            request_canonical_bytes: request_summary
                .request_canonical_bytes
                .clone(),
            receipt_body_sha256: body_sha256.clone(),
            receipt_body_canonical_bytes: body_canonical_bytes.clone(),
            terminal_evidence_root_sha256: body
                .terminal_evidence_root_sha256
                .clone(),
            terminal_state_root_sha256: body
                .terminal_state_root_sha256
                .clone(),
            body_trust_observation_sha256: body
                .body_trust_observation_sha256
                .clone(),
            authenticated_at,
        }
    };
    let existing_authentication = if prepared.disposition
        == TransitionDispositionV12::ExactRetry
    {
        ledger.settled_artifact_for_prepared(
            &ledger_identity_sha256,
            LedgerStageV12::Authenticated,
            &prepared.binding.prepared_binding_sha256,
        )?
    } else {
        None
    };
    let (
        authentication,
        authentication_envelope_sha256,
        authentication_bytes,
    ) = if let Some(existing) = existing_authentication {
        let authentication: ReceiptAuthenticationEnvelopeV12 =
            parse_canonical_json(
                &existing.exact_bytes,
                MAX_AUTHORITY_RESPONSE_BYTES,
            )?;
        let authentication_envelope_sha256 =
            verify_receipt_authentication_envelope_v12(
                &authentication,
                &config.strict_verifier_pins.receipt_authentication,
            )?;
        if authentication.payload
            != authentication_payload(
                authentication.payload.authenticated_at.clone(),
            )
        {
            return Err(
                "durable AUTHENTICATED artifact does not join PREPARED state"
                    .into(),
            );
        }
        (
            authentication,
            authentication_envelope_sha256,
            existing.exact_bytes,
        )
    } else {
        let authenticated_at = now_utc_rfc3339()?;
        let authentication = sign_envelope(
            RECEIPT_AUTHENTICATION_DOMAIN,
            AuthorityRoleV12::ReceiptAuthentication,
            authentication_payload(authenticated_at.clone()),
            config.receipt_authentication_authorization.clone(),
            receipt_key,
            &authenticated_at,
            &authenticated_at,
        )?;
        let authentication_envelope_sha256 =
            envelope_digest(&authentication)?;
        let authentication_bytes =
            canonical_json(&authentication, MAX_AUTHORITY_RESPONSE_BYTES)?;
        (
            authentication,
            authentication_envelope_sha256,
            authentication_bytes,
        )
    };
    ledger.authenticate(
        &ledger_identity_sha256,
        authentication_envelope_sha256.clone(),
        &authentication_bytes,
        authentication.payload.authenticated_at.clone(),
    )?;

    let log_outcome = ledger.log_with(
        &ledger_identity_sha256,
        &sha256_bytes(&authentication_bytes),
        |context| {
            let log_append_binding_sha256 = receipt_contract_v12::h12(
                "log-authority-append",
                &[
                    config.log_id.as_bytes(),
                    &body_sha256.decode()?,
                    &authentication_envelope_sha256.decode()?,
                    &context
                        .previous_checkpoint
                        .signed_tree_head_envelope_sha256
                        .decode()?,
                ],
            );
            let log_response: LogAuthorityResponseV12 = authority_rpc(
                &config.log_authority_socket_path,
                config.log_authority_uid,
                &LogAuthorityRequestV12 {
                    operation: "APPEND_AUTHENTICATED_RECEIPT".to_owned(),
                    log_id: config.log_id.clone(),
                    receipt_body: body.clone(),
                    receipt_body_sha256: body_sha256.clone(),
                    receipt_authentication_envelope: authentication.clone(),
                    receipt_authentication_envelope_sha256:
                        authentication_envelope_sha256.clone(),
                    expected_previous_tree_head_envelope_sha256: context
                        .previous_checkpoint
                        .signed_tree_head_envelope_sha256
                        .clone(),
                    log_append_binding_sha256: log_append_binding_sha256.clone(),
                    deadline: request.deadline.clone(),
                },
                &request.deadline,
            )
            .map_err(|error| {
                receipt_ledger::LedgerError::InvalidOwned(format!(
                    "log authority RPC failed: {error}"
                ))
            })?;
            if log_response.operation != "APPEND_AUTHENTICATED_RECEIPT"
                || log_response.disposition != "SETTLED"
                || log_response.log_append_binding_sha256
                    != log_append_binding_sha256
                || log_response.previous_checkpoint
                    != context.previous_checkpoint
                || log_response.pre_final_log_leaf.leaf_ordinal.get()?
                    != context.leaf_ordinal
            {
                return Err(receipt_ledger::LedgerError::Invalid(
                    "log authority response is not request-bound",
                ));
            }
            let tree_head = log_response.signed_tree_head;
            let tree_head_envelope_sha256 =
                envelope_digest(&tree_head)?;
            if tree_head_envelope_sha256
                != log_response.signed_tree_head_envelope_sha256
            {
                return Err(receipt_ledger::LedgerError::Invalid(
                    "log authority tree-head digest mismatch",
                ));
            }
            let leaf = log_response.pre_final_log_leaf;
            let inclusion = log_response.inclusion_proof;
            let consistency = log_response.consistency_proof;
            let tree_size = tree_head.payload.tree_size.clone();
            let tree_root_sha256 = tree_head.payload.root_sha256.clone();
            let issued_at = tree_head.payload.issued_at.clone();
            let bundle = LoggedReceiptBundleV12 {
                contract_version: RECEIPT_CONTRACT_VERSION,
                request_contract_version: REQUEST_CONTRACT_VERSION,
                receipt_id: request.receipt_id.clone(),
                receipt_sequence: body.receipt_sequence.clone(),
                requester_principal_id: request.requester_principal_id.clone(),
                replay_identity: request.replay_identity.clone(),
                request_v11: request_v11.clone(),
                request_admission: request.request_admission.clone(),
                request_admission_sha256: request_admission_sha256.clone(),
                request_v11_sha256: request_summary.request_v11_sha256.clone(),
                request_envelope_sha256: request_summary
                    .request_envelope_sha256
                    .clone(),
                request_canonical_bytes: request_summary
                    .request_canonical_bytes
                    .clone(),
                receipt_body: body.clone(),
                receipt_body_sha256: body_sha256.clone(),
                receipt_body_canonical_bytes: body_canonical_bytes.clone(),
                receipt_authentication_envelope: authentication.clone(),
                receipt_authentication_envelope_sha256:
                    authentication_envelope_sha256.clone(),
                previous_checkpoint: log_response.previous_checkpoint,
                pre_final_log_leaf: leaf.clone(),
                signed_tree_head: tree_head,
                signed_tree_head_envelope_sha256:
                    tree_head_envelope_sha256.clone(),
                inclusion_proof: inclusion,
                consistency_proof: consistency,
            };
            let exact_logged_bundle_bytes =
                canonical_json(&bundle, MAX_AUTHORITY_RESPONSE_BYTES)?;
            let verified_bundle = verify_logged_bundle_v12(
                &exact_logged_bundle_bytes,
                &config.strict_verifier_pins,
                &context.verifier_high_water,
            )?;
            let logged_bundle_sha256 =
                logged_receipt_bundle_digest(&bundle)?;
            if verified_bundle.logged_bundle_sha256 != logged_bundle_sha256 {
                return Err(receipt_ledger::LedgerError::Invalid(
                    "strict verifier disagrees with logged-bundle digest",
                ));
            }
            Ok(BuiltLogAppendV12 {
                logged_bundle_sha256,
                exact_bytes_sha256: sha256_bytes(&exact_logged_bundle_bytes),
                exact_logged_bundle_bytes,
                leaf_sha256: leaf.leaf_sha256,
                tree_size,
                tree_root_sha256,
                signed_tree_head_envelope_sha256: tree_head_envelope_sha256,
                committed_at: issued_at,
            })
        },
    )?;
    let settled_bundle: LoggedReceiptBundleV12 = parse_canonical_json(
        &log_outcome.exact_bytes,
        MAX_AUTHORITY_RESPONSE_BYTES,
    )?;
    let response = ReceiptAuthorityResponseV12 {
        operation: "AUTHENTICATE_AND_LOG".to_owned(),
        disposition: "SETTLED".to_owned(),
        logged_bundle_sha256: logged_receipt_bundle_digest(&settled_bundle)?,
        logged_bundle: settled_bundle,
        final_settlement: None,
    };
    let response_bytes = canonical_json(&response, MAX_AUTHORITY_RESPONSE_BYTES)?;
    if log_outcome.disposition == TransitionDispositionV12::ExactRetry {
        // The response remains byte-identical because disposition is deliberately SETTLED.
    }
    Ok(response_bytes)
}

fn reconcile_next_finalization(
    config: &ReceiptAuthorityConfigV12,
    ledger: &ReceiptLedgerV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(pending) = ledger.next_pending_logged()? else {
        return Ok(());
    };
    let authority_request: ReceiptAuthorityRequestV12 = parse_canonical_json(
        &pending.exact_prepared_request_bytes,
        MAX_AUTHORITY_REQUEST_BYTES,
    )?;
    let logged_bundle: LoggedReceiptBundleV12 = parse_canonical_json(
        &pending.exact_logged_bundle_bytes,
        MAX_AUTHORITY_RESPONSE_BYTES,
    )?;
    let logged_bundle_sha256 = logged_receipt_bundle_digest(&logged_bundle)?;
    let high_water = ledger.verifier_high_water()?;
    let remaining = authority_request.deadline.require_live()?;
    let terminal_abort = remaining <= FINALIZATION_ABORT_RESERVE_NS;

    let trust_request_binding = receipt_contract_v12::h12(
        "trust-generation-resolve-request",
        &[
            logged_bundle.receipt_id.as_bytes(),
            logged_bundle.receipt_sequence.as_str().as_bytes(),
            &logged_bundle.replay_identity.replay_key_sha256.decode()?,
            &logged_bundle_sha256.decode()?,
            high_water
                .trust_generation_sequence
                .as_str()
                .as_bytes(),
        ],
    );
    let trust_response: TrustGenerationResolveResponseV12 = authority_rpc(
        &config.trust_generation_authority_socket_path,
        config.trust_generation_authority_uid,
        &TrustGenerationResolveRequestV12 {
            operation: "RESOLVE_FRESH_TRUST_GENERATION".to_owned(),
            receipt_id: logged_bundle.receipt_id.clone(),
            receipt_sequence: logged_bundle.receipt_sequence.clone(),
            replay_key_sha256: logged_bundle
                .replay_identity
                .replay_key_sha256
                .clone(),
            logged_bundle_sha256: logged_bundle_sha256.clone(),
            minimum_generation_sequence: CanonicalU64::new(
                high_water
                    .trust_generation_sequence
                    .get()?
                    .checked_add(1)
                    .ok_or("trust-generation sequence exhausted")?,
            ),
            deadline: authority_request.deadline.clone(),
        },
        &authority_request.deadline,
    )?;
    if trust_response.operation != "RESOLVE_FRESH_TRUST_GENERATION"
        || trust_response.request_binding_sha256 != trust_request_binding
    {
        return Err("trust-generation response is not request-bound".into());
    }
    let trust_generation = trust_response.trust_generation;
    let trust_generation_sha256 = verify_trust_generation_bundle(
        &trust_generation,
        &config.strict_verifier_pins,
        &high_water,
        true,
    )?;

    let witness_request_binding = receipt_contract_v12::h12(
        "witness-finalization-request",
        &[
            &logged_bundle_sha256.decode()?,
            &logged_bundle.signed_tree_head_envelope_sha256.decode()?,
            &trust_generation_sha256.decode()?,
        ],
    );
    let witness_response: WitnessFinalizationResponseV12 = authority_rpc(
        &config.external_witness_authority_socket_path,
        config.external_witness_authority_uid,
        &WitnessFinalizationRequestV12 {
            operation: "WITNESS_FINALIZATION".to_owned(),
            logged_bundle_sha256: logged_bundle_sha256.clone(),
            signed_tree_head: logged_bundle.signed_tree_head.clone(),
            trust_generation_envelope_sha256: trust_generation_sha256.clone(),
            deadline: authority_request.deadline.clone(),
        },
        &authority_request.deadline,
    )?;
    if witness_response.operation != "WITNESS_FINALIZATION"
        || witness_response.request_binding_sha256 != witness_request_binding
    {
        return Err("external-witness response is not request-bound".into());
    }
    let witness = witness_response.external_witness_checkpoint;
    let witness_sha256 = envelope_digest(&witness)?;

    let (receipt, terminal_abort_reason, finalization_binding_sha256) =
        if terminal_abort {
            let reason = "canonical request deadline reached before final verdict"
                .to_owned();
            let binding = receipt_contract_v12::h12(
                "terminal-abort-finalization",
                &[
                    &logged_bundle_sha256.decode()?,
                    &witness_sha256.decode()?,
                    &trust_generation_sha256.decode()?,
                    reason.as_bytes(),
                ],
            );
            (None, Some(reason), binding)
        } else {
            let observed_at = now_utc_rfc3339()?;
            let final_trust = build_final_trust_observation(
                trust_generation.clone(),
                &config.strict_verifier_pins,
                &high_water,
                verify_canonical_request_v11_admission(
                    &logged_bundle.request_v11,
                    &logged_bundle.request_admission,
                    &config.strict_verifier_pins,
                    false,
                )?
                .trust_observation_sha256,
                logged_bundle
                    .receipt_body
                    .body_trust_observation_sha256
                    .clone(),
                logged_bundle.signed_tree_head_envelope_sha256.clone(),
                witness_sha256.clone(),
                observed_at,
            )?;
            let final_trust_sha256 =
                final_trust_observation_digest(&final_trust)?;
            let finalization_binding_sha256 = finalization_binding_digest(
                &logged_bundle_sha256,
                &witness_sha256,
                &final_trust_sha256,
                logged_bundle.receipt_body.verdict,
            )?;
            let response: FinalVerdictAuthorityResponseV12 = authority_rpc(
                &config.final_verdict_authority_socket_path,
                config.final_verdict_authority_uid,
                &FinalVerdictAuthorityRequestV12 {
                    operation: "FINALIZE".to_owned(),
                    logged_bundle: logged_bundle.clone(),
                    logged_bundle_sha256: logged_bundle_sha256.clone(),
                    external_witness_checkpoint: witness.clone(),
                    final_trust_observation: final_trust,
                    requested_verdict: logged_bundle.receipt_body.verdict,
                    expected_finalization_binding_sha256:
                        finalization_binding_sha256.clone(),
                    deadline: authority_request.deadline.clone(),
                },
                &authority_request.deadline,
            )?;
            if response.operation != "FINALIZE"
                || response.disposition != "SIGNED"
            {
                return Err("final-verdict authority did not sign receipt".into());
            }
            (
                Some(response.receipt),
                None,
                finalization_binding_sha256,
            )
        };

    let settlement_request_binding = receipt_contract_v12::h12(
        "final-settlement-request",
        &[
            &logged_bundle_sha256.decode()?,
            &receipt
                .as_ref()
                .map(|value| value.receipt_envelope_sha256.clone())
                .unwrap_or_else(receipt_contract_v12::DigestHex::zero)
                .decode()?,
            terminal_abort_reason
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            &witness_sha256.decode()?,
            &trust_generation_sha256.decode()?,
            &high_water
                .settlement_checkpoint_envelope_sha256
                .decode()?,
        ],
    );
    let settlement_response: FinalSettlementResponseV12 = authority_rpc(
        &config.final_settlement_authority_socket_path,
        config.final_settlement_authority_uid,
        &FinalSettlementRequestV12 {
            operation: "SETTLE_FINAL".to_owned(),
            logged_bundle: logged_bundle.clone(),
            logged_bundle_sha256,
            receipt,
            terminal_abort_reason,
            external_witness_checkpoint: witness,
            trust_generation,
            expected_previous_settlement_checkpoint_envelope_sha256: high_water
                .settlement_checkpoint_envelope_sha256
                .clone(),
            deadline: authority_request.deadline.clone(),
        },
        &authority_request.deadline,
    )?;
    if settlement_response.operation != "SETTLE_FINAL"
        || settlement_response.request_binding_sha256
            != settlement_request_binding
    {
        return Err("external final-settlement response is not request-bound".into());
    }
    let artifact = settlement_response.artifact;
    let next_high_water = verify_final_settlement_artifact_v12(
        &artifact,
        &config.strict_verifier_pins,
        &high_water,
    )?;
    let exact_artifact =
        canonical_json(&artifact, MAX_AUTHORITY_RESPONSE_BYTES)?;
    ledger.finalize(
        &pending.ledger_identity_sha256,
        finalization_binding_sha256,
        &exact_artifact,
        next_high_water,
        artifact
            .final_settlement_checkpoint
            .payload
            .settled_at
            .clone(),
    )?;
    Ok(())
}

fn authority_rpc<T, R>(
    socket_path: &Path,
    expected_peer_uid: u32,
    request: &T,
    deadline: &AuthorityDeadlineV12,
) -> Result<R, Box<dyn std::error::Error>>
where
    T: Serialize,
    R: for<'de> Deserialize<'de>,
{
    let (response, _) = authority_rpc_v12(
        socket_path,
        expected_peer_uid,
        request,
        deadline,
        MAX_AUTHORITY_REQUEST_BYTES,
        MAX_AUTHORITY_RESPONSE_BYTES,
    )?;
    Ok(response)
}

fn validate_config(config: &ReceiptAuthorityConfigV12) -> Result<(), Box<dyn std::error::Error>> {
    if config.config_version != 12
        || config.allowed_peer_uids != vec![config.controller_uid]
        || config.allowed_peer_uids.contains(&0)
        || config.receipt_authentication_authorization.role
            != AuthorityRoleV12::ReceiptAuthentication
        || !config.log_authority_socket_path.is_absolute()
        || !config.final_verdict_authority_socket_path.is_absolute()
        || !config.trust_generation_authority_socket_path.is_absolute()
        || !config.external_witness_authority_socket_path.is_absolute()
        || !config.final_settlement_authority_socket_path.is_absolute()
        || !config.external_settlement_anchor_path.is_absolute()
    {
        return Err("invalid receipt authority configuration".into());
    }
    let uids = [
        config.controller_uid,
        config.receipt_authority_uid,
        config.log_authority_uid,
        config.final_verdict_authority_uid,
        config.trust_generation_authority_uid,
        config.external_witness_authority_uid,
        config.final_settlement_authority_uid,
    ];
    for (index, left) in uids.iter().enumerate() {
        if *left == 0 || uids.iter().skip(index + 1).any(|right| right == left) {
            return Err("authority UIDs must be non-root and pairwise distinct".into());
        }
    }
    config.strict_verifier_pins.validate()?;
    require_authorization_matches_pin(
        &config.receipt_authentication_authorization,
        &config.strict_verifier_pins.receipt_authentication,
    )?;
    Ok(())
}

fn require_authorization_matches_pin(
    authorization: &KeyAuthorizationV12,
    pin: &receipt_verifier_v12::AuthorityPinV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if authorization.role != pin.role
        || authorization.principal_id != pin.principal_id
        || authorization.key_id != pin.key_id
        || authorization.spki_der_sha256 != pin.spki_der_sha256
        || authorization.physical_private_key_identity_sha256
            != pin.physical_private_key_identity_sha256
        || authorization.key_authorization_sha256
            != pin.key_authorization_sha256
        || authorization.authorization_root_sha256
            != pin.authorization_root_sha256
        || authorization.authorization_revision != pin.authorization_revision
        || authorization.revocation_root_sha256 != pin.revocation_root_sha256
        || authorization.revocation_revision != pin.revocation_revision
        || authorization.high_water != pin.high_water
        || authorization.valid_from != pin.valid_from
        || authorization.valid_until != pin.valid_until
        || authorization.status != pin.status
    {
        return Err("authority authorization differs from current pin".into());
    }
    Ok(())
}

fn activated_listener(
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<UnixListener, Box<dyn std::error::Error>> {
    let listen_pid: u32 = env::var("LISTEN_PID")?.parse()?;
    let listen_fds: u32 = env::var("LISTEN_FDS")?.parse()?;
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err("exactly one systemd-activated listener is required".into());
    }
    inspect_activated_listener_v12(
        SYSTEMD_LISTEN_FD,
        expected_owner_uid,
        expected_mode,
    )?;
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    Ok(listener)
}

fn read_signing_key(path: &Path, expected_owner_uid: u32) -> io::Result<SigningKey> {
    let mut bytes = read_secure_file(path, 32, expected_owner_uid, true)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signing key must be 32 raw bytes",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    bytes.zeroize();
    Ok(key)
}

fn read_secure_file(
    path: &Path,
    maximum_bytes: usize,
    expected_owner_uid: u32,
    private: bool,
) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let forbidden_mode = if private { 0o077 } else { 0o022 };
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.len() == 0
        || metadata.len() > maximum_bytes as u64
        || metadata.mode() & forbidden_mode != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authority file ownership, mode, type, or length is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority file changed while being read",
        ));
    }
    Ok(bytes)
}
