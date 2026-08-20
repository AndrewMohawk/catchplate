#![allow(dead_code)]

#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{pkcs8::DecodePublicKey, SigningKey, VerifyingKey};
use receipt_contract_v12::{
    build_consistency_proof, build_inclusion_proof, canonical_json,
    ed25519_spki_sha256, envelope_digest,
    inspect_activated_listener_v12, notify_systemd_v12, now_utc_rfc3339,
    make_log_leaf, merkle_root, parse_canonical_json, peer_uid_v12,
    read_authority_frame_v12, receipt_body_digest, sign_envelope,
    write_authority_frame_v12, AuthorityRoleV12, CanonicalU64,
    CheckpointKindV12, DigestHex, KeyAuthorizationV12, LogAuthorityRequestV12,
    LogAuthorityResponseV12, PreviousCheckpointV12, TreeHeadPayloadV12,
    VerificationHighWaterV12, RECEIPT_TREE_HEAD_DOMAIN,
    MAX_AUTHORITY_REQUEST_BYTES, MAX_AUTHORITY_RESPONSE_BYTES,
};
use receipt_verifier_v12::{
    verify_receipt_authentication_envelope_v12, AuthorityPinV12,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SYSTEMD_LISTEN_FD: i32 = 3;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_STARTUP_STATE_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogCustodyConfigV12 {
    config_version: u64,
    authority_profile: String,
    log_id: String,
    state_root: PathBuf,
    receipt_authority_uid: u32,
    log_authority_uid: u32,
    listener_owner_uid: u32,
    listener_mode: u32,
    signing_key_path: PathBuf,
    key_authorization_path: PathBuf,
    receipt_authentication_authorization_path: PathBuf,
    receipt_authentication_public_key_path: PathBuf,
    genesis_checkpoint_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogHighWaterV12 {
    checkpoint_sequence: CanonicalU64,
    tree_size: CanonicalU64,
    tree_root_sha256: DigestHex,
    signed_tree_head_envelope_sha256: DigestHex,
    log_append_binding_sha256: DigestHex,
    latest_receipt_sequence: CanonicalU64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogLedgerV12 {
    leaves: Vec<DigestHex>,
    high_water: LogHighWaterV12,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("log-custody authority hard-unready: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(
            "usage: serverware-coder-log-custody-authority-v12 --config ABSOLUTE_PATH"
                .into(),
        );
    }
    let config_bytes = secure_read(Path::new(&arguments[1]), MAX_CONFIG_BYTES, 0, false)?;
    let config: LogCustodyConfigV12 =
        parse_canonical_json(&config_bytes, MAX_CONFIG_BYTES)?;
    let uid = unsafe { libc::geteuid() };
    if config.config_version != 12
        || config.authority_profile != "local-trusted-host"
        || uid == 0
        || uid != config.log_authority_uid
        || config.log_id.is_empty()
        || config.listener_owner_uid != 0
        || config.listener_mode != 0o660
        || config.receipt_authority_uid == config.log_authority_uid
        || !config.state_root.is_absolute()
        || !config.signing_key_path.is_absolute()
        || !config.key_authorization_path.is_absolute()
        || !config
            .receipt_authentication_authorization_path
            .is_absolute()
        || !config.receipt_authentication_public_key_path.is_absolute()
        || !config.genesis_checkpoint_path.is_absolute()
    {
        return Err(
            "log-custody configuration is invalid or stronger external mode lacks an adapter"
                .into(),
        );
    }
    load_receipt_authentication_material(&config)?;
    verify_genesis_checkpoint(&config)?;
    fs::create_dir_all(&config.state_root)?;
    fs::set_permissions(&config.state_root, fs::Permissions::from_mode(0o700))?;
    reconcile_startup_state(&config)?;
    let authorization_bytes =
        secure_read(&config.key_authorization_path, MAX_CONFIG_BYTES, 0, false)?;
    let authorization: KeyAuthorizationV12 =
        parse_canonical_json(&authorization_bytes, MAX_CONFIG_BYTES)?;
    if authorization.role != AuthorityRoleV12::ReceiptLog {
        return Err("log key authorization has the wrong authority role".into());
    }
    let signing_key = read_signing_key(&config.signing_key_path, uid)?;
    if ed25519_spki_sha256(&signing_key.verifying_key())
        != authorization.spki_der_sha256
    {
        return Err("log private key does not match its authorization".into());
    }
    let listener = activated_listener(&config)?;
    notify_systemd_v12("log-custody-v12 local ledger ready")?;
    loop {
        let (stream, _) = listener.accept()?;
        if let Err(error) = handle_connection(&config, &signing_key, stream) {
            eprintln!("log-custody authority rejected request: {error}");
        }
    }
}

fn reconcile_startup_state(
    config: &LogCustodyConfigV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = load_log_ledger(config)?;
    let current_sequence = ledger.high_water.checkpoint_sequence.get()?;
    let expected_genesis = LogHighWaterV12 {
        checkpoint_sequence: CanonicalU64::new(0),
        tree_size: CanonicalU64::new(0),
        tree_root_sha256: VerificationHighWaterV12::genesis()
            .tree_root_sha256,
        signed_tree_head_envelope_sha256: DigestHex::zero(),
        log_append_binding_sha256: DigestHex::zero(),
        latest_receipt_sequence: CanonicalU64::new(0),
    };
    if ledger.leaves.len() as u64 != ledger.high_water.tree_size.get()?
        || merkle_root(&ledger.leaves)? != ledger.high_water.tree_root_sha256
        || (ledger.leaves.is_empty() && ledger.high_water != expected_genesis)
        || (!ledger.leaves.is_empty()
            && (ledger.high_water.checkpoint_sequence
                != ledger.high_water.tree_size
                || ledger.high_water.latest_receipt_sequence
                    != ledger.high_water.tree_size
                || ledger.high_water.signed_tree_head_envelope_sha256
                    == DigestHex::zero()))
    {
        return Err("durable log ledger is not internally consistent".into());
    }
    let mut future_responses = Vec::new();
    let mut entry_count = 0usize;
    for entry in fs::read_dir(&config.state_root)? {
        entry_count = entry_count
            .checked_add(1)
            .ok_or("log startup state entry count overflow")?;
        if entry_count > MAX_STARTUP_STATE_ENTRIES {
            return Err("log startup state exceeds the bounded entry count".into());
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "log state filename is not UTF-8")?;
        if name == "ledger-v12.json" {
            continue;
        }
        let metadata = entry.metadata()?;
        if name.starts_with('.') && name.ends_with(".tmp") {
            if !metadata.is_file() || metadata.uid() != config.log_authority_uid {
                return Err("log temporary state entry is unsafe".into());
            }
            fs::remove_file(entry.path())?;
            continue;
        }
        let binding = name
            .strip_prefix("response-")
            .and_then(|name| name.strip_suffix(".json"))
            .ok_or("log state directory contains an unknown entry")?;
        DigestHex::parse(binding.to_owned())?;
        let bytes = secure_read(
            &entry.path(),
            MAX_AUTHORITY_RESPONSE_BYTES,
            config.log_authority_uid,
            false,
        )?;
        let response: LogAuthorityResponseV12 =
            parse_canonical_json(&bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
        let sequence = response
            .signed_tree_head
            .payload
            .checkpoint_sequence
            .get()?;
        if sequence > current_sequence {
            future_responses.push((sequence, response));
        }
    }
    File::open(&config.state_root)?.sync_all()?;
    future_responses.sort_by_key(|(sequence, _)| *sequence);
    let next_sequence = current_sequence.checked_add(1);
    if future_responses.len() > 1
        || future_responses.first().is_some_and(|(sequence, _)| {
            next_sequence != Some(*sequence)
        })
    {
        return Err(
            "log startup found a gap or multiple unsettled future responses".into(),
        );
    }
    if let Some((_, response)) = future_responses.first() {
        reconcile_response_state(config, response)?;
    }
    Ok(())
}

fn verify_genesis_checkpoint(
    config: &LogCustodyConfigV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes =
        secure_read(&config.genesis_checkpoint_path, MAX_CONFIG_BYTES, 0, false)?;
    let text = std::str::from_utf8(&bytes)?;
    if text.as_bytes().iter().any(|byte| {
        *byte == 0 || (*byte < 0x20 && !matches!(*byte, b'\n'))
    }) {
        return Err("log genesis contains noncanonical bytes".into());
    }
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or("log genesis line lacks '='")?;
        if name.is_empty()
            || value.is_empty()
            || fields.insert(name, value).is_some()
        {
            return Err("log genesis contains an empty or duplicate field".into());
        }
    }
    let zero_digest =
        "0000000000000000000000000000000000000000000000000000000000000000";
    if fields.len() != 9
        || fields.get("document_version").copied() != Some("12")
        || fields.get("log_id").copied() != Some(config.log_id.as_str())
        || fields.get("genesis_kind").copied()
            != Some("binary-fixed-empty-root-v12")
        || fields.get("checkpoint_sequence").copied() != Some("0")
        || fields.get("tree_size").copied() != Some("0")
        || fields
            .get("previous_signed_tree_head_envelope_sha256")
            .copied()
            != Some(zero_digest)
        || fields.get("integrity_mode").copied() != Some("UserspaceDigestOnly")
        || fields.get("runtime_continuity").copied()
            != Some("state-root-high-water-and-ledger")
    {
        return Err("log genesis contract is not the exact local v12 profile".into());
    }
    let tree_root = DigestHex::parse(
        fields
            .get("tree_root_sha256")
            .ok_or("log genesis tree root is absent")?
            .to_string(),
    )?;
    if tree_root != VerificationHighWaterV12::genesis().tree_root_sha256 {
        return Err(
            "log genesis tree root differs from the compiled Merkle empty root".into(),
        );
    }
    Ok(())
}

fn handle_connection(
    config: &LogCustodyConfigV12,
    signing_key: &SigningKey,
    stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    if peer_uid_v12(&stream)? != config.receipt_authority_uid {
        return Err("log-custody peer is not the receipt authority".into());
    }
    let (request_bytes, frame) =
        read_authority_frame_v12(&stream, MAX_AUTHORITY_REQUEST_BYTES)?;
    let request: LogAuthorityRequestV12 =
        parse_canonical_json(&request_bytes, MAX_AUTHORITY_REQUEST_BYTES)?;
    if request.operation != "APPEND_AUTHENTICATED_RECEIPT"
        || request.log_id.is_empty()
        || request.deadline.boottime_deadline_ns.get()?
            != frame.boottime_deadline_ns
    {
        return Err("log-custody request operation or frame binding is invalid".into());
    }
    request.deadline.require_live()?;
    validate_authenticated_append(config, &request)?;
    let response_path = config.state_root.join(format!(
        "response-{}.json",
        request.log_append_binding_sha256.as_str(),
    ));
    let response = if response_path.exists() {
        let bytes = secure_read(
            &response_path,
            MAX_AUTHORITY_RESPONSE_BYTES,
            config.log_authority_uid,
            false,
        )?;
        let response =
            parse_canonical_json(&bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
        reconcile_response_state(config, &response)?;
        response
    } else {
        settle_append(config, signing_key, &request, &response_path)?
    };
    let response_bytes = canonical_json(&response, MAX_AUTHORITY_RESPONSE_BYTES)?;
    write_authority_frame_v12(
        &stream,
        &response_bytes,
        MAX_AUTHORITY_RESPONSE_BYTES,
        frame.boottime_deadline_ns,
    )?;
    Ok(())
}

fn settle_append(
    config: &LogCustodyConfigV12,
    signing_key: &SigningKey,
    request: &LogAuthorityRequestV12,
    response_path: &Path,
) -> Result<LogAuthorityResponseV12, Box<dyn std::error::Error>> {
    let mut ledger = load_log_ledger(config)?;
    if ledger.leaves.len() as u64 != ledger.high_water.tree_size.get()?
        || merkle_root(&ledger.leaves)? != ledger.high_water.tree_root_sha256
        || request.expected_previous_tree_head_envelope_sha256
            != ledger.high_water.signed_tree_head_envelope_sha256
        || request.receipt_body.receipt_sequence.get()?
            != ledger
                .high_water
                .latest_receipt_sequence
                .get()?
                .checked_add(1)
                .ok_or("receipt sequence exhausted")?
    {
        return Err("log append does not extend the durable custody ledger".into());
    }

    let accepted_at = now_utc_rfc3339()?;
    let previous_checkpoint = PreviousCheckpointV12 {
        checkpoint_kind: if ledger.leaves.is_empty() {
            CheckpointKindV12::Genesis
        } else {
            CheckpointKindV12::SignedTreeHead
        },
        tree_size: ledger.high_water.tree_size.clone(),
        root_sha256: ledger.high_water.tree_root_sha256.clone(),
        signed_tree_head_envelope_sha256: ledger
            .high_water
            .signed_tree_head_envelope_sha256
            .clone(),
    };
    let leaf = make_log_leaf(
        request.log_id.clone(),
        ledger.leaves.len() as u64,
        &request.receipt_body,
        request.receipt_body_sha256.clone(),
        request.receipt_authentication_envelope_sha256.clone(),
    )?;
    let old_tree_size = ledger.leaves.len();
    ledger.leaves.push(leaf.leaf_sha256.clone());
    let tree_size = CanonicalU64::new(ledger.leaves.len() as u64);
    let tree_root_sha256 = merkle_root(&ledger.leaves)?;
    let tree_head_payload = TreeHeadPayloadV12 {
        log_id: request.log_id.clone(),
        checkpoint_sequence: CanonicalU64::new(
            ledger
                .high_water
                .checkpoint_sequence
                .get()?
                .checked_add(1)
                .ok_or("log checkpoint sequence exhausted")?,
        ),
        tree_size: tree_size.clone(),
        root_sha256: tree_root_sha256.clone(),
        previous_signed_tree_head_envelope_sha256: ledger
            .high_water
            .signed_tree_head_envelope_sha256
            .clone(),
        latest_leaf_sha256: leaf.leaf_sha256.clone(),
        latest_receipt_sequence: request.receipt_body.receipt_sequence.clone(),
        issued_at: accepted_at.clone(),
    };
    let signed_tree_head = sign_envelope(
        RECEIPT_TREE_HEAD_DOMAIN,
        AuthorityRoleV12::ReceiptLog,
        tree_head_payload,
        parse_canonical_json(
            &secure_read(
                &config.key_authorization_path,
                MAX_CONFIG_BYTES,
                0,
                false,
            )?,
            MAX_CONFIG_BYTES,
        )?,
        signing_key,
        &accepted_at,
        &accepted_at,
    )?;
    let signed_tree_head_envelope_sha256 = envelope_digest(&signed_tree_head)?;
    let response = LogAuthorityResponseV12 {
        operation: "APPEND_AUTHENTICATED_RECEIPT".to_owned(),
        disposition: "SETTLED".to_owned(),
        log_append_binding_sha256: request.log_append_binding_sha256.clone(),
        previous_checkpoint,
        pre_final_log_leaf: leaf,
        signed_tree_head,
        signed_tree_head_envelope_sha256: signed_tree_head_envelope_sha256.clone(),
        inclusion_proof: build_inclusion_proof(
            &ledger.leaves,
            ledger.leaves.len() - 1,
        )?,
        consistency_proof: build_consistency_proof(
            &ledger.leaves,
            old_tree_size,
        )?,
    };
    let response_bytes = canonical_json(&response, MAX_AUTHORITY_RESPONSE_BYTES)?;
    atomic_write(response_path, &response_bytes, config.log_authority_uid)?;
    ledger.high_water = LogHighWaterV12 {
        checkpoint_sequence: response
            .signed_tree_head
            .payload
            .checkpoint_sequence
            .clone(),
        tree_size,
        tree_root_sha256,
        signed_tree_head_envelope_sha256,
        log_append_binding_sha256: request.log_append_binding_sha256.clone(),
        latest_receipt_sequence: request.receipt_body.receipt_sequence.clone(),
    };
    atomic_write(
        &config.state_root.join("ledger-v12.json"),
        &canonical_json(&ledger, MAX_AUTHORITY_RESPONSE_BYTES)?,
        config.log_authority_uid,
    )?;
    Ok(response)
}

fn validate_authenticated_append(
    config: &LogCustodyConfigV12,
    request: &LogAuthorityRequestV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.log_id != config.log_id
        || receipt_body_digest(&request.receipt_body)?.0
            != request.receipt_body_sha256
        || envelope_digest(&request.receipt_authentication_envelope)?
            != request.receipt_authentication_envelope_sha256
    {
        return Err("log append body or authentication digest is invalid".into());
    }
    let (receipt_authorization, receipt_authentication_pin) =
        load_receipt_authentication_material(config)?;
    if request
        .receipt_authentication_envelope
        .signature
        .key_authorization
        != receipt_authorization
    {
        return Err(
            "receipt authentication differs from the root-owned authorization"
                .into(),
        );
    }
    verify_receipt_authentication_envelope_v12(
        &request.receipt_authentication_envelope,
        &receipt_authentication_pin,
    )?;
    let payload = &request.receipt_authentication_envelope.payload;
    let body = &request.receipt_body;
    if payload.receipt_id != body.receipt_id
        || payload.receipt_sequence != body.receipt_sequence
        || payload.requester_principal_id != body.requester_principal_id
        || payload.replay_key_sha256 != body.replay_key_sha256
        || payload.request_v11_sha256 != body.request_v11_sha256
        || payload.request_envelope_sha256 != body.request_envelope_sha256
        || payload.request_canonical_bytes != body.request_canonical_bytes
        || payload.receipt_body_sha256 != request.receipt_body_sha256
        || payload.terminal_evidence_root_sha256
            != body.terminal_evidence_root_sha256
        || payload.terminal_state_root_sha256 != body.terminal_state_root_sha256
        || payload.body_trust_observation_sha256
            != body.body_trust_observation_sha256
    {
        return Err("receipt authentication does not bind the submitted body".into());
    }
    let expected_binding = receipt_contract_v12::h12(
        "log-authority-append",
        &[
            request.log_id.as_bytes(),
            &request.receipt_body_sha256.decode()?,
            &request
                .receipt_authentication_envelope_sha256
                .decode()?,
            &request
                .expected_previous_tree_head_envelope_sha256
                .decode()?,
        ],
    );
    if expected_binding != request.log_append_binding_sha256 {
        return Err("log append binding is not canonical".into());
    }
    Ok(())
}

fn load_receipt_authentication_material(
    config: &LogCustodyConfigV12,
) -> Result<(KeyAuthorizationV12, AuthorityPinV12), Box<dyn std::error::Error>> {
    let authorization: KeyAuthorizationV12 = parse_canonical_json(
        &secure_read(
            &config.receipt_authentication_authorization_path,
            MAX_CONFIG_BYTES,
            0,
            false,
        )?,
        MAX_CONFIG_BYTES,
    )?;
    if authorization.role != AuthorityRoleV12::ReceiptAuthentication
        || authorization.algorithm != "Ed25519"
    {
        return Err("receipt authentication authorization is invalid".into());
    }
    let public_key_bytes = secure_read(
        &config.receipt_authentication_public_key_path,
        64 * 1024,
        0,
        false,
    )?;
    let public_key = if public_key_bytes.len() == 32 {
        VerifyingKey::from_bytes(
            &public_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "receipt authentication public key length changed")?,
        )?
    } else {
        VerifyingKey::from_public_key_pem(std::str::from_utf8(
            &public_key_bytes,
        )?)?
    };
    if ed25519_spki_sha256(&public_key) != authorization.spki_der_sha256 {
        return Err(
            "receipt authentication public key does not match its authorization"
                .into(),
        );
    }
    let pin = AuthorityPinV12 {
        role: authorization.role,
        principal_id: authorization.principal_id.clone(),
        key_id: authorization.key_id.clone(),
        verifying_key_base64url: URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
        spki_der_sha256: authorization.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: authorization
            .physical_private_key_identity_sha256
            .clone(),
        key_authorization_sha256: authorization.key_authorization_sha256.clone(),
        authorization_root_sha256: authorization.authorization_root_sha256.clone(),
        authorization_revision: authorization.authorization_revision.clone(),
        revocation_root_sha256: authorization.revocation_root_sha256.clone(),
        revocation_revision: authorization.revocation_revision.clone(),
        high_water: authorization.high_water.clone(),
        valid_from: authorization.valid_from.clone(),
        valid_until: authorization.valid_until.clone(),
        status: authorization.status.clone(),
    };
    pin.verifying_key()?;
    Ok((authorization, pin))
}

fn load_log_ledger(
    config: &LogCustodyConfigV12,
) -> Result<LogLedgerV12, Box<dyn std::error::Error>> {
    let path = config.state_root.join("ledger-v12.json");
    if path.exists() {
        let bytes = secure_read(
            &path,
            MAX_AUTHORITY_RESPONSE_BYTES,
            config.log_authority_uid,
            false,
        )?;
        return Ok(parse_canonical_json(
            &bytes,
            MAX_AUTHORITY_RESPONSE_BYTES,
        )?);
    }
    Ok(LogLedgerV12 {
        leaves: Vec::new(),
        high_water: LogHighWaterV12 {
            checkpoint_sequence: CanonicalU64::new(0),
            tree_size: CanonicalU64::new(0),
            tree_root_sha256: VerificationHighWaterV12::genesis()
                .tree_root_sha256,
            signed_tree_head_envelope_sha256: DigestHex::zero(),
            log_append_binding_sha256: DigestHex::zero(),
            latest_receipt_sequence: CanonicalU64::new(0),
        },
    })
}

fn reconcile_response_state(
    config: &LogCustodyConfigV12,
    response: &LogAuthorityResponseV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if response.operation != "APPEND_AUTHENTICATED_RECEIPT"
        || response.disposition != "SETTLED"
        || envelope_digest(&response.signed_tree_head)?
            != response.signed_tree_head_envelope_sha256
    {
        return Err("persisted log response is invalid".into());
    }
    let mut ledger = load_log_ledger(config)?;
    if ledger.high_water.signed_tree_head_envelope_sha256
        == response.signed_tree_head_envelope_sha256
    {
        return Ok(());
    }
    if ledger.high_water.signed_tree_head_envelope_sha256
            != response
                .previous_checkpoint
                .signed_tree_head_envelope_sha256
        || response.pre_final_log_leaf.leaf_ordinal.get()?
            != ledger.leaves.len() as u64
    {
        return Err("persisted log response cannot extend durable state".into());
    }
    ledger
        .leaves
        .push(response.pre_final_log_leaf.leaf_sha256.clone());
    if merkle_root(&ledger.leaves)?
            != response.signed_tree_head.payload.root_sha256
        || response.signed_tree_head.payload.tree_size.get()?
            != ledger.leaves.len() as u64
    {
        return Err("persisted log response has an invalid Merkle transition".into());
    }
    ledger.high_water = LogHighWaterV12 {
        checkpoint_sequence: response
            .signed_tree_head
            .payload
            .checkpoint_sequence
            .clone(),
        tree_size: response.signed_tree_head.payload.tree_size.clone(),
        tree_root_sha256: response.signed_tree_head.payload.root_sha256.clone(),
        signed_tree_head_envelope_sha256: response
            .signed_tree_head_envelope_sha256
            .clone(),
        log_append_binding_sha256: response
            .log_append_binding_sha256
            .clone(),
        latest_receipt_sequence: response
            .signed_tree_head
            .payload
            .latest_receipt_sequence
            .clone(),
    };
    atomic_write(
        &config.state_root.join("ledger-v12.json"),
        &canonical_json(&ledger, MAX_AUTHORITY_RESPONSE_BYTES)?,
        config.log_authority_uid,
    )?;
    Ok(())
}

fn activated_listener(
    config: &LogCustodyConfigV12,
) -> Result<UnixListener, Box<dyn std::error::Error>> {
    let listen_pid: u32 = std::env::var("LISTEN_PID")?.parse()?;
    let listen_fds: u32 = std::env::var("LISTEN_FDS")?.parse()?;
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err("exactly one systemd-activated log listener is required".into());
    }
    inspect_activated_listener_v12(
        SYSTEMD_LISTEN_FD,
        config.listener_owner_uid,
        config.listener_mode,
    )?;
    Ok(unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) })
}

fn read_signing_key(path: &Path, owner: u32) -> std::io::Result<SigningKey> {
    let mut bytes = secure_read(path, 32, owner, true)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "log signing key must be a raw 32-byte seed",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    bytes.zeroize();
    Ok(key)
}

fn secure_read(
    path: &Path,
    maximum: usize,
    owner: u32,
    private: bool,
) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    let forbidden = if private { 0o077 } else { 0o022 };
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.len() == 0
        || metadata.len() > maximum as u64
        || metadata.mode() & forbidden != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log authority file metadata is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "log authority file changed during read",
        ));
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8], owner: u32) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "state path has no parent")
    })?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("state"),
        std::process::id(),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if file.metadata()?.uid() != owner {
        let _ = fs::remove_file(&temporary);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log state owner changed",
        ));
    }
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()
}
