#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;

use ed25519_dalek::SigningKey;
use receipt_contract_v12::{
    canonical_json, envelope_digest, final_trust_observation_digest,
    finalization_binding_digest, log_bundle_digest, logged_receipt_bundle_digest,
    inspect_activated_listener_v12, notify_systemd_v12, parse_canonical_json,
    peer_uid_v12,
    read_authority_frame_v12, seal_receipt,
    sign_envelope, write_authority_frame_v12,
    AuthorityRoleV12, CanonicalU64, DigestHex, FinalVerdictAuthorityRequestV12,
    FinalVerdictAuthorityResponseV12, FinalVerdictPayloadV12, KeyAuthorizationV12,
    ReceiptV12, VerificationHighWaterV12,
    FINAL_VERDICT_DOMAIN, MAX_AUTHORITY_REQUEST_BYTES, MAX_AUTHORITY_RESPONSE_BYTES,
    RECEIPT_CONTRACT_VERSION, REQUEST_CONTRACT_VERSION,
};
use receipt_verifier_v12::{
    build_final_trust_observation, verify_logged_bundle_v12, verify_receipt_v12,
    verify_trust_generation_bundle, StrictVerifierPinsV12,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SYSTEMD_LISTEN_FD: i32 = 3;
const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalVerdictAuthorityConfigV12 {
    config_version: u64,
    receipt_authority_uid: u32,
    final_verdict_authority_uid: u32,
    allowed_peer_uids: Vec<u32>,
    disjoint_authority_uids: Vec<u32>,
    listener_owner_uid: u32,
    listener_mode: u32,
    final_verdict_signing_key_path: PathBuf,
    final_verdict_authorization: KeyAuthorizationV12,
    strict_verifier_pins: StrictVerifierPinsV12,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("final-verdict authority hard-unready: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::var_os("SERVERWARE_FINAL_VERDICT_AUTHORITY_CONFIG")
        .ok_or("SERVERWARE_FINAL_VERDICT_AUTHORITY_CONFIG is required")?;
    let config_bytes =
        read_secure_file(Path::new(&config_path), MAX_CONFIG_BYTES, 0, false)?;
    let config: FinalVerdictAuthorityConfigV12 =
        parse_canonical_json(&config_bytes, MAX_CONFIG_BYTES)?;
    validate_config(&config)?;
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 || effective_uid != config.final_verdict_authority_uid {
        return Err("final-verdict authority must run as its pinned non-root UID".into());
    }
    let final_key =
        read_signing_key(&config.final_verdict_signing_key_path, effective_uid)?;
    if receipt_contract_v12::ed25519_spki_sha256(&final_key.verifying_key())
        != config.strict_verifier_pins.final_verdict.spki_der_sha256
    {
        return Err("final-verdict private key does not match current pin".into());
    }
    let listener = activated_listener(
        config.listener_owner_uid,
        config.listener_mode,
    )?;
    notify_systemd_v12("final-verdict-v12 verifier ready")?;
    loop {
        let (stream, _) = listener.accept()?;
        if let Err(error) = handle_connection(stream, &config, &final_key) {
            eprintln!("final-verdict authority rejected request: {error}");
        }
    }
}

fn handle_connection(
    stream: UnixStream,
    config: &FinalVerdictAuthorityConfigV12,
    final_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    if peer_uid_v12(&stream)? != config.receipt_authority_uid {
        return Err("final-verdict peer UID is not the receipt authority".into());
    }
    let (request_bytes, frame) =
        read_authority_frame_v12(&stream, MAX_AUTHORITY_REQUEST_BYTES)?;
    let request: FinalVerdictAuthorityRequestV12 =
        parse_canonical_json(&request_bytes, MAX_AUTHORITY_REQUEST_BYTES)?;
    if request.deadline.boottime_deadline_ns.get()?
        != frame.boottime_deadline_ns
    {
        return Err("final-verdict request changed CLOCK_BOOTTIME deadline".into());
    }
    request.deadline.require_live()?;
    let response = process_request(request, config, final_key)?;
    let response_bytes = canonical_json(&response, MAX_AUTHORITY_RESPONSE_BYTES)?;
    write_authority_frame_v12(
        &stream,
        &response_bytes,
        MAX_AUTHORITY_RESPONSE_BYTES,
        frame.boottime_deadline_ns,
    )?;
    Ok(())
}

fn process_request(
    request: FinalVerdictAuthorityRequestV12,
    config: &FinalVerdictAuthorityConfigV12,
    final_key: &SigningKey,
) -> Result<FinalVerdictAuthorityResponseV12, Box<dyn std::error::Error>> {
    if request.operation != "FINALIZE" {
        return Err("unsupported final-verdict operation".into());
    }
    let logged_bundle_bytes =
        canonical_json(&request.logged_bundle, MAX_AUTHORITY_REQUEST_BYTES)?;
    let logged_bundle_sha256 =
        logged_receipt_bundle_digest(&request.logged_bundle)?;
    if logged_bundle_sha256 != request.logged_bundle_sha256 {
        return Err("logged receipt bundle digest mismatch".into());
    }
    let trust = &request.final_trust_observation.trust_generation;
    let predecessor = predecessor_high_water(&request)?;
    verify_trust_generation_bundle(
        trust,
        &config.strict_verifier_pins,
        &predecessor,
        true,
    )?;
    let verified_logged = verify_logged_bundle_v12(
        &logged_bundle_bytes,
        &config.strict_verifier_pins,
        &predecessor,
    )?;
    if verified_logged.logged_bundle_sha256 != logged_bundle_sha256
        || request.requested_verdict != request.logged_bundle.receipt_body.verdict
    {
        return Err("logged bundle or verdict does not join finalization".into());
    }
    let witness_envelope_sha256 =
        envelope_digest(&request.external_witness_checkpoint)?;
    let expected_trust = build_final_trust_observation(
        trust.clone(),
        &config.strict_verifier_pins,
        &predecessor,
        verified_logged.request.trust_observation_sha256,
        request
            .logged_bundle
            .receipt_body
            .body_trust_observation_sha256
            .clone(),
        request
            .logged_bundle
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_envelope_sha256.clone(),
        request.final_trust_observation.observed_at.clone(),
    )?;
    if expected_trust != request.final_trust_observation {
        return Err("final trust observation is not the fresh signed generation".into());
    }
    let trust_observation_sha256 =
        final_trust_observation_digest(&request.final_trust_observation)?;
    let finalization_binding_sha256 = finalization_binding_digest(
        &logged_bundle_sha256,
        &witness_envelope_sha256,
        &trust_observation_sha256,
        request.requested_verdict,
    )?;
    if finalization_binding_sha256
        != request.expected_finalization_binding_sha256
    {
        return Err("finalization binding digest mismatch".into());
    }
    let log_bundle_sha256 = log_bundle_digest(
        &request.logged_bundle.previous_checkpoint,
        &request.logged_bundle.pre_final_log_leaf,
        &request.logged_bundle.signed_tree_head_envelope_sha256,
        &request.logged_bundle.inclusion_proof,
        &request.logged_bundle.consistency_proof,
        &witness_envelope_sha256,
    )?;
    let issued_at = request.final_trust_observation.observed_at.clone();
    let final_payload = FinalVerdictPayloadV12 {
        receipt_id: request.logged_bundle.receipt_id.clone(),
        receipt_sequence: request.logged_bundle.receipt_sequence.clone(),
        requester_principal_id: request
            .logged_bundle
            .requester_principal_id
            .clone(),
        replay_key_sha256: request
            .logged_bundle
            .replay_identity
            .replay_key_sha256
            .clone(),
        request_v11_sha256: request.logged_bundle.request_v11_sha256.clone(),
        request_envelope_sha256: request
            .logged_bundle
            .request_envelope_sha256
            .clone(),
        request_canonical_bytes: request
            .logged_bundle
            .request_canonical_bytes
            .clone(),
        receipt_body_sha256: request.logged_bundle.receipt_body_sha256.clone(),
        receipt_body_canonical_bytes: request
            .logged_bundle
            .receipt_body_canonical_bytes
            .clone(),
        terminal_evidence_root_sha256: request
            .logged_bundle
            .receipt_body
            .terminal_evidence_root_sha256
            .clone(),
        terminal_state_root_sha256: request
            .logged_bundle
            .receipt_body
            .terminal_state_root_sha256
            .clone(),
        receipt_authentication_envelope_sha256: request
            .logged_bundle
            .receipt_authentication_envelope_sha256
            .clone(),
        signed_tree_head_envelope_sha256: request
            .logged_bundle
            .signed_tree_head_envelope_sha256
            .clone(),
        external_witness_checkpoint_envelope_sha256:
            witness_envelope_sha256.clone(),
        log_bundle_sha256: log_bundle_sha256.clone(),
        final_trust_observation_sha256: trust_observation_sha256.clone(),
        tree_size: request.logged_bundle.signed_tree_head.payload.tree_size.clone(),
        tree_root_sha256: request
            .logged_bundle
            .signed_tree_head
            .payload
            .root_sha256
            .clone(),
        verdict: request.requested_verdict,
        issued_at: issued_at.clone(),
    };
    let final_verdict_envelope = sign_envelope(
        FINAL_VERDICT_DOMAIN,
        AuthorityRoleV12::FinalVerdict,
        final_payload,
        config.final_verdict_authorization.clone(),
        final_key,
        &issued_at,
        &issued_at,
    )?;
    let final_verdict_envelope_sha256 =
        envelope_digest(&final_verdict_envelope)?;
    let unsealed = ReceiptV12 {
        contract_version: RECEIPT_CONTRACT_VERSION,
        request_contract_version: REQUEST_CONTRACT_VERSION,
        receipt_id: request.logged_bundle.receipt_id,
        receipt_sequence: request.logged_bundle.receipt_sequence,
        requester_principal_id: request.logged_bundle.requester_principal_id,
        replay_identity: request.logged_bundle.replay_identity,
        request_v11: request.logged_bundle.request_v11,
        request_admission: request.logged_bundle.request_admission,
        request_admission_sha256: request.logged_bundle.request_admission_sha256,
        request_v11_sha256: request.logged_bundle.request_v11_sha256,
        request_envelope_sha256: request.logged_bundle.request_envelope_sha256,
        request_canonical_bytes: request.logged_bundle.request_canonical_bytes,
        receipt_body: request.logged_bundle.receipt_body,
        receipt_body_sha256: request.logged_bundle.receipt_body_sha256,
        receipt_body_canonical_bytes: request
            .logged_bundle
            .receipt_body_canonical_bytes,
        receipt_authentication_envelope: request
            .logged_bundle
            .receipt_authentication_envelope,
        receipt_authentication_envelope_sha256: request
            .logged_bundle
            .receipt_authentication_envelope_sha256,
        previous_checkpoint: request.logged_bundle.previous_checkpoint,
        pre_final_log_leaf: request.logged_bundle.pre_final_log_leaf,
        signed_tree_head: request.logged_bundle.signed_tree_head,
        signed_tree_head_envelope_sha256: request
            .logged_bundle
            .signed_tree_head_envelope_sha256,
        inclusion_proof: request.logged_bundle.inclusion_proof,
        consistency_proof: request.logged_bundle.consistency_proof,
        external_witness_checkpoint: request.external_witness_checkpoint,
        external_witness_checkpoint_envelope_sha256: witness_envelope_sha256,
        log_bundle_sha256,
        final_trust_observation: request.final_trust_observation,
        final_trust_observation_sha256: trust_observation_sha256,
        final_verdict_envelope,
        final_verdict_envelope_sha256,
        receipt_envelope_sha256: DigestHex::zero(),
        receipt_canonical_bytes: CanonicalU64::new(0),
    };
    let (receipt, exact_receipt_bytes) = seal_receipt(unsealed)?;
    verify_receipt_v12(
        &exact_receipt_bytes,
        &config.strict_verifier_pins,
        &predecessor,
    )?;
    Ok(FinalVerdictAuthorityResponseV12 {
        operation: "FINALIZE".to_owned(),
        disposition: "SIGNED".to_owned(),
        receipt,
    })
}

fn predecessor_high_water(
    request: &FinalVerdictAuthorityRequestV12,
) -> Result<VerificationHighWaterV12, Box<dyn std::error::Error>> {
    let trust = &request.final_trust_observation.trust_generation.generation.payload;
    Ok(VerificationHighWaterV12 {
        receipt_sequence: request
            .final_trust_observation
            .minimum_accepted_receipt_sequence
            .clone(),
        receipt_envelope_sha256: DigestHex::zero(),
        tree_size: request.logged_bundle.previous_checkpoint.tree_size.clone(),
        tree_root_sha256: request
            .logged_bundle
            .previous_checkpoint
            .root_sha256
            .clone(),
        signed_tree_head_envelope_sha256: request
            .logged_bundle
            .previous_checkpoint
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sequence: request
            .final_trust_observation
            .minimum_accepted_witness_sequence
            .clone(),
        witness_checkpoint_envelope_sha256: request
            .external_witness_checkpoint
            .payload
            .previous_witness_checkpoint_envelope_sha256
            .clone(),
        settlement_sequence: CanonicalU64::new(
            request.logged_bundle.previous_checkpoint.tree_size.get()?,
        ),
        settlement_checkpoint_envelope_sha256: DigestHex::zero(),
        trust_generation_sequence: CanonicalU64::new(
            trust.generation_sequence.get()?.saturating_sub(1),
        ),
        trust_generation_envelope_sha256: trust
            .previous_generation_envelope_sha256
            .clone(),
        trust_rollback_floor: trust.rollback_floor.clone(),
        authorization_high_water: CanonicalU64::new(0),
        revocation_high_water: CanonicalU64::new(0),
    })
}

fn validate_config(
    config: &FinalVerdictAuthorityConfigV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.config_version != 12
        || config.allowed_peer_uids != vec![config.receipt_authority_uid]
        || config.final_verdict_authorization.role != AuthorityRoleV12::FinalVerdict
        || config.disjoint_authority_uids.len() < 7
    {
        return Err("invalid final-verdict authority configuration".into());
    }
    let mut uids = config.disjoint_authority_uids.clone();
    uids.sort_unstable();
    uids.dedup();
    if uids.len() != config.disjoint_authority_uids.len()
        || uids.contains(&0)
        || !uids.contains(&config.receipt_authority_uid)
        || !uids.contains(&config.final_verdict_authority_uid)
    {
        return Err("authority UIDs are not non-root and pairwise distinct".into());
    }
    config.strict_verifier_pins.validate()?;
    let pin = &config.strict_verifier_pins.final_verdict;
    let authorization = &config.final_verdict_authorization;
    if authorization.principal_id != pin.principal_id
        || authorization.key_id != pin.key_id
        || authorization.spki_der_sha256 != pin.spki_der_sha256
        || authorization.physical_private_key_identity_sha256
            != pin.physical_private_key_identity_sha256
        || authorization.key_authorization_sha256 != pin.key_authorization_sha256
        || authorization.authorization_root_sha256 != pin.authorization_root_sha256
        || authorization.authorization_revision != pin.authorization_revision
        || authorization.revocation_root_sha256 != pin.revocation_root_sha256
        || authorization.revocation_revision != pin.revocation_revision
        || authorization.high_water != pin.high_water
        || authorization.valid_from != pin.valid_from
        || authorization.valid_until != pin.valid_until
        || authorization.status != pin.status
    {
        return Err("final-verdict authorization differs from current pin".into());
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
    Ok(unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) })
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
