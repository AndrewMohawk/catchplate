#![allow(dead_code)]

#[path = "../coder_controller_v11.rs"]
mod coder_controller_v11;
#[path = "../receipt_contract_v12.rs"]
mod receipt_contract_v12;
#[path = "../receipt_verifier_v12.rs"]
mod receipt_verifier_v12;

use ed25519_dalek::SigningKey;
use receipt_contract_v12::{
    canonical_json, ed25519_spki_sha256, envelope_digest, h12,
    inspect_activated_listener_v12, logged_receipt_bundle_digest,
    notify_systemd_v12, now_utc_rfc3339, parse_canonical_json,
    peer_uid_v12, read_authority_frame_v12, sign_envelope,
    validate_identifier, verify_envelope_cryptography,
    write_authority_frame_v12,
    AuthorityDeadlineV12, AuthorityRoleV12, AuthorityTrustMaterialV12,
    CanonicalU64, DigestHex, ExternalWitnessPayloadV12,
    FinalSettlementArtifactV12, FinalSettlementCheckpointV12,
    FinalSettlementOutcomeV12, FinalSettlementPayloadV12,
    FinalSettlementRequestV12, FinalSettlementResponseV12,
    KeyAuthorizationV12, SignedTreeHeadV12,
    TrustGenerationBundleV12, TrustGenerationResolveRequestV12,
    TrustGenerationResolveResponseV12, VerificationHighWaterV12,
    WitnessFinalizationRequestV12, WitnessFinalizationResponseV12,
    EXTERNAL_WITNESS_DOMAIN, FINAL_SETTLEMENT_DOMAIN,
    MAX_AUTHORITY_REQUEST_BYTES, MAX_AUTHORITY_RESPONSE_BYTES,
    MAX_RECEIPT_BYTES, RECEIPT_TREE_HEAD_DOMAIN,
};
use receipt_verifier_v12::{
    logged_bundle_from_receipt, verify_final_settlement_artifact_v12,
    verify_genesis_final_settlement_anchor_v12, verify_logged_bundle_v12,
    verify_receipt_v12, verify_trust_generation_bundle, AuthorityPinV12,
    StrictVerifierPinsV12,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SYSTEMD_LISTEN_FD: i32 = 3;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_STATE_BYTES: usize = MAX_AUTHORITY_RESPONSE_BYTES;
const MAX_RESPONSE_RECORDS: usize = 1_000_000;
const STATE_VERSION: u64 = 12;
const TRUST_STATE_FILE: &str = "trust-generation-high-water-v12.json";
const WITNESS_STATE_FILE: &str = "external-witness-high-water-v12.json";
const SETTLEMENT_STATE_FILE: &str = "final-settlement-high-water-v12.json";
const WITNESS_RESPONSES_DIRECTORY: &str = "external-witness-responses-v12";
const SETTLEMENT_RESPONSES_DIRECTORY: &str = "final-settlement-responses-v12";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum LocalAuthorityRoleV12 {
    #[serde(rename = "trust-generation")]
    TrustGeneration,
    #[serde(rename = "external-witness")]
    ExternalWitness,
    #[serde(rename = "final-settlement")]
    FinalSettlement,
}

impl LocalAuthorityRoleV12 {
    fn label(self) -> &'static str {
        match self {
            Self::TrustGeneration => "trust-generation",
            Self::ExternalWitness => "external-witness",
            Self::FinalSettlement => "final-settlement",
        }
    }

    fn signing_role(self) -> Option<AuthorityRoleV12> {
        match self {
            Self::TrustGeneration => None,
            Self::ExternalWitness => Some(AuthorityRoleV12::ExternalWitness),
            Self::FinalSettlement => Some(AuthorityRoleV12::FinalSettlement),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalTrustAuthorityConfigV12 {
    config_version: u64,
    authority_profile: String,
    role: LocalAuthorityRoleV12,
    co_located: bool,
    fault_domain_independent: bool,
    authority_uid: u32,
    allowed_peer_uids: Vec<u32>,
    listener_owner_uid: u32,
    listener_mode: u32,
    state_root: PathBuf,
    strict_verifier_pins: StrictVerifierPinsV12,
    trust_generation_bundle_path: PathBuf,
    signing_key_path: Option<PathBuf>,
    key_authorization_path: Option<PathBuf>,
    genesis_checkpoint_path: Option<PathBuf>,
    witness_id: Option<String>,
    key_provider: Option<String>,
}

struct RuntimeV12 {
    config: LocalTrustAuthorityConfigV12,
    trust_generation: TrustGenerationBundleV12,
    trust_generation_envelope_sha256: DigestHex,
    signing_key: Option<SigningKey>,
    key_authorization: Option<KeyAuthorizationV12>,
    genesis_checkpoint_sha256: Option<DigestHex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustGenerationHighWaterV12 {
    state_version: u64,
    generation_sequence: CanonicalU64,
    generation_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WitnessHighWaterV12 {
    state_version: u64,
    witness_sequence: CanonicalU64,
    witness_checkpoint_envelope_sha256: DigestHex,
    log_id: String,
    checkpoint_sequence: CanonicalU64,
    tree_size: CanonicalU64,
    tree_root_sha256: DigestHex,
    signed_tree_head_envelope_sha256: DigestHex,
    trust_generation_envelope_sha256: DigestHex,
}

impl WitnessHighWaterV12 {
    fn genesis() -> Self {
        Self {
            state_version: STATE_VERSION,
            witness_sequence: CanonicalU64::new(0),
            witness_checkpoint_envelope_sha256: DigestHex::zero(),
            log_id: String::new(),
            checkpoint_sequence: CanonicalU64::new(0),
            tree_size: CanonicalU64::new(0),
            tree_root_sha256: VerificationHighWaterV12::genesis()
                .tree_root_sha256,
            signed_tree_head_envelope_sha256: DigestHex::zero(),
            trust_generation_envelope_sha256: DigestHex::zero(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedWitnessResponseV12 {
    state_version: u64,
    request_binding_sha256: DigestHex,
    request: WitnessFinalizationRequestV12,
    trust_generation: TrustGenerationBundleV12,
    predecessor: WitnessHighWaterV12,
    response: WitnessFinalizationResponseV12,
    next_high_water: WitnessHighWaterV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettlementHighWaterV12 {
    state_version: u64,
    genesis_checkpoint_envelope_sha256: DigestHex,
    high_water: VerificationHighWaterV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedSettlementResponseV12 {
    state_version: u64,
    request_binding_sha256: DigestHex,
    predecessor: VerificationHighWaterV12,
    response: FinalSettlementResponseV12,
    next_high_water: VerificationHighWaterV12,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("local trusted-host authority hard-unready: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--config" {
        return Err(
            "usage: catchplate-coder-local-trust-authority-v12 --config ABSOLUTE_PATH"
                .into(),
        );
    }
    let config_path = Path::new(&arguments[1]);
    if !config_path.is_absolute() {
        return Err("authority configuration path must be absolute".into());
    }
    let config_bytes = secure_read(config_path, MAX_CONFIG_BYTES, 0, false)?;
    let config: LocalTrustAuthorityConfigV12 =
        parse_canonical_json(&config_bytes, MAX_CONFIG_BYTES)?;

    if config.authority_profile == "external-production" {
        return Err(
            "external-production requires an external authority adapter; local fallback is forbidden"
                .into(),
        );
    }
    validate_local_config(&config)?;
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 || effective_uid != config.authority_uid {
        return Err("local authority must run as its configured non-root UID".into());
    }
    validate_private_directory(&config.state_root, config.authority_uid)?;

    let trust_generation_bytes = secure_read(
        &config.trust_generation_bundle_path,
        MAX_CONFIG_BYTES,
        0,
        false,
    )?;
    let trust_generation: TrustGenerationBundleV12 =
        parse_canonical_json(&trust_generation_bytes, MAX_CONFIG_BYTES)?;
    let trust_predecessor = trust_generation_predecessor(&trust_generation)?;
    let trust_generation_envelope_sha256 = verify_trust_generation_bundle(
        &trust_generation,
        &config.strict_verifier_pins,
        &trust_predecessor,
        true,
    )?;
    if trust_generation_envelope_sha256
        != trust_generation.generation_envelope_sha256
    {
        return Err("provisioned trust generation has an inconsistent digest".into());
    }

    let (signing_key, key_authorization) =
        load_role_signing_material(&config, effective_uid)?;
    let genesis_checkpoint_sha256 =
        load_and_verify_genesis(&config)?;
    let runtime = RuntimeV12 {
        config,
        trust_generation,
        trust_generation_envelope_sha256,
        signing_key,
        key_authorization,
        genesis_checkpoint_sha256,
    };

    reconcile_role_state(&runtime)?;
    let listener = activated_listener(
        runtime.config.listener_owner_uid,
        runtime.config.listener_mode,
    )?;
    notify_systemd_v12(&format!(
        "local-trusted-host role={} coLocated=true faultDomainIndependent=false; file-provisioned Ed25519 only",
        runtime.config.role.label(),
    ))?;
    loop {
        let (stream, _) = listener.accept()?;
        if let Err(error) = handle_connection(&runtime, stream) {
            eprintln!(
                "local trusted-host {} authority rejected request: {error}",
                runtime.config.role.label(),
            );
        }
    }
}

fn validate_local_config(
    config: &LocalTrustAuthorityConfigV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.config_version != 12
        || config.authority_profile != "local-trusted-host"
        || !config.co_located
        || config.fault_domain_independent
        || config.authority_uid == 0
        || config.listener_owner_uid != 0
        || config.listener_mode != 0o660
        || config.allowed_peer_uids.is_empty()
        || config.allowed_peer_uids.len() > 8
        || !config.state_root.is_absolute()
        || !config.trust_generation_bundle_path.is_absolute()
    {
        return Err("invalid local-trusted-host authority configuration".into());
    }
    let mut peer_uids = config.allowed_peer_uids.clone();
    peer_uids.sort_unstable();
    peer_uids.dedup();
    if peer_uids.len() != config.allowed_peer_uids.len()
        || peer_uids.contains(&config.authority_uid)
    {
        return Err("authority peer UID allowlist is invalid".into());
    }
    config.strict_verifier_pins.validate()?;

    match config.role {
        LocalAuthorityRoleV12::TrustGeneration => {
            if config.signing_key_path.is_some()
                || config.key_authorization_path.is_some()
                || config.genesis_checkpoint_path.is_some()
                || config.witness_id.is_some()
                || config.key_provider.is_some()
            {
                return Err(
                    "trust-generation resolver must not be configured with local signing material"
                        .into(),
                );
            }
        }
        LocalAuthorityRoleV12::ExternalWitness => {
            require_signing_config(config)?;
            let witness_id = config
                .witness_id
                .as_deref()
                .ok_or("external-witness role requires witnessId")?;
            validate_identifier(witness_id)?;
            if config.genesis_checkpoint_path.is_some() {
                return Err(
                    "external-witness role must not consume final-settlement genesis"
                        .into(),
                );
            }
        }
        LocalAuthorityRoleV12::FinalSettlement => {
            require_signing_config(config)?;
            if config.witness_id.is_some()
                || !config
                    .genesis_checkpoint_path
                    .as_ref()
                    .is_some_and(|path| path.is_absolute())
            {
                return Err(
                    "final-settlement role requires an absolute genesis path and no witnessId"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

fn require_signing_config(
    config: &LocalTrustAuthorityConfigV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.key_provider.as_deref() != Some("provisioned-file-ed25519")
        || !config
            .signing_key_path
            .as_ref()
            .is_some_and(|path| path.is_absolute())
        || !config
            .key_authorization_path
            .as_ref()
            .is_some_and(|path| path.is_absolute())
    {
        return Err(
            "local signing roles require provisioned-file-ed25519 and absolute provisioned paths"
                .into(),
        );
    }
    Ok(())
}

fn load_role_signing_material(
    config: &LocalTrustAuthorityConfigV12,
    effective_uid: u32,
) -> Result<(Option<SigningKey>, Option<KeyAuthorizationV12>), Box<dyn std::error::Error>>
{
    let Some(role) = config.role.signing_role() else {
        return Ok((None, None));
    };
    let signing_key_path = config
        .signing_key_path
        .as_deref()
        .ok_or("signing role lacks signing key path")?;
    let authorization_path = config
        .key_authorization_path
        .as_deref()
        .ok_or("signing role lacks key authorization path")?;
    let key = read_signing_key(signing_key_path, effective_uid)?;
    let authorization_bytes =
        secure_read(authorization_path, MAX_CONFIG_BYTES, 0, false)?;
    let authorization: KeyAuthorizationV12 =
        parse_canonical_json(&authorization_bytes, MAX_CONFIG_BYTES)?;
    let pin = pin_for_role(&config.strict_verifier_pins, role)?;
    require_authorization_matches_pin(&authorization, pin, role)?;
    if ed25519_spki_sha256(&key.verifying_key()) != pin.spki_der_sha256 {
        return Err("provisioned private key does not match its authority pin".into());
    }
    Ok((Some(key), Some(authorization)))
}

fn load_and_verify_genesis(
    config: &LocalTrustAuthorityConfigV12,
) -> Result<Option<DigestHex>, Box<dyn std::error::Error>> {
    if config.role != LocalAuthorityRoleV12::FinalSettlement {
        return Ok(None);
    }
    let path = config
        .genesis_checkpoint_path
        .as_deref()
        .ok_or("final-settlement genesis path is absent")?;
    let bytes = secure_read(path, MAX_AUTHORITY_RESPONSE_BYTES, 0, false)?;
    let checkpoint: FinalSettlementCheckpointV12 =
        parse_canonical_json(&bytes, MAX_AUTHORITY_RESPONSE_BYTES)?;
    verify_genesis_final_settlement_anchor_v12(
        &checkpoint,
        &config.strict_verifier_pins,
    )?;
    Ok(Some(envelope_digest(&checkpoint)?))
}

fn reconcile_role_state(
    runtime: &RuntimeV12,
) -> Result<(), Box<dyn std::error::Error>> {
    match runtime.config.role {
        LocalAuthorityRoleV12::TrustGeneration => {
            reconcile_trust_generation(runtime)
        }
        LocalAuthorityRoleV12::ExternalWitness => {
            ensure_private_subdirectory(
                &runtime
                    .config
                    .state_root
                    .join(WITNESS_RESPONSES_DIRECTORY),
                runtime.config.authority_uid,
            )?;
            reconcile_witness(runtime)
        }
        LocalAuthorityRoleV12::FinalSettlement => {
            ensure_private_subdirectory(
                &runtime
                    .config
                    .state_root
                    .join(SETTLEMENT_RESPONSES_DIRECTORY),
                runtime.config.authority_uid,
            )?;
            reconcile_settlement(runtime)
        }
    }
}

fn reconcile_trust_generation(
    runtime: &RuntimeV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = runtime.config.state_root.join(TRUST_STATE_FILE);
    let generation_sequence = runtime
        .trust_generation
        .generation
        .payload
        .generation_sequence
        .get()?;
    let next = TrustGenerationHighWaterV12 {
        state_version: STATE_VERSION,
        generation_sequence: CanonicalU64::new(generation_sequence),
        generation_envelope_sha256: runtime
            .trust_generation_envelope_sha256
            .clone(),
    };
    if path.exists() {
        let current: TrustGenerationHighWaterV12 =
            read_state(&path, runtime.config.authority_uid)?;
        if current.state_version != STATE_VERSION {
            return Err("trust-generation state version is invalid".into());
        }
        let current_sequence = current.generation_sequence.get()?;
        if generation_sequence < current_sequence
            || (generation_sequence == current_sequence
                && current.generation_envelope_sha256
                    != runtime.trust_generation_envelope_sha256)
            || (generation_sequence > current_sequence
                && (Some(generation_sequence)
                    != current_sequence.checked_add(1)
                    || runtime
                        .trust_generation
                        .generation
                        .payload
                        .previous_generation_envelope_sha256
                        != current.generation_envelope_sha256))
        {
            return Err(
                "provisioned trust generation rolls back, forks, or skips durable state"
                    .into(),
            );
        }
        if current == next {
            return Ok(());
        }
    }
    atomic_write_state(
        &path,
        &canonical_json(&next, MAX_STATE_BYTES)?,
        runtime.config.authority_uid,
    )?;
    Ok(())
}

fn handle_connection(
    runtime: &RuntimeV12,
    stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_uid = peer_uid_v12(&stream)?;
    if !runtime.config.allowed_peer_uids.contains(&peer_uid) {
        return Err("peer UID is not authorized for this local authority role".into());
    }
    let (request_bytes, frame) =
        read_authority_frame_v12(&stream, MAX_AUTHORITY_REQUEST_BYTES)?;
    let request_value: Value =
        parse_canonical_json(&request_bytes, MAX_AUTHORITY_REQUEST_BYTES)?;
    let operation = request_value
        .as_object()
        .and_then(|object| object.get("operation"))
        .and_then(Value::as_str)
        .ok_or("authority request has no canonical operation")?;

    let response_bytes = match runtime.config.role {
        LocalAuthorityRoleV12::TrustGeneration => {
            if !matches!(
                operation,
                "RESOLVE_FRESH_TRUST_GENERATION"
                    | "RESOLVE_CURRENT_TRUST_GENERATION"
            ) {
                return Err("operation is not supported by trust-generation role".into());
            }
            let request: TrustGenerationResolveRequestV12 =
                parse_canonical_json(
                    &request_bytes,
                    MAX_AUTHORITY_REQUEST_BYTES,
                )?;
            require_frame_deadline(&request.deadline, frame.boottime_deadline_ns)?;
            canonical_json(
                &process_trust_generation(runtime, &request)?,
                MAX_AUTHORITY_RESPONSE_BYTES,
            )?
        }
        LocalAuthorityRoleV12::ExternalWitness => {
            if !matches!(
                operation,
                "WITNESS_FINALIZATION" | "WITNESS_LOGGED_RECEIPT"
            ) {
                return Err("operation is not supported by external-witness role".into());
            }
            let request: WitnessFinalizationRequestV12 =
                parse_canonical_json(
                    &request_bytes,
                    MAX_AUTHORITY_REQUEST_BYTES,
                )?;
            require_frame_deadline(&request.deadline, frame.boottime_deadline_ns)?;
            canonical_json(
                &process_witness(runtime, &request)?,
                MAX_AUTHORITY_RESPONSE_BYTES,
            )?
        }
        LocalAuthorityRoleV12::FinalSettlement => {
            if operation != "SETTLE_FINAL" {
                return Err("operation is not supported by final-settlement role".into());
            }
            let request: FinalSettlementRequestV12 =
                parse_canonical_json(
                    &request_bytes,
                    MAX_AUTHORITY_REQUEST_BYTES,
                )?;
            require_frame_deadline(&request.deadline, frame.boottime_deadline_ns)?;
            canonical_json(
                &process_settlement(runtime, &request)?,
                MAX_AUTHORITY_RESPONSE_BYTES,
            )?
        }
    };
    write_authority_frame_v12(
        &stream,
        &response_bytes,
        MAX_AUTHORITY_RESPONSE_BYTES,
        frame.boottime_deadline_ns,
    )?;
    Ok(())
}

fn require_frame_deadline(
    deadline: &AuthorityDeadlineV12,
    frame_deadline: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if deadline.boottime_deadline_ns.get()? != frame_deadline {
        return Err("request changed the exact framed CLOCK_BOOTTIME deadline".into());
    }
    deadline.require_live()?;
    Ok(())
}

fn process_trust_generation(
    runtime: &RuntimeV12,
    request: &TrustGenerationResolveRequestV12,
) -> Result<TrustGenerationResolveResponseV12, Box<dyn std::error::Error>> {
    if request.receipt_id.is_empty()
        || request.receipt_sequence.get()? == 0
        || request.replay_key_sha256 == DigestHex::zero()
        || request.logged_bundle_sha256 == DigestHex::zero()
    {
        return Err("trust-generation request identity is incomplete".into());
    }
    validate_identifier(&request.receipt_id)?;
    let durable: TrustGenerationHighWaterV12 = read_state(
        &runtime.config.state_root.join(TRUST_STATE_FILE),
        runtime.config.authority_uid,
    )?;
    let minimum = request.minimum_generation_sequence.get()?;
    let available = durable.generation_sequence.get()?;
    if minimum > available
        || durable.generation_envelope_sha256
            != runtime.trust_generation_envelope_sha256
    {
        return Err(
            "no provisioned trust generation satisfies the monotonic requested minimum"
                .into(),
        );
    }
    Ok(TrustGenerationResolveResponseV12 {
        operation: request.operation.clone(),
        request_binding_sha256: trust_request_binding(request)?,
        trust_generation: runtime.trust_generation.clone(),
    })
}

fn process_witness(
    runtime: &RuntimeV12,
    request: &WitnessFinalizationRequestV12,
) -> Result<WitnessFinalizationResponseV12, Box<dyn std::error::Error>> {
    let binding = witness_request_binding(request)?;
    let response_path = response_path(
        runtime,
        WITNESS_RESPONSES_DIRECTORY,
        &binding,
    );
    if response_path.exists() {
        let record: PersistedWitnessResponseV12 =
            read_state(&response_path, runtime.config.authority_uid)?;
        verify_witness_record(runtime, &record)?;
        if record.request != *request {
            return Err(
                "external-witness retry differs from its persisted exact request"
                    .into(),
            );
        }
        reconcile_one_witness_record(runtime, &record)?;
        return Ok(record.response);
    }

    let predecessor = read_witness_high_water(runtime)?;
    let tree_head_digest = verify_tree_head_request(
        runtime,
        request,
        &runtime.trust_generation,
        &predecessor,
    )?;
    let next_witness_sequence = predecessor
        .witness_sequence
        .get()?
        .checked_add(1)
        .ok_or("external-witness sequence exhausted")?;
    let observed_at = now_utc_rfc3339()?;
    let checkpoint = sign_envelope(
        EXTERNAL_WITNESS_DOMAIN,
        AuthorityRoleV12::ExternalWitness,
        ExternalWitnessPayloadV12 {
            witness_id: runtime
                .config
                .witness_id
                .clone()
                .ok_or("external-witness configuration lacks witnessId")?,
            log_id: request.signed_tree_head.payload.log_id.clone(),
            signed_tree_head_envelope_sha256: tree_head_digest.clone(),
            tree_size: request.signed_tree_head.payload.tree_size.clone(),
            root_sha256: request.signed_tree_head.payload.root_sha256.clone(),
            witness_sequence: CanonicalU64::new(next_witness_sequence),
            previous_witness_checkpoint_envelope_sha256: predecessor
                .witness_checkpoint_envelope_sha256
                .clone(),
            observed_at: observed_at.clone(),
        },
        runtime
            .key_authorization
            .clone()
            .ok_or("external-witness key authorization is absent")?,
        runtime
            .signing_key
            .as_ref()
            .ok_or("external-witness signing key is absent")?,
        &observed_at,
        &observed_at,
    )?;
    let checkpoint_digest = envelope_digest(&checkpoint)?;
    let response = WitnessFinalizationResponseV12 {
        operation: request.operation.clone(),
        request_binding_sha256: binding.clone(),
        external_witness_checkpoint: checkpoint,
    };
    let next_high_water = WitnessHighWaterV12 {
        state_version: STATE_VERSION,
        witness_sequence: CanonicalU64::new(next_witness_sequence),
        witness_checkpoint_envelope_sha256: checkpoint_digest,
        log_id: request.signed_tree_head.payload.log_id.clone(),
        checkpoint_sequence: request
            .signed_tree_head
            .payload
            .checkpoint_sequence
            .clone(),
        tree_size: request.signed_tree_head.payload.tree_size.clone(),
        tree_root_sha256: request.signed_tree_head.payload.root_sha256.clone(),
        signed_tree_head_envelope_sha256: tree_head_digest,
        trust_generation_envelope_sha256: request
            .trust_generation_envelope_sha256
            .clone(),
    };
    let record = PersistedWitnessResponseV12 {
        state_version: STATE_VERSION,
        request_binding_sha256: binding,
        request: request.clone(),
        trust_generation: runtime.trust_generation.clone(),
        predecessor,
        response: response.clone(),
        next_high_water,
    };
    verify_witness_record(runtime, &record)?;
    atomic_write_state(
        &response_path,
        &canonical_json(&record, MAX_STATE_BYTES)?,
        runtime.config.authority_uid,
    )?;
    reconcile_one_witness_record(runtime, &record)?;
    Ok(response)
}

fn verify_tree_head_request(
    runtime: &RuntimeV12,
    request: &WitnessFinalizationRequestV12,
    trust_generation: &TrustGenerationBundleV12,
    predecessor: &WitnessHighWaterV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    if request.logged_bundle_sha256 == DigestHex::zero() {
        return Err(
            "external-witness request lacks its logged-bundle binding"
                .into(),
        );
    }
    let trust_predecessor =
        trust_generation_predecessor(trust_generation)?;
    let trust_generation_envelope_sha256 = verify_trust_generation_bundle(
        trust_generation,
        &runtime.config.strict_verifier_pins,
        &trust_predecessor,
        false,
    )?;
    if request.trust_generation_envelope_sha256
        != trust_generation_envelope_sha256
    {
        return Err(
            "external-witness request differs from its signed trust generation"
                .into(),
        );
    }
    let pin = authority_pin_from_material(
        &trust_generation
            .generation
            .payload
            .receipt_log,
    );
    let tree_head_digest = verify_envelope_against_pin(
        &request.signed_tree_head,
        RECEIPT_TREE_HEAD_DOMAIN,
        AuthorityRoleV12::ReceiptLog,
        &pin,
    )?;
    let payload = &request.signed_tree_head.payload;
    validate_identifier(&payload.log_id)?;
    if payload.issued_at != request.signed_tree_head.signature.signed_at
        || payload.issued_at != request.signed_tree_head.signature.accepted_at
        || payload.latest_leaf_sha256 == DigestHex::zero()
        || payload.root_sha256 == DigestHex::zero()
        || payload.tree_size.get()?
            != predecessor
                .tree_size
                .get()?
                .checked_add(1)
                .ok_or("witness tree size exhausted")?
        || payload.checkpoint_sequence.get()?
            != predecessor
                .checkpoint_sequence
                .get()?
                .checked_add(1)
                .ok_or("witness checkpoint sequence exhausted")?
        || payload.previous_signed_tree_head_envelope_sha256
            != predecessor.signed_tree_head_envelope_sha256
        || (predecessor.tree_size.get()? == 0 && payload.tree_size.get()? != 1)
        || (predecessor.tree_size.get()? != 0
            && payload.log_id != predecessor.log_id)
    {
        return Err(
            "signed tree head does not extend the witness durable high-water"
                .into(),
        );
    }
    Ok(tree_head_digest)
}

fn verify_witness_record(
    runtime: &RuntimeV12,
    record: &PersistedWitnessResponseV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if record.state_version != STATE_VERSION
        || record.response.request_binding_sha256
            != record.request_binding_sha256
        || witness_request_binding(&record.request)?
            != record.request_binding_sha256
        || record.next_high_water.state_version != STATE_VERSION
    {
        return Err("persisted external-witness response metadata is invalid".into());
    }
    let tree_head_digest = verify_tree_head_request(
        runtime,
        &record.request,
        &record.trust_generation,
        &record.predecessor,
    )?;
    let witness_pin = authority_pin_from_material(
        &record
            .trust_generation
            .generation
            .payload
            .external_witness,
    );
    let checkpoint = &record.response.external_witness_checkpoint;
    let digest = verify_envelope_against_pin(
        checkpoint,
        EXTERNAL_WITNESS_DOMAIN,
        AuthorityRoleV12::ExternalWitness,
        &witness_pin,
    )?;
    let payload = &checkpoint.payload;
    if payload.witness_id.as_str()
        != runtime
            .config
            .witness_id
            .as_deref()
            .ok_or("external-witness configuration lacks witnessId")?
        || payload.observed_at != checkpoint.signature.signed_at
        || payload.observed_at != checkpoint.signature.accepted_at
        || payload.witness_sequence.get()?
            != record
                .predecessor
                .witness_sequence
                .get()?
                .checked_add(1)
                .ok_or("persisted witness sequence exhausted")?
        || payload.previous_witness_checkpoint_envelope_sha256
            != record
                .predecessor
                .witness_checkpoint_envelope_sha256
        || record.next_high_water.witness_sequence
            != payload.witness_sequence
        || record.next_high_water.witness_checkpoint_envelope_sha256 != digest
        || record.next_high_water.log_id != payload.log_id
        || record.next_high_water.tree_size != payload.tree_size
        || record.next_high_water.tree_root_sha256 != payload.root_sha256
        || record.next_high_water.signed_tree_head_envelope_sha256
            != payload.signed_tree_head_envelope_sha256
        || record.next_high_water.signed_tree_head_envelope_sha256
            != tree_head_digest
        || record.next_high_water.trust_generation_envelope_sha256
            != record.request.trust_generation_envelope_sha256
    {
        return Err("persisted external-witness response does not extend its predecessor".into());
    }
    Ok(())
}

fn reconcile_witness(
    runtime: &RuntimeV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = runtime.config.state_root.join(WITNESS_STATE_FILE);
    if !state_path.exists() {
        write_witness_high_water(runtime, &WitnessHighWaterV12::genesis())?;
    }
    let records = read_response_records::<PersistedWitnessResponseV12>(
        &runtime
            .config
            .state_root
            .join(WITNESS_RESPONSES_DIRECTORY),
        runtime.config.authority_uid,
    )?;
    let mut records = records;
    records.sort_by_key(|record| {
        record
            .next_high_water
            .witness_sequence
            .get()
            .unwrap_or(u64::MAX)
    });
    let mut current = read_witness_high_water(runtime)?;
    for record in records {
        verify_witness_record(runtime, &record)?;
        if record.predecessor == current {
            current = record.next_high_water;
            write_witness_high_water(runtime, &current)?;
            continue;
        }
        if record.next_high_water.witness_sequence.get()?
            <= current.witness_sequence.get()?
        {
            continue;
        }
        return Err("external-witness response ledger has a gap or fork".into());
    }
    Ok(())
}

fn reconcile_one_witness_record(
    runtime: &RuntimeV12,
    record: &PersistedWitnessResponseV12,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_witness_record(runtime, record)?;
    let current = read_witness_high_water(runtime)?;
    if current == record.next_high_water {
        return Ok(());
    }
    if current != record.predecessor {
        if current.witness_sequence.get()?
            > record.next_high_water.witness_sequence.get()?
        {
            return Ok(());
        }
        return Err("external-witness high-water cannot reconcile response".into());
    }
    write_witness_high_water(runtime, &record.next_high_water)
}

fn read_witness_high_water(
    runtime: &RuntimeV12,
) -> Result<WitnessHighWaterV12, Box<dyn std::error::Error>> {
    let state: WitnessHighWaterV12 = read_state(
        &runtime.config.state_root.join(WITNESS_STATE_FILE),
        runtime.config.authority_uid,
    )?;
    if state.state_version != STATE_VERSION {
        return Err("external-witness high-water version is invalid".into());
    }
    Ok(state)
}

fn write_witness_high_water(
    runtime: &RuntimeV12,
    state: &WitnessHighWaterV12,
) -> Result<(), Box<dyn std::error::Error>> {
    atomic_write_state(
        &runtime.config.state_root.join(WITNESS_STATE_FILE),
        &canonical_json(state, MAX_STATE_BYTES)?,
        runtime.config.authority_uid,
    )?;
    Ok(())
}

fn process_settlement(
    runtime: &RuntimeV12,
    request: &FinalSettlementRequestV12,
) -> Result<FinalSettlementResponseV12, Box<dyn std::error::Error>> {
    let binding = settlement_request_binding(request)?;
    let response_path = response_path(
        runtime,
        SETTLEMENT_RESPONSES_DIRECTORY,
        &binding,
    );
    if response_path.exists() {
        let record: PersistedSettlementResponseV12 =
            read_state(&response_path, runtime.config.authority_uid)?;
        verify_settlement_record(runtime, &record)?;
        reconcile_one_settlement_record(runtime, &record)?;
        return Ok(record.response);
    }

    let state = read_settlement_high_water(runtime)?;
    let predecessor = state.high_water;
    if request.expected_previous_settlement_checkpoint_envelope_sha256
        != predecessor.settlement_checkpoint_envelope_sha256
    {
        return Err(
            "final-settlement request does not extend durable settlement high-water"
                .into(),
        );
    }
    if logged_receipt_bundle_digest(&request.logged_bundle)?
        != request.logged_bundle_sha256
    {
        return Err("final-settlement logged bundle digest mismatch".into());
    }
    let logged_bytes =
        canonical_json(&request.logged_bundle, MAX_RECEIPT_BYTES)?;
    verify_logged_bundle_v12(
        &logged_bytes,
        &runtime.config.strict_verifier_pins,
        &predecessor,
    )?;
    let trust_generation_envelope_sha256 = verify_trust_generation_bundle(
        &request.trust_generation,
        &runtime.config.strict_verifier_pins,
        &predecessor,
        true,
    )?;
    if trust_generation_envelope_sha256
            != runtime.trust_generation_envelope_sha256
        || request.trust_generation != runtime.trust_generation
    {
        return Err(
            "final-settlement request does not use the provisioned trust generation"
                .into(),
        );
    }
    let witness_checkpoint_sha256 =
        verify_settlement_witness(runtime, request, &predecessor)?;

    let (outcome, receipt_envelope_sha256, terminal_abort_reason_sha256) =
        match (&request.receipt, &request.terminal_abort_reason) {
            (Some(receipt), None) => {
                let receipt_bytes =
                    canonical_json(receipt, MAX_RECEIPT_BYTES)?;
                let verified = verify_receipt_v12(
                    &receipt_bytes,
                    &runtime.config.strict_verifier_pins,
                    &predecessor,
                )?;
                if logged_bundle_from_receipt(receipt)
                        != request.logged_bundle
                    || receipt.external_witness_checkpoint
                        != request.external_witness_checkpoint
                    || receipt.final_trust_observation.trust_generation
                        != request.trust_generation
                    || verified.receipt.receipt_envelope_sha256
                        != receipt.receipt_envelope_sha256
                {
                    return Err(
                        "receipt settlement does not bind the exact verified request inputs"
                            .into(),
                    );
                }
                (
                    FinalSettlementOutcomeV12::Receipt,
                    receipt.receipt_envelope_sha256.clone(),
                    DigestHex::zero(),
                )
            }
            (None, Some(reason))
                if !reason.is_empty() && reason.len() <= 1024 =>
            {
                (
                    FinalSettlementOutcomeV12::TerminalAbort,
                    DigestHex::zero(),
                    h12("terminal-abort-reason", &[reason.as_bytes()]),
                )
            }
            _ => {
                return Err(
                    "final settlement must contain exactly one receipt or terminal abort"
                        .into(),
                )
            }
        };
    let settled_at = now_utc_rfc3339()?;
    let settlement_sequence = predecessor
        .settlement_sequence
        .get()?
        .checked_add(1)
        .ok_or("final-settlement sequence exhausted")?;
    let payload = FinalSettlementPayloadV12 {
        outcome,
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
        pre_final_log_leaf_sha256: request
            .logged_bundle
            .pre_final_log_leaf
            .leaf_sha256
            .clone(),
        receipt_envelope_sha256,
        terminal_abort_reason_sha256,
        settlement_sequence: CanonicalU64::new(settlement_sequence),
        previous_settlement_checkpoint_envelope_sha256: predecessor
            .settlement_checkpoint_envelope_sha256
            .clone(),
        tree_size: request
            .logged_bundle
            .signed_tree_head
            .payload
            .tree_size
            .clone(),
        tree_root_sha256: request
            .logged_bundle
            .signed_tree_head
            .payload
            .root_sha256
            .clone(),
        signed_tree_head_envelope_sha256: request
            .logged_bundle
            .signed_tree_head_envelope_sha256
            .clone(),
        witness_sequence: request
            .external_witness_checkpoint
            .payload
            .witness_sequence
            .clone(),
        witness_checkpoint_envelope_sha256:
            witness_checkpoint_sha256,
        trust_generation_envelope_sha256,
        trust_generation_sequence: request
            .trust_generation
            .generation
            .payload
            .generation_sequence
            .clone(),
        settled_at: settled_at.clone(),
    };
    let checkpoint = sign_envelope(
        FINAL_SETTLEMENT_DOMAIN,
        AuthorityRoleV12::FinalSettlement,
        payload,
        runtime
            .key_authorization
            .clone()
            .ok_or("final-settlement key authorization is absent")?,
        runtime
            .signing_key
            .as_ref()
            .ok_or("final-settlement signing key is absent")?,
        &settled_at,
        &settled_at,
    )?;
    let checkpoint_sha256 = envelope_digest(&checkpoint)?;
    let artifact = FinalSettlementArtifactV12 {
        outcome,
        logged_bundle: request.logged_bundle.clone(),
        external_witness_checkpoint: request
            .external_witness_checkpoint
            .clone(),
        receipt: request.receipt.clone(),
        terminal_abort_reason: request.terminal_abort_reason.clone(),
        trust_generation: request.trust_generation.clone(),
        final_settlement_checkpoint: checkpoint,
        final_settlement_checkpoint_envelope_sha256:
            checkpoint_sha256,
    };
    let next_high_water = verify_final_settlement_artifact_v12(
        &artifact,
        &runtime.config.strict_verifier_pins,
        &predecessor,
    )?;
    let response = FinalSettlementResponseV12 {
        operation: request.operation.clone(),
        request_binding_sha256: binding.clone(),
        artifact,
    };
    let record = PersistedSettlementResponseV12 {
        state_version: STATE_VERSION,
        request_binding_sha256: binding,
        predecessor,
        response: response.clone(),
        next_high_water,
    };
    verify_settlement_record(runtime, &record)?;
    atomic_write_state(
        &response_path,
        &canonical_json(&record, MAX_STATE_BYTES)?,
        runtime.config.authority_uid,
    )?;
    reconcile_one_settlement_record(runtime, &record)?;
    Ok(response)
}

fn verify_settlement_witness(
    runtime: &RuntimeV12,
    request: &FinalSettlementRequestV12,
    predecessor: &VerificationHighWaterV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    let witness = &request.external_witness_checkpoint;
    let digest = verify_envelope_against_pin(
        witness,
        EXTERNAL_WITNESS_DOMAIN,
        AuthorityRoleV12::ExternalWitness,
        &runtime.config.strict_verifier_pins.external_witness,
    )?;
    let payload = &witness.payload;
    if payload.signed_tree_head_envelope_sha256
            != request.logged_bundle.signed_tree_head_envelope_sha256
        || payload.log_id
            != request.logged_bundle.signed_tree_head.payload.log_id
        || payload.tree_size
            != request.logged_bundle.signed_tree_head.payload.tree_size
        || payload.root_sha256
            != request.logged_bundle.signed_tree_head.payload.root_sha256
        || payload.witness_sequence.get()?
            != predecessor
                .witness_sequence
                .get()?
                .checked_add(1)
                .ok_or("settlement witness sequence exhausted")?
        || payload.previous_witness_checkpoint_envelope_sha256
            != predecessor.witness_checkpoint_envelope_sha256
        || payload.observed_at != witness.signature.signed_at
        || payload.observed_at != witness.signature.accepted_at
    {
        return Err(
            "final-settlement witness does not extend the durable high-water"
                .into(),
        );
    }
    Ok(digest)
}

fn verify_settlement_record(
    runtime: &RuntimeV12,
    record: &PersistedSettlementResponseV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if record.state_version != STATE_VERSION
        || record.response.request_binding_sha256
            != record.request_binding_sha256
        || record.response.operation != "SETTLE_FINAL"
        || settlement_artifact_request_binding(
            &record.response.artifact,
        )? != record.request_binding_sha256
    {
        return Err("persisted final-settlement response metadata is invalid".into());
    }
    let verified = verify_final_settlement_artifact_v12(
        &record.response.artifact,
        &runtime.config.strict_verifier_pins,
        &record.predecessor,
    )?;
    if verified != record.next_high_water {
        return Err(
            "persisted final-settlement response has an invalid next high-water"
                .into(),
        );
    }
    Ok(())
}

fn reconcile_settlement(
    runtime: &RuntimeV12,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = runtime.config.state_root.join(SETTLEMENT_STATE_FILE);
    let genesis_checkpoint_envelope_sha256 = runtime
        .genesis_checkpoint_sha256
        .clone()
        .ok_or("final-settlement genesis digest is absent")?;
    if !state_path.exists() {
        let mut genesis_high_water = VerificationHighWaterV12::genesis();
        genesis_high_water.settlement_checkpoint_envelope_sha256 =
            genesis_checkpoint_envelope_sha256.clone();
        write_settlement_high_water(
            runtime,
            &SettlementHighWaterV12 {
                state_version: STATE_VERSION,
                genesis_checkpoint_envelope_sha256:
                    genesis_checkpoint_envelope_sha256.clone(),
                high_water: genesis_high_water,
            },
        )?;
    }
    let initial = read_settlement_high_water(runtime)?;
    if initial.genesis_checkpoint_envelope_sha256
        != genesis_checkpoint_envelope_sha256
    {
        return Err(
            "provisioned final-settlement genesis differs from durable state"
                .into(),
        );
    }

    let mut records =
        read_response_records::<PersistedSettlementResponseV12>(
            &runtime
                .config
                .state_root
                .join(SETTLEMENT_RESPONSES_DIRECTORY),
            runtime.config.authority_uid,
        )?;
    records.sort_by_key(|record| {
        record
            .next_high_water
            .settlement_sequence
            .get()
            .unwrap_or(u64::MAX)
    });
    let mut current = initial;
    for record in records {
        verify_settlement_record(runtime, &record)?;
        if record.predecessor == current.high_water {
            current.high_water = record.next_high_water;
            write_settlement_high_water(runtime, &current)?;
            continue;
        }
        if record.next_high_water.settlement_sequence.get()?
            <= current.high_water.settlement_sequence.get()?
        {
            continue;
        }
        return Err("final-settlement response ledger has a gap or fork".into());
    }
    Ok(())
}

fn reconcile_one_settlement_record(
    runtime: &RuntimeV12,
    record: &PersistedSettlementResponseV12,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_settlement_record(runtime, record)?;
    let mut current = read_settlement_high_water(runtime)?;
    if current.high_water == record.next_high_water {
        return Ok(());
    }
    if current.high_water != record.predecessor {
        if current.high_water.settlement_sequence.get()?
            > record.next_high_water.settlement_sequence.get()?
        {
            return Ok(());
        }
        return Err("final-settlement high-water cannot reconcile response".into());
    }
    current.high_water = record.next_high_water.clone();
    write_settlement_high_water(runtime, &current)
}

fn read_settlement_high_water(
    runtime: &RuntimeV12,
) -> Result<SettlementHighWaterV12, Box<dyn std::error::Error>> {
    let state: SettlementHighWaterV12 = read_state(
        &runtime.config.state_root.join(SETTLEMENT_STATE_FILE),
        runtime.config.authority_uid,
    )?;
    if state.state_version != STATE_VERSION {
        return Err("final-settlement high-water version is invalid".into());
    }
    Ok(state)
}

fn write_settlement_high_water(
    runtime: &RuntimeV12,
    state: &SettlementHighWaterV12,
) -> Result<(), Box<dyn std::error::Error>> {
    atomic_write_state(
        &runtime.config.state_root.join(SETTLEMENT_STATE_FILE),
        &canonical_json(state, MAX_STATE_BYTES)?,
        runtime.config.authority_uid,
    )?;
    Ok(())
}

fn trust_generation_predecessor(
    bundle: &TrustGenerationBundleV12,
) -> Result<VerificationHighWaterV12, Box<dyn std::error::Error>> {
    let generation = &bundle.generation.payload;
    let sequence = generation.generation_sequence.get()?;
    if sequence == 0 {
        return Err("provisioned trust generation sequence must be non-zero".into());
    }
    let mut high_water = VerificationHighWaterV12::genesis();
    high_water.trust_generation_sequence =
        CanonicalU64::new(sequence - 1);
    high_water.trust_generation_envelope_sha256 =
        generation.previous_generation_envelope_sha256.clone();
    high_water.trust_rollback_floor = generation.rollback_floor.clone();
    Ok(high_water)
}

fn trust_request_binding(
    request: &TrustGenerationResolveRequestV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    if request.operation == "RESOLVE_FRESH_TRUST_GENERATION" {
        return Ok(h12(
            "trust-generation-resolve-request",
            &[
                request.receipt_id.as_bytes(),
                request.receipt_sequence.as_str().as_bytes(),
                &request.replay_key_sha256.decode()?,
                &request.logged_bundle_sha256.decode()?,
                request
                    .minimum_generation_sequence
                    .as_str()
                    .as_bytes(),
            ],
        ));
    }
    if request.operation == "RESOLVE_CURRENT_TRUST_GENERATION" {
        return exact_request_binding(request);
    }
    Err("unsupported trust-generation operation".into())
}

fn witness_request_binding(
    request: &WitnessFinalizationRequestV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    if request.operation == "WITNESS_FINALIZATION" {
        return Ok(h12(
            "witness-finalization-request",
            &[
                &request.logged_bundle_sha256.decode()?,
                &envelope_digest(&request.signed_tree_head)?.decode()?,
                &request
                    .trust_generation_envelope_sha256
                    .decode()?,
            ],
        ));
    }
    if request.operation == "WITNESS_LOGGED_RECEIPT" {
        return exact_request_binding(request);
    }
    Err("unsupported external-witness operation".into())
}

fn settlement_request_binding(
    request: &FinalSettlementRequestV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    if request.operation != "SETTLE_FINAL" {
        return Err("unsupported final-settlement operation".into());
    }
    let witness_sha256 =
        envelope_digest(&request.external_witness_checkpoint)?;
    let verified_trust_sha256 =
        request.trust_generation.generation_envelope_sha256.clone();
    if verified_trust_sha256 == DigestHex::zero() {
        return Err("final-settlement trust binding is empty".into());
    }
    Ok(h12(
        "final-settlement-request",
        &[
            &request.logged_bundle_sha256.decode()?,
            &request
                .receipt
                .as_ref()
                .map(|receipt| receipt.receipt_envelope_sha256.clone())
                .unwrap_or_else(DigestHex::zero)
                .decode()?,
            request
                .terminal_abort_reason
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            &witness_sha256.decode()?,
            &verified_trust_sha256.decode()?,
            &request
                .expected_previous_settlement_checkpoint_envelope_sha256
                .decode()?,
        ],
    ))
}

fn settlement_artifact_request_binding(
    artifact: &FinalSettlementArtifactV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    let witness_sha256 =
        envelope_digest(&artifact.external_witness_checkpoint)?;
    Ok(h12(
        "final-settlement-request",
        &[
            &logged_receipt_bundle_digest(&artifact.logged_bundle)?.decode()?,
            &artifact
                .receipt
                .as_ref()
                .map(|receipt| receipt.receipt_envelope_sha256.clone())
                .unwrap_or_else(DigestHex::zero)
                .decode()?,
            artifact
                .terminal_abort_reason
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            &witness_sha256.decode()?,
            &artifact
                .trust_generation
                .generation_envelope_sha256
                .decode()?,
            &artifact
                .final_settlement_checkpoint
                .payload
                .previous_settlement_checkpoint_envelope_sha256
                .decode()?,
        ],
    ))
}

fn exact_request_binding<T: Serialize>(
    request: &T,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    let bytes = canonical_json(request, MAX_AUTHORITY_REQUEST_BYTES)?;
    Ok(h12("authority-exact-request-binding-v12", &[&bytes]))
}

fn verify_envelope_against_pin<T: Serialize>(
    envelope: &receipt_contract_v12::SignedEnvelopeV12<T>,
    domain: &str,
    role: AuthorityRoleV12,
    pin: &AuthorityPinV12,
) -> Result<DigestHex, Box<dyn std::error::Error>> {
    let key = pin.verifying_key()?;
    let digest =
        verify_envelope_cryptography(envelope, domain, role, &key)?;
    require_authorization_matches_pin(
        &envelope.signature.key_authorization,
        pin,
        role,
    )?;
    if envelope.signature.signer_principal_id != pin.principal_id
        || envelope.signature.signer_key_id != pin.key_id
        || envelope.signature.signer_spki_der_sha256 != pin.spki_der_sha256
    {
        return Err("signed envelope identity differs from current pin".into());
    }
    Ok(digest)
}

fn require_authorization_matches_pin(
    authorization: &KeyAuthorizationV12,
    pin: &AuthorityPinV12,
    role: AuthorityRoleV12,
) -> Result<(), Box<dyn std::error::Error>> {
    if authorization.role != role
        || pin.role != role
        || authorization.principal_id != pin.principal_id
        || authorization.key_id != pin.key_id
        || authorization.spki_der_sha256 != pin.spki_der_sha256
        || authorization.physical_private_key_identity_sha256
            != pin.physical_private_key_identity_sha256
        || authorization.key_authorization_sha256
            != pin.key_authorization_sha256
        || authorization.authorization_root_sha256
            != pin.authorization_root_sha256
        || authorization.authorization_revision
            != pin.authorization_revision
        || authorization.revocation_root_sha256
            != pin.revocation_root_sha256
        || authorization.revocation_revision != pin.revocation_revision
        || authorization.high_water != pin.high_water
        || authorization.valid_from != pin.valid_from
        || authorization.valid_until != pin.valid_until
        || authorization.status != pin.status
    {
        return Err("key authorization differs from the strict authority pin".into());
    }
    Ok(())
}

fn pin_for_role(
    pins: &StrictVerifierPinsV12,
    role: AuthorityRoleV12,
) -> Result<&AuthorityPinV12, Box<dyn std::error::Error>> {
    match role {
        AuthorityRoleV12::ExternalWitness => Ok(&pins.external_witness),
        AuthorityRoleV12::FinalSettlement => Ok(&pins.final_settlement),
        _ => Err("local authority role has no supported signing pin".into()),
    }
}

fn authority_pin_from_material(
    material: &AuthorityTrustMaterialV12,
) -> AuthorityPinV12 {
    AuthorityPinV12 {
        role: material.role,
        principal_id: material.principal_id.clone(),
        key_id: material.key_id.clone(),
        verifying_key_base64url: material.verifying_key_base64url.clone(),
        spki_der_sha256: material.spki_der_sha256.clone(),
        physical_private_key_identity_sha256: material
            .physical_private_key_identity_sha256
            .clone(),
        key_authorization_sha256: material
            .key_authorization_sha256
            .clone(),
        authorization_root_sha256: material
            .authorization_root_sha256
            .clone(),
        authorization_revision: material.authorization_revision.clone(),
        revocation_root_sha256: material.revocation_root_sha256.clone(),
        revocation_revision: material.revocation_revision.clone(),
        high_water: material.authorization_high_water.clone(),
        valid_from: material.valid_from.clone(),
        valid_until: material.valid_until.clone(),
        status: material.status.clone(),
    }
}

fn activated_listener(
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<UnixListener, Box<dyn std::error::Error>> {
    let listen_pid: u32 = env::var("LISTEN_PID")?.parse()?;
    let listen_fds: u32 = env::var("LISTEN_FDS")?.parse()?;
    if listen_pid != std::process::id() || listen_fds != 1 {
        return Err(
            "exactly one systemd-activated bounded stream listener is required"
                .into(),
        );
    }
    inspect_activated_listener_v12(
        SYSTEMD_LISTEN_FD,
        expected_owner_uid,
        expected_mode,
    )?;
    Ok(unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) })
}

fn read_signing_key(
    path: &Path,
    expected_owner_uid: u32,
) -> io::Result<SigningKey> {
    let mut bytes = secure_read(path, 32, expected_owner_uid, true)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Ed25519 signing key must be a raw 32-byte seed",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    bytes.zeroize();
    Ok(key)
}

fn validate_private_directory(path: &Path, owner: u32) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state directory is not absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state directory must be authority-owned mode 0700",
        ));
    }
    Ok(())
}

fn ensure_private_subdirectory(path: &Path, owner: u32) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        File::open(
            path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "state subdirectory has no parent",
                )
            })?,
        )?
        .sync_all()?;
    }
    validate_private_directory(path, owner)
}

fn secure_read(
    path: &Path,
    maximum_bytes: usize,
    expected_owner_uid: u32,
    private: bool,
) -> io::Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authority file path is not absolute",
        ));
    }
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
            "authority file ownership, mode, type, or length is unsafe",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authority file changed during bounded read",
        ));
    }
    Ok(bytes)
}

fn read_state<T: serde::de::DeserializeOwned>(
    path: &Path,
    owner: u32,
) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = secure_read(path, MAX_STATE_BYTES, owner, true)?;
    Ok(parse_canonical_json(&bytes, MAX_STATE_BYTES)?)
}

fn atomic_write_state(
    path: &Path,
    bytes: &[u8],
    owner: u32,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable authority state is outside its byte bound",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable state path has no parent",
        )
    })?;
    validate_private_directory(parent, owner)?;
    let nonce = receipt_contract_v12::boottime_now_ns()
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id(),
        nonce,
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if file.metadata()?.uid() != owner {
        let _ = fs::remove_file(&temporary);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable state temporary file has the wrong owner",
        ));
    }
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()
}

fn response_path(
    runtime: &RuntimeV12,
    directory: &str,
    binding: &DigestHex,
) -> PathBuf {
    runtime
        .config
        .state_root
        .join(directory)
        .join(format!("{}.json", binding.as_str()))
}

fn read_response_records<T: serde::de::DeserializeOwned>(
    directory: &Path,
    owner: u32,
) -> Result<Vec<T>, Box<dyn std::error::Error>> {
    validate_private_directory(directory, owner)?;
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)? {
        if records.len() >= MAX_RESPONSE_RECORDS {
            return Err("authority response ledger exceeds its entry bound".into());
        }
        let entry = entry?;
        let file_name = entry.file_name();
        let canonical_name = file_name.to_str().is_some_and(|name| {
            name.len() == 69
                && name.ends_with(".json")
                && name[..64].bytes().all(|byte| {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                })
        });
        if !entry.file_type()?.is_file() || !canonical_name {
            return Err(
                "authority response ledger contains a non-canonical entry"
                    .into(),
            );
        }
        records.push(read_state(&entry.path(), owner)?);
    }
    Ok(records)
}
