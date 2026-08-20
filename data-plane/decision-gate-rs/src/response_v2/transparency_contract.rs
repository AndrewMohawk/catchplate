use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;

pub const RELEASE_TRANSPARENCY_PROOF_API_VERSION: &str =
    "serverware.responseV2.releaseTransparencyProof/v2";
pub const RELEASE_TRANSPARENCY_PROOF_KIND: &str =
    "ServerwareResponseV2ReleaseTransparencyProof";
pub const RELEASE_IDENTITY_RECORD_API_VERSION: &str =
    "serverware.responseV2.releaseIdentityRecord/v2";
pub const RELEASE_IDENTITY_RECORD_KIND: &str =
    "ServerwareResponseV2ReleaseIdentityRecord";
pub const RELEASE_TRANSPARENCY_LEAF_API_VERSION: &str =
    "serverware.responseV2.releaseTransparencyLeaf/v2";
pub const RELEASE_TRANSPARENCY_LEAF_KIND: &str =
    "ServerwareResponseV2ReleaseTransparencyLeaf";
pub const RELEASE_TRANSPARENCY_CHECKPOINT_API_VERSION: &str =
    "serverware.responseV2.releaseTransparencyCheckpoint/v2";
pub const RELEASE_TRANSPARENCY_CHECKPOINT_KIND: &str =
    "ServerwareResponseV2ReleaseTransparencyCheckpoint";
pub const RELEASE_TRANSPARENCY_TRUST_PIN_API_VERSION: &str =
    "serverware.responseV2.releaseTransparencyTrustPin/v2";
pub const RELEASE_TRANSPARENCY_TRUST_PIN_KIND: &str =
    "ServerwareResponseV2ReleaseTransparencyTrustPin";

const RELEASE_IDENTITY_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.releaseIdentityRecord.signature/v2";
const RELEASE_IDENTITY_SIGNATURE_DOMAIN: &[u8] =
    b"SERVERWARE\0RESPONSE-V2-RELEASE-IDENTITY\0V2\0";
const TRANSPARENCY_CHECKPOINT_SIGNATURE_DOMAIN_NAME: &str =
    "serverware.responseV2.releaseTransparencyCheckpoint.signature/v2";
const TRANSPARENCY_CHECKPOINT_SIGNATURE_DOMAIN: &[u8] =
    b"SERVERWARE\0RESPONSE-V2-RELEASE-TRANSPARENCY-CHECKPOINT\0V2\0";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
    0x00,
];
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_MERKLE_PATH: usize = 64;
const MAX_CHECKPOINT_AGE_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct TransparencyContractError {
    pub code: &'static str,
    pub message: String,
}

impl TransparencyContractError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for TransparencyContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TransparencyContractError {}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIdentityRecordPayloadV2 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub release_record_id: String,
    pub generation_id: String,
    pub provider_generation: u64,
    pub source_commit_sha256: String,
    pub source_tree_sha256: String,
    pub executable_sha256: String,
    pub configuration_sha256: String,
    pub issued_at_epoch_ms: u64,
    pub not_before_epoch_ms: u64,
    pub not_after_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIdentityRecordAuthenticationV2 {
    pub algorithm: String,
    pub signer_role: String,
    pub key_id: String,
    pub public_key_base64: String,
    pub public_key_sha256: String,
    pub public_key_spki_sha256: String,
    pub signing_domain: String,
    pub signed_payload_sha256: String,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseIdentityRecordV2 {
    pub payload: ReleaseIdentityRecordPayloadV2,
    pub authentication: ReleaseIdentityRecordAuthenticationV2,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyLeafV2 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub log_id: String,
    pub release_record_sha256: String,
    pub release_record: SignedReleaseIdentityRecordV2,
    pub integrated_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyCheckpointPayloadV2 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub checkpoint_id: String,
    pub log_id: String,
    pub provider_generation: u64,
    pub tree_size: u64,
    pub root_sha256: String,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyCheckpointAuthenticationV2 {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_spki_base64: String,
    pub public_key_spki_sha256: String,
    pub signing_domain: String,
    pub signed_payload_sha256: String,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseTransparencyCheckpointV2 {
    pub payload: ReleaseTransparencyCheckpointPayloadV2,
    pub authentication: ReleaseTransparencyCheckpointAuthenticationV2,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyProofV2 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub digest_algorithm: String,
    pub merkle_tree_algorithm: String,
    pub leaf_canonicalization: String,
    pub leaf: ReleaseTransparencyLeafV2,
    pub leaf_sha256: String,
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path_sha256: Vec<String>,
    pub anchor_tree_size: u64,
    pub anchor_root_sha256: String,
    pub consistency_path_sha256: Vec<String>,
    pub checkpoint: SignedReleaseTransparencyCheckpointV2,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyArtifactV2 {
    pub release_transparency_proof: ReleaseTransparencyProofV2,
    pub release_transparency_proof_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseTransparencyTrustPinV2 {
    pub api_version: String,
    pub kind: String,
    pub schema_version: String,
    pub generation_id: String,
    pub provider_generation: u64,
    pub proof_pins_root_sha256: String,
    pub log_id: String,
    pub log_key_id: String,
    pub log_key_spki_base64: String,
    pub log_key_spki_sha256: String,
    pub anchor_tree_size: u64,
    pub anchor_root_sha256: String,
    pub trust_checkpoint_sha256: String,
    pub revocation_epoch: u64,
    pub valid_from_epoch_ms: u64,
    pub valid_until_epoch_ms: u64,
    pub revoked_at_epoch_ms: Option<u64>,
    pub maximum_checkpoint_age_ms: u64,
}

pub struct ReleaseTransparencyExpectation<'a> {
    pub generation_id: &'a str,
    pub provider_generation: u64,
    pub proof_pins_root_sha256: &'a str,
    pub trust_checkpoint_sha256: &'a str,
    pub minimum_revocation_epoch: u64,
    pub source_commit_sha256: &'a str,
    pub source_tree_sha256: &'a str,
    pub executable_sha256: &'a str,
    pub configuration_sha256: &'a str,
    pub runtime_attestation_key_id: &'a str,
    pub runtime_attestation_public_key_base64: &'a str,
    pub runtime_attestation_public_key_sha256: &'a str,
    pub artifact_issued_at_epoch_ms: u64,
    pub verification_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReleaseTransparencySummary {
    pub release_record_sha256: String,
    pub leaf_sha256: String,
    pub checkpoint_sha256: String,
    pub checkpoint_id: String,
    pub tree_size: u64,
    pub root_sha256: String,
}

pub fn canonical_transparency_sha256<T: Serialize>(
    value: &T,
) -> Result<String, TransparencyContractError> {
    Ok(sha256_prefixed(&canonical_bytes(value)?))
}

pub fn validate_release_transparency_proof_untrusted(
    proof: &ReleaseTransparencyProofV2,
) -> Result<VerifiedReleaseTransparencySummary, TransparencyContractError> {
    if proof.api_version != RELEASE_TRANSPARENCY_PROOF_API_VERSION
        || proof.kind != RELEASE_TRANSPARENCY_PROOF_KIND
        || proof.schema_version != "2"
        || proof.digest_algorithm != "SHA-256"
        || proof.merkle_tree_algorithm != "RFC6962"
        || proof.leaf_canonicalization != "RFC8785"
    {
        return invalid("release transparency proof version or kind is invalid");
    }
    validate_identifier(&proof.leaf.log_id, "leaf.logId")?;
    if proof.leaf.api_version != RELEASE_TRANSPARENCY_LEAF_API_VERSION
        || proof.leaf.kind != RELEASE_TRANSPARENCY_LEAF_KIND
        || proof.leaf.schema_version != "2"
        || proof.leaf.integrated_at_epoch_ms == 0
        || proof.leaf.integrated_at_epoch_ms > MAX_SAFE_INTEGER
    {
        return invalid("release transparency leaf contract is invalid");
    }
    let record = &proof.leaf.release_record;
    validate_release_identity_record(record)?;
    let release_record_sha256 = canonical_transparency_sha256(record)?;
    if proof.leaf.release_record_sha256 != release_record_sha256 {
        return invalid("release record digest does not match exact signed record");
    }
    let leaf_bytes = canonical_bytes(&proof.leaf)?;
    let leaf_digest = rfc6962_leaf_hash(&leaf_bytes);
    let leaf_sha256 = format_digest(&leaf_digest);
    if proof.leaf_sha256 != leaf_sha256
        || proof.leaf_index >= proof.tree_size
        || proof.tree_size == 0
        || proof.tree_size > MAX_SAFE_INTEGER
        || proof.audit_path_sha256.len() > MAX_MERKLE_PATH
        || proof.consistency_path_sha256.len() > MAX_MERKLE_PATH
        || proof.anchor_tree_size == 0
        || proof.anchor_tree_size > proof.tree_size
        || proof.anchor_tree_size > MAX_SAFE_INTEGER
        || !is_sha256_digest(&proof.anchor_root_sha256)
    {
        return invalid("release transparency proof bounds or leaf digest are invalid");
    }
    let checkpoint = &proof.checkpoint;
    validate_signed_checkpoint(checkpoint)?;
    let checkpoint_sha256 = canonical_transparency_sha256(checkpoint)?;
    if proof.checkpoint_sha256 != checkpoint_sha256
        || checkpoint.payload.log_id != proof.leaf.log_id
        || checkpoint.payload.tree_size != proof.tree_size
        || checkpoint.payload.issued_at_epoch_ms
            < proof.leaf.integrated_at_epoch_ms
        || record.payload.issued_at_epoch_ms
            > proof.leaf.integrated_at_epoch_ms
        || record.payload.not_before_epoch_ms
            > proof.leaf.integrated_at_epoch_ms
        || record.payload.not_after_epoch_ms
            <= proof.leaf.integrated_at_epoch_ms
    {
        return invalid("signed checkpoint does not bind the preexisting release leaf");
    }
    let audit_path = decode_digest_path(
        &proof.audit_path_sha256,
        "auditPathSha256",
    )?;
    let root = rfc6962_root_from_inclusion(
        leaf_digest,
        proof.leaf_index,
        proof.tree_size,
        &audit_path,
    )?;
    if format_digest(&root) != checkpoint.payload.root_sha256 {
        return invalid("RFC6962 inclusion path does not produce signed checkpoint root");
    }
    let anchor_root = decode_digest(
        &proof.anchor_root_sha256,
        "anchorRootSha256",
    )?;
    let current_root = decode_digest(
        &checkpoint.payload.root_sha256,
        "checkpoint.payload.rootSha256",
    )?;
    let consistency_path = decode_digest_path(
        &proof.consistency_path_sha256,
        "consistencyPathSha256",
    )?;
    verify_rfc6962_consistency(
        proof.anchor_tree_size,
        proof.tree_size,
        anchor_root,
        current_root,
        &consistency_path,
    )?;
    Ok(VerifiedReleaseTransparencySummary {
        release_record_sha256,
        leaf_sha256,
        checkpoint_sha256,
        checkpoint_id: checkpoint.payload.checkpoint_id.clone(),
        tree_size: proof.tree_size,
        root_sha256: checkpoint.payload.root_sha256.clone(),
    })
}

pub fn verify_release_transparency_proof_with_pin(
    proof: &ReleaseTransparencyProofV2,
    pin: &ReleaseTransparencyTrustPinV2,
    expected: &ReleaseTransparencyExpectation<'_>,
) -> Result<VerifiedReleaseTransparencySummary, TransparencyContractError> {
    let summary = validate_release_transparency_proof_untrusted(proof)?;
    validate_trust_pin(pin, expected.verification_epoch_ms)?;
    let record = &proof.leaf.release_record;
    let checkpoint = &proof.checkpoint;
    let runtime_key = decode_canonical_standard_base64_32(
        expected.runtime_attestation_public_key_base64,
        "runtimeAttestationPublicKeyBase64",
    )?;
    let runtime_spki = ed25519_spki(&runtime_key);
    if pin.generation_id != expected.generation_id
        || pin.provider_generation != expected.provider_generation
        || pin.proof_pins_root_sha256 != expected.proof_pins_root_sha256
        || pin.trust_checkpoint_sha256
            != expected.trust_checkpoint_sha256
        || pin.revocation_epoch < expected.minimum_revocation_epoch
        || pin.log_id != proof.leaf.log_id
        || pin.anchor_tree_size != proof.anchor_tree_size
        || pin.anchor_root_sha256 != proof.anchor_root_sha256
        || pin.log_key_id != checkpoint.authentication.key_id
        || pin.log_key_spki_base64
            != checkpoint.authentication.public_key_spki_base64
        || pin.log_key_spki_sha256
            != checkpoint.authentication.public_key_spki_sha256
        || checkpoint.payload.provider_generation
            != expected.provider_generation
        || checkpoint.payload.trust_checkpoint_sha256
            != expected.trust_checkpoint_sha256
        || checkpoint.payload.revocation_epoch
            < expected.minimum_revocation_epoch
        || checkpoint.payload.revocation_epoch != pin.revocation_epoch
        || checkpoint.payload.issued_at_epoch_ms
            > expected.artifact_issued_at_epoch_ms
        || expected.artifact_issued_at_epoch_ms
            > expected.verification_epoch_ms
        || checkpoint.payload.issued_at_epoch_ms
            > expected.verification_epoch_ms
        || checkpoint.payload.expires_at_epoch_ms
            <= expected.verification_epoch_ms
        || expected
            .verification_epoch_ms
            .saturating_sub(checkpoint.payload.issued_at_epoch_ms)
            > pin.maximum_checkpoint_age_ms
        || record.payload.generation_id != expected.generation_id
        || record.payload.provider_generation
            != expected.provider_generation
        || record.payload.source_commit_sha256
            != expected.source_commit_sha256
        || record.payload.source_tree_sha256
            != expected.source_tree_sha256
        || record.payload.executable_sha256 != expected.executable_sha256
        || record.payload.configuration_sha256
            != expected.configuration_sha256
        || record.payload.not_before_epoch_ms
            > expected.verification_epoch_ms
        || record.payload.not_after_epoch_ms
            <= expected.verification_epoch_ms
        || record.authentication.signer_role != "runtime-attestation"
        || record.authentication.key_id
            != expected.runtime_attestation_key_id
        || record.authentication.public_key_base64
            != expected.runtime_attestation_public_key_base64
        || record.authentication.public_key_sha256
            != expected.runtime_attestation_public_key_sha256
        || record.authentication.public_key_spki_sha256
            != sha256_prefixed(&runtime_spki)
    {
        return invalid(
            "release transparency proof does not match independent log, release, generation, trust, or freshness pins",
        );
    }
    Ok(summary)
}

pub fn validate_release_transparency_trust_pin(
    pin: &ReleaseTransparencyTrustPinV2,
    verification_epoch_ms: u64,
) -> Result<(), TransparencyContractError> {
    validate_trust_pin(pin, verification_epoch_ms)
}

fn validate_release_identity_record(
    record: &SignedReleaseIdentityRecordV2,
) -> Result<(), TransparencyContractError> {
    let payload = &record.payload;
    let authentication = &record.authentication;
    validate_identifier(&payload.release_record_id, "releaseRecordId")?;
    validate_identifier(&payload.generation_id, "generationId")?;
    for (value, field) in [
        (&payload.source_commit_sha256, "sourceCommitSha256"),
        (&payload.source_tree_sha256, "sourceTreeSha256"),
        (&payload.executable_sha256, "executableSha256"),
        (&payload.configuration_sha256, "configurationSha256"),
    ] {
        require_digest(value, field)?;
    }
    if payload.api_version != RELEASE_IDENTITY_RECORD_API_VERSION
        || payload.kind != RELEASE_IDENTITY_RECORD_KIND
        || payload.schema_version != "2"
        || payload.provider_generation == 0
        || payload.provider_generation > MAX_SAFE_INTEGER
        || payload.issued_at_epoch_ms == 0
        || payload.issued_at_epoch_ms > MAX_SAFE_INTEGER
        || payload.not_before_epoch_ms > payload.issued_at_epoch_ms
        || payload.issued_at_epoch_ms >= payload.not_after_epoch_ms
        || payload.not_after_epoch_ms > MAX_SAFE_INTEGER
        || authentication.algorithm != "Ed25519"
        || authentication.signer_role != "runtime-attestation"
        || authentication.signing_domain
            != RELEASE_IDENTITY_SIGNATURE_DOMAIN_NAME
    {
        return invalid("signed release identity record contract is invalid");
    }
    validate_identifier(&authentication.key_id, "releaseRecord.keyId")?;
    require_digest(
        &authentication.public_key_sha256,
        "releaseRecord.publicKeySha256",
    )?;
    require_digest(
        &authentication.public_key_spki_sha256,
        "releaseRecord.publicKeySpkiSha256",
    )?;
    let key = decode_canonical_standard_base64_32(
        &authentication.public_key_base64,
        "releaseRecord.publicKeyBase64",
    )?;
    let spki = ed25519_spki(&key);
    let payload_bytes = canonical_bytes(payload)?;
    if authentication.public_key_sha256 != sha256_prefixed(&key)
        || authentication.public_key_spki_sha256 != sha256_prefixed(&spki)
        || authentication.signed_payload_sha256
            != sha256_prefixed(&payload_bytes)
    {
        return invalid("release record key or payload digest is invalid");
    }
    verify_ed25519_signature(
        &key,
        RELEASE_IDENTITY_SIGNATURE_DOMAIN,
        &payload_bytes,
        &authentication.signature_base64url,
        "release identity record",
    )
}

fn validate_signed_checkpoint(
    checkpoint: &SignedReleaseTransparencyCheckpointV2,
) -> Result<(), TransparencyContractError> {
    let payload = &checkpoint.payload;
    let authentication = &checkpoint.authentication;
    validate_identifier(&payload.checkpoint_id, "checkpointId")?;
    validate_identifier(&payload.log_id, "checkpoint.logId")?;
    require_digest(&payload.root_sha256, "checkpoint.rootSha256")?;
    require_digest(
        &payload.trust_checkpoint_sha256,
        "checkpoint.trustCheckpointSha256",
    )?;
    if payload.api_version
        != RELEASE_TRANSPARENCY_CHECKPOINT_API_VERSION
        || payload.kind != RELEASE_TRANSPARENCY_CHECKPOINT_KIND
        || payload.schema_version != "2"
        || payload.provider_generation == 0
        || payload.provider_generation > MAX_SAFE_INTEGER
        || payload.tree_size == 0
        || payload.tree_size > MAX_SAFE_INTEGER
        || payload.issued_at_epoch_ms == 0
        || payload.issued_at_epoch_ms >= payload.expires_at_epoch_ms
        || payload.expires_at_epoch_ms > MAX_SAFE_INTEGER
        || payload.revocation_epoch == 0
        || payload.revocation_epoch > MAX_SAFE_INTEGER
        || authentication.algorithm != "Ed25519"
        || authentication.signing_domain
            != TRANSPARENCY_CHECKPOINT_SIGNATURE_DOMAIN_NAME
    {
        return invalid("signed transparency checkpoint contract is invalid");
    }
    validate_identifier(&authentication.key_id, "checkpoint.keyId")?;
    require_digest(
        &authentication.public_key_spki_sha256,
        "checkpoint.publicKeySpkiSha256",
    )?;
    let (spki, key) = decode_ed25519_spki(
        &authentication.public_key_spki_base64,
        "checkpoint.publicKeySpkiBase64",
    )?;
    let payload_bytes = canonical_bytes(payload)?;
    if authentication.public_key_spki_sha256 != sha256_prefixed(&spki)
        || authentication.signed_payload_sha256
            != sha256_prefixed(&payload_bytes)
    {
        return invalid("checkpoint key or payload digest is invalid");
    }
    verify_ed25519_signature(
        &key,
        TRANSPARENCY_CHECKPOINT_SIGNATURE_DOMAIN,
        &payload_bytes,
        &authentication.signature_base64url,
        "transparency checkpoint",
    )
}

fn validate_trust_pin(
    pin: &ReleaseTransparencyTrustPinV2,
    verification_epoch_ms: u64,
) -> Result<(), TransparencyContractError> {
    validate_identifier(&pin.generation_id, "pin.generationId")?;
    validate_identifier(&pin.log_id, "pin.logId")?;
    validate_identifier(&pin.log_key_id, "pin.logKeyId")?;
    for (value, field) in [
        (&pin.proof_pins_root_sha256, "pin.proofPinsRootSha256"),
        (&pin.log_key_spki_sha256, "pin.logKeySpkiSha256"),
        (&pin.anchor_root_sha256, "pin.anchorRootSha256"),
        (&pin.trust_checkpoint_sha256, "pin.trustCheckpointSha256"),
    ] {
        require_digest(value, field)?;
    }
    let (spki, _) = decode_ed25519_spki(
        &pin.log_key_spki_base64,
        "pin.logKeySpkiBase64",
    )?;
    if pin.api_version != RELEASE_TRANSPARENCY_TRUST_PIN_API_VERSION
        || pin.kind != RELEASE_TRANSPARENCY_TRUST_PIN_KIND
        || pin.schema_version != "2"
        || pin.provider_generation == 0
        || pin.provider_generation > MAX_SAFE_INTEGER
        || pin.anchor_tree_size == 0
        || pin.anchor_tree_size > MAX_SAFE_INTEGER
        || pin.revocation_epoch == 0
        || pin.revocation_epoch > MAX_SAFE_INTEGER
        || pin.valid_from_epoch_ms == 0
        || pin.valid_from_epoch_ms > MAX_SAFE_INTEGER
        || pin.valid_from_epoch_ms >= pin.valid_until_epoch_ms
        || pin.valid_until_epoch_ms > MAX_SAFE_INTEGER
        || verification_epoch_ms < pin.valid_from_epoch_ms
        || verification_epoch_ms >= pin.valid_until_epoch_ms
        || pin.revoked_at_epoch_ms.is_some_and(|revoked| {
            revoked == 0 || revoked <= verification_epoch_ms
        })
        || pin.maximum_checkpoint_age_ms == 0
        || pin.maximum_checkpoint_age_ms > MAX_CHECKPOINT_AGE_MS
        || pin.log_key_spki_sha256 != sha256_prefixed(&spki)
    {
        return invalid("independent transparency trust pin is invalid or inactive");
    }
    Ok(())
}

fn verify_ed25519_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    signature_base64url: &str,
    label: &str,
) -> Result<(), TransparencyContractError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| {
            TransparencyContractError::new(
                "transparency_signature_encoding_invalid",
                format!("{label} signature is not canonical base64url"),
            )
        })?;
    if signature_bytes.len() != 64
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_base64url
    {
        return invalid("transparency signature encoding is non-canonical");
    }
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        TransparencyContractError::new(
            "transparency_signature_invalid",
            format!("{label} signature length is invalid"),
        )
    })?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| {
        TransparencyContractError::new(
            "transparency_key_invalid",
            format!("{label} Ed25519 key is invalid"),
        )
    })?;
    let mut signing_digest = Sha256::new();
    signing_digest.update(domain);
    signing_digest.update((payload.len() as u64).to_be_bytes());
    signing_digest.update(payload);
    let message: [u8; 32] = signing_digest.finalize().into();
    key.verify(&message, &signature).map_err(|_| {
        TransparencyContractError::new(
            "transparency_signature_invalid",
            format!("{label} signature verification failed"),
        )
    })
}

fn rfc6962_root_from_inclusion(
    mut hash: [u8; 32],
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[[u8; 32]],
) -> Result<[u8; 32], TransparencyContractError> {
    if tree_size == 0 || leaf_index >= tree_size {
        return invalid("RFC6962 inclusion coordinates are invalid");
    }
    let mut node = leaf_index;
    let mut last_node = tree_size - 1;
    for sibling in audit_path {
        if last_node == 0 {
            return invalid("RFC6962 inclusion path has trailing nodes");
        }
        if node & 1 == 1 || node == last_node {
            hash = rfc6962_node_hash(sibling, &hash);
            while node != 0 && node & 1 == 0 {
                node >>= 1;
                last_node >>= 1;
            }
        } else {
            hash = rfc6962_node_hash(&hash, sibling);
        }
        node >>= 1;
        last_node >>= 1;
    }
    if last_node != 0 {
        return invalid("RFC6962 inclusion path is incomplete");
    }
    Ok(hash)
}

fn verify_rfc6962_consistency(
    old_size: u64,
    new_size: u64,
    old_root: [u8; 32],
    new_root: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), TransparencyContractError> {
    if old_size == 0 || old_size > new_size {
        return invalid("RFC6962 consistency coordinates are invalid");
    }
    if old_size == new_size {
        if !proof.is_empty() || old_root != new_root {
            return invalid("equal-size RFC6962 checkpoints are inconsistent");
        }
        return Ok(());
    }
    let mut first = old_size - 1;
    let mut second = new_size - 1;
    while first & 1 == 1 {
        first >>= 1;
        second >>= 1;
    }
    let (mut old_hash, mut new_hash, mut index) = if first == 0 {
        (old_root, old_root, 0usize)
    } else {
        let initial = *proof.first().ok_or_else(|| {
            TransparencyContractError::new(
                "transparency_consistency_invalid",
                "RFC6962 consistency path is empty",
            )
        })?;
        (initial, initial, 1usize)
    };
    while index < proof.len() {
        let node = &proof[index];
        if second == 0 {
            return invalid("RFC6962 consistency path has trailing nodes");
        }
        if first & 1 == 1 || first == second {
            old_hash = rfc6962_node_hash(node, &old_hash);
            new_hash = rfc6962_node_hash(node, &new_hash);
            while first != 0 && first & 1 == 0 {
                first >>= 1;
                second >>= 1;
            }
        } else {
            new_hash = rfc6962_node_hash(&new_hash, node);
        }
        first >>= 1;
        second >>= 1;
        index += 1;
    }
    if second != 0 || old_hash != old_root || new_hash != new_root {
        return invalid("RFC6962 append-only consistency proof is invalid");
    }
    Ok(())
}

fn rfc6962_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf);
    hasher.finalize().into()
}

fn rfc6962_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn decode_digest_path(
    path: &[String],
    field: &str,
) -> Result<Vec<[u8; 32]>, TransparencyContractError> {
    if path.len() > MAX_MERKLE_PATH {
        return invalid("Merkle path exceeds the fixed bound");
    }
    path.iter()
        .enumerate()
        .map(|(index, digest)| {
            decode_digest(digest, &format!("{field}[{index}]"))
        })
        .collect()
}

fn decode_digest(
    digest: &str,
    field: &str,
) -> Result<[u8; 32], TransparencyContractError> {
    require_digest(digest, field)?;
    let decoded = hex::decode(&digest["sha256:".len()..]).map_err(|_| {
        TransparencyContractError::new(
            "transparency_digest_invalid",
            format!("{field} is not lowercase SHA-256"),
        )
    })?;
    decoded.try_into().map_err(|_| {
        TransparencyContractError::new(
            "transparency_digest_invalid",
            format!("{field} is not 32 bytes"),
        )
    })
}

fn decode_canonical_standard_base64_32(
    encoded: &str,
    field: &str,
) -> Result<[u8; 32], TransparencyContractError> {
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        TransparencyContractError::new(
            "transparency_key_encoding_invalid",
            format!("{field} is not standard base64"),
        )
    })?;
    if STANDARD.encode(&decoded) != encoded {
        return invalid("Ed25519 public key encoding is non-canonical");
    }
    decoded.try_into().map_err(|_| {
        TransparencyContractError::new(
            "transparency_key_invalid",
            format!("{field} is not a 32-byte Ed25519 key"),
        )
    })
}

fn decode_ed25519_spki(
    encoded: &str,
    field: &str,
) -> Result<(Vec<u8>, [u8; 32]), TransparencyContractError> {
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        TransparencyContractError::new(
            "transparency_spki_encoding_invalid",
            format!("{field} is not standard base64"),
        )
    })?;
    if STANDARD.encode(&decoded) != encoded
        || decoded.len() != ED25519_SPKI_PREFIX.len() + 32
        || !decoded.starts_with(ED25519_SPKI_PREFIX)
    {
        return invalid("log key is not canonical Ed25519 SubjectPublicKeyInfo DER");
    }
    let key: [u8; 32] = decoded[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .map_err(|_| {
            TransparencyContractError::new(
                "transparency_spki_invalid",
                format!("{field} has an invalid Ed25519 BIT STRING"),
            )
        })?;
    VerifyingKey::from_bytes(&key).map_err(|_| {
        TransparencyContractError::new(
            "transparency_spki_invalid",
            format!("{field} contains an invalid Ed25519 key"),
        )
    })?;
    Ok((decoded, key))
}

fn ed25519_spki(key: &[u8; 32]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + key.len());
    spki.extend_from_slice(ED25519_SPKI_PREFIX);
    spki.extend_from_slice(key);
    spki
}

fn canonical_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, TransparencyContractError> {
    let value = serde_json::to_value(value).map_err(|error| {
        TransparencyContractError::new(
            "transparency_canonicalization_failed",
            error.to_string(),
        )
    })?;
    serde_json::to_vec(&value).map_err(|error| {
        TransparencyContractError::new(
            "transparency_canonicalization_failed",
            error.to_string(),
        )
    })
}

fn sha256_prefixed(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

fn format_digest(value: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(value))
}

fn require_digest(
    value: &str,
    field: &str,
) -> Result<(), TransparencyContractError> {
    if !is_sha256_digest(value) {
        return Err(TransparencyContractError::new(
            "transparency_digest_invalid",
            format!("{field} must be a lowercase SHA-256 digest"),
        ));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_identifier(
    value: &str,
    field: &str,
) -> Result<(), TransparencyContractError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-'))
        })
    {
        return Err(TransparencyContractError::new(
            "transparency_identifier_invalid",
            format!("{field} is not a bounded identifier"),
        ));
    }
    Ok(())
}

fn invalid<T>(
    message: impl Into<String>,
) -> Result<T, TransparencyContractError> {
    Err(TransparencyContractError::new(
        "release_transparency_proof_invalid",
        message,
    ))
}
