#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const RECEIPT_CONTRACT_VERSION: u64 = 12;
pub const REQUEST_CONTRACT_VERSION: u64 = 11;
pub const MAX_AUTHORITY_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_AUTHORITY_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CANONICAL_DEPTH: usize = 64;
pub const MAX_CANONICAL_MEMBERS: usize = 65_536;
pub const MAX_CANONICAL_STRING_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MERKLE_PROOF_NODES: usize = 256;

pub const RECEIPT_AUTHENTICATION_DOMAIN: &str =
    "serverware/receipt-authentication/v12";
pub const RECEIPT_TREE_HEAD_DOMAIN: &str =
    "serverware/receipt-tree-head/v12";
pub const EXTERNAL_WITNESS_DOMAIN: &str =
    "serverware/receipt-external-witness/v12";
pub const FINAL_VERDICT_DOMAIN: &str = "serverware/final-verdict/v12";
pub const CONTROLLER_RECEIVE_DOMAIN: &str =
    "serverware/controller-trusted-receive/v12";
pub const TRUST_GENERATION_AUTHORIZATION_DOMAIN: &str =
    "serverware/trust-generation-authorization/v12";
pub const TRUST_GENERATION_DOMAIN: &str =
    "serverware/trust-generation/v12";
pub const FINAL_SETTLEMENT_DOMAIN: &str =
    "serverware/final-settlement/v12";
pub const RECEIPT_LOG_TREE_DOMAIN: &str =
    "SERVERWARE_CONTROLLER_RECEIPTS_V12";
pub const AUTHORITY_FRAME_MAGIC: [u8; 8] = *b"SWRPC12\0";
pub const AUTHORITY_FRAME_BYTES: usize = 96;
pub const V11_PREALLOCATION_FRAME_BYTES: usize = 256;
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub enum ContractError {
    Invalid(&'static str),
    InvalidOwned(String),
    Json(serde_json::Error),
    Signature(ed25519_dalek::SignatureError),
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidOwned(message) => formatter.write_str(message),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Signature(error) => write!(formatter, "signature error: {error}"),
        }
    }
}

impl std::error::Error for ContractError {}

impl From<serde_json::Error> for ContractError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<ed25519_dalek::SignatureError> for ContractError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        Self::Signature(value)
    }
}

pub type Result<T> = std::result::Result<T, ContractError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DigestHex(String);

impl DigestHex {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ContractError::Invalid("digest is not lowercase SHA-256 hex"));
        }
        Ok(Self(value))
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn decode(&self) -> Result<[u8; 32]> {
        let mut decoded = [0u8; 32];
        for (index, pair) in self.0.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(decoded)
    }
}

impl fmt::Display for DigestHex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalU64(String);

impl CanonicalU64 {
    pub fn new(value: u64) -> Self {
        Self(format!("{value:020}"))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 20 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
            return Err(ContractError::Invalid("u64 is not canonical D20"));
        }
        value
            .parse::<u64>()
            .map_err(|_| ContractError::Invalid("D20 exceeds u64"))?;
        Ok(Self(value))
    }

    pub fn get(&self) -> Result<u64> {
        self.0
            .parse::<u64>()
            .map_err(|_| ContractError::Invalid("D20 exceeds u64"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityRoleV12 {
    #[serde(rename = "controllerIngress")]
    ControllerIngress,
    #[serde(rename = "controllerReceiptAuthentication")]
    ReceiptAuthentication,
    #[serde(rename = "controllerReceiptLog")]
    ReceiptLog,
    #[serde(rename = "controllerReceiptExternalWitness")]
    ExternalWitness,
    #[serde(rename = "controllerFinalVerdict")]
    FinalVerdict,
    #[serde(rename = "controllerTrustRoot")]
    TrustRoot,
    #[serde(rename = "controllerTrustGeneration")]
    TrustGeneration,
    #[serde(rename = "controllerFinalSettlement")]
    FinalSettlement,
}

impl AuthorityRoleV12 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControllerIngress => "controllerIngress",
            Self::ReceiptAuthentication => "controllerReceiptAuthentication",
            Self::ReceiptLog => "controllerReceiptLog",
            Self::ExternalWitness => "controllerReceiptExternalWitness",
            Self::FinalVerdict => "controllerFinalVerdict",
            Self::TrustRoot => "controllerTrustRoot",
            Self::TrustGeneration => "controllerTrustGeneration",
            Self::FinalSettlement => "controllerFinalSettlement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictV12 {
    Pass,
    Fail,
    Unknown,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplayIdentityV12 {
    pub replay_namespace: String,
    pub replay_key: String,
    pub replay_key_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyAuthorizationV12 {
    pub role: AuthorityRoleV12,
    pub principal_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_authorization_sha256: DigestHex,
    pub authorization_root_sha256: DigestHex,
    pub authorization_revision: CanonicalU64,
    pub revocation_root_sha256: DigestHex,
    pub revocation_revision: CanonicalU64,
    pub high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureV12 {
    pub domain: String,
    pub payload_sha256: DigestHex,
    pub signed_at: String,
    pub accepted_at: String,
    pub signer_role: AuthorityRoleV12,
    pub signer_principal_id: String,
    pub signer_key_id: String,
    pub signer_spki_der_sha256: DigestHex,
    pub key_authorization: KeyAuthorizationV12,
    pub signature_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedEnvelopeV12<T> {
    pub domain: String,
    pub payload: T,
    pub payload_sha256: DigestHex,
    pub signature: SignatureV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityDeadlineV12 {
    pub boot_id_sha256: DigestHex,
    pub boottime_deadline_ns: CanonicalU64,
    pub request_deadline_unix_ms: CanonicalU64,
}

impl AuthorityDeadlineV12 {
    pub fn require_live(&self) -> Result<u64> {
        if self.boot_id_sha256 != boot_id_sha256_v12()? {
            return Err(ContractError::Invalid(
                "authority deadline belongs to a different host boot",
            ));
        }
        let deadline = self.boottime_deadline_ns.get()?;
        let now = boottime_now_ns()?;
        if deadline <= now {
            return Err(ContractError::Invalid("authority CLOCK_BOOTTIME deadline expired"));
        }
        Ok(deadline - now)
    }

    pub fn current(
        boottime_deadline_ns: u64,
        request_deadline_unix_ms: u64,
    ) -> Result<Self> {
        Ok(Self {
            boot_id_sha256: boot_id_sha256_v12()?,
            boottime_deadline_ns: CanonicalU64::new(boottime_deadline_ns),
            request_deadline_unix_ms: CanonicalU64::new(request_deadline_unix_ms),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedReceivePayloadV12 {
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub preallocation_frame_sha256: DigestHex,
    pub frame_received_at_unix_ms: CanonicalU64,
    pub frame_received_boottime_ns: CanonicalU64,
    pub boot_id_sha256: DigestHex,
    pub request_deadline_unix_ms: CanonicalU64,
    pub requester_key_leaf_sha256: DigestHex,
    pub requester_authorization_sha256: DigestHex,
    pub requester_authorization_high_water: CanonicalU64,
    pub requester_revocation_high_water: CanonicalU64,
    pub canonical_verifier_profile_sha256: DigestHex,
    pub verified_relationships_sha256: DigestHex,
    pub controller_configuration_sha256: DigestHex,
    pub accepted_at: String,
}

pub type TrustedReceiveEnvelopeV12 =
    SignedEnvelopeV12<TrustedReceivePayloadV12>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalRequestAdmissionV12 {
    pub preallocation_frame_base64url: String,
    pub exact_request_base64url: String,
    pub trusted_receive_envelope: TrustedReceiveEnvelopeV12,
    pub trusted_receive_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequesterTrustMaterialV11 {
    pub principal_id: String,
    pub key_id: String,
    pub verifying_key_base64url: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_leaf_sha256: DigestHex,
    pub trust_root_sha256: DigestHex,
    pub trust_revision: CanonicalU64,
    pub non_revocation_root_sha256: DigestHex,
    pub non_revocation_revision: CanonicalU64,
    pub authorization_high_water: CanonicalU64,
    pub revocation_high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityTrustMaterialV12 {
    pub role: AuthorityRoleV12,
    pub principal_id: String,
    pub key_id: String,
    pub verifying_key_base64url: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_authorization_sha256: DigestHex,
    pub authorization_root_sha256: DigestHex,
    pub authorization_revision: CanonicalU64,
    pub revocation_root_sha256: DigestHex,
    pub revocation_revision: CanonicalU64,
    pub authorization_high_water: CanonicalU64,
    pub revocation_high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustGenerationAuthorizationPayloadV12 {
    pub trust_root_generation: CanonicalU64,
    pub generation_principal_id: String,
    pub generation_key_id: String,
    pub generation_verifying_key_base64url: String,
    pub generation_spki_der_sha256: DigestHex,
    pub generation_physical_private_key_identity_sha256: DigestHex,
    pub minimum_generation_sequence: CanonicalU64,
    pub maximum_generation_sequence: CanonicalU64,
    pub authorization_high_water: CanonicalU64,
    pub revocation_high_water: CanonicalU64,
    pub valid_from: String,
    pub valid_until: String,
    pub issued_at: String,
}

pub type TrustGenerationAuthorizationEnvelopeV12 =
    SignedEnvelopeV12<TrustGenerationAuthorizationPayloadV12>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustGenerationPayloadV12 {
    pub generation_sequence: CanonicalU64,
    pub rollback_floor: CanonicalU64,
    pub previous_generation_envelope_sha256: DigestHex,
    pub authorization_chain_envelope_sha256: DigestHex,
    pub request_v11_schema_sha256: DigestHex,
    pub receipt_v12_schema_sha256: DigestHex,
    pub requester: RequesterTrustMaterialV11,
    pub controller_ingress: AuthorityTrustMaterialV12,
    pub receipt_authentication: AuthorityTrustMaterialV12,
    pub receipt_log: AuthorityTrustMaterialV12,
    pub external_witness: AuthorityTrustMaterialV12,
    pub final_verdict: AuthorityTrustMaterialV12,
    pub final_settlement: AuthorityTrustMaterialV12,
    pub generated_at: String,
}

pub type SignedTrustGenerationV12 =
    SignedEnvelopeV12<TrustGenerationPayloadV12>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustGenerationBundleV12 {
    pub authorization_chain: TrustGenerationAuthorizationEnvelopeV12,
    pub authorization_chain_envelope_sha256: DigestHex,
    pub generation: SignedTrustGenerationV12,
    pub generation_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptBodyV12 {
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub execution_result_sha256: DigestHex,
    pub verdict: VerdictV12,
    pub body_trust_observation_sha256: DigestHex,
    pub completed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptAuthenticationPayloadV12 {
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body_sha256: DigestHex,
    pub receipt_body_canonical_bytes: CanonicalU64,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub body_trust_observation_sha256: DigestHex,
    pub authenticated_at: String,
}

pub type ReceiptAuthenticationEnvelopeV12 =
    SignedEnvelopeV12<ReceiptAuthenticationPayloadV12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckpointKindV12 {
    Genesis,
    SignedTreeHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviousCheckpointV12 {
    pub checkpoint_kind: CheckpointKindV12,
    pub tree_size: CanonicalU64,
    pub root_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreFinalLogLeafV12 {
    pub log_id: String,
    pub leaf_ordinal: CanonicalU64,
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub receipt_body_sha256: DigestHex,
    pub receipt_authentication_envelope_sha256: DigestHex,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub leaf_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreeHeadPayloadV12 {
    pub log_id: String,
    pub checkpoint_sequence: CanonicalU64,
    pub tree_size: CanonicalU64,
    pub root_sha256: DigestHex,
    pub previous_signed_tree_head_envelope_sha256: DigestHex,
    pub latest_leaf_sha256: DigestHex,
    pub latest_receipt_sequence: CanonicalU64,
    pub issued_at: String,
}

pub type SignedTreeHeadV12 = SignedEnvelopeV12<TreeHeadPayloadV12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofDirectionV12 {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MerkleProofNodeV12 {
    pub direction: ProofDirectionV12,
    pub sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InclusionProofV12 {
    pub tree_domain: String,
    pub leaf_ordinal: CanonicalU64,
    pub tree_size: CanonicalU64,
    pub leaf_sha256: DigestHex,
    pub root_sha256: DigestHex,
    pub path: Vec<MerkleProofNodeV12>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsistencyProofV12 {
    pub tree_domain: String,
    pub from_tree_size: CanonicalU64,
    pub from_root_sha256: DigestHex,
    pub to_tree_size: CanonicalU64,
    pub to_root_sha256: DigestHex,
    pub nodes: Vec<DigestHex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalWitnessPayloadV12 {
    pub witness_id: String,
    pub log_id: String,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub tree_size: CanonicalU64,
    pub root_sha256: DigestHex,
    pub witness_sequence: CanonicalU64,
    pub previous_witness_checkpoint_envelope_sha256: DigestHex,
    pub observed_at: String,
}

pub type ExternalWitnessCheckpointV12 =
    SignedEnvelopeV12<ExternalWitnessPayloadV12>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityTrustObservationV12 {
    pub role: AuthorityRoleV12,
    pub principal_id: String,
    pub key_id: String,
    pub spki_der_sha256: DigestHex,
    pub physical_private_key_identity_sha256: DigestHex,
    pub key_authorization_sha256: DigestHex,
    pub authorization_root_sha256: DigestHex,
    pub authorization_revision: CanonicalU64,
    pub revocation_root_sha256: DigestHex,
    pub revocation_revision: CanonicalU64,
    pub high_water: CanonicalU64,
    pub observed_at: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalTrustObservationV12 {
    pub trust_generation: TrustGenerationBundleV12,
    pub trust_generation_envelope_sha256: DigestHex,
    pub trust_generation_sequence: CanonicalU64,
    pub trust_rollback_floor: CanonicalU64,
    pub controller_ingress_authority: AuthorityTrustObservationV12,
    pub receipt_authentication_authority: AuthorityTrustObservationV12,
    pub receipt_log_authority: AuthorityTrustObservationV12,
    pub external_witness_authority: AuthorityTrustObservationV12,
    pub final_verdict_authority: AuthorityTrustObservationV12,
    pub final_settlement_authority: AuthorityTrustObservationV12,
    pub receipt_schema_sha256: DigestHex,
    pub request_trust_observation_sha256: DigestHex,
    pub body_trust_observation_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub external_witness_checkpoint_envelope_sha256: DigestHex,
    pub minimum_accepted_receipt_sequence: CanonicalU64,
    pub minimum_accepted_tree_size: CanonicalU64,
    pub minimum_accepted_witness_sequence: CanonicalU64,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalVerdictPayloadV12 {
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body_sha256: DigestHex,
    pub receipt_body_canonical_bytes: CanonicalU64,
    pub terminal_evidence_root_sha256: DigestHex,
    pub terminal_state_root_sha256: DigestHex,
    pub receipt_authentication_envelope_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub external_witness_checkpoint_envelope_sha256: DigestHex,
    pub log_bundle_sha256: DigestHex,
    pub final_trust_observation_sha256: DigestHex,
    pub tree_size: CanonicalU64,
    pub tree_root_sha256: DigestHex,
    pub verdict: VerdictV12,
    pub issued_at: String,
}

pub type FinalVerdictEnvelopeV12 = SignedEnvelopeV12<FinalVerdictPayloadV12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinalSettlementOutcomeV12 {
    Genesis,
    Receipt,
    TerminalAbort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalSettlementPayloadV12 {
    pub outcome: FinalSettlementOutcomeV12,
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_key_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub pre_final_log_leaf_sha256: DigestHex,
    pub receipt_envelope_sha256: DigestHex,
    pub terminal_abort_reason_sha256: DigestHex,
    pub settlement_sequence: CanonicalU64,
    pub previous_settlement_checkpoint_envelope_sha256: DigestHex,
    pub tree_size: CanonicalU64,
    pub tree_root_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub witness_sequence: CanonicalU64,
    pub witness_checkpoint_envelope_sha256: DigestHex,
    pub trust_generation_envelope_sha256: DigestHex,
    pub trust_generation_sequence: CanonicalU64,
    pub settled_at: String,
}

pub type FinalSettlementCheckpointV12 =
    SignedEnvelopeV12<FinalSettlementPayloadV12>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalSettlementArtifactV12 {
    pub outcome: FinalSettlementOutcomeV12,
    pub logged_bundle: LoggedReceiptBundleV12,
    pub external_witness_checkpoint: ExternalWitnessCheckpointV12,
    pub receipt: Option<ReceiptV12>,
    pub terminal_abort_reason: Option<String>,
    pub trust_generation: TrustGenerationBundleV12,
    pub final_settlement_checkpoint: FinalSettlementCheckpointV12,
    pub final_settlement_checkpoint_envelope_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoggedReceiptBundleV12 {
    pub contract_version: u64,
    pub request_contract_version: u64,
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_identity: ReplayIdentityV12,
    pub request_v11: Value,
    pub request_admission: CanonicalRequestAdmissionV12,
    pub request_admission_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body: ReceiptBodyV12,
    pub receipt_body_sha256: DigestHex,
    pub receipt_body_canonical_bytes: CanonicalU64,
    pub receipt_authentication_envelope: ReceiptAuthenticationEnvelopeV12,
    pub receipt_authentication_envelope_sha256: DigestHex,
    pub previous_checkpoint: PreviousCheckpointV12,
    pub pre_final_log_leaf: PreFinalLogLeafV12,
    pub signed_tree_head: SignedTreeHeadV12,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub inclusion_proof: InclusionProofV12,
    pub consistency_proof: ConsistencyProofV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptV12 {
    pub contract_version: u64,
    pub request_contract_version: u64,
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub requester_principal_id: String,
    pub replay_identity: ReplayIdentityV12,
    pub request_v11: Value,
    pub request_admission: CanonicalRequestAdmissionV12,
    pub request_admission_sha256: DigestHex,
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub receipt_body: ReceiptBodyV12,
    pub receipt_body_sha256: DigestHex,
    pub receipt_body_canonical_bytes: CanonicalU64,
    pub receipt_authentication_envelope: ReceiptAuthenticationEnvelopeV12,
    pub receipt_authentication_envelope_sha256: DigestHex,
    pub previous_checkpoint: PreviousCheckpointV12,
    pub pre_final_log_leaf: PreFinalLogLeafV12,
    pub signed_tree_head: SignedTreeHeadV12,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub inclusion_proof: InclusionProofV12,
    pub consistency_proof: ConsistencyProofV12,
    pub external_witness_checkpoint: ExternalWitnessCheckpointV12,
    pub external_witness_checkpoint_envelope_sha256: DigestHex,
    pub log_bundle_sha256: DigestHex,
    pub final_trust_observation: FinalTrustObservationV12,
    pub final_trust_observation_sha256: DigestHex,
    pub final_verdict_envelope: FinalVerdictEnvelopeV12,
    pub final_verdict_envelope_sha256: DigestHex,
    pub receipt_envelope_sha256: DigestHex,
    pub receipt_canonical_bytes: CanonicalU64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptAuthorityRequestV12 {
    pub operation: String,
    pub receipt_id: String,
    pub replay_identity: ReplayIdentityV12,
    pub requester_principal_id: String,
    pub request_admission: CanonicalRequestAdmissionV12,
    pub receipt_body_template: ReceiptBodyV12,
    pub submission_binding_sha256: DigestHex,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptAuthorityResponseV12 {
    pub operation: String,
    pub disposition: String,
    pub logged_bundle: LoggedReceiptBundleV12,
    pub logged_bundle_sha256: DigestHex,
    pub final_settlement: Option<FinalSettlementArtifactV12>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogAuthorityRequestV12 {
    pub operation: String,
    pub log_id: String,
    pub receipt_body: ReceiptBodyV12,
    pub receipt_body_sha256: DigestHex,
    pub receipt_authentication_envelope: ReceiptAuthenticationEnvelopeV12,
    pub receipt_authentication_envelope_sha256: DigestHex,
    pub expected_previous_tree_head_envelope_sha256: DigestHex,
    pub log_append_binding_sha256: DigestHex,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogAuthorityResponseV12 {
    pub operation: String,
    pub disposition: String,
    pub log_append_binding_sha256: DigestHex,
    pub previous_checkpoint: PreviousCheckpointV12,
    pub pre_final_log_leaf: PreFinalLogLeafV12,
    pub signed_tree_head: SignedTreeHeadV12,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub inclusion_proof: InclusionProofV12,
    pub consistency_proof: ConsistencyProofV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalVerdictAuthorityRequestV12 {
    pub operation: String,
    pub logged_bundle: LoggedReceiptBundleV12,
    pub logged_bundle_sha256: DigestHex,
    pub external_witness_checkpoint: ExternalWitnessCheckpointV12,
    pub final_trust_observation: FinalTrustObservationV12,
    pub requested_verdict: VerdictV12,
    pub expected_finalization_binding_sha256: DigestHex,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalVerdictAuthorityResponseV12 {
    pub operation: String,
    pub disposition: String,
    pub receipt: ReceiptV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustGenerationResolveRequestV12 {
    pub operation: String,
    pub receipt_id: String,
    pub receipt_sequence: CanonicalU64,
    pub replay_key_sha256: DigestHex,
    pub logged_bundle_sha256: DigestHex,
    pub minimum_generation_sequence: CanonicalU64,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustGenerationResolveResponseV12 {
    pub operation: String,
    pub request_binding_sha256: DigestHex,
    pub trust_generation: TrustGenerationBundleV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessFinalizationRequestV12 {
    pub operation: String,
    pub logged_bundle_sha256: DigestHex,
    pub signed_tree_head: SignedTreeHeadV12,
    pub trust_generation_envelope_sha256: DigestHex,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessFinalizationResponseV12 {
    pub operation: String,
    pub request_binding_sha256: DigestHex,
    pub external_witness_checkpoint: ExternalWitnessCheckpointV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalSettlementRequestV12 {
    pub operation: String,
    pub logged_bundle: LoggedReceiptBundleV12,
    pub logged_bundle_sha256: DigestHex,
    pub receipt: Option<ReceiptV12>,
    pub terminal_abort_reason: Option<String>,
    pub external_witness_checkpoint: ExternalWitnessCheckpointV12,
    pub trust_generation: TrustGenerationBundleV12,
    pub expected_previous_settlement_checkpoint_envelope_sha256: DigestHex,
    pub deadline: AuthorityDeadlineV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalSettlementResponseV12 {
    pub operation: String,
    pub request_binding_sha256: DigestHex,
    pub artifact: FinalSettlementArtifactV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationHighWaterV12 {
    pub receipt_sequence: CanonicalU64,
    pub receipt_envelope_sha256: DigestHex,
    pub tree_size: CanonicalU64,
    pub tree_root_sha256: DigestHex,
    pub signed_tree_head_envelope_sha256: DigestHex,
    pub witness_sequence: CanonicalU64,
    pub witness_checkpoint_envelope_sha256: DigestHex,
    pub settlement_sequence: CanonicalU64,
    pub settlement_checkpoint_envelope_sha256: DigestHex,
    pub trust_generation_sequence: CanonicalU64,
    pub trust_generation_envelope_sha256: DigestHex,
    pub trust_rollback_floor: CanonicalU64,
    pub authorization_high_water: CanonicalU64,
    pub revocation_high_water: CanonicalU64,
}

impl VerificationHighWaterV12 {
    pub fn genesis() -> Self {
        Self {
            receipt_sequence: CanonicalU64::new(0),
            receipt_envelope_sha256: DigestHex::zero(),
            tree_size: CanonicalU64::new(0),
            tree_root_sha256: h12(
                "merkle-empty",
                &[RECEIPT_LOG_TREE_DOMAIN.as_bytes()],
            ),
            signed_tree_head_envelope_sha256: DigestHex::zero(),
            witness_sequence: CanonicalU64::new(0),
            witness_checkpoint_envelope_sha256: DigestHex::zero(),
            settlement_sequence: CanonicalU64::new(0),
            settlement_checkpoint_envelope_sha256: DigestHex::zero(),
            trust_generation_sequence: CanonicalU64::new(0),
            trust_generation_envelope_sha256: DigestHex::zero(),
            trust_rollback_floor: CanonicalU64::new(0),
            authorization_high_water: CanonicalU64::new(0),
            revocation_high_water: CanonicalU64::new(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerHighWaterRequestV12 {
    pub operation: String,
    pub request_nonce_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerHighWaterResponseV12 {
    pub operation: String,
    pub request_nonce_sha256: DigestHex,
    pub high_water: VerificationHighWaterV12,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedLookupRequestV12 {
    pub operation: String,
    pub replay_key_sha256: DigestHex,
    pub finalization_binding_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedLookupResponseV12 {
    pub operation: String,
    pub disposition: String,
    pub replay_key_sha256: DigestHex,
    pub finalization_binding_sha256: DigestHex,
    pub artifact: Option<FinalSettlementArtifactV12>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedCommitRequestV12 {
    pub operation: String,
    pub finalization_binding_sha256: DigestHex,
    pub artifact: FinalSettlementArtifactV12,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizedCommitResponseV12 {
    pub operation: String,
    pub disposition: String,
    pub finalization_binding_sha256: DigestHex,
    pub artifact: FinalSettlementArtifactV12,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestV11Summary {
    pub request_v11_sha256: DigestHex,
    pub request_envelope_sha256: DigestHex,
    pub request_canonical_bytes: CanonicalU64,
    pub request_domain: String,
    pub request_payload_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFrameHeaderV12 {
    pub payload_bytes: u64,
    pub boottime_deadline_ns: u64,
    pub boot_id_sha256: DigestHex,
    pub payload_sha256: DigestHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerIdentityV12 {
    pub device: CanonicalU64,
    pub inode: CanonicalU64,
    pub owner_uid: CanonicalU64,
    pub mode: CanonicalU64,
}

impl AuthorityFrameHeaderV12 {
    pub fn decode(bytes: &[u8; AUTHORITY_FRAME_BYTES], maximum: usize) -> Result<Self> {
        if bytes[..8] != AUTHORITY_FRAME_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != 12
            || u16::from_be_bytes([bytes[10], bytes[11]]) != 1
            || u32::from_be_bytes(bytes[12..16].try_into().map_err(|_| {
                ContractError::Invalid("authority frame header is malformed")
            })?) != AUTHORITY_FRAME_BYTES as u32
        {
            return Err(ContractError::Invalid("authority frame identity is invalid"));
        }
        let payload_bytes = u64::from_be_bytes(bytes[16..24].try_into().map_err(|_| {
            ContractError::Invalid("authority frame length is malformed")
        })?);
        let boottime_deadline_ns =
            u64::from_be_bytes(bytes[24..32].try_into().map_err(|_| {
                ContractError::Invalid("authority frame deadline is malformed")
            })?);
        let boot_id_sha256 = DigestHex::parse(hex::encode(&bytes[32..64]))?;
        let payload_sha256 = DigestHex::parse(hex::encode(&bytes[64..96]))?;
        if payload_bytes == 0 || payload_bytes > maximum as u64 {
            return Err(ContractError::Invalid(
                "authority frame payload length is outside bound",
            ));
        }
        if boottime_deadline_ns <= boottime_now_ns()? {
            return Err(ContractError::Invalid(
                "authority frame CLOCK_BOOTTIME deadline expired",
            ));
        }
        if boot_id_sha256 != boot_id_sha256_v12()? {
            return Err(ContractError::Invalid(
                "authority frame belongs to a different host boot",
            ));
        }
        Ok(Self {
            payload_bytes,
            boottime_deadline_ns,
            boot_id_sha256,
            payload_sha256,
        })
    }

    pub fn encode(&self, maximum: usize) -> Result<[u8; AUTHORITY_FRAME_BYTES]> {
        if self.payload_bytes == 0
            || self.payload_bytes > maximum as u64
            || self.boottime_deadline_ns <= boottime_now_ns()?
            || self.boot_id_sha256 != boot_id_sha256_v12()?
            || self.payload_sha256 == DigestHex::zero()
        {
            return Err(ContractError::Invalid("invalid authority frame"));
        }
        let mut bytes = [0u8; AUTHORITY_FRAME_BYTES];
        bytes[..8].copy_from_slice(&AUTHORITY_FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&12u16.to_be_bytes());
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&(AUTHORITY_FRAME_BYTES as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&self.payload_bytes.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.boottime_deadline_ns.to_be_bytes());
        bytes[32..64].copy_from_slice(&self.boot_id_sha256.decode()?);
        bytes[64..96].copy_from_slice(&self.payload_sha256.decode()?);
        Ok(bytes)
    }

    pub fn for_payload(
        payload: &[u8],
        boottime_deadline_ns: u64,
        maximum: usize,
    ) -> Result<Self> {
        let header = Self {
            payload_bytes: payload.len() as u64,
            boottime_deadline_ns,
            boot_id_sha256: boot_id_sha256_v12()?,
            payload_sha256: sha256_bytes(payload),
        };
        header.encode(maximum)?;
        Ok(header)
    }
}

pub fn boottime_now_ns() -> Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(ContractError::InvalidOwned(format!(
            "CLOCK_BOOTTIME unavailable: {}",
            std::io::Error::last_os_error(),
        )));
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or(ContractError::Invalid("CLOCK_BOOTTIME value overflow"))
}

pub fn boot_id_sha256_v12() -> Result<DigestHex> {
    let bytes = std::fs::read("/proc/sys/kernel/random/boot_id").map_err(|error| {
        ContractError::InvalidOwned(format!("read kernel boot identity: {error}"))
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ContractError::Invalid("kernel boot identity is not UTF-8"))?
        .trim();
    if text.len() != 36
        || text.as_bytes().iter().enumerate().any(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                .then_some(*byte != b'-')
                .unwrap_or(!byte.is_ascii_hexdigit())
        })
    {
        return Err(ContractError::Invalid("kernel boot identity is malformed"));
    }
    Ok(sha256_bytes(text.as_bytes()))
}

pub fn read_authority_frame_v12(
    stream: &UnixStream,
    maximum: usize,
) -> Result<(Vec<u8>, AuthorityFrameHeaderV12)> {
    let mut header_bytes = [0u8; AUTHORITY_FRAME_BYTES];
    let header_deadline = boottime_now_ns()?
        .checked_add(5_000_000_000)
        .ok_or(ContractError::Invalid("authority header deadline overflow"))?;
    read_exact_until(
        stream.as_raw_fd(),
        &mut header_bytes,
        header_deadline,
    )?;
    let header = AuthorityFrameHeaderV12::decode(&header_bytes, maximum)?;
    let mut payload = vec![0u8; header.payload_bytes as usize];
    read_exact_until(
        stream.as_raw_fd(),
        &mut payload,
        header.boottime_deadline_ns,
    )?;
    if sha256_bytes(&payload) != header.payload_sha256 {
        return Err(ContractError::Invalid(
            "authority frame payload digest mismatch",
        ));
    }
    preflight_canonical_json(&payload)?;
    Ok((payload, header))
}

pub fn read_authority_frame_until_v12(
    stream: &UnixStream,
    maximum: usize,
    expected_boottime_deadline_ns: u64,
) -> Result<(Vec<u8>, AuthorityFrameHeaderV12)> {
    let mut header_bytes = [0u8; AUTHORITY_FRAME_BYTES];
    read_exact_until(
        stream.as_raw_fd(),
        &mut header_bytes,
        expected_boottime_deadline_ns,
    )?;
    let header = AuthorityFrameHeaderV12::decode(&header_bytes, maximum)?;
    if header.boottime_deadline_ns != expected_boottime_deadline_ns {
        return Err(ContractError::Invalid(
            "authority response changed CLOCK_BOOTTIME deadline",
        ));
    }
    let mut payload = vec![0u8; header.payload_bytes as usize];
    read_exact_until(
        stream.as_raw_fd(),
        &mut payload,
        expected_boottime_deadline_ns,
    )?;
    if sha256_bytes(&payload) != header.payload_sha256 {
        return Err(ContractError::Invalid(
            "authority response payload digest mismatch",
        ));
    }
    preflight_canonical_json(&payload)?;
    Ok((payload, header))
}

pub fn write_authority_frame_v12(
    stream: &UnixStream,
    bytes: &[u8],
    maximum: usize,
    boottime_deadline_ns: u64,
) -> Result<()> {
    let header =
        AuthorityFrameHeaderV12::for_payload(bytes, boottime_deadline_ns, maximum)?
            .encode(maximum)?;
    write_all_until(stream.as_raw_fd(), &header, boottime_deadline_ns)?;
    write_all_until(stream.as_raw_fd(), bytes, boottime_deadline_ns)
}

pub fn connect_authority_v12(
    path: &Path,
    expected_peer_uid: u32,
    boottime_deadline_ns: u64,
) -> Result<UnixStream> {
    if !path.is_absolute() {
        return Err(ContractError::Invalid("authority socket path is not absolute"));
    }
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.is_empty()
        || path_bytes.len() >= std::mem::size_of::<libc::sockaddr_un>() - 2
    {
        return Err(ContractError::Invalid("authority socket path length is invalid"));
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(ContractError::InvalidOwned(format!(
            "create authority socket: {}",
            io::Error::last_os_error(),
        )));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes.iter()) {
        *target = *source as libc::c_char;
    }
    let address_len = (std::mem::size_of::<libc::sa_family_t>()
        + path_bytes.len()
        + 1) as libc::socklen_t;
    let connected = unsafe {
        libc::connect(
            fd,
            &address as *const _ as *const libc::sockaddr,
            address_len,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return Err(ContractError::InvalidOwned(format!(
                "connect authority socket: {error}",
            )));
        }
        if let Err(error) = poll_fd_until(fd, libc::POLLOUT, boottime_deadline_ns) {
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut socket_error as *mut _ as *mut libc::c_void,
                &mut length,
            )
        } != 0
            || socket_error != 0
        {
            unsafe { libc::close(fd) };
            return Err(ContractError::Invalid("authority socket connect failed"));
        }
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if peer_uid_v12(&stream)? != expected_peer_uid {
        return Err(ContractError::Invalid("authority peer UID does not match pin"));
    }
    Ok(stream)
}

pub fn authority_rpc_v12<T, R>(
    path: &Path,
    expected_peer_uid: u32,
    request: &T,
    deadline: &AuthorityDeadlineV12,
    maximum_request: usize,
    maximum_response: usize,
) -> Result<(R, Vec<u8>)>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let deadline_ns = deadline.boottime_deadline_ns.get()?;
    deadline.require_live()?;
    let stream = connect_authority_v12(path, expected_peer_uid, deadline_ns)?;
    let request_bytes = canonical_json(request, maximum_request)?;
    write_authority_frame_v12(
        &stream,
        &request_bytes,
        maximum_request,
        deadline_ns,
    )?;
    let (response_bytes, response_frame) =
        read_authority_frame_until_v12(&stream, maximum_response, deadline_ns)?;
    if response_frame.boottime_deadline_ns != deadline_ns {
        return Err(ContractError::Invalid(
            "authority response changed the exact caller deadline",
        ));
    }
    let response = parse_canonical_json(&response_bytes, maximum_response)?;
    Ok((response, response_bytes))
}

pub fn notify_systemd_v12(status: &str) -> Result<()> {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = socket
        .to_str()
        .ok_or(ContractError::Invalid("NOTIFY_SOCKET is not UTF-8"))?;
    let message = format!("READY=1\nSTATUS={status}");
    if !socket.starts_with('@') {
        UnixDatagram::unbound()
            .and_then(|datagram| datagram.send_to(message.as_bytes(), socket))
            .map_err(|error| {
                ContractError::InvalidOwned(format!("send sd_notify datagram: {error}"))
            })?;
        return Ok(());
    }

    let name = &socket.as_bytes()[1..];
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if name.is_empty() || name.len() + 1 > address.sun_path.len() {
        return Err(ContractError::Invalid(
            "abstract NOTIFY_SOCKET is outside sockaddr_un",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path[1..].iter_mut().zip(name.iter()) {
        *target = *source as libc::c_char;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(ContractError::InvalidOwned(format!(
            "create sd_notify socket: {}",
            io::Error::last_os_error(),
        )));
    }
    let sent = unsafe {
        libc::sendto(
            fd,
            message.as_ptr() as *const libc::c_void,
            message.len(),
            libc::MSG_NOSIGNAL,
            &address as *const _ as *const libc::sockaddr,
            (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len())
                as libc::socklen_t,
        )
    };
    unsafe { libc::close(fd) };
    if sent != message.len() as isize {
        return Err(ContractError::InvalidOwned(format!(
            "send sd_notify datagram: {}",
            io::Error::last_os_error(),
        )));
    }
    Ok(())
}

pub fn peer_uid_v12(stream: &UnixStream) -> Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(ContractError::InvalidOwned(format!(
            "read SO_PEERCRED: {}",
            io::Error::last_os_error(),
        )));
    }
    Ok(credentials.uid)
}

pub fn verify_activated_listener_v12(
    fd: RawFd,
    expected: &ListenerIdentityV12,
) -> Result<()> {
    let mut socket_type: libc::c_int = 0;
    let mut accept_conn: libc::c_int = 0;
    let mut option_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut _ as *mut libc::c_void,
            &mut option_length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(ContractError::Invalid(
            "activated descriptor is not a stream socket",
        ));
    }
    option_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut accept_conn as *mut _ as *mut libc::c_void,
            &mut option_length,
        )
    } != 0
        || accept_conn != 1
    {
        return Err(ContractError::Invalid(
            "activated descriptor is not an accepting listener",
        ));
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length =
        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            &mut address as *mut _ as *mut libc::sockaddr,
            &mut address_length,
        )
    } != 0
        || address.ss_family as libc::c_int != libc::AF_UNIX
    {
        return Err(ContractError::Invalid(
            "activated listener is not AF_UNIX",
        ));
    }
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0
        || (metadata.st_mode & libc::S_IFMT) != libc::S_IFSOCK
        || metadata.st_dev as u64 != expected.device.get()?
        || metadata.st_ino as u64 != expected.inode.get()?
        || metadata.st_uid as u64 != expected.owner_uid.get()?
        || (metadata.st_mode as u64 & 0o7777) != expected.mode.get()?
    {
        return Err(ContractError::Invalid(
            "activated listener identity differs from immutable pin",
        ));
    }
    Ok(())
}

pub fn inspect_activated_listener_v12(
    fd: RawFd,
    expected_owner_uid: u32,
    expected_mode: u32,
) -> Result<ListenerIdentityV12> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(ContractError::InvalidOwned(format!(
            "inspect activated listener: {}",
            io::Error::last_os_error(),
        )));
    }
    let identity = ListenerIdentityV12 {
        device: CanonicalU64::new(metadata.st_dev as u64),
        inode: CanonicalU64::new(metadata.st_ino as u64),
        owner_uid: CanonicalU64::new(metadata.st_uid as u64),
        mode: CanonicalU64::new(metadata.st_mode as u64 & 0o7777),
    };
    if metadata.st_uid != expected_owner_uid
        || (metadata.st_mode & 0o7777) != expected_mode
    {
        return Err(ContractError::Invalid(
            "activated listener owner or mode differs from configuration",
        ));
    }
    verify_activated_listener_v12(fd, &identity)?;
    Ok(identity)
}

fn read_exact_until(fd: RawFd, bytes: &mut [u8], deadline: u64) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        poll_fd_until(fd, libc::POLLIN, deadline)?;
        let read = unsafe {
            libc::recv(
                fd,
                bytes[offset..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - offset,
                libc::MSG_DONTWAIT,
            )
        };
        if read > 0 {
            offset += read as usize;
            continue;
        }
        if read == 0 {
            return Err(ContractError::Invalid("authority peer closed frame"));
        }
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
        {
            continue;
        }
        return Err(ContractError::InvalidOwned(format!(
            "read authority frame: {error}",
        )));
    }
    Ok(())
}

fn write_all_until(fd: RawFd, bytes: &[u8], deadline: u64) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        poll_fd_until(fd, libc::POLLOUT, deadline)?;
        let written = unsafe {
            libc::send(
                fd,
                bytes[offset..].as_ptr() as *const libc::c_void,
                bytes.len() - offset,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if written > 0 {
            offset += written as usize;
            continue;
        }
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
        {
            continue;
        }
        return Err(ContractError::InvalidOwned(format!(
            "write authority frame: {error}",
        )));
    }
    Ok(())
}

fn poll_fd_until(fd: RawFd, events: libc::c_short, deadline: u64) -> Result<()> {
    let now = boottime_now_ns()?;
    if deadline <= now {
        return Err(ContractError::Invalid(
            "authority CLOCK_BOOTTIME deadline expired",
        ));
    }
    let remaining_ms = deadline
        .saturating_sub(now)
        .saturating_add(999_999)
        / 1_000_000;
    let timeout = i32::try_from(remaining_ms.min(i32::MAX as u64))
        .map_err(|_| ContractError::Invalid("authority poll timeout overflow"))?;
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
    if result == 0 {
        return Err(ContractError::Invalid(
            "authority CLOCK_BOOTTIME deadline expired",
        ));
    }
    if result < 0
        || descriptor.revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
        || descriptor.revents & events == 0
    {
        return Err(ContractError::InvalidOwned(format!(
            "authority poll failed: {}",
            io::Error::last_os_error(),
        )));
    }
    Ok(())
}

pub fn canonical_json<T: Serialize>(value: &T, maximum_bytes: usize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    validate_json_shape(&value, 0, &mut 0usize)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    if output.len() > maximum_bytes {
        return Err(ContractError::Invalid("canonical JSON exceeds bound"));
    }
    Ok(output)
}

pub fn parse_canonical_json<T: DeserializeOwned>(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(ContractError::Invalid("canonical JSON length is outside bound"));
    }
    preflight_canonical_json(bytes)?;
    let value: Value = serde_json::from_slice(bytes)?;
    validate_json_shape(&value, 0, &mut 0usize)?;
    let mut canonical = Vec::with_capacity(bytes.len());
    write_canonical_value(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(ContractError::Invalid(
            "input is not exact bounded canonical JSON",
        ));
    }
    Ok(serde_json::from_value(value)?)
}

pub fn preflight_canonical_json(bytes: &[u8]) -> Result<()> {
    std::str::from_utf8(bytes)
        .map_err(|_| ContractError::Invalid("canonical JSON is not UTF-8"))?;
    let mut parser = CanonicalJsonPreflight {
        bytes,
        cursor: 0,
        members: 0,
    };
    parser.parse_value(0)?;
    if parser.cursor != bytes.len() {
        return Err(ContractError::Invalid(
            "canonical JSON has trailing or whitespace bytes",
        ));
    }
    Ok(())
}

struct CanonicalJsonPreflight<'a> {
    bytes: &'a [u8],
    cursor: usize,
    members: usize,
}

impl<'a> CanonicalJsonPreflight<'a> {
    fn parse_value(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_CANONICAL_DEPTH {
            return Err(ContractError::Invalid("canonical JSON nesting exceeds bound"));
        }
        self.members = self
            .members
            .checked_add(1)
            .ok_or(ContractError::Invalid("canonical JSON member count overflow"))?;
        if self.members > MAX_CANONICAL_MEMBERS {
            return Err(ContractError::Invalid("canonical JSON members exceed bound"));
        }
        match self.peek()? {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => {
                self.parse_string()?;
                Ok(())
            }
            b't' => self.consume_literal(b"true"),
            b'f' => self.consume_literal(b"false"),
            b'n' => self.consume_literal(b"null"),
            b'0'..=b'9' => self.parse_integer(),
            b'-' => Err(ContractError::Invalid(
                "negative JSON integers are forbidden; counters use D20 strings",
            )),
            _ => Err(ContractError::Invalid("invalid canonical JSON token")),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<()> {
        self.expect(b'{')?;
        let mut keys: BTreeSet<&'a [u8]> = BTreeSet::new();
        if self.take_if(b'}') {
            return Ok(());
        }
        loop {
            let key = self.parse_string()?;
            if !keys.insert(key) {
                return Err(ContractError::Invalid(
                    "duplicate canonical JSON object member",
                ));
            }
            self.expect(b':')?;
            self.parse_value(depth)?;
            if self.take_if(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<()> {
        self.expect(b'[')?;
        if self.take_if(b']') {
            return Ok(());
        }
        loop {
            self.parse_value(depth)?;
            if self.take_if(b']') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn parse_string(&mut self) -> Result<&'a [u8]> {
        self.expect(b'"')?;
        let start = self.cursor;
        while self.cursor < self.bytes.len() {
            match self.bytes[self.cursor] {
                b'"' => {
                    let end = self.cursor;
                    self.cursor += 1;
                    if end - start > MAX_CANONICAL_STRING_BYTES {
                        return Err(ContractError::Invalid(
                            "canonical JSON string exceeds bound",
                        ));
                    }
                    return Ok(&self.bytes[start..end]);
                }
                0x00..=0x1f => {
                    return Err(ContractError::Invalid(
                        "unescaped control byte in canonical JSON string",
                    ))
                }
                b'\\' => {
                    self.cursor += 1;
                    let escape = self.peek()?;
                    match escape {
                        b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.cursor += 1;
                        }
                        b'u' => {
                            self.cursor += 1;
                            let end = self.cursor.checked_add(4).ok_or(
                                ContractError::Invalid("JSON escape length overflow"),
                            )?;
                            if end > self.bytes.len()
                                || !self.bytes[self.cursor..end]
                                    .iter()
                                    .all(u8::is_ascii_hexdigit)
                            {
                                return Err(ContractError::Invalid(
                                    "invalid canonical JSON Unicode escape",
                                ));
                            }
                            self.cursor = end;
                        }
                        _ => {
                            return Err(ContractError::Invalid(
                                "noncanonical JSON string escape",
                            ))
                        }
                    }
                }
                _ => self.cursor += 1,
            }
        }
        Err(ContractError::Invalid("unterminated canonical JSON string"))
    }

    fn parse_integer(&mut self) -> Result<()> {
        let start = self.cursor;
        while self.cursor < self.bytes.len()
            && self.bytes[self.cursor].is_ascii_digit()
        {
            self.cursor += 1;
        }
        let encoded = &self.bytes[start..self.cursor];
        if encoded.len() > 1 && encoded[0] == b'0' {
            return Err(ContractError::Invalid("JSON integer has a leading zero"));
        }
        if matches!(self.bytes.get(self.cursor), Some(b'.' | b'e' | b'E')) {
            return Err(ContractError::Invalid(
                "floating-point JSON values are forbidden",
            ));
        }
        let text = std::str::from_utf8(encoded)
            .map_err(|_| ContractError::Invalid("JSON integer is not ASCII"))?;
        let value = text
            .parse::<u64>()
            .map_err(|_| ContractError::Invalid("JSON integer exceeds u64"))?;
        if value > MAX_SAFE_JSON_INTEGER {
            return Err(ContractError::Invalid(
                "unsafe JSON integer exceeds 2^53-1; use a D20 string",
            ));
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<()> {
        if self.bytes.get(self.cursor..self.cursor + literal.len()) != Some(literal) {
            return Err(ContractError::Invalid("invalid canonical JSON literal"));
        }
        self.cursor += literal.len();
        Ok(())
    }

    fn peek(&self) -> Result<u8> {
        self.bytes
            .get(self.cursor)
            .copied()
            .ok_or(ContractError::Invalid("truncated canonical JSON"))
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        if self.peek()? != expected {
            return Err(ContractError::Invalid("invalid canonical JSON delimiter"));
        }
        self.cursor += 1;
        Ok(())
    }

    fn take_if(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
}

pub fn parse_rfc3339(value: &str) -> Result<OffsetDateTime> {
    if !value.ends_with('Z') {
        return Err(ContractError::Invalid(
            "timestamp is not canonical RFC3339 UTC",
        ));
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ContractError::Invalid("invalid RFC3339 timestamp"))?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(ContractError::Invalid("timestamp is not UTC"));
    }
    Ok(parsed)
}

pub fn now_utc_rfc3339() -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let year = now.year();
    if !(0..=9999).contains(&year) {
        return Err(ContractError::Invalid(
            "authority UTC year is outside RFC3339 bounds",
        ));
    }
    let mut encoded = format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    );
    if now.nanosecond() != 0 {
        let fraction = format!("{:09}", now.nanosecond());
        encoded.push('.');
        encoded.push_str(fraction.trim_end_matches('0'));
    }
    encoded.push('Z');
    Ok(encoded)
}

pub fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric() || b"._:@/-".contains(byte)
        })
        || !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(ContractError::Invalid("identifier is not canonical"));
    }
    Ok(())
}

pub fn sha256_bytes(bytes: &[u8]) -> DigestHex {
    encode_digest(Sha256::digest(bytes).as_slice())
}

pub fn h12(tag: &str, parts: &[&[u8]]) -> DigestHex {
    hash_framed(b"serverware/controller/v12/", tag, parts)
}

pub fn h11(tag: &str, parts: &[&[u8]]) -> DigestHex {
    hash_framed(b"serverware/controller/v11/", tag, parts)
}

pub fn lf11(tag: &str, parts: &[&[u8]]) -> Vec<u8> {
    framed_bytes(b"serverware/controller/v11/", tag, parts)
}

pub fn replay_identity_digest(replay: &ReplayIdentityV12) -> Result<DigestHex> {
    if replay.replay_namespace != "serverware/controller-receipt/v12" {
        return Err(ContractError::Invalid("wrong replay namespace"));
    }
    if replay.replay_key.len() < 16
        || replay.replay_key.len() > 256
        || !replay
            .replay_key
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(byte))
    {
        return Err(ContractError::Invalid(
            "replay key length or character set is invalid",
        ));
    }
    let digest = h12(
        "replay-identity",
        &[
            replay.replay_namespace.as_bytes(),
            replay.replay_key.as_bytes(),
        ],
    );
    if digest != replay.replay_key_sha256 {
        return Err(ContractError::Invalid("replay identity digest mismatch"));
    }
    Ok(digest)
}

pub fn requester_replay_identity_digest(
    requester_principal_id: &str,
    replay_key_sha256: &DigestHex,
) -> Result<DigestHex> {
    validate_identifier(requester_principal_id)?;
    Ok(h12(
        "requester-replay-identity",
        &[
            requester_principal_id.as_bytes(),
            &replay_key_sha256.decode()?,
        ],
    ))
}

pub fn payload_digest<T: Serialize>(domain: &str, payload: &T) -> Result<DigestHex> {
    let canonical = canonical_json(payload, MAX_RECEIPT_BYTES)?;
    Ok(h12("payload", &[domain.as_bytes(), &canonical]))
}

pub fn envelope_digest<T: Serialize>(envelope: &SignedEnvelopeV12<T>) -> Result<DigestHex> {
    let signature = canonical_json(&envelope.signature, 64 * 1024)?;
    let payload_digest = envelope.payload_sha256.decode()?;
    Ok(h12(
        "typed-envelope",
        &[
            envelope.domain.as_bytes(),
            &payload_digest,
            &signature,
        ],
    ))
}

pub fn receipt_body_digest(body: &ReceiptBodyV12) -> Result<(DigestHex, CanonicalU64)> {
    let canonical = canonical_json(body, MAX_RECEIPT_BYTES)?;
    Ok((
        h12("receipt-body", &[&canonical]),
        CanonicalU64::new(canonical.len() as u64),
    ))
}

pub fn final_trust_observation_digest(
    observation: &FinalTrustObservationV12,
) -> Result<DigestHex> {
    let canonical = canonical_json(observation, 1024 * 1024)?;
    Ok(h12("final-trust-observation", &[&canonical]))
}

pub fn pre_final_log_leaf_digest(leaf: &PreFinalLogLeafV12) -> Result<DigestHex> {
    let mut projected = leaf.clone();
    projected.leaf_sha256 = DigestHex::zero();
    let canonical = canonical_json(&projected, 1024 * 1024)?;
    Ok(h12("pre-final-log-leaf", &[&canonical]))
}

pub fn log_bundle_digest(
    previous: &PreviousCheckpointV12,
    leaf: &PreFinalLogLeafV12,
    signed_tree_head_envelope_sha256: &DigestHex,
    inclusion: &InclusionProofV12,
    consistency: &ConsistencyProofV12,
    external_witness_checkpoint_envelope_sha256: &DigestHex,
) -> Result<DigestHex> {
    let previous_bytes = canonical_json(previous, 64 * 1024)?;
    let leaf_bytes = canonical_json(leaf, 64 * 1024)?;
    let inclusion_bytes = canonical_json(inclusion, 64 * 1024)?;
    let consistency_bytes = canonical_json(consistency, 64 * 1024)?;
    Ok(h12(
        "log-bundle",
        &[
            &previous_bytes,
            &leaf_bytes,
            &signed_tree_head_envelope_sha256.decode()?,
            &inclusion_bytes,
            &consistency_bytes,
            &external_witness_checkpoint_envelope_sha256.decode()?,
        ],
    ))
}

pub fn prepared_binding_digest(
    receipt_id: &str,
    requester_principal_id: &str,
    replay: &ReplayIdentityV12,
    request: &RequestV11Summary,
    request_admission_sha256: &DigestHex,
    body: &ReceiptBodyV12,
) -> Result<DigestHex> {
    let body_bytes = canonical_json(body, MAX_RECEIPT_BYTES)?;
    Ok(h12(
        "ledger-prepared-binding",
        &[
            receipt_id.as_bytes(),
            requester_principal_id.as_bytes(),
            &replay.replay_key_sha256.decode()?,
            &request.request_v11_sha256.decode()?,
            &request.request_envelope_sha256.decode()?,
            request.request_canonical_bytes.as_str().as_bytes(),
            &request_admission_sha256.decode()?,
            &body_bytes,
        ],
    ))
}

pub fn receipt_authority_submission_digest(
    receipt_id: &str,
    requester_principal_id: &str,
    replay: &ReplayIdentityV12,
    request: &RequestV11Summary,
    request_admission_sha256: &DigestHex,
    body_template: &ReceiptBodyV12,
) -> Result<DigestHex> {
    let body_bytes = canonical_json(body_template, MAX_RECEIPT_BYTES)?;
    Ok(h12(
        "receipt-authority-submission",
        &[
            receipt_id.as_bytes(),
            requester_principal_id.as_bytes(),
            &replay.replay_key_sha256.decode()?,
            &request.request_v11_sha256.decode()?,
            &request.request_envelope_sha256.decode()?,
            request.request_canonical_bytes.as_str().as_bytes(),
            &request_admission_sha256.decode()?,
            &body_bytes,
        ],
    ))
}

pub fn finalization_binding_digest(
    logged_bundle_sha256: &DigestHex,
    witness_envelope_sha256: &DigestHex,
    trust_observation_sha256: &DigestHex,
    verdict: VerdictV12,
) -> Result<DigestHex> {
    let verdict = serde_json::to_string(&verdict)?;
    Ok(h12(
        "ledger-finalization-binding",
        &[
            &logged_bundle_sha256.decode()?,
            &witness_envelope_sha256.decode()?,
            &trust_observation_sha256.decode()?,
            verdict.as_bytes(),
        ],
    ))
}

pub fn request_admission_digest(
    admission: &CanonicalRequestAdmissionV12,
) -> Result<DigestHex> {
    let canonical = canonical_json(admission, MAX_AUTHORITY_REQUEST_BYTES)?;
    Ok(h12("canonical-request-admission-v11", &[&canonical]))
}

pub fn trust_generation_bundle_digest(
    trust: &TrustGenerationBundleV12,
) -> Result<DigestHex> {
    let canonical = canonical_json(trust, 4 * 1024 * 1024)?;
    Ok(h12("trust-generation-bundle", &[&canonical]))
}

pub fn final_settlement_artifact_digest(
    artifact: &FinalSettlementArtifactV12,
) -> Result<DigestHex> {
    let canonical = canonical_json(artifact, MAX_RECEIPT_BYTES)?;
    Ok(h12("final-settlement-artifact", &[&canonical]))
}

pub fn logged_receipt_bundle_digest(
    bundle: &LoggedReceiptBundleV12,
) -> Result<DigestHex> {
    let canonical = canonical_json(bundle, MAX_RECEIPT_BYTES)?;
    Ok(h12("logged-receipt-bundle", &[&canonical]))
}

pub fn sign_envelope<T>(
    domain: &str,
    role: AuthorityRoleV12,
    payload: T,
    authorization: KeyAuthorizationV12,
    signing_key: &SigningKey,
    signed_at: &str,
    accepted_at: &str,
) -> Result<SignedEnvelopeV12<T>>
where
    T: Serialize,
{
    validate_authorization_shape(&authorization, role)?;
    let payload_sha256 = payload_digest(domain, &payload)?;
    let verifying_key = signing_key.verifying_key();
    let spki_der_sha256 = ed25519_spki_sha256(&verifying_key);
    if spki_der_sha256 != authorization.spki_der_sha256 {
        return Err(ContractError::Invalid(
            "signing key does not match authorized SPKI",
        ));
    }
    let mut signature = SignatureV12 {
        domain: domain.to_owned(),
        payload_sha256: payload_sha256.clone(),
        signed_at: signed_at.to_owned(),
        accepted_at: accepted_at.to_owned(),
        signer_role: role,
        signer_principal_id: authorization.principal_id.clone(),
        signer_key_id: authorization.key_id.clone(),
        signer_spki_der_sha256: spki_der_sha256,
        key_authorization: authorization,
        signature_base64url: String::new(),
    };
    let message = signature_message_digest(&signature)?;
    signature.signature_base64url =
        URL_SAFE_NO_PAD.encode(signing_key.sign(&message.decode()?).to_bytes());
    Ok(SignedEnvelopeV12 {
        domain: domain.to_owned(),
        payload,
        payload_sha256,
        signature,
    })
}

pub fn verify_envelope_cryptography<T>(
    envelope: &SignedEnvelopeV12<T>,
    expected_domain: &str,
    expected_role: AuthorityRoleV12,
    verifying_key: &VerifyingKey,
) -> Result<DigestHex>
where
    T: Serialize,
{
    if envelope.domain != expected_domain
        || envelope.signature.domain != expected_domain
        || envelope.signature.signer_role != expected_role
        || envelope.payload_sha256 != envelope.signature.payload_sha256
    {
        return Err(ContractError::Invalid("signed envelope domain or role mismatch"));
    }
    validate_authorization_shape(&envelope.signature.key_authorization, expected_role)?;
    let computed_payload = payload_digest(expected_domain, &envelope.payload)?;
    if computed_payload != envelope.payload_sha256 {
        return Err(ContractError::Invalid("signed payload digest mismatch"));
    }
    if ed25519_spki_sha256(verifying_key) != envelope.signature.signer_spki_der_sha256 {
        return Err(ContractError::Invalid("verifier SPKI digest mismatch"));
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.signature.signature_base64url)
        .map_err(|_| ContractError::Invalid("signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)?;
    let message = signature_message_digest(&envelope.signature)?;
    verifying_key.verify(&message.decode()?, &signature)?;
    envelope_digest(envelope)
}

pub fn signature_message_digest(signature: &SignatureV12) -> Result<DigestHex> {
    Ok(h12(
        "signature-message",
        &[
            signature.domain.as_bytes(),
            &signature.payload_sha256.decode()?,
            signature.signed_at.as_bytes(),
            signature.accepted_at.as_bytes(),
            signature.signer_role.as_str().as_bytes(),
            signature.signer_principal_id.as_bytes(),
            signature.signer_key_id.as_bytes(),
            &signature.signer_spki_der_sha256.decode()?,
            &signature
                .key_authorization
                .key_authorization_sha256
                .decode()?,
        ],
    ))
}

pub fn ed25519_spki_sha256(key: &VerifyingKey) -> DigestHex {
    let mut spki = [0u8; 44];
    spki[..12].copy_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
        0x00,
    ]);
    spki[12..].copy_from_slice(key.as_bytes());
    sha256_bytes(&spki)
}

pub fn extract_request_v11_summary(request: &Value) -> Result<RequestV11Summary> {
    let object = request
        .as_object()
        .ok_or(ContractError::Invalid("request v11 root is not an object"))?;
    if object.get("contractVersion").and_then(Value::as_u64) != Some(11) {
        return Err(ContractError::Invalid("request contract version is not v11"));
    }
    let request_envelope_sha256 = DigestHex::parse(
        object
            .get("requestEnvelopeSha256")
            .and_then(Value::as_str)
            .ok_or(ContractError::Invalid("request envelope digest is missing"))?,
    )?;
    let request_canonical_bytes = CanonicalU64::parse(
        object
            .get("requestCanonicalBytes")
            .and_then(Value::as_str)
            .ok_or(ContractError::Invalid("request canonical length is missing"))?,
    )?;
    let canonical = canonical_json(request, MAX_AUTHORITY_REQUEST_BYTES)?;
    if canonical.len() as u64 != request_canonical_bytes.get()? {
        return Err(ContractError::Invalid("request v11 canonical length mismatch"));
    }
    let envelope = object
        .get("requestEnvelope")
        .and_then(Value::as_object)
        .ok_or(ContractError::Invalid("request v11 envelope is missing"))?;
    let domain = envelope
        .get("domain")
        .and_then(Value::as_str)
        .ok_or(ContractError::Invalid("request v11 domain is missing"))?
        .to_owned();
    let payload = envelope
        .get("payload")
        .ok_or(ContractError::Invalid("request v11 payload is missing"))?;
    let payload_sha256 = DigestHex::parse(
        envelope
            .get("payloadSha256")
            .and_then(Value::as_str)
            .ok_or(ContractError::Invalid("request payload digest is missing"))?,
    )?;
    let signature = envelope
        .get("signature")
        .ok_or(ContractError::Invalid("request v11 signature is missing"))?;
    let payload_bytes = canonical_json(payload, MAX_AUTHORITY_REQUEST_BYTES)?;
    let computed_payload = h11("payload", &[domain.as_bytes(), &payload_bytes]);
    if computed_payload != payload_sha256 {
        return Err(ContractError::Invalid("request v11 payload digest mismatch"));
    }
    let signature_bytes = canonical_json(signature, 1024 * 1024)?;
    let computed_envelope = h11(
        "typed-envelope",
        &[
            domain.as_bytes(),
            &payload_sha256.decode()?,
            &signature_bytes,
        ],
    );
    if computed_envelope != request_envelope_sha256 {
        return Err(ContractError::Invalid("request v11 envelope digest mismatch"));
    }
    let frame = object
        .get("preAllocationFrame")
        .and_then(Value::as_object)
        .ok_or(ContractError::Invalid("request v11 preallocation frame is missing"))?;
    if frame
        .get("requestEnvelopeSha256")
        .and_then(Value::as_str)
        != Some(request_envelope_sha256.as_str())
        || frame
            .get("declaredCanonicalRequestBytes")
            .and_then(Value::as_str)
            != Some(request_canonical_bytes.as_str())
    {
        return Err(ContractError::Invalid(
            "request v11 frame does not join the request root",
        ));
    }
    Ok(RequestV11Summary {
        request_v11_sha256: h12("canonical-request-v11", &[&canonical]),
        request_envelope_sha256,
        request_canonical_bytes,
        request_domain: domain,
        request_payload_sha256: payload_sha256,
    })
}

pub fn make_log_leaf(
    log_id: String,
    leaf_ordinal: u64,
    body: &ReceiptBodyV12,
    receipt_body_sha256: DigestHex,
    receipt_authentication_envelope_sha256: DigestHex,
) -> Result<PreFinalLogLeafV12> {
    let mut leaf = PreFinalLogLeafV12 {
        log_id,
        leaf_ordinal: CanonicalU64::new(leaf_ordinal),
        receipt_id: body.receipt_id.clone(),
        receipt_sequence: body.receipt_sequence.clone(),
        requester_principal_id: body.requester_principal_id.clone(),
        replay_key_sha256: body.replay_key_sha256.clone(),
        request_v11_sha256: body.request_v11_sha256.clone(),
        request_envelope_sha256: body.request_envelope_sha256.clone(),
        receipt_body_sha256,
        receipt_authentication_envelope_sha256,
        terminal_evidence_root_sha256: body.terminal_evidence_root_sha256.clone(),
        terminal_state_root_sha256: body.terminal_state_root_sha256.clone(),
        leaf_sha256: DigestHex::zero(),
    };
    leaf.leaf_sha256 = pre_final_log_leaf_digest(&leaf)?;
    Ok(leaf)
}

pub fn merkle_root(leaves: &[DigestHex]) -> Result<DigestHex> {
    if leaves.is_empty() {
        return Ok(h12(
            "merkle-empty",
            &[RECEIPT_LOG_TREE_DOMAIN.as_bytes()],
        ));
    }
    merkle_subtree_root(leaves)
}

pub fn build_inclusion_proof(
    leaves: &[DigestHex],
    leaf_ordinal: usize,
) -> Result<InclusionProofV12> {
    if leaves.is_empty() || leaf_ordinal >= leaves.len() {
        return Err(ContractError::Invalid("inclusion ordinal is outside tree"));
    }
    let mut path = Vec::new();
    build_inclusion_path(leaves, leaf_ordinal, &mut path)?;
    if path.len() > MAX_MERKLE_PROOF_NODES {
        return Err(ContractError::Invalid("inclusion proof exceeds bound"));
    }
    Ok(InclusionProofV12 {
        tree_domain: RECEIPT_LOG_TREE_DOMAIN.to_owned(),
        leaf_ordinal: CanonicalU64::new(leaf_ordinal as u64),
        tree_size: CanonicalU64::new(leaves.len() as u64),
        leaf_sha256: leaves[leaf_ordinal].clone(),
        root_sha256: merkle_root(leaves)?,
        path,
    })
}

pub fn verify_inclusion_proof(proof: &InclusionProofV12) -> Result<()> {
    if proof.tree_domain != RECEIPT_LOG_TREE_DOMAIN {
        return Err(ContractError::Invalid("wrong inclusion tree domain"));
    }
    let ordinal = proof.leaf_ordinal.get()?;
    let tree_size = proof.tree_size.get()?;
    if tree_size == 0 || ordinal >= tree_size || proof.path.len() > 64 {
        return Err(ContractError::Invalid("invalid inclusion proof shape"));
    }
    let mut expected_directions = Vec::new();
    collect_inclusion_directions(
        tree_size as usize,
        ordinal as usize,
        &mut expected_directions,
    );
    if proof.path.len() != expected_directions.len()
        || proof
            .path
            .iter()
            .zip(expected_directions.iter())
            .any(|(node, expected)| node.direction != *expected)
    {
        return Err(ContractError::Invalid(
            "inclusion path does not match ordinal and tree shape",
        ));
    }
    let mut current = merkle_leaf_node(&proof.leaf_sha256)?;
    for node in &proof.path {
        current = match node.direction {
            ProofDirectionV12::Left => merkle_internal_node(&node.sha256, &current)?,
            ProofDirectionV12::Right => merkle_internal_node(&current, &node.sha256)?,
        };
    }
    if current != proof.root_sha256 {
        return Err(ContractError::Invalid("inclusion proof root mismatch"));
    }
    Ok(())
}

pub fn build_consistency_proof(
    leaves: &[DigestHex],
    from_tree_size: usize,
) -> Result<ConsistencyProofV12> {
    if from_tree_size > leaves.len() || leaves.is_empty() {
        return Err(ContractError::Invalid("invalid consistency tree sizes"));
    }
    let from_root = merkle_root(&leaves[..from_tree_size])?;
    let to_root = merkle_root(leaves)?;
    let mut nodes = Vec::new();
    if from_tree_size != 0 && from_tree_size != leaves.len() {
        build_consistency_nodes(from_tree_size, leaves, true, &mut nodes)?;
    }
    if nodes.len() > MAX_MERKLE_PROOF_NODES {
        return Err(ContractError::Invalid("consistency proof exceeds bound"));
    }
    Ok(ConsistencyProofV12 {
        tree_domain: RECEIPT_LOG_TREE_DOMAIN.to_owned(),
        from_tree_size: CanonicalU64::new(from_tree_size as u64),
        from_root_sha256: from_root,
        to_tree_size: CanonicalU64::new(leaves.len() as u64),
        to_root_sha256: to_root,
        nodes,
    })
}

pub fn verify_consistency_proof(proof: &ConsistencyProofV12) -> Result<()> {
    if proof.tree_domain != RECEIPT_LOG_TREE_DOMAIN {
        return Err(ContractError::Invalid("wrong consistency tree domain"));
    }
    let old_size = proof.from_tree_size.get()?;
    let new_size = proof.to_tree_size.get()?;
    if old_size > new_size || new_size == 0 || proof.nodes.len() > 64 {
        return Err(ContractError::Invalid("invalid consistency proof shape"));
    }
    if old_size == 0 {
        if !proof.nodes.is_empty()
            || proof.from_root_sha256
                != h12("merkle-empty", &[RECEIPT_LOG_TREE_DOMAIN.as_bytes()])
        {
            return Err(ContractError::Invalid("invalid genesis consistency proof"));
        }
        return Ok(());
    }
    if old_size == new_size {
        if !proof.nodes.is_empty()
            || proof.from_root_sha256 != proof.to_root_sha256
        {
            return Err(ContractError::Invalid("invalid equal-size consistency proof"));
        }
        return Ok(());
    }

    let mut old_index = old_size - 1;
    let mut new_index = new_size - 1;
    while old_index & 1 == 1 {
        old_index >>= 1;
        new_index >>= 1;
    }

    let mut proof_index = 0usize;
    let (mut old_root, mut new_root) = if old_index == 0 {
        (
            proof.from_root_sha256.clone(),
            proof.from_root_sha256.clone(),
        )
    } else {
        let first = proof
            .nodes
            .first()
            .ok_or(ContractError::Invalid("consistency proof is truncated"))?
            .clone();
        proof_index = 1;
        (first.clone(), first)
    };

    while proof_index < proof.nodes.len() {
        if new_index == 0 {
            return Err(ContractError::Invalid("consistency proof has excess nodes"));
        }
        let node = &proof.nodes[proof_index];
        if old_index & 1 == 1 || old_index == new_index {
            old_root = merkle_internal_node(node, &old_root)?;
            new_root = merkle_internal_node(node, &new_root)?;
            while old_index != 0 && old_index & 1 == 0 {
                old_index >>= 1;
                new_index >>= 1;
            }
        } else {
            new_root = merkle_internal_node(&new_root, node)?;
        }
        old_index >>= 1;
        new_index >>= 1;
        proof_index += 1;
    }

    if old_root != proof.from_root_sha256
        || new_root != proof.to_root_sha256
        || new_index != 0
    {
        return Err(ContractError::Invalid("consistency proof root mismatch"));
    }
    Ok(())
}

pub fn seal_receipt(mut receipt: ReceiptV12) -> Result<(ReceiptV12, Vec<u8>)> {
    receipt.receipt_envelope_sha256 = DigestHex::zero();
    receipt.receipt_canonical_bytes = CanonicalU64::new(0);
    let projected = canonical_json(&receipt, MAX_RECEIPT_BYTES)?;
    receipt.receipt_canonical_bytes = CanonicalU64::new(projected.len() as u64);
    receipt.receipt_envelope_sha256 = receipt_envelope_digest(&receipt)?;
    let exact = canonical_json(&receipt, MAX_RECEIPT_BYTES)?;
    if exact.len() as u64 != receipt.receipt_canonical_bytes.get()? {
        return Err(ContractError::Invalid(
            "fixed-width receipt length projection changed",
        ));
    }
    Ok((receipt, exact))
}

pub fn receipt_envelope_digest(receipt: &ReceiptV12) -> Result<DigestHex> {
    Ok(h12(
        "receipt-envelope",
        &[
            b"12",
            b"11",
            receipt.receipt_id.as_bytes(),
            receipt.receipt_sequence.as_str().as_bytes(),
            receipt.requester_principal_id.as_bytes(),
            &receipt.replay_identity.replay_key_sha256.decode()?,
            &receipt.request_v11_sha256.decode()?,
            &receipt.request_envelope_sha256.decode()?,
            receipt.request_canonical_bytes.as_str().as_bytes(),
            &receipt.request_admission_sha256.decode()?,
            &receipt.receipt_body_sha256.decode()?,
            receipt.receipt_body_canonical_bytes.as_str().as_bytes(),
            &receipt
                .receipt_authentication_envelope_sha256
                .decode()?,
            &receipt.signed_tree_head_envelope_sha256.decode()?,
            &receipt
                .external_witness_checkpoint_envelope_sha256
                .decode()?,
            &receipt.log_bundle_sha256.decode()?,
            &receipt
                .final_trust_observation
                .trust_generation_envelope_sha256
                .decode()?,
            &receipt.final_trust_observation_sha256.decode()?,
            &receipt.final_verdict_envelope_sha256.decode()?,
        ],
    ))
}

fn validate_authorization_shape(
    authorization: &KeyAuthorizationV12,
    expected_role: AuthorityRoleV12,
) -> Result<()> {
    if authorization.role != expected_role
        || authorization.algorithm != "Ed25519"
        || authorization.status != "ACTIVE"
        || authorization.authorization_revision.get()? == 0
        || authorization.high_water.get()? == 0
    {
        return Err(ContractError::Invalid("invalid key authorization shape"));
    }
    validate_identifier(&authorization.principal_id)?;
    validate_identifier(&authorization.key_id)?;
    let valid_from = parse_rfc3339(&authorization.valid_from)?;
    let valid_until = parse_rfc3339(&authorization.valid_until)?;
    if valid_from >= valid_until {
        return Err(ContractError::Invalid("invalid key validity interval"));
    }
    Ok(())
}

fn validate_json_shape(value: &Value, depth: usize, members: &mut usize) -> Result<()> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(ContractError::Invalid("canonical JSON nesting exceeds bound"));
    }
    *members = members
        .checked_add(1)
        .ok_or(ContractError::Invalid("canonical JSON member count overflow"))?;
    if *members > MAX_CANONICAL_MEMBERS {
        return Err(ContractError::Invalid("canonical JSON members exceed bound"));
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            let Some(integer) = number.as_u64() else {
                return Err(ContractError::Invalid(
                    "negative or floating-point JSON values are forbidden",
                ));
            };
            if integer > MAX_SAFE_JSON_INTEGER {
                return Err(ContractError::Invalid(
                    "unsafe JSON integer exceeds 2^53-1; use a D20 string",
                ));
            }
            Ok(())
        }
        Value::String(value) => {
            if value.len() > MAX_CANONICAL_STRING_BYTES {
                return Err(ContractError::Invalid("canonical JSON string exceeds bound"));
            }
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                validate_json_shape(value, depth + 1, members)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > MAX_CANONICAL_STRING_BYTES {
                    return Err(ContractError::Invalid("canonical JSON key exceeds bound"));
                }
                validate_json_shape(value, depth + 1, members)?;
            }
            Ok(())
        }
    }
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| {
                left.0.encode_utf16().cmp(right.0.encode_utf16())
            });
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn hash_framed(prefix: &[u8], tag: &str, parts: &[&[u8]]) -> DigestHex {
    encode_digest(Sha256::digest(framed_bytes(prefix, tag, parts)).as_slice())
}

fn framed_bytes(prefix: &[u8], tag: &str, parts: &[&[u8]]) -> Vec<u8> {
    let capacity = prefix.len()
        + 8
        + tag.len()
        + parts
            .iter()
            .map(|part| 8usize.saturating_add(part.len()))
            .sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(prefix);
    output.extend_from_slice(&(tag.len() as u64).to_be_bytes());
    output.extend_from_slice(tag.as_bytes());
    for part in parts {
        output.extend_from_slice(&(part.len() as u64).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

fn encode_digest(bytes: &[u8]) -> DigestHex {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    DigestHex(encoded)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ContractError::Invalid("digest contains a non-hex byte")),
    }
}

fn merkle_leaf_node(leaf: &DigestHex) -> Result<DigestHex> {
    Ok(h12(
        "merkle-leaf",
        &[RECEIPT_LOG_TREE_DOMAIN.as_bytes(), &leaf.decode()?],
    ))
}

fn merkle_internal_node(left: &DigestHex, right: &DigestHex) -> Result<DigestHex> {
    Ok(h12(
        "merkle-node",
        &[
            RECEIPT_LOG_TREE_DOMAIN.as_bytes(),
            &left.decode()?,
            &right.decode()?,
        ],
    ))
}

fn merkle_subtree_root(leaves: &[DigestHex]) -> Result<DigestHex> {
    if leaves.len() == 1 {
        return merkle_leaf_node(&leaves[0]);
    }
    let split = largest_power_of_two_less_than(leaves.len());
    let left = merkle_subtree_root(&leaves[..split])?;
    let right = merkle_subtree_root(&leaves[split..])?;
    merkle_internal_node(&left, &right)
}

fn build_inclusion_path(
    leaves: &[DigestHex],
    ordinal: usize,
    path: &mut Vec<MerkleProofNodeV12>,
) -> Result<()> {
    if leaves.len() == 1 {
        return Ok(());
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if ordinal < split {
        build_inclusion_path(&leaves[..split], ordinal, path)?;
        path.push(MerkleProofNodeV12 {
            direction: ProofDirectionV12::Right,
            sha256: merkle_subtree_root(&leaves[split..])?,
        });
    } else {
        build_inclusion_path(&leaves[split..], ordinal - split, path)?;
        path.push(MerkleProofNodeV12 {
            direction: ProofDirectionV12::Left,
            sha256: merkle_subtree_root(&leaves[..split])?,
        });
    }
    Ok(())
}

fn build_consistency_nodes(
    old_size: usize,
    leaves: &[DigestHex],
    complete_subtree: bool,
    proof: &mut Vec<DigestHex>,
) -> Result<()> {
    if old_size == leaves.len() {
        if !complete_subtree {
            proof.push(merkle_subtree_root(leaves)?);
        }
        return Ok(());
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if old_size <= split {
        build_consistency_nodes(old_size, &leaves[..split], complete_subtree, proof)?;
        proof.push(merkle_subtree_root(&leaves[split..])?);
    } else {
        build_consistency_nodes(old_size - split, &leaves[split..], false, proof)?;
        proof.push(merkle_subtree_root(&leaves[..split])?);
    }
    Ok(())
}

fn collect_inclusion_directions(
    tree_size: usize,
    ordinal: usize,
    directions: &mut Vec<ProofDirectionV12>,
) {
    if tree_size == 1 {
        return;
    }
    let split = largest_power_of_two_less_than(tree_size);
    if ordinal < split {
        collect_inclusion_directions(split, ordinal, directions);
        directions.push(ProofDirectionV12::Right);
    } else {
        collect_inclusion_directions(tree_size - split, ordinal - split, directions);
        directions.push(ProofDirectionV12::Left);
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    let shift = usize::BITS - 1 - (value - 1).leading_zeros();
    1usize << shift
}
