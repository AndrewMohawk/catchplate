//! Fail-closed policy-shadow evidence and readiness verification.
//!
//! Wire values are deliberately untrusted. `SignedEnvelope<T>` can be decoded,
//! but only `verify_envelope` can construct `VerifiedSignedEnvelope<T>`. The
//! verification boundary recomputes canonical payload bytes, verifies Ed25519,
//! checks a pinned signer, and uses a trusted clock. Candidate plans are a
//! separate Rust type and this module exposes no candidate execution capability
//! Verification alone has no activation side effect; publication is available
//! only through the crate-private atomic custody transaction.
//!
//! Canonical JSON profile:
//! `serverware.canonicalJson/ascii-integer-v1`. Values MUST contain only JSON
//! null, booleans, signed 64-bit integers, ASCII strings, arrays, and objects
//! with ASCII keys. Object keys are ordered by their raw ASCII bytes. Strings
//! use JSON escapes for quote, backslash, and U+0000..U+001f, with the shortest
//! lowercase escape form. Whitespace is forbidden. Floats are forbidden. This
//! implementation walks `serde_json::Value` and emits those bytes itself;
//! `serde_json::to_vec` is never considered canonicalization.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use ring::hmac;
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "policy_shadow_opening.rs"]
pub(crate) mod native_opening;
#[path = "policy_shadow_heartbeat.rs"]
pub(crate) mod native_heartbeat;
#[path="policy_shadow_runtime.rs"]
pub(crate) mod native_runtime;
#[path="policy_shadow_checkpoint.rs"]
pub(crate) mod native_checkpoint;
#[path="policy_shadow_cumulative.rs"]
pub(crate) mod native_cumulative;
#[path = "policy_shadow_final_cumulative.rs"]
pub(crate) mod native_final_cumulative;
#[cfg(target_os="linux")]
#[path="policy_custody/native_activation/mod.rs"]
pub(crate) mod native_activation;

#[cfg(target_os = "linux")]
#[path = "policy_custody/mod.rs"]
mod policy_custody;

#[cfg(target_os = "linux")]
#[path = "policy_custody/native_closure.rs"]
pub(in crate::policy_shadow) mod native_custody_closure;

#[cfg(target_os = "linux")]
pub(crate) fn run_native_shadow_guest()->! {
    policy_custody::services::guest::native_guest::run()
}
#[cfg(target_os="linux")]
pub(crate) fn run_native_shadow_guest_supervisor()->! {
    policy_custody::services::guest::native_guest::run_parent()
}
#[cfg(target_os="linux")]
pub(crate) fn run_native_shadow_retrieval_pair()->! {
    policy_custody::services::guest::native_guest::run_retrieval_pair()
}
#[cfg(target_os="linux")]
pub(crate) fn run_native_shadow_proof_cohort()->! {
    policy_custody::services::guest::native_guest::run_proof_cohort()
}

#[cfg(target_os = "linux")]
pub(crate) use policy_custody::{
    PreparedGuestServiceDelivery,
    install_policy_shadow_custody_generation_from_retained_file,
    run_bounded_cleanup_helper_from_env,
    run_cleanup_authorization_consumer_from_env,
    run_current_signature_authority_from_env,
    run_durable_recovery_store_from_env,
    run_production_rpc_service_from_env,
    run_policy_shadow_custody_server_from_env,
    run_recovery_target_provider_from_env,
    InlineReceiptReference, InlineSha256Digest,
    ModeledReservationKind, ModeledReservationToken,
    PolicyCoreModeledReceiptArena,
    PolicyShadowCustodyProcessClient, ReceiptArenaError,
    ReceiptReferenceKind, ReceiptSlotHandle,
    MODELED_RECEIPT_REFERENCE_BUDGET_BYTES,
    MODELED_RECEIPT_REFERENCE_BUDGET_LABEL,
    POLICY_CORE_MODELED_RECEIPT_RESERVATION_SLOTS,
};

pub(crate) const POLICY_SHADOW_SCHEMA_VERSION: u32 = 1;
pub(crate) const CANONICAL_PROFILE: &str = "serverware.canonicalJson/ascii-integer-v1";
pub(crate) const SIGNATURE_ALGORITHM: &str = "Ed25519";
pub(crate) const SIGNED_ENVELOPE_DOMAIN: &[u8] = b"serverware.signedEnvelope/v1";
pub(crate) const REQUEST_COMMITMENT_DOMAIN_TEXT: &str =
    "serverware.policyShadowRequestCommitment/v1";
pub(crate) const REQUEST_COMMITMENT_DOMAIN: &[u8] = REQUEST_COMMITMENT_DOMAIN_TEXT.as_bytes();
pub(crate) const MERKLE_LEAF_DOMAIN: &[u8] = b"serverware.policyShadowMerkleLeaf/v1";
pub(crate) const MERKLE_NODE_DOMAIN: &[u8] = b"serverware.policyShadowMerkleNode/v1";
pub(crate) const MERKLE_EMPTY_DOMAIN: &[u8] = b"serverware.policyShadowMerkleEmpty/v1";
pub(crate) const READINESS_CORE_DOMAIN: &[u8] = b"serverware.policyReadinessCore/v2";
pub(crate) const ASSIGNMENT_DOMAIN: &str = "serverware.policyShadowAssignment/v1";
pub(crate) const LOAD_RECEIPT_DOMAIN: &str = "serverware.policyShadowLoadReceipt/v1";
pub(crate) const INGRESS_EVIDENCE_DOMAIN: &str =
    "serverware.policyShadowIngressEvidence/v1";
pub(crate) const ACTIVE_DECISION_DOMAIN: &str =
    "serverware.policyShadowActiveDecision/v1";
pub(crate) const OBSERVATION_DOMAIN: &str = "serverware.policyShadowObservation/v1";
pub(crate) const CHECKPOINT_DOMAIN: &str = "serverware.policyShadowCheckpoint/v1";
pub(crate) const HEARTBEAT_DOMAIN: &str = "serverware.policyShadowHeartbeat/v1";
pub(crate) const WINDOW_CLOSURE_DOMAIN: &str =
    "serverware.policyShadowWindowClosure/v1";
pub(crate) const ACTIVATION_APPROVAL_DOMAIN: &str =
    "serverware.policyActivationApproval/v2";
pub(crate) const POLICY_AUTHORITY_ANALYSIS_DOMAIN: &str =
    "serverware.policyAuthorityAnalysis/v1";
pub(crate) const READINESS_DOMAIN: &str = "serverware.policyActivationReadiness/v2";

const MAX_SIGNED_INTEGER: u64 = i64::MAX as u64;
const MAX_ENVELOPE_AGE_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_ACTIVATION_CHECKPOINT_AGE_NANOS: i64 = 5 * 60 * 1_000_000_000;
const MAX_COLLECTION_ITEMS: usize = 4096;
const MAX_CUMULATIVE_OBSERVATIONS: usize = 65_536;
const MAX_CUMULATIVE_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VERIFICATION_WORK_UNITS: u64 = 1_000_000;
const MAX_EXPANSION_CELLS: usize = 128;
const MAX_RESPONSE_OBLIGATIONS: usize = 512;
const MAX_PLAN_ITEMS: usize = 128;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_EXPRESSION_BYTES: usize = 512;
const MAX_PROTECTED_FACTS_BYTES: usize = 1_048_576;

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShadowError {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    CanonicalizationFailure(&'static str),
    PayloadDigestMismatch,
    EnvelopeDomainMismatch,
    EnvelopeMetadataMismatch,
    SignerBindingMismatch,
    SignatureEncodingInvalid,
    SignatureInvalid,
    TrustResolutionFailed,
    TrustedTimeUnavailable,
    EvidenceNotYetValid,
    EvidenceExpired,
    EvidenceTooOld,
    BindingDrift,
    CandidateSequenceNotAdvanced,
    CandidateCapabilityExposure,
    PurposeMismatch,
    ObservationShapeMismatch,
    IngressEvidenceMismatch,
    RequestCommitmentMismatch,
    NonContiguousObservationSequence,
    NonContiguousIngressSequence,
    PreviousObservationHashMismatch,
    PreviousCheckpointHashMismatch,
    CumulativeCheckpointRegression,
    CounterOverflow,
    CounterMismatch,
    MerkleRootMismatch,
    SealInvalid,
    SealDeadlineExceeded,
    FleetCoverageIncomplete,
    ReadinessUnsafe,
    ApprovalMissing,
    ApprovalUnexpected,
    ApprovalBindingMismatch,
    ApprovalExpired,
    ApproverNotHardwareBacked,
    ApproverUserPresenceMissing,
    ApproverUserVerificationMissing,
    ApproverPrincipalReused,
    ApproverCredentialReused,
    ExpansionCellMismatch,
    ExpansionLimitExceeded,
    ActiveDecisionEvidenceMismatch,
    PolicyAuthorityAnalysisMismatch,
    ResponseCoverageIncomplete,
    EvidenceBudgetExceeded,
    ActivationConsumptionBindingMismatch,
    TrustCheckpointMismatch,
    RuntimeAttestationRevoked,
    CustodyUnavailable,
    GenerationIdentityMismatch,
    GenerationTombstoned,
    CheckpointForkDetected,
    ActiveEnforcementEvidenceMismatch,
    ResponseEvidenceMismatch,
}

impl fmt::Display for ShadowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::CanonicalizationFailure(reason) => {
                write!(formatter, "canonicalization failed: {reason}")
            }
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl std::error::Error for ShadowError {}

fn invalid(field: &'static str, reason: &'static str) -> ShadowError {
    ShadowError::InvalidField { field, reason }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShadowError> {
        let value = value.into();
        let Some(hexadecimal) = value.strip_prefix("sha256:") else {
            return Err(invalid("sha256", "canonical sha256: prefix required"));
        };
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("sha256", "64 lowercase hexadecimal digits required"));
        }
        Ok(Self(value))
    }

    pub fn compute(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    fn raw_bytes(&self) -> Result<[u8; 32], ShadowError> {
        let decoded = hex::decode(&self.0[7..])
            .map_err(|_| invalid("sha256", "invalid hexadecimal digest"))?;
        decoded
            .try_into()
            .map_err(|_| invalid("sha256", "invalid digest length"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct HmacSha256Digest(String);

impl HmacSha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShadowError> {
        let value = value.into();
        let Some(hexadecimal) = value.strip_prefix("hmac-sha256:") else {
            return Err(invalid(
                "hmac_sha256",
                "canonical hmac-sha256: prefix required",
            ));
        };
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                "hmac_sha256",
                "64 lowercase hexadecimal digits required",
            ));
        }
        Ok(Self(value))
    }

    fn raw_bytes(&self) -> Result<[u8; 32], ShadowError> {
        let decoded = hex::decode(&self.0[12..])
            .map_err(|_| ShadowError::RequestCommitmentMismatch)?;
        decoded
            .try_into()
            .map_err(|_| ShadowError::RequestCommitmentMismatch)
    }
}

impl<'de> Deserialize<'de> for HmacSha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct Identifier(String);

impl Identifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShadowError> {
        let value = value.into();
        let mut bytes = value.bytes();
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !bytes.next().is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !bytes.all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'@' | b'+' | b'-')
            })
        {
            return Err(invalid("identifier", "non-canonical identifier"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct CanonicalAscii(String);

impl CanonicalAscii {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShadowError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 2048
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(invalid(
                "ascii_string",
                "must be 1..=2048 printable ASCII bytes",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CanonicalAscii {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct SpiffeId(String);

impl SpiffeId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ShadowError> {
        let value = value.into();
        if value.len() > 2048 || !value.is_ascii() {
            return Err(invalid("spiffe_id", "must be bounded ASCII"));
        }
        let rest = value
            .strip_prefix("spiffe://")
            .ok_or_else(|| invalid("spiffe_id", "lowercase spiffe scheme required"))?;
        let (trust_domain, path) = rest
            .split_once('/')
            .ok_or_else(|| invalid("spiffe_id", "at least one path segment required"))?;
        if trust_domain.is_empty()
            || trust_domain.len() > 253
            || trust_domain.starts_with('.')
            || trust_domain.ends_with('.')
            || trust_domain.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            })
        {
            return Err(invalid("spiffe_id", "non-canonical trust domain"));
        }
        if path.is_empty() || path.ends_with('/') {
            return Err(invalid("spiffe_id", "empty path segment"));
        }
        for segment in path.split('/') {
            if segment.is_empty() || matches!(segment, "." | "..") {
                return Err(invalid("spiffe_id", "empty or dot path segment"));
            }
            let bytes = segment.as_bytes();
            let mut index = 0;
            while index < bytes.len() {
                let byte = bytes[index];
                if byte == b'%' {
                    if index + 2 >= bytes.len()
                        || !bytes[index + 1].is_ascii_hexdigit()
                        || !bytes[index + 2].is_ascii_hexdigit()
                        || bytes[index + 1].is_ascii_lowercase()
                        || bytes[index + 2].is_ascii_lowercase()
                    {
                        return Err(invalid("spiffe_id", "non-canonical percent escape"));
                    }
                    index += 3;
                    continue;
                }
                if !(byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\''
                            | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
                            | b'@'
                    ))
                {
                    return Err(invalid("spiffe_id", "disallowed path byte"));
                }
                index += 1;
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct CanonicalEd25519Signature(String);

impl CanonicalEd25519Signature {
    fn decode(&self) -> Result<[u8; 64], ShadowError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.0)
            .map_err(|_| ShadowError::SignatureEncodingInvalid)?;
        if bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&bytes) != self.0 {
            return Err(ShadowError::SignatureEncodingInvalid);
        }
        bytes
            .try_into()
            .map_err(|_| ShadowError::SignatureEncodingInvalid)
    }
}

impl<'de> Deserialize<'de> for CanonicalEd25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let signature = Self(value);
        signature.decode().map_err(de::Error::custom)?;
        Ok(signature)
    }
}

pub(crate) trait EnvelopePayload: Serialize + Clone {
    const API_VERSION: &'static str;
    const KIND: &'static str;
    const SIGNATURE_DOMAIN: &'static str;

    fn issued_at_unix_nanos(&self) -> i64;
    fn expires_at_unix_nanos(&self) -> i64;
    fn validate_intrinsic(&self) -> Result<(), ShadowError>;
}

/// Deserializable wire evidence. This type carries no verification authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedEnvelope<T> {
    api_version: String,
    kind: String,
    canonical_profile: String,
    signature_domain: String,
    payload: T,
    payload_sha256: Sha256Digest,
    signature_algorithm: String,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
}

impl<T: EnvelopePayload> SignedEnvelope<T> {
    pub(crate) fn untrusted_payload(&self) -> &T {
        &self.payload
    }

    pub(crate) fn untrusted_signer(
        &self,
    ) -> (&Sha256Digest, &Sha256Digest) {
        (&self.signing_key_id, &self.signing_key_spki_sha256)
    }

    /// Crate-only assembly after custody has signed the exact canonical
    /// signature preimage. This remains unverified wire evidence.
    pub(crate) fn from_external_signature(
        payload: T,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
    ) -> Result<Self, ShadowError> {
        payload.validate_intrinsic()?;
        let canonical_payload = canonical_json_bytes(&payload)?;
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        Ok(Self {
            api_version: T::API_VERSION.to_string(),
            kind: T::KIND.to_string(),
            canonical_profile: CANONICAL_PROFILE.to_string(),
            signature_domain: T::SIGNATURE_DOMAIN.to_string(),
            payload,
            payload_sha256: Sha256Digest::compute(&canonical_payload),
            signature_algorithm: SIGNATURE_ALGORITHM.to_string(),
            signing_key_id,
            signing_key_spki_sha256,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExpectedSigner<'a> {
    pub(crate) key_id: &'a Sha256Digest,
    pub(crate) key_spki_sha256: &'a Sha256Digest,
}

pub(crate) trait TrustedTime {
    fn now_unix_nanos(&self) -> Result<i64, ShadowError>;
    /// Exact clocks retain their old semantics. An uncertain native clock
    /// overrides this with one sampled conservative [earliest, latest] pair.
    fn now_interval_unix_nanos(&self) -> Result<(i64, i64), ShadowError> {
        let now = self.now_unix_nanos()?;
        Ok((now, now))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AtomicTrustCheckpoint {
    pub(crate) checkpoint_id: Sha256Digest,
    pub(crate) as_of_unix_nanos: i64,
    pub(crate) revocation_generation: u64,
    pub(crate) revocation_root_sha256: Sha256Digest,
}

impl AtomicTrustCheckpoint {
    pub(crate) fn new(
        checkpoint_id: Sha256Digest,
        as_of_unix_nanos: i64,
        revocation_generation: u64,
        revocation_root_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            revocation_generation,
            "trust_checkpoint.revocation_generation",
        )?;
        Ok(Self {
            checkpoint_id,
            as_of_unix_nanos,
            revocation_generation,
            revocation_root_sha256,
        })
    }

    fn permits_successor(&self, successor: &Self) -> bool {
        successor.revocation_generation > self.revocation_generation
            || (successor.revocation_generation == self.revocation_generation
                && successor.checkpoint_id == self.checkpoint_id
                && successor.revocation_root_sha256 == self.revocation_root_sha256
                && successor.as_of_unix_nanos >= self.as_of_unix_nanos)
    }
}

/// Resolves only administratively trusted, non-revoked keys for the exact
/// domain and exact key bindings. Returning a key is an authorization decision.
pub(crate) trait EnvelopeKeyTrust {
    fn current_checkpoint(&self) -> Result<AtomicTrustCheckpoint, ShadowError>;

    fn resolve_ed25519_key(
        &self,
        checkpoint: &AtomicTrustCheckpoint,
        signature_domain: &str,
        key_id: &Sha256Digest,
        key_spki_sha256: &Sha256Digest,
    ) -> Result<VerifyingKey, ShadowError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PolicyShadowCustodySignerRole {
    IngressAdmission,
    UnavailableIngress,
    DispatchBarrier,
    ActiveEffectBarrier,
    ActiveEffectCommit,
    TerminalAppend,
    LedgerAppend,
    SpoolCompaction,
    PublicationReconciliation,
    ActivationPublication,
}

impl PolicyShadowCustodySignerRole {
    pub(crate) fn signature_domain(self) -> &'static str {
        match self {
            Self::IngressAdmission => {
                "serverware.policyShadowIngressAdmission/v1"
            }
            Self::UnavailableIngress => {
                "serverware.policyShadowUnavailableIngress/v1"
            }
            Self::DispatchBarrier => {
                "serverware.policyShadowDispatchBarrier/v1"
            }
            Self::ActiveEffectBarrier => {
                "serverware.policyShadowActiveEffectBarrier/v1"
            }
            Self::ActiveEffectCommit => {
                "serverware.policyShadowActiveEffectCommit/v1"
            }
            Self::TerminalAppend => {
                "serverware.policyShadowTerminalAppend/v1"
            }
            Self::LedgerAppend => "serverware.policyShadowLedgerAppend/v1",
            Self::SpoolCompaction => {
                "serverware.policyShadowSpoolCompaction/v1"
            }
            Self::PublicationReconciliation => {
                "serverware.policyShadowPublicationReconciliation/v1"
            }
            Self::ActivationPublication => {
                "serverware.policyActivationPublication/v1"
            }
        }
    }

    pub(crate) fn domain(self) -> &'static str {
        self.signature_domain()
    }
}

/// Assignment-selected persistence and retrieval authority. The constructor
/// remains private to `ProductionCustodyConfiguration`; endpoint adapters can
/// inspect the exact scope but cannot substitute a different realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProductionCustodyProofScope {
    assignment_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_id: Sha256Digest,
    storage_realm_sha256: Sha256Digest,
    retrieval_namespace_sha256: Sha256Digest,
    authority_key_independence_sha256: Sha256Digest,
    production_configuration_binding_sha256: Sha256Digest,
    asserted_custody_key_set_root_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    store_response_authority: ProductionCustodyKeyBinding,
    retrieval_response_authority: ProductionCustodyKeyBinding,
    binding_sha256: Sha256Digest,
}

impl ProductionCustodyProofScope {
    pub(crate) fn assignment_id(&self) -> &Sha256Digest {
        &self.assignment_id
    }

    pub(crate) fn assignment_payload_sha256(&self) -> &Sha256Digest {
        &self.assignment_payload_sha256
    }

    pub(crate) fn assignment_revision(&self) -> u64 {
        self.assignment_revision
    }

    pub(crate) fn authority_id(&self) -> &Sha256Digest {
        &self.authority_id
    }

    pub(crate) fn storage_realm_sha256(&self) -> &Sha256Digest {
        &self.storage_realm_sha256
    }

    pub(crate) fn retrieval_namespace_sha256(&self) -> &Sha256Digest {
        &self.retrieval_namespace_sha256
    }

    pub(crate) fn authority_key_independence_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.authority_key_independence_sha256
    }

    pub(crate) fn production_configuration_binding_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.production_configuration_binding_sha256
    }

    pub(crate) fn asserted_custody_key_set_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.asserted_custody_key_set_root_sha256
    }

    pub(crate) fn execution_closure_manifest_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.execution_closure_manifest_sha256
    }

    pub(crate) fn structurally_verified_seccomp_policy_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.structurally_verified_seccomp_policy_sha256
    }

    pub(crate) fn store_response_authority(
        &self,
    ) -> &ProductionCustodyKeyBinding {
        &self.store_response_authority
    }

    pub(crate) fn retrieval_response_authority(
        &self,
    ) -> &ProductionCustodyKeyBinding {
        &self.retrieval_response_authority
    }

    pub(crate) fn binding_sha256(&self) -> &Sha256Digest {
        &self.binding_sha256
    }

    fn assignment_bound_canonical_payload(
        &self,
        role: PolicyShadowCustodySignerRole,
        canonical_receipt_payload: &[u8],
    ) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            "serverware.policyShadowAssignmentBoundCustodyReceipt/v1",
            &self.binding_sha256,
            &self.execution_closure_manifest_sha256,
            &self.structurally_verified_seccomp_policy_sha256,
            role,
            Sha256Digest::compute(canonical_receipt_payload),
        ))
    }
}

/// Persistence and retrieval are verified independently of signer-controlled
/// wire fields. Implementations resolve immutable storage evidence by pinned
/// namespace and compare the exact canonical payload bytes.
pub(crate) trait PolicyShadowPersistenceProofVerifier {
    fn verify_persistence_receipt(
        &self,
        role: PolicyShadowCustodySignerRole,
        persistence_receipt_sha256: &Sha256Digest,
        canonical_payload: &[u8],
    ) -> Result<(), ShadowError>;

    fn verify_immutable_retrieval(
        &self,
        role: PolicyShadowCustodySignerRole,
        retrieval_id_sha256: &Sha256Digest,
        retrieval_proof_sha256: &Sha256Digest,
        canonical_payload: &[u8],
    ) -> Result<(), ShadowError>;

    /// Production adapters must override this method and verify that the
    /// external persistence receipt binds both the raw receipt payload and the
    /// assignment-bound authority payload. The default is deliberately
    /// unavailable so a legacy verifier cannot silently authorize production.
    fn verify_assignment_bound_persistence_receipt(
        &self,
        _scope: &ProductionCustodyProofScope,
        _role: PolicyShadowCustodySignerRole,
        _persistence_receipt_sha256: &Sha256Digest,
        _canonical_receipt_payload: &[u8],
        _signed_authority_payload: &[u8],
    ) -> Result<(), ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }

    /// Production adapters must resolve immutable retrieval in the exact
    /// assignment namespace and prove both payload bindings.
    fn verify_assignment_bound_immutable_retrieval(
        &self,
        _scope: &ProductionCustodyProofScope,
        _role: PolicyShadowCustodySignerRole,
        _retrieval_id_sha256: &Sha256Digest,
        _retrieval_proof_sha256: &Sha256Digest,
        _canonical_receipt_payload: &[u8],
        _signed_authority_payload: &[u8],
    ) -> Result<(), ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }
}

fn validate_custody_receipt_freshness(
    trusted_observed_at_unix_nanos: i64,
    trusted_now_unix_nanos: i64,
    maximum_age_nanos: i64,
) -> Result<(), ShadowError> {
    if maximum_age_nanos <= 0
        || trusted_observed_at_unix_nanos <= 0
        || trusted_now_unix_nanos < trusted_observed_at_unix_nanos
        || trusted_now_unix_nanos
            .saturating_sub(trusted_observed_at_unix_nanos)
            > maximum_age_nanos
    {
        return Err(ShadowError::EvidenceTooOld);
    }
    Ok(())
}

enum CustodyReceiptVerificationAuthority<'a> {
    #[cfg(test)]
    Legacy(ExpectedSigner<'a>),
    Production {
        configuration: &'a ProductionCustodyConfiguration,
        authority: ProductionCustodySignerAuthority<'a>,
    },
}

fn verify_custody_receipt_authority_inner(
    role: PolicyShadowCustodySignerRole,
    signing_key_id: &Sha256Digest,
    signing_key_spki_sha256: &Sha256Digest,
    signature: &CanonicalEd25519Signature,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: &Sha256Digest,
    persistence_receipt_sha256: &Sha256Digest,
    retrieval_id_sha256: &Sha256Digest,
    retrieval_proof_sha256: &Sha256Digest,
    canonical_payload: &[u8],
    verification_authority: CustodyReceiptVerificationAuthority<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<AtomicTrustCheckpoint, ShadowError> {
    let (
        expected_key_id,
        expected_key_spki_sha256,
        expected_key_material_sha256,
        production_configuration,
        production_scope,
    ) = match &verification_authority {
        #[cfg(test)]
        CustodyReceiptVerificationAuthority::Legacy(expected) => (
            expected.key_id,
            expected.key_spki_sha256,
            None,
            None,
            None,
        ),
        CustodyReceiptVerificationAuthority::Production {
            configuration,
            authority,
        } => {
            if authority.role() != role
                || authority.proof_scope() != configuration.proof_scope()
            {
                return Err(ShadowError::SignerBindingMismatch);
            }
            (
                authority.key_id(),
                authority.key_spki_sha256(),
                Some(authority.key_material_sha256()),
                Some(*configuration),
                Some(authority.proof_scope()),
            )
        }
    };
    if signing_key_id != expected_key_id
        || signing_key_spki_sha256 != expected_key_spki_sha256
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let now = trusted_time.now_unix_nanos()?;
    validate_custody_receipt_freshness(
        trusted_observed_at_unix_nanos,
        now,
        maximum_age_nanos,
    )?;
    let checkpoint = key_trust.current_checkpoint()?;
    if checkpoint.checkpoint_id != *trusted_time_checkpoint_sha256 {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let signed_authority_payload = match production_scope {
        Some(scope) => scope.assignment_bound_canonical_payload(
            role,
            canonical_payload,
        )?,
        None => canonical_payload.to_vec(),
    };
    let key = key_trust.resolve_ed25519_key(
        &checkpoint,
        role.signature_domain(),
        signing_key_id,
        signing_key_spki_sha256,
    )?;
    if let Some(expected_key_material_sha256) =
        expected_key_material_sha256
    {
        if &ed25519_public_key_material_sha256(&key)
            != expected_key_material_sha256
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
    }
    key.verify_strict(
        &signature_preimage(
            role.signature_domain(),
            &signed_authority_payload,
        ),
        &Signature::from_bytes(&signature.decode()?),
    )
    .map_err(|_| ShadowError::SignatureInvalid)?;
    match production_scope {
        Some(scope) => {
            proof_verifier.verify_assignment_bound_persistence_receipt(
                scope,
                role,
                persistence_receipt_sha256,
                canonical_payload,
                &signed_authority_payload,
            )?;
            proof_verifier.verify_assignment_bound_immutable_retrieval(
                scope,
                role,
                retrieval_id_sha256,
                retrieval_proof_sha256,
                canonical_payload,
                &signed_authority_payload,
            )?;
        }
        None => {
            proof_verifier.verify_persistence_receipt(
                role,
                persistence_receipt_sha256,
                canonical_payload,
            )?;
            proof_verifier.verify_immutable_retrieval(
                role,
                retrieval_id_sha256,
                retrieval_proof_sha256,
                canonical_payload,
            )?;
        }
    }
    let post_proof_checkpoint = key_trust.current_checkpoint()?;
    if let Some(configuration) = production_configuration {
        configuration.revalidate_active_attestation_at_checkpoint(
            &post_proof_checkpoint,
            key_trust,
        )?;
        configuration.revalidate_retained_assignment_at_checkpoint(
            &post_proof_checkpoint,
            key_trust,
        )?;
    } else if post_proof_checkpoint != checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let final_now = trusted_time.now_unix_nanos()?;
    if final_now < now {
        return Err(ShadowError::TrustedTimeUnavailable);
    }
    validate_custody_receipt_freshness(
        trusted_observed_at_unix_nanos,
        final_now,
        maximum_age_nanos,
    )?;
    if let Some(configuration) = production_configuration {
        configuration.validate_authority_evidence_freshness_at(final_now)?;
    }
    if key_trust.current_checkpoint()? != post_proof_checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(post_proof_checkpoint)
}

#[cfg(test)]
fn verify_custody_receipt_authority(
    role: PolicyShadowCustodySignerRole,
    signing_key_id: &Sha256Digest,
    signing_key_spki_sha256: &Sha256Digest,
    signature: &CanonicalEd25519Signature,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: &Sha256Digest,
    persistence_receipt_sha256: &Sha256Digest,
    retrieval_id_sha256: &Sha256Digest,
    retrieval_proof_sha256: &Sha256Digest,
    canonical_payload: &[u8],
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<AtomicTrustCheckpoint, ShadowError> {
    verify_custody_receipt_authority_inner(
        role,
        signing_key_id,
        signing_key_spki_sha256,
        signature,
        trusted_observed_at_unix_nanos,
        trusted_time_checkpoint_sha256,
        persistence_receipt_sha256,
        retrieval_id_sha256,
        retrieval_proof_sha256,
        canonical_payload,
        CustodyReceiptVerificationAuthority::Legacy(expected_signer),
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )
}

/// This cannot be deserialized or constructed outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedSignedEnvelope<T> {
    envelope: SignedEnvelope<T>,
    canonical_payload_sha256: Sha256Digest,
    canonical_envelope_sha256: Sha256Digest,
    verified_at_unix_nanos: i64,
    trust_checkpoint: AtomicTrustCheckpoint,
}

impl<T> VerifiedSignedEnvelope<T> {
    pub(crate) fn wire(&self) -> &SignedEnvelope<T> {
        &self.envelope
    }

    pub(crate) fn payload(&self) -> &T {
        &self.envelope.payload
    }

    pub(crate) fn payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn envelope_sha256(&self) -> &Sha256Digest {
        &self.canonical_envelope_sha256
    }

    pub(crate) fn verified_at_unix_nanos(&self) -> i64 {
        self.verified_at_unix_nanos
    }
}

pub(crate) fn verify_envelope<T: EnvelopePayload>(
    envelope: SignedEnvelope<T>,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    maximum_age_nanos: i64,
) -> Result<VerifiedSignedEnvelope<T>, ShadowError> {
    if envelope.api_version != T::API_VERSION
        || envelope.kind != T::KIND
        || envelope.signature_domain != T::SIGNATURE_DOMAIN
    {
        return Err(ShadowError::EnvelopeDomainMismatch);
    }
    if envelope.canonical_profile != CANONICAL_PROFILE
        || envelope.signature_algorithm != SIGNATURE_ALGORITHM
    {
        return Err(ShadowError::EnvelopeMetadataMismatch);
    }
    if &envelope.signing_key_id != expected_signer.key_id
        || &envelope.signing_key_spki_sha256 != expected_signer.key_spki_sha256
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    envelope.payload.validate_intrinsic()?;
    let now = validate_trusted_freshness(
        envelope.payload.issued_at_unix_nanos(),
        envelope.payload.expires_at_unix_nanos(),
        trusted_time,
        maximum_age_nanos,
    )?;
    let canonical_payload = canonical_json_bytes(&envelope.payload)?;
    let payload_sha256 = Sha256Digest::compute(&canonical_payload);
    if payload_sha256 != envelope.payload_sha256 {
        return Err(ShadowError::PayloadDigestMismatch);
    }
    let trust_checkpoint = key_trust.current_checkpoint()?;
    let key = key_trust.resolve_ed25519_key(
        &trust_checkpoint,
        &envelope.signature_domain,
        &envelope.signing_key_id,
        &envelope.signing_key_spki_sha256,
    )?;
    let post_resolution_checkpoint = key_trust.current_checkpoint()?;
    if trust_checkpoint != post_resolution_checkpoint {
        return Err(ShadowError::TrustResolutionFailed);
    }
    let signature = Signature::from_bytes(&envelope.signature.decode()?);
    key.verify_strict(
        &signature_preimage(&envelope.signature_domain, &canonical_payload),
        &signature,
    )
    .map_err(|_| ShadowError::SignatureInvalid)?;
    if key_trust.current_checkpoint()? != trust_checkpoint {
        return Err(ShadowError::TrustResolutionFailed);
    }
    let canonical_envelope_sha256 = Sha256Digest::compute(&canonical_json_bytes(&envelope)?);
    Ok(VerifiedSignedEnvelope {
        envelope,
        canonical_payload_sha256: payload_sha256,
        canonical_envelope_sha256,
        verified_at_unix_nanos: now,
        trust_checkpoint,
    })
}

fn validate_freshness(
    issued_at: i64,
    expires_at: i64,
    trusted_now: i64,
    maximum_age_nanos: i64,
) -> Result<(), ShadowError> {
    if expires_at <= issued_at || maximum_age_nanos <= 0 {
        return Err(invalid("validity", "invalid evidence validity interval"));
    }
    if trusted_now < issued_at {
        return Err(ShadowError::EvidenceNotYetValid);
    }
    if trusted_now >= expires_at {
        return Err(ShadowError::EvidenceExpired);
    }
    if trusted_now.saturating_sub(issued_at) > maximum_age_nanos {
        return Err(ShadowError::EvidenceTooOld);
    }
    Ok(())
}

fn validate_trusted_freshness(issued_at: i64, expires_at: i64,
    time: &dyn TrustedTime, maximum_age_nanos: i64) -> Result<i64, ShadowError> {
    let (earliest, latest) = time.now_interval_unix_nanos()?;
    if earliest > latest { return Err(ShadowError::TrustedTimeUnavailable); }
    validate_freshness(issued_at, expires_at, earliest, maximum_age_nanos)?;
    validate_freshness(issued_at, expires_at, latest, maximum_age_nanos)?;
    Ok(latest)
}

pub(crate) fn revalidate_verified_freshness<T: EnvelopePayload>(
    evidence: &VerifiedSignedEnvelope<T>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    maximum_age_nanos: i64,
) -> Result<i64, ShadowError> {
    let current_checkpoint = key_trust.current_checkpoint()?;
    if !evidence
        .trust_checkpoint
        .permits_successor(&current_checkpoint)
    {
        return Err(ShadowError::TrustResolutionFailed);
    }
    key_trust.resolve_ed25519_key(
        &current_checkpoint,
        &evidence.envelope.signature_domain,
        &evidence.envelope.signing_key_id,
        &evidence.envelope.signing_key_spki_sha256,
    )?;
    let post_resolution_checkpoint = key_trust.current_checkpoint()?;
    if current_checkpoint != post_resolution_checkpoint {
        return Err(ShadowError::TrustResolutionFailed);
    }
    let now = validate_trusted_freshness(
        evidence.payload().issued_at_unix_nanos(),
        evidence.payload().expires_at_unix_nanos(),
        trusted_time,
        maximum_age_nanos,
    )?;
    Ok(now)
}

pub(crate) fn revalidate_verified_at_checkpoint<T: EnvelopePayload>(
    evidence: &VerifiedSignedEnvelope<T>,
    checkpoint: &AtomicTrustCheckpoint,
    key_trust: &dyn EnvelopeKeyTrust,
    maximum_age_nanos: i64,
) -> Result<(), ShadowError> {
    if key_trust.current_checkpoint()? != *checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let key = key_trust.resolve_ed25519_key(
        checkpoint,
        &evidence.envelope.signature_domain,
        &evidence.envelope.signing_key_id,
        &evidence.envelope.signing_key_spki_sha256,
    )?;
    if key_trust.current_checkpoint()? != *checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    validate_freshness(
        evidence.payload().issued_at_unix_nanos(),
        evidence.payload().expires_at_unix_nanos(),
        checkpoint.as_of_unix_nanos,
        maximum_age_nanos,
    )?;
    let canonical_payload = canonical_json_bytes(evidence.payload())?;
    if Sha256Digest::compute(&canonical_payload)
        != evidence.canonical_payload_sha256
    {
        return Err(ShadowError::PayloadDigestMismatch);
    }
    let signature = Signature::from_bytes(
        &evidence.envelope.signature.decode()?,
    );
    key.verify_strict(
        &signature_preimage(
            &evidence.envelope.signature_domain,
            &canonical_payload,
        ),
        &signature,
    )
    .map_err(|_| ShadowError::SignatureInvalid)?;
    if key_trust.current_checkpoint()? != *checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(())
}

pub(crate) fn verify_wire_at_checkpoint<T: EnvelopePayload>(
    envelope: &SignedEnvelope<T>,
    expected_signer: ExpectedSigner<'_>,
    checkpoint: &AtomicTrustCheckpoint,
    key_trust: &dyn EnvelopeKeyTrust,
    maximum_age_nanos: i64,
) -> Result<(), ShadowError> {
    if envelope.api_version != T::API_VERSION
        || envelope.kind != T::KIND
        || envelope.signature_domain != T::SIGNATURE_DOMAIN
        || envelope.canonical_profile != CANONICAL_PROFILE
        || envelope.signature_algorithm != SIGNATURE_ALGORITHM
        || &envelope.signing_key_id != expected_signer.key_id
        || &envelope.signing_key_spki_sha256
            != expected_signer.key_spki_sha256
    {
        return Err(ShadowError::EnvelopeMetadataMismatch);
    }
    envelope.payload.validate_intrinsic()?;
    validate_freshness(
        envelope.payload.issued_at_unix_nanos(),
        envelope.payload.expires_at_unix_nanos(),
        checkpoint.as_of_unix_nanos,
        maximum_age_nanos,
    )?;
    let canonical_payload = canonical_json_bytes(&envelope.payload)?;
    if Sha256Digest::compute(&canonical_payload) != envelope.payload_sha256 {
        return Err(ShadowError::PayloadDigestMismatch);
    }
    let key = key_trust.resolve_ed25519_key(
        checkpoint,
        &envelope.signature_domain,
        &envelope.signing_key_id,
        &envelope.signing_key_spki_sha256,
    )?;
    if key_trust.current_checkpoint()? != *checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let signature = Signature::from_bytes(&envelope.signature.decode()?);
    key.verify_strict(
        &signature_preimage(&envelope.signature_domain, &canonical_payload),
        &signature,
    )
    .map_err(|_| ShadowError::SignatureInvalid)?;
    if key_trust.current_checkpoint()? != *checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(())
}

fn signature_preimage(domain: &str, canonical_payload: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        SIGNED_ENVELOPE_DOMAIN.len() + domain.len() + CANONICAL_PROFILE.len()
            + canonical_payload.len()
            + 3,
    );
    preimage.extend_from_slice(SIGNED_ENVELOPE_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(domain.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(CANONICAL_PROFILE.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(canonical_payload);
    preimage
}

pub(crate) fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ShadowError> {
    let value = serde_json::to_value(value)
        .map_err(|_| ShadowError::CanonicalizationFailure("serialization failed"))?;
    let mut output = Vec::new();
    canonicalize_json_value(&value, &mut output)?;
    Ok(output)
}

fn canonicalize_json_value(value: &Value, output: &mut Vec<u8>) -> Result<(), ShadowError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                output.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                if value > MAX_SIGNED_INTEGER {
                    return Err(ShadowError::CanonicalizationFailure(
                        "integer exceeds signed 64-bit range",
                    ));
                }
                output.extend_from_slice(value.to_string().as_bytes());
            } else {
                return Err(ShadowError::CanonicalizationFailure(
                    "floating point numbers are forbidden",
                ));
            }
        }
        Value::String(value) => canonicalize_ascii_string(value, output)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonicalize_json_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            if values.keys().any(|key| !key.is_ascii()) {
                return Err(ShadowError::CanonicalizationFailure(
                    "object keys must be ASCII",
                ));
            }
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonicalize_ascii_string(key, output)?;
                output.push(b':');
                canonicalize_json_value(
                    values
                        .get(*key)
                        .ok_or(ShadowError::CanonicalizationFailure("missing object value"))?,
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn canonicalize_ascii_string(value: &str, output: &mut Vec<u8>) -> Result<(), ShadowError> {
    if !value.is_ascii() {
        return Err(ShadowError::CanonicalizationFailure(
            "strings must be ASCII",
        ));
    }
    output.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(br#"\""#),
            b'\\' => output.extend_from_slice(br#"\\"#),
            0x08 => output.extend_from_slice(br#"\b"#),
            0x09 => output.extend_from_slice(br#"\t"#),
            0x0a => output.extend_from_slice(br#"\n"#),
            0x0c => output.extend_from_slice(br#"\f"#),
            0x0d => output.extend_from_slice(br#"\r"#),
            0x00..=0x1f => {
                output.extend_from_slice(format!(r#"\u{byte:04x}"#).as_bytes())
            }
            _ => output.push(byte),
        }
    }
    output.push(b'"');
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyIdentity {
    candidate_policy_sha256: Sha256Digest,
    candidate_policy_sequence: u64,
    predecessor_policy_sha256: Sha256Digest,
    predecessor_policy_sequence: u64,
    policy_bundle_sha256: Sha256Digest,
    policy_compiler_binary_sha256: Sha256Digest,
    policy_compiler_configuration_sha256: Sha256Digest,
    policy_schema_sha256: Sha256Digest,
    policy_semantic_model_sha256: Sha256Digest,
    decision_gate_binary_sha256: Sha256Digest,
    rollback_epoch: u64,
}

impl PolicyIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_policy_sha256: Sha256Digest,
        candidate_policy_sequence: u64,
        predecessor_policy_sha256: Sha256Digest,
        predecessor_policy_sequence: u64,
        policy_bundle_sha256: Sha256Digest,
        policy_compiler_binary_sha256: Sha256Digest,
        policy_compiler_configuration_sha256: Sha256Digest,
        policy_schema_sha256: Sha256Digest,
        policy_semantic_model_sha256: Sha256Digest,
        decision_gate_binary_sha256: Sha256Digest,
        rollback_epoch: u64,
    ) -> Result<Self, ShadowError> {
        let identity = Self {
            candidate_policy_sha256,
            candidate_policy_sequence,
            predecessor_policy_sha256,
            predecessor_policy_sequence,
            policy_bundle_sha256,
            policy_compiler_binary_sha256,
            policy_compiler_configuration_sha256,
            policy_schema_sha256,
            policy_semantic_model_sha256,
            decision_gate_binary_sha256,
            rollback_epoch,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), ShadowError> {
        validate_positive(self.candidate_policy_sequence, "candidate_policy_sequence")?;
        validate_positive(self.predecessor_policy_sequence, "predecessor_policy_sequence")?;
        validate_positive(self.rollback_epoch, "rollback_epoch")?;
        if self.candidate_policy_sequence <= self.predecessor_policy_sequence {
            return Err(ShadowError::CandidateSequenceNotAdvanced);
        }
        if self.candidate_policy_sha256 == self.predecessor_policy_sha256 {
            return Err(invalid(
                "candidate_policy_sha256",
                "candidate and predecessor digests must differ",
            ));
        }
        Ok(())
    }

    pub fn candidate_policy_sha256(&self) -> &Sha256Digest {
        &self.candidate_policy_sha256
    }

    pub fn candidate_policy_sequence(&self) -> u64 {
        self.candidate_policy_sequence
    }

    pub fn predecessor_policy_sha256(&self) -> &Sha256Digest {
        &self.predecessor_policy_sha256
    }

    pub fn predecessor_policy_sequence(&self) -> u64 {
        self.predecessor_policy_sequence
    }

    pub fn rollback_epoch(&self) -> u64 {
        self.rollback_epoch
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_runtime_compiler_contract(
        &self,
        policy_bundle_sha256: &Sha256Digest,
        policy_compiler_binary_sha256: &Sha256Digest,
        policy_compiler_configuration_sha256: &Sha256Digest,
        policy_schema_sha256: &Sha256Digest,
        policy_semantic_model_sha256: &Sha256Digest,
        decision_gate_binary_sha256: &Sha256Digest,
    ) -> bool {
        self.policy_bundle_sha256 == *policy_bundle_sha256
            && self.policy_compiler_binary_sha256
                == *policy_compiler_binary_sha256
            && self.policy_compiler_configuration_sha256
                == *policy_compiler_configuration_sha256
            && self.policy_schema_sha256 == *policy_schema_sha256
            && self.policy_semantic_model_sha256
                == *policy_semantic_model_sha256
            && self.decision_gate_binary_sha256
                == *decision_gate_binary_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TeePlatform {
    TrustedHostNoTee,
    AwsNitroEnclave,
    AmdSevSnp,
    IntelTdx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum CustodyAttestationMode {
    TrustedHost {
        host_evidence_profile_sha256: Sha256Digest,
        host_evidence_policy_sha256: Sha256Digest,
    },
    Tee {
        platform: TeePlatform,
        expected_measurement_sha256: Sha256Digest,
        endorsement_root_sha256: Sha256Digest,
        collateral_policy_sha256: Sha256Digest,
        revocation_source_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FleetMember {
    pub(crate) instance_id: Identifier,
    pub(crate) spiffe_id: SpiffeId,
    pub(crate) boot_id_sha256: Sha256Digest,
    pub(crate) tee_platform: TeePlatform,
    pub(crate) tee_measurement_sha256: Sha256Digest,
    pub(crate) tee_attestation_key_id: Sha256Digest,
    pub(crate) tee_attestation_key_spki_sha256: Sha256Digest,
    pub(crate) ingress_signing_key_id: Sha256Digest,
    pub(crate) ingress_signing_key_spki_sha256: Sha256Digest,
    pub(crate) active_decision_signing_key_id: Sha256Digest,
    pub(crate) active_decision_signing_key_spki_sha256: Sha256Digest,
    pub(crate) shadow_signing_key_id: Sha256Digest,
    pub(crate) shadow_signing_key_spki_sha256: Sha256Digest,
}

impl FleetMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: Identifier,
        spiffe_id: SpiffeId,
        boot_id_sha256: Sha256Digest,
        tee_platform: TeePlatform,
        tee_measurement_sha256: Sha256Digest,
        tee_attestation_key_id: Sha256Digest,
        tee_attestation_key_spki_sha256: Sha256Digest,
        ingress_signing_key_id: Sha256Digest,
        ingress_signing_key_spki_sha256: Sha256Digest,
        active_decision_signing_key_id: Sha256Digest,
        active_decision_signing_key_spki_sha256: Sha256Digest,
        shadow_signing_key_id: Sha256Digest,
        shadow_signing_key_spki_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        let member = Self {
            instance_id,
            spiffe_id,
            boot_id_sha256,
            tee_platform,
            tee_measurement_sha256,
            tee_attestation_key_id,
            tee_attestation_key_spki_sha256,
            ingress_signing_key_id,
            ingress_signing_key_spki_sha256,
            active_decision_signing_key_id,
            active_decision_signing_key_spki_sha256,
            shadow_signing_key_id,
            shadow_signing_key_spki_sha256,
        };
        member.validate()?;
        Ok(member)
    }

    fn validate(&self) -> Result<(), ShadowError> {
        let key_ids = [
            &self.tee_attestation_key_id,
            &self.ingress_signing_key_id,
            &self.active_decision_signing_key_id,
            &self.shadow_signing_key_id,
        ];
        let key_spkis = [
            &self.tee_attestation_key_spki_sha256,
            &self.ingress_signing_key_spki_sha256,
            &self.active_decision_signing_key_spki_sha256,
            &self.shadow_signing_key_spki_sha256,
        ];
        if key_ids.iter().collect::<BTreeSet<_>>().len() != key_ids.len()
            || key_spkis.iter().collect::<BTreeSet<_>>().len() != key_spkis.len()
        {
            return Err(invalid(
                "fleet_member.signing_keys",
                "TEE, ingress, active-decision, and shadow keys must be distinct",
            ));
        }
        Ok(())
    }

    pub fn instance_id(&self) -> &Identifier {
        &self.instance_id
    }

    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    pub fn boot_id_sha256(&self) -> &Sha256Digest {
        &self.boot_id_sha256
    }

    pub(crate) fn tee_measurement_sha256(&self) -> &Sha256Digest {
        &self.tee_measurement_sha256
    }

    pub(crate) fn shadow_signing_key_id(&self) -> &Sha256Digest {
        &self.shadow_signing_key_id
    }

    pub(crate) fn shadow_signing_key_spki_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.shadow_signing_key_spki_sha256
    }

}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeIdentity {
    pub(crate) instance_id: Identifier,
    pub(crate) spiffe_id: SpiffeId,
    pub(crate) boot_id_sha256: Sha256Digest,
    pub(crate) tee_platform: TeePlatform,
    pub(crate) tee_evidence_sha256: Sha256Digest,
    pub(crate) tee_measurement_sha256: Sha256Digest,
    pub(crate) tee_attestation_key_id: Sha256Digest,
    pub(crate) tee_attestation_key_spki_sha256: Sha256Digest,
    pub(crate) ingress_signing_key_id: Sha256Digest,
    pub(crate) ingress_signing_key_spki_sha256: Sha256Digest,
    pub(crate) active_decision_signing_key_id: Sha256Digest,
    pub(crate) active_decision_signing_key_spki_sha256: Sha256Digest,
    pub(crate) shadow_signing_key_id: Sha256Digest,
    pub(crate) shadow_signing_key_spki_sha256: Sha256Digest,
}

impl RuntimeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: Identifier,
        spiffe_id: SpiffeId,
        boot_id_sha256: Sha256Digest,
        tee_platform: TeePlatform,
        tee_evidence_sha256: Sha256Digest,
        tee_measurement_sha256: Sha256Digest,
        tee_attestation_key_id: Sha256Digest,
        tee_attestation_key_spki_sha256: Sha256Digest,
        ingress_signing_key_id: Sha256Digest,
        ingress_signing_key_spki_sha256: Sha256Digest,
        active_decision_signing_key_id: Sha256Digest,
        active_decision_signing_key_spki_sha256: Sha256Digest,
        shadow_signing_key_id: Sha256Digest,
        shadow_signing_key_spki_sha256: Sha256Digest,
    ) -> Self {
        Self {
            instance_id,
            spiffe_id,
            boot_id_sha256,
            tee_platform,
            tee_evidence_sha256,
            tee_measurement_sha256,
            tee_attestation_key_id,
            tee_attestation_key_spki_sha256,
            ingress_signing_key_id,
            ingress_signing_key_spki_sha256,
            active_decision_signing_key_id,
            active_decision_signing_key_spki_sha256,
            shadow_signing_key_id,
            shadow_signing_key_spki_sha256,
        }
    }

    fn matches_member(&self, member: &FleetMember) -> bool {
        self.instance_id == member.instance_id
            && self.spiffe_id == member.spiffe_id
            && self.boot_id_sha256 == member.boot_id_sha256
            && self.tee_platform == member.tee_platform
            && self.tee_measurement_sha256 == member.tee_measurement_sha256
            && self.tee_attestation_key_id == member.tee_attestation_key_id
            && self.tee_attestation_key_spki_sha256
                == member.tee_attestation_key_spki_sha256
            && self.ingress_signing_key_id == member.ingress_signing_key_id
            && self.ingress_signing_key_spki_sha256
                == member.ingress_signing_key_spki_sha256
            && self.active_decision_signing_key_id
                == member.active_decision_signing_key_id
            && self.active_decision_signing_key_spki_sha256
                == member.active_decision_signing_key_spki_sha256
            && self.shadow_signing_key_id == member.shadow_signing_key_id
            && self.shadow_signing_key_spki_sha256
                == member.shadow_signing_key_spki_sha256
    }

    pub fn instance_id(&self) -> &Identifier {
        &self.instance_id
    }

    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    pub fn boot_id_sha256(&self) -> &Sha256Digest {
        &self.boot_id_sha256
    }

    pub(crate) fn tee_evidence_sha256(&self) -> &Sha256Digest {
        &self.tee_evidence_sha256
    }

    pub(crate) fn tee_measurement_sha256(&self) -> &Sha256Digest {
        &self.tee_measurement_sha256
    }

    pub(crate) fn shadow_signing_key_id(&self) -> &Sha256Digest {
        &self.shadow_signing_key_id
    }

    pub(crate) fn shadow_signing_key_spki_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.shadow_signing_key_spki_sha256
    }

    pub(crate) fn tee_platform_label(&self) -> &'static str {
        match self.tee_platform {
            TeePlatform::TrustedHostNoTee => "trusted-host-no-tee",
            TeePlatform::AwsNitroEnclave => "aws-nitro-enclave",
            TeePlatform::AmdSevSnp => "amd-sev-snp",
            TeePlatform::IntelTdx => "intel-tdx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FleetAssignment {
    fleet_id: Sha256Digest,
    membership_revision: u64,
    membership_root_sha256: Sha256Digest,
    members: Vec<FleetMember>,
}

const MAX_CUSTODY_EXECUTION_CLOSURE_ARTIFACTS: usize = 512;
const MAX_CUSTODY_SECCOMP_INSTRUCTIONS: usize = 4096;
const MAX_CUSTODY_SECCOMP_SYSCALL_RULES: usize = 1024;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodyClosureArtifactRole {
    StaticWorkerExecutable,
    DynamicWorkerExecutable,
    DynamicLoader,
    ScriptInterpreter,
    SharedObject,
    SeccompFilter,
    RootFilesystem,
    RuntimeConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyClosureArtifact {
    role: ProductionCustodyClosureArtifactRole,
    canonical_absolute_path: CanonicalAscii,
    content_sha256: Sha256Digest,
    fs_verity_root_sha256: Sha256Digest,
    ima_template_sha256: Sha256Digest,
    ima_appraisal_policy_sha256: Sha256Digest,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    fs_verity_enabled: bool,
    ima_appraisal_enforced: bool,
    read_only_mount: bool,
}

impl ProductionCustodyClosureArtifact {
    fn validate(
        &self,
        expected_role: ProductionCustodyClosureArtifactRole,
    ) -> Result<(), ShadowError> {
        let path = self.canonical_absolute_path.as_str();
        if self.role != expected_role
            || !path.starts_with('/')
            || (path.len() > 1 && path.ends_with('/'))
            || path.contains("//")
            || path
                .split('/')
                .skip(1)
                .any(|component| matches!(component, "." | ".."))
            || self.owner_uid != 0
            || self.mode & 0o022 != 0
            || !self.fs_verity_enabled
            || !self.ima_appraisal_enforced
            || !self.read_only_mount
        {
            return Err(invalid(
                "production_custody.execution_closure.artifact",
                "artifact must be an exact root-owned, immutable, fs-verity and IMA-appraised path",
            ));
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn role(
        &self,
    ) -> ProductionCustodyClosureArtifactRole {
        self.role
    }

    pub(in crate::policy_shadow) fn canonical_absolute_path(
        &self,
    ) -> &str {
        self.canonical_absolute_path.as_str()
    }

    pub(in crate::policy_shadow) fn content_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.content_sha256
    }

    pub(in crate::policy_shadow) fn fs_verity_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.fs_verity_root_sha256
    }

    pub(in crate::policy_shadow) fn ima_template_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.ima_template_sha256
    }

    pub(in crate::policy_shadow) fn ima_appraisal_policy_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.ima_appraisal_policy_sha256
    }

    pub(in crate::policy_shadow) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub(in crate::policy_shadow) fn owner_gid(&self) -> u32 {
        self.owner_gid
    }

    pub(in crate::policy_shadow) fn mode(&self) -> u32 {
        self.mode
    }

    pub(in crate::policy_shadow) fn requires_enforced_appraisal(
        &self,
    ) -> bool {
        self.fs_verity_enabled
            && self.ima_appraisal_enforced
            && self.read_only_mount
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodySeccompArchitecture {
    X86_64,
    Aarch64,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodySeccompAction {
    Allow,
    KillProcess,
    Trap,
    Errno,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodySeccompArgumentOperator {
    Equal,
    MaskedEqual,
    LessThanOrEqual,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodySeccompArgumentRule {
    argument_index: u8,
    operator: ProductionCustodySeccompArgumentOperator,
    value_high: u32,
    value_low: u32,
    mask_high: u32,
    mask_low: u32,
}

impl ProductionCustodySeccompArgumentRule {
    fn validate(&self) -> Result<(), ShadowError> {
        if self.argument_index > 5
            || (self.operator
                != ProductionCustodySeccompArgumentOperator::MaskedEqual
                && (self.mask_high != u32::MAX
                    || self.mask_low != u32::MAX))
        {
            return Err(invalid(
                "production_custody.seccomp.argument_rule",
                "argument rule is not an exact six-argument seccomp comparison",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodySeccompSyscallRule {
    syscall_number: u32,
    action: ProductionCustodySeccompAction,
    errno: u16,
    argument_rules: Vec<ProductionCustodySeccompArgumentRule>,
}

impl ProductionCustodySeccompSyscallRule {
    fn validate(&self) -> Result<(), ShadowError> {
        validate_len(
            "production_custody.seccomp.argument_rules",
            self.argument_rules.len(),
            0,
            6,
        )?;
        if self.argument_rules.windows(2).any(|pair| {
            pair[0].argument_index >= pair[1].argument_index
        })
            || (self.action == ProductionCustodySeccompAction::Errno
                && self.errno == 0)
            || (self.action != ProductionCustodySeccompAction::Errno
                && self.errno != 0)
        {
            return Err(invalid(
                "production_custody.seccomp.syscall_rule",
                "syscall action or argument rules are non-canonical",
            ));
        }
        for rule in &self.argument_rules {
            rule.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodySeccompInstruction {
    ordinal: u32,
    code: u16,
    jump_if_true: u8,
    jump_if_false: u8,
    operand: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct StructurallyVerifiedCustodySeccompPolicy {
    architecture: ProductionCustodySeccompArchitecture,
    default_action: ProductionCustodySeccompAction,
    no_new_privileges_required: bool,
    installed_before_untrusted_input: bool,
    instructions: Vec<ProductionCustodySeccompInstruction>,
    syscall_rules: Vec<ProductionCustodySeccompSyscallRule>,
    exact_instruction_stream_sha256: Sha256Digest,
    raw_bpf_sha256: Sha256Digest,
    exact_argument_semantics_sha256: Sha256Digest,
    structurally_verified_policy_sha256: Sha256Digest,
}

impl StructurallyVerifiedCustodySeccompPolicy {
    pub(in crate::policy_shadow) fn validate(
        &self,
    ) -> Result<(), ShadowError> {
        validate_len(
            "production_custody.seccomp.instructions",
            self.instructions.len(),
            1,
            MAX_CUSTODY_SECCOMP_INSTRUCTIONS,
        )?;
        validate_len(
            "production_custody.seccomp.syscall_rules",
            self.syscall_rules.len(),
            2,
            MAX_CUSTODY_SECCOMP_SYSCALL_RULES,
        )?;
        if self.default_action != ProductionCustodySeccompAction::KillProcess
            || !self.no_new_privileges_required
            || !self.installed_before_untrusted_input
            || self
                .instructions
                .iter()
                .enumerate()
                .any(|(index, instruction)| {
                    usize::try_from(instruction.ordinal).ok()
                        != Some(index)
                        || index
                            .checked_add(1)
                            .and_then(|next| {
                                next.checked_add(usize::from(
                                    instruction.jump_if_true,
                                ))
                            })
                            .is_none_or(|target| {
                                target > self.instructions.len()
                            })
                        || index
                            .checked_add(1)
                            .and_then(|next| {
                                next.checked_add(usize::from(
                                    instruction.jump_if_false,
                                ))
                            })
                            .is_none_or(|target| {
                                target > self.instructions.len()
                            })
                })
            || self
                .instructions
                .last()
                .is_none_or(|instruction| instruction.code & 0x07 != 0x06)
            || self
                .syscall_rules
                .windows(2)
                .any(|pair| {
                    pair[0].syscall_number >= pair[1].syscall_number
                })
        {
            return Err(invalid(
                "production_custody.seccomp",
                "filter must be bounded, forward-only, default-deny, and terminate in BPF_RET",
            ));
        }
        for rule in &self.syscall_rules {
            rule.validate()?;
        }
        let canonical_instructions = compile_custody_seccomp_rules(
            self.architecture,
            &self.syscall_rules,
            self.default_action,
        )?;
        if self.instructions != canonical_instructions {
            return Err(invalid(
                "production_custody.seccomp.instructions",
                "instruction stream is not the exact generated syscall and argument policy",
            ));
        }
        let (execve_number, execveat_number) = match self.architecture {
            ProductionCustodySeccompArchitecture::X86_64 => (59, 322),
            ProductionCustodySeccompArchitecture::Aarch64 => (221, 281),
        };
        for forbidden in [execve_number, execveat_number] {
            let rule = self
                .syscall_rules
                .iter()
                .find(|rule| rule.syscall_number == forbidden)
                .ok_or_else(|| {
                    invalid(
                        "production_custody.seccomp.exec",
                        "execve and execveat must have explicit deny rules",
                    )
                })?;
            if rule.action != ProductionCustodySeccompAction::KillProcess
                || !rule.argument_rules.is_empty()
            {
                return Err(invalid(
                    "production_custody.seccomp.exec",
                    "post-launch worker must unconditionally kill execve and execveat",
                ));
            }
        }
        let exact_instruction_stream_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodySeccompInstructions/v1",
            &[&canonical_json_bytes(&self.instructions)?],
        );
        let raw_bpf_sha256 =
            Sha256Digest::compute(&custody_seccomp_raw_bytes(
                &self.instructions,
            ));
        let exact_argument_semantics_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodySeccompSemantics/v1",
            &[&canonical_json_bytes(&(
                self.architecture,
                self.default_action,
                self.no_new_privileges_required,
                self.installed_before_untrusted_input,
                &self.syscall_rules,
            ))?],
        );
        let structurally_verified_policy_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodySeccompPolicy/v2",
            &[&canonical_json_bytes(&(
                &exact_instruction_stream_sha256,
                &raw_bpf_sha256,
                &exact_argument_semantics_sha256,
            ))?],
        );
        if self.exact_instruction_stream_sha256
                != exact_instruction_stream_sha256
            || self.raw_bpf_sha256 != raw_bpf_sha256
            || self.exact_argument_semantics_sha256
                != exact_argument_semantics_sha256
            || self.structurally_verified_policy_sha256
                != structurally_verified_policy_sha256
        {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn policy_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.structurally_verified_policy_sha256
    }

    pub(in crate::policy_shadow) fn raw_bpf_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.raw_bpf_sha256
    }

    pub(in crate::policy_shadow) fn exact_instructions(
        &self,
    ) -> &[ProductionCustodySeccompInstruction] {
        &self.instructions
    }
}

fn custody_seccomp_action_word(
    action: ProductionCustodySeccompAction,
    errno: u16,
) -> Result<u32, ShadowError> {
    match action {
        ProductionCustodySeccompAction::Allow if errno == 0 => {
            Ok(0x7fff_0000)
        }
        ProductionCustodySeccompAction::KillProcess if errno == 0 => {
            Ok(0x8000_0000)
        }
        ProductionCustodySeccompAction::Trap if errno == 0 => {
            Ok(0x0003_0000)
        }
        ProductionCustodySeccompAction::Errno if errno != 0 => {
            Ok(0x0005_0000 | u32::from(errno))
        }
        _ => Err(ShadowError::BindingDrift),
    }
}

fn custody_seccomp_raw_bytes(
    instructions: &[ProductionCustodySeccompInstruction],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(instructions.len() * 8);
    for instruction in instructions {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.push(instruction.jump_if_true);
        bytes.push(instruction.jump_if_false);
        bytes.extend_from_slice(&instruction.operand.to_le_bytes());
    }
    bytes
}

fn compile_custody_seccomp_rules(
    architecture: ProductionCustodySeccompArchitecture,
    rules: &[ProductionCustodySeccompSyscallRule],
    default_action: ProductionCustodySeccompAction,
) -> Result<Vec<ProductionCustodySeccompInstruction>, ShadowError> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGT_K: u16 = 0x25;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_NR: u32 = 0;
    const SECCOMP_DATA_ARCH: u32 = 4;
    const SECCOMP_DATA_ARGS: u32 = 16;
    let audit_arch = match architecture {
        ProductionCustodySeccompArchitecture::X86_64 => 0xc000_003e,
        ProductionCustodySeccompArchitecture::Aarch64 => 0xc000_00b7,
    };
    let kill = custody_seccomp_action_word(
        ProductionCustodySeccompAction::KillProcess,
        0,
    )?;
    let mut stream = vec![
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH),
        (BPF_JMP_JEQ_K, 1, 0, audit_arch),
        (BPF_RET_K, 0, 0, kill),
    ];
    for rule in rules {
        let mut body = Vec::new();
        for argument in &rule.argument_rules {
            let low_offset = SECCOMP_DATA_ARGS
                + u32::from(argument.argument_index) * 8;
            let high_offset = low_offset + 4;
            match argument.operator {
                ProductionCustodySeccompArgumentOperator::Equal => {
                    body.extend([
                        (BPF_LD_W_ABS, 0, 0, high_offset),
                        (BPF_JMP_JEQ_K, 1, 0, argument.value_high),
                        (BPF_RET_K, 0, 0, kill),
                        (BPF_LD_W_ABS, 0, 0, low_offset),
                        (BPF_JMP_JEQ_K, 1, 0, argument.value_low),
                        (BPF_RET_K, 0, 0, kill),
                    ]);
                }
                ProductionCustodySeccompArgumentOperator::MaskedEqual => {
                    body.extend([
                        (BPF_LD_W_ABS, 0, 0, high_offset),
                        (BPF_ALU_AND_K, 0, 0, argument.mask_high),
                        (
                            BPF_JMP_JEQ_K,
                            1,
                            0,
                            argument.value_high & argument.mask_high,
                        ),
                        (BPF_RET_K, 0, 0, kill),
                        (BPF_LD_W_ABS, 0, 0, low_offset),
                        (BPF_ALU_AND_K, 0, 0, argument.mask_low),
                        (
                            BPF_JMP_JEQ_K,
                            1,
                            0,
                            argument.value_low & argument.mask_low,
                        ),
                        (BPF_RET_K, 0, 0, kill),
                    ]);
                }
                ProductionCustodySeccompArgumentOperator::LessThanOrEqual => {
                    body.extend([
                        (BPF_LD_W_ABS, 0, 0, high_offset),
                        (BPF_JMP_JGT_K, 0, 1, argument.value_high),
                        (BPF_RET_K, 0, 0, kill),
                        (BPF_JMP_JEQ_K, 0, 3, argument.value_high),
                        (BPF_LD_W_ABS, 0, 0, low_offset),
                        (BPF_JMP_JGT_K, 0, 1, argument.value_low),
                        (BPF_RET_K, 0, 0, kill),
                    ]);
                }
            }
        }
        body.push((
            BPF_RET_K,
            0,
            0,
            custody_seccomp_action_word(rule.action, rule.errno)?,
        ));
        let skip = u8::try_from(body.len())
            .map_err(|_| ShadowError::CounterOverflow)?;
        stream.push((BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR));
        stream.push((
            BPF_JMP_JEQ_K,
            0,
            skip,
            rule.syscall_number,
        ));
        stream.extend(body);
    }
    stream.push((
        BPF_RET_K,
        0,
        0,
        custody_seccomp_action_word(default_action, 0)?,
    ));
    stream
        .into_iter()
        .enumerate()
        .map(|(ordinal, (code, jump_if_true, jump_if_false, operand))| {
            Ok(ProductionCustodySeccompInstruction {
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| ShadowError::CounterOverflow)?,
                code,
                jump_if_true,
                jump_if_false,
                operand,
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "linkage",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(in crate::policy_shadow) enum ProductionCustodyExecutableImage {
    Static {
        executable: ProductionCustodyClosureArtifact,
    },
    Dynamic {
        executable: ProductionCustodyClosureArtifact,
        loader: ProductionCustodyClosureArtifact,
        interpreter: Option<ProductionCustodyClosureArtifact>,
        shared_objects: Vec<ProductionCustodyClosureArtifact>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyBuildProvenance {
    source_tree_sha256: Sha256Digest,
    dependency_lock_sha256: Sha256Digest,
    build_recipe_sha256: Sha256Digest,
    toolchain_closure_sha256: Sha256Digest,
    provenance_statement_sha256: Sha256Digest,
    transparency_log_entry_sha256: Sha256Digest,
    reproducible_build_required: bool,
    provenance_sha256: Sha256Digest,
}

impl ProductionCustodyBuildProvenance {
    fn validate(&self) -> Result<(), ShadowError> {
        let expected = hash_domain_frames(
            b"serverware.policyShadowCustodyBuildProvenance/v1",
            &[&canonical_json_bytes(&(
                &self.source_tree_sha256,
                &self.dependency_lock_sha256,
                &self.build_recipe_sha256,
                &self.toolchain_closure_sha256,
                &self.provenance_statement_sha256,
                &self.transparency_log_entry_sha256,
                self.reproducible_build_required,
            ))?],
        );
        if !self.reproducible_build_required
            || self.provenance_sha256 != expected
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }
}

impl ProductionCustodyExecutableImage {
    fn validate(&self) -> Result<(), ShadowError> {
        match self {
            Self::Static { executable } => executable.validate(
                ProductionCustodyClosureArtifactRole::StaticWorkerExecutable,
            ),
            Self::Dynamic {
                executable,
                loader,
                interpreter,
                shared_objects,
            } => {
                executable.validate(
                    ProductionCustodyClosureArtifactRole::DynamicWorkerExecutable,
                )?;
                loader.validate(
                    ProductionCustodyClosureArtifactRole::DynamicLoader,
                )?;
                if let Some(interpreter) = interpreter {
                    interpreter.validate(
                        ProductionCustodyClosureArtifactRole::ScriptInterpreter,
                    )?;
                }
                validate_len(
                    "production_custody.execution_closure.shared_objects",
                    shared_objects.len(),
                    1,
                    MAX_CUSTODY_EXECUTION_CLOSURE_ARTIFACTS,
                )?;
                if shared_objects.windows(2).any(|pair| {
                    pair[0].canonical_absolute_path
                        >= pair[1].canonical_absolute_path
                }) {
                    return Err(invalid(
                        "production_custody.execution_closure.shared_objects",
                        "shared objects must be complete, unique, and path-sorted",
                    ));
                }
                for shared_object in shared_objects {
                    shared_object.validate(
                        ProductionCustodyClosureArtifactRole::SharedObject,
                    )?;
                }
                Ok(())
            }
        }
    }

    fn worker_executable(&self) -> &ProductionCustodyClosureArtifact {
        match self {
            Self::Static { executable }
            | Self::Dynamic { executable, .. } => executable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyExecutionClosureManifest {
    build_provenance: ProductionCustodyBuildProvenance,
    executable_image: ProductionCustodyExecutableImage,
    seccomp_filter_artifact: ProductionCustodyClosureArtifact,
    seccomp_policy: StructurallyVerifiedCustodySeccompPolicy,
    root_filesystem: ProductionCustodyClosureArtifact,
    runtime_configuration: Vec<ProductionCustodyClosureArtifact>,
    artifact_set_root_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
}

impl ProductionCustodyExecutionClosureManifest {
    pub(in crate::policy_shadow) fn validate(
        &self,
    ) -> Result<(), ShadowError> {
        self.build_provenance.validate()?;
        self.executable_image.validate()?;
        self.seccomp_filter_artifact.validate(
            ProductionCustodyClosureArtifactRole::SeccompFilter,
        )?;
        self.seccomp_policy.validate()?;
        if self.seccomp_filter_artifact.content_sha256
            != *self.seccomp_policy.raw_bpf_sha256()
        {
            return Err(ShadowError::BindingDrift);
        }
        self.root_filesystem.validate(
            ProductionCustodyClosureArtifactRole::RootFilesystem,
        )?;
        validate_len(
            "production_custody.execution_closure.runtime_configuration",
            self.runtime_configuration.len(),
            1,
            MAX_CUSTODY_EXECUTION_CLOSURE_ARTIFACTS,
        )?;
        if self.runtime_configuration.windows(2).any(|pair| {
            pair[0].canonical_absolute_path
                >= pair[1].canonical_absolute_path
        }) {
            return Err(invalid(
                "production_custody.execution_closure.runtime_configuration",
                "configuration artifacts must be complete, unique, and path-sorted",
            ));
        }
        for configuration in &self.runtime_configuration {
            configuration.validate(
                ProductionCustodyClosureArtifactRole::RuntimeConfiguration,
            )?;
        }
        for required_build_evidence in [
            &self.build_provenance.dependency_lock_sha256,
            &self.build_provenance.build_recipe_sha256,
            &self
                .build_provenance
                .provenance_statement_sha256,
        ] {
            if !self.runtime_configuration.iter().any(|artifact| {
                artifact.content_sha256() == required_build_evidence
            }) {
                return Err(ShadowError::BindingDrift);
            }
        }
        let mut artifacts = Vec::new();
        match &self.executable_image {
            ProductionCustodyExecutableImage::Static { executable } => {
                artifacts.push(executable);
            }
            ProductionCustodyExecutableImage::Dynamic {
                executable,
                loader,
                interpreter,
                shared_objects,
            } => {
                artifacts.push(executable);
                artifacts.push(loader);
                if let Some(interpreter) = interpreter {
                    artifacts.push(interpreter);
                }
                artifacts.extend(shared_objects);
            }
        }
        artifacts.push(&self.seccomp_filter_artifact);
        artifacts.push(&self.root_filesystem);
        artifacts.extend(&self.runtime_configuration);
        validate_len(
            "production_custody.execution_closure.artifacts",
            artifacts.len(),
            4,
            MAX_CUSTODY_EXECUTION_CLOSURE_ARTIFACTS,
        )?;
        let mut artifact_paths = BTreeSet::new();
        if artifacts.iter().any(|artifact| {
            !artifact_paths.insert(artifact.canonical_absolute_path.as_str())
        }) {
            return Err(invalid(
                "production_custody.execution_closure.artifacts",
                "every closure path must be unique",
            ));
        }
        let artifact_leaves = artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| {
                Ok((
                    u64::try_from(index + 1)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                    hash_domain_frames(
                        b"serverware.policyShadowCustodyClosureArtifact/v1",
                        &[&canonical_json_bytes(artifact)?],
                    ),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        let artifact_set_root_sha256 = merkle_root(&artifact_leaves)?;
        let manifest_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyExecutionClosure/v1",
            &[&canonical_json_bytes(&(
                &self.build_provenance,
                &self.executable_image,
                &self.seccomp_filter_artifact,
                &self.seccomp_policy,
                &self.root_filesystem,
                &self.runtime_configuration,
                &artifact_set_root_sha256,
            ))?],
        );
        if self.artifact_set_root_sha256 != artifact_set_root_sha256
            || self.manifest_sha256 != manifest_sha256
        {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn manifest_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub(in crate::policy_shadow) fn seccomp_policy_sha256(
        &self,
    ) -> &Sha256Digest {
        self.seccomp_policy.policy_sha256()
    }

    pub(in crate::policy_shadow) fn worker_executable_sha256(
        &self,
    ) -> &Sha256Digest {
        self.executable_image.worker_executable().content_sha256()
    }

    pub(in crate::policy_shadow) fn has_static_worker_executable(
        &self,
    ) -> bool {
        matches!(
            &self.executable_image,
            ProductionCustodyExecutableImage::Static { .. }
        )
    }

    pub(in crate::policy_shadow) fn seccomp_policy(
        &self,
    ) -> &StructurallyVerifiedCustodySeccompPolicy {
        &self.seccomp_policy
    }

    pub(in crate::policy_shadow) fn artifacts(
        &self,
    ) -> Vec<&ProductionCustodyClosureArtifact> {
        let mut artifacts = Vec::new();
        match &self.executable_image {
            ProductionCustodyExecutableImage::Static { executable } => {
                artifacts.push(executable);
            }
            ProductionCustodyExecutableImage::Dynamic {
                executable,
                loader,
                interpreter,
                shared_objects,
            } => {
                artifacts.push(executable);
                artifacts.push(loader);
                if let Some(interpreter) = interpreter {
                    artifacts.push(interpreter);
                }
                artifacts.extend(shared_objects);
            }
        }
        artifacts.push(&self.seccomp_filter_artifact);
        artifacts.push(&self.root_filesystem);
        artifacts.extend(&self.runtime_configuration);
        artifacts
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CustodyAuthority {
    authority_id: Sha256Digest,
    storage_realm_sha256: Sha256Digest,
    retrieval_namespace_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    attestation_mode: CustodyAttestationMode,
    ingress_admission_key_id: Sha256Digest,
    ingress_admission_key_spki_sha256: Sha256Digest,
    unavailable_ingress_key_id: Sha256Digest,
    unavailable_ingress_key_spki_sha256: Sha256Digest,
    dispatch_barrier_key_id: Sha256Digest,
    dispatch_barrier_key_spki_sha256: Sha256Digest,
    active_effect_barrier_key_id: Sha256Digest,
    active_effect_barrier_key_spki_sha256: Sha256Digest,
    active_effect_commit_key_id: Sha256Digest,
    active_effect_commit_key_spki_sha256: Sha256Digest,
    terminal_append_key_id: Sha256Digest,
    terminal_append_key_spki_sha256: Sha256Digest,
    ledger_append_key_id: Sha256Digest,
    ledger_append_key_spki_sha256: Sha256Digest,
    spool_compaction_key_id: Sha256Digest,
    spool_compaction_key_spki_sha256: Sha256Digest,
    publication_reconciliation_key_id: Sha256Digest,
    publication_reconciliation_key_spki_sha256: Sha256Digest,
    activation_publication_key_id: Sha256Digest,
    activation_publication_key_spki_sha256: Sha256Digest,
    result_envelope_key_id: Sha256Digest,
    result_envelope_key_spki_sha256: Sha256Digest,
    store_response_key_id: Sha256Digest,
    store_response_key_spki_sha256: Sha256Digest,
    signer_response_key_id: Sha256Digest,
    signer_response_key_spki_sha256: Sha256Digest,
    retrieval_response_key_id: Sha256Digest,
    retrieval_response_key_spki_sha256: Sha256Digest,
    trusted_time_response_key_id: Sha256Digest,
    trusted_time_response_key_spki_sha256: Sha256Digest,
    provider_response_key_id: Sha256Digest,
    provider_response_key_spki_sha256: Sha256Digest,
    attestation_verifier_key_id: Sha256Digest,
    attestation_verifier_key_spki_sha256: Sha256Digest,
    supervisor_capability_key_id: Sha256Digest,
    supervisor_capability_key_spki_sha256: Sha256Digest,
}

impl CustodyAuthority {
    fn role_signers(&self) -> Vec<(&Sha256Digest, &Sha256Digest)> {
        vec![
            (
                &self.ingress_admission_key_id,
                &self.ingress_admission_key_spki_sha256,
            ),
            (
                &self.unavailable_ingress_key_id,
                &self.unavailable_ingress_key_spki_sha256,
            ),
            (
                &self.dispatch_barrier_key_id,
                &self.dispatch_barrier_key_spki_sha256,
            ),
            (
                &self.active_effect_barrier_key_id,
                &self.active_effect_barrier_key_spki_sha256,
            ),
            (
                &self.active_effect_commit_key_id,
                &self.active_effect_commit_key_spki_sha256,
            ),
            (
                &self.terminal_append_key_id,
                &self.terminal_append_key_spki_sha256,
            ),
            (
                &self.ledger_append_key_id,
                &self.ledger_append_key_spki_sha256,
            ),
            (
                &self.spool_compaction_key_id,
                &self.spool_compaction_key_spki_sha256,
            ),
            (
                &self.publication_reconciliation_key_id,
                &self.publication_reconciliation_key_spki_sha256,
            ),
            (
                &self.activation_publication_key_id,
                &self.activation_publication_key_spki_sha256,
            ),
            (
                &self.result_envelope_key_id,
                &self.result_envelope_key_spki_sha256,
            ),
            (
                &self.store_response_key_id,
                &self.store_response_key_spki_sha256,
            ),
            (
                &self.signer_response_key_id,
                &self.signer_response_key_spki_sha256,
            ),
            (
                &self.retrieval_response_key_id,
                &self.retrieval_response_key_spki_sha256,
            ),
            (
                &self.trusted_time_response_key_id,
                &self.trusted_time_response_key_spki_sha256,
            ),
            (
                &self.provider_response_key_id,
                &self.provider_response_key_spki_sha256,
            ),
            (
                &self.attestation_verifier_key_id,
                &self.attestation_verifier_key_spki_sha256,
            ),
            (
                &self.supervisor_capability_key_id,
                &self.supervisor_capability_key_spki_sha256,
            ),
        ]
    }

    pub(crate) fn attestation_mode(&self) -> &CustodyAttestationMode {
        &self.attestation_mode
    }
}

fn enforce_cross_document_role_key_independence<'a>(
    roles: impl IntoIterator<
        Item = (&'a Sha256Digest, &'a Sha256Digest),
    >,
) -> Result<(), ShadowError> {
    let mut key_ids = BTreeSet::new();
    let mut key_material = BTreeSet::new();
    for (key_id, key_spki_sha256) in roles {
        if !key_ids.insert(key_id.as_str())
            || !key_material.insert(key_spki_sha256.as_str())
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
    }
    Ok(())
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthorityRole {
    CompilerAnalysis,
    ActivationReadiness,
    ActivationApproval,
    FleetTeeAttestation,
    FleetIngress,
    FleetActiveDecision,
    FleetShadow,
    CustodyIngressAdmission,
    CustodyUnavailableIngress,
    CustodyDispatchBarrier,
    CustodyTerminalAppend,
    CustodyLedgerAppend,
    CustodySpoolCompaction,
    CustodyActiveEffectBarrier,
    CustodyActiveEffectCommit,
    CustodyPublicationReconciliation,
    CustodyActivationPublication,
    CustodyResultEnvelope,
    CustodyStoreResponse,
    CustodySignerResponse,
    CustodyRetrievalResponse,
    CustodyTrustedTimeResponse,
    CustodyProviderResponse,
    CustodyAttestationVerifier,
    CustodySupervisorCapability,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityRoleKeyBinding {
    role: AuthorityRole,
    scope_sha256: Sha256Digest,
    key_algorithm: Identifier,
    key_id: Sha256Digest,
    key_spki_sha256: Sha256Digest,
    key_material_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AuthorityKeyIndependence {
    bindings: Vec<AuthorityRoleKeyBinding>,
    key_id_set_root_sha256: Sha256Digest,
    spki_set_root_sha256: Sha256Digest,
    key_material_set_root_sha256: Sha256Digest,
    independence_root_sha256: Sha256Digest,
}

impl AuthorityKeyIndependence {
    fn binding(
        &self,
        role: AuthorityRole,
        scope_sha256: &Sha256Digest,
    ) -> Result<&AuthorityRoleKeyBinding, ShadowError> {
        let mut matches = self.bindings.iter().filter(|binding| {
            binding.role == role
                && binding.scope_sha256 == *scope_sha256
        });
        let binding = matches
            .next()
            .ok_or(ShadowError::SignerBindingMismatch)?;
        if matches.next().is_some() {
            return Err(ShadowError::SignerBindingMismatch);
        }
        Ok(binding)
    }

    fn validate(
        &self,
        assignment_id: &Sha256Digest,
        fleet: &FleetAssignment,
        custody: &CustodyAuthority,
    ) -> Result<(), ShadowError> {
        validate_len(
            "authority_key_independence.bindings",
            self.bindings.len(),
            25,
            16_404,
        )?;
        if self.bindings.windows(2).any(|pair| pair[0] >= pair[1])
            || self.bindings.iter().any(|binding| {
                !binding
                    .key_algorithm
                    .as_str()
                    .eq_ignore_ascii_case("ed25519")
            })
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        let mut key_ids = BTreeSet::new();
        let mut spkis = BTreeSet::new();
        let mut materials = BTreeSet::new();
        for binding in &self.bindings {
            if !key_ids.insert(binding.key_id.clone())
                || !spkis.insert(binding.key_spki_sha256.clone())
                || !materials.insert(binding.key_material_sha256.clone())
            {
                return Err(ShadowError::SignerBindingMismatch);
            }
        }
        let key_id_leaves = key_ids
            .iter()
            .enumerate()
            .map(|(index, digest)| {
                Ok((
                    u64::try_from(index + 1)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                    digest.clone(),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        let spki_leaves = spkis
            .iter()
            .enumerate()
            .map(|(index, digest)| {
                Ok((
                    u64::try_from(index + 1)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                    digest.clone(),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        let material_leaves = materials
            .iter()
            .enumerate()
            .map(|(index, digest)| {
                Ok((
                    u64::try_from(index + 1)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                    digest.clone(),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        if merkle_root(&key_id_leaves)?
                != self.key_id_set_root_sha256
            || merkle_root(&spki_leaves)? != self.spki_set_root_sha256
            || merkle_root(&material_leaves)?
                != self.key_material_set_root_sha256
        {
            return Err(ShadowError::MerkleRootMismatch);
        }
        let expected_independence_root = hash_domain_frames(
            b"serverware.policyAuthorityKeyIndependence/v1",
            &[&canonical_json_bytes(&(
                &self.bindings,
                &self.key_id_set_root_sha256,
                &self.spki_set_root_sha256,
                &self.key_material_set_root_sha256,
            ))?],
        );
        if expected_independence_root != self.independence_root_sha256 {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        for role in [
            AuthorityRole::CompilerAnalysis,
            AuthorityRole::ActivationReadiness,
            AuthorityRole::ActivationApproval,
        ] {
            self.binding(role, assignment_id)?;
        }
        for member in &fleet.members {
            let scope_sha256 = fleet_member_authority_scope(member)?;
            for (role, key_id, key_spki_sha256) in [
                (
                    AuthorityRole::FleetTeeAttestation,
                    &member.tee_attestation_key_id,
                    &member.tee_attestation_key_spki_sha256,
                ),
                (
                    AuthorityRole::FleetIngress,
                    &member.ingress_signing_key_id,
                    &member.ingress_signing_key_spki_sha256,
                ),
                (
                    AuthorityRole::FleetActiveDecision,
                    &member.active_decision_signing_key_id,
                    &member.active_decision_signing_key_spki_sha256,
                ),
                (
                    AuthorityRole::FleetShadow,
                    &member.shadow_signing_key_id,
                    &member.shadow_signing_key_spki_sha256,
                ),
            ] {
                let binding = self.binding(role, &scope_sha256)?;
                if binding.key_id != *key_id
                    || binding.key_spki_sha256 != *key_spki_sha256
                {
                    return Err(ShadowError::SignerBindingMismatch);
                }
            }
        }
        for (role, key_id, key_spki_sha256) in [
            (
                AuthorityRole::CustodyIngressAdmission,
                &custody.ingress_admission_key_id,
                &custody.ingress_admission_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyUnavailableIngress,
                &custody.unavailable_ingress_key_id,
                &custody.unavailable_ingress_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyDispatchBarrier,
                &custody.dispatch_barrier_key_id,
                &custody.dispatch_barrier_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyTerminalAppend,
                &custody.terminal_append_key_id,
                &custody.terminal_append_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyLedgerAppend,
                &custody.ledger_append_key_id,
                &custody.ledger_append_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodySpoolCompaction,
                &custody.spool_compaction_key_id,
                &custody.spool_compaction_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyActiveEffectBarrier,
                &custody.active_effect_barrier_key_id,
                &custody.active_effect_barrier_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyActiveEffectCommit,
                &custody.active_effect_commit_key_id,
                &custody.active_effect_commit_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyPublicationReconciliation,
                &custody.publication_reconciliation_key_id,
                &custody.publication_reconciliation_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyActivationPublication,
                &custody.activation_publication_key_id,
                &custody.activation_publication_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyResultEnvelope,
                &custody.result_envelope_key_id,
                &custody.result_envelope_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyStoreResponse,
                &custody.store_response_key_id,
                &custody.store_response_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodySignerResponse,
                &custody.signer_response_key_id,
                &custody.signer_response_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyRetrievalResponse,
                &custody.retrieval_response_key_id,
                &custody.retrieval_response_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyTrustedTimeResponse,
                &custody.trusted_time_response_key_id,
                &custody.trusted_time_response_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyProviderResponse,
                &custody.provider_response_key_id,
                &custody.provider_response_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodyAttestationVerifier,
                &custody.attestation_verifier_key_id,
                &custody.attestation_verifier_key_spki_sha256,
            ),
            (
                AuthorityRole::CustodySupervisorCapability,
                &custody.supervisor_capability_key_id,
                &custody.supervisor_capability_key_spki_sha256,
            ),
        ] {
            let binding = self.binding(role, assignment_id)?;
            if binding.key_id != *key_id
                || binding.key_spki_sha256 != *key_spki_sha256
            {
                return Err(ShadowError::SignerBindingMismatch);
            }
        }
        let expected_count = fleet
            .members
            .len()
            .checked_mul(4)
            .and_then(|value| value.checked_add(21))
            .ok_or(ShadowError::CounterOverflow)?;
        if self.bindings.len() != expected_count {
            return Err(ShadowError::SignerBindingMismatch);
        }
        Ok(())
    }
}

fn fleet_member_authority_scope(
    member: &FleetMember,
) -> Result<Sha256Digest, ShadowError> {
    Ok(hash_domain_frames(
        b"serverware.policyAuthorityFleetMemberScope/v1",
        &[&canonical_json_bytes(&(
            &member.instance_id,
            &member.spiffe_id,
            &member.boot_id_sha256,
            &member.tee_measurement_sha256,
        ))?],
    ))
}

fn authority_role_signature_domain(role: AuthorityRole) -> &'static str {
    match role {
        AuthorityRole::CompilerAnalysis => {
            POLICY_AUTHORITY_ANALYSIS_DOMAIN
        }
        AuthorityRole::ActivationReadiness => READINESS_DOMAIN,
        AuthorityRole::ActivationApproval => ACTIVATION_APPROVAL_DOMAIN,
        AuthorityRole::FleetTeeAttestation => {
            "serverware.runtimeAttestation/v1"
        }
        AuthorityRole::FleetIngress => INGRESS_EVIDENCE_DOMAIN,
        AuthorityRole::FleetActiveDecision => ACTIVE_DECISION_DOMAIN,
        AuthorityRole::FleetShadow => OBSERVATION_DOMAIN,
        AuthorityRole::CustodyIngressAdmission => {
            PolicyShadowCustodySignerRole::IngressAdmission
                .signature_domain()
        }
        AuthorityRole::CustodyUnavailableIngress => {
            PolicyShadowCustodySignerRole::UnavailableIngress
                .signature_domain()
        }
        AuthorityRole::CustodyDispatchBarrier => {
            PolicyShadowCustodySignerRole::DispatchBarrier
                .signature_domain()
        }
        AuthorityRole::CustodyTerminalAppend => {
            PolicyShadowCustodySignerRole::TerminalAppend
                .signature_domain()
        }
        AuthorityRole::CustodyLedgerAppend => {
            PolicyShadowCustodySignerRole::LedgerAppend
                .signature_domain()
        }
        AuthorityRole::CustodySpoolCompaction => {
            PolicyShadowCustodySignerRole::SpoolCompaction
                .signature_domain()
        }
        AuthorityRole::CustodyActiveEffectBarrier => {
            PolicyShadowCustodySignerRole::ActiveEffectBarrier
                .signature_domain()
        }
        AuthorityRole::CustodyActiveEffectCommit => {
            PolicyShadowCustodySignerRole::ActiveEffectCommit
                .signature_domain()
        }
        AuthorityRole::CustodyPublicationReconciliation => {
            PolicyShadowCustodySignerRole::PublicationReconciliation
                .signature_domain()
        }
        AuthorityRole::CustodyActivationPublication => {
            PolicyShadowCustodySignerRole::ActivationPublication
                .signature_domain()
        }
        AuthorityRole::CustodyResultEnvelope => {
            "serverware.policyShadowCustodyResultEnvelope/v1"
        }
        AuthorityRole::CustodyStoreResponse => {
            "serverware.policyShadowCustodyStoreResponse/v1"
        }
        AuthorityRole::CustodySignerResponse => {
            "serverware.policyShadowCustodySignerResponse/v1"
        }
        AuthorityRole::CustodyRetrievalResponse => {
            "serverware.policyShadowCustodyRetrievalResponse/v1"
        }
        AuthorityRole::CustodyTrustedTimeResponse => {
            "serverware.policyShadowCustodyTrustedTimeResponse/v1"
        }
        AuthorityRole::CustodyProviderResponse => {
            "serverware.policyShadowCustodyProviderResponse/v1"
        }
        AuthorityRole::CustodyAttestationVerifier => {
            "serverware.policyShadowCustodyAttestationVerifier/v1"
        }
        AuthorityRole::CustodySupervisorCapability => {
            "serverware.policyShadowCustodySupervisorCapability/v1"
        }
    }
}

fn ed25519_public_key_material_sha256(
    key: &VerifyingKey,
) -> Sha256Digest {
    const ED25519_SPKI_PREFIX: &[u8] =
        &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let mut der = Vec::with_capacity(
        ED25519_SPKI_PREFIX.len() + key.as_bytes().len(),
    );
    der.extend_from_slice(ED25519_SPKI_PREFIX);
    der.extend_from_slice(key.as_bytes());
    hash_domain_frames(
        b"serverware.policyAuthorityPublicKeyMaterial/v1",
        &[b"ed25519", der.as_slice()],
    )
}

fn verify_assignment_authority_key_material(
    assignment: &VerifiedAssignment,
    key_trust: &dyn EnvelopeKeyTrust,
) -> Result<(), ShadowError> {
    let checkpoint = key_trust.current_checkpoint()?;
    verify_assignment_authority_key_material_at_checkpoint(
        assignment,
        &checkpoint,
        key_trust,
    )?;
    if key_trust.current_checkpoint()? != checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(())
}

fn verify_assignment_authority_key_material_at_checkpoint(
    assignment: &VerifiedAssignment,
    checkpoint: &AtomicTrustCheckpoint,
    key_trust: &dyn EnvelopeKeyTrust,
) -> Result<(), ShadowError> {
    for binding in &assignment
        .payload()
        .authority_key_independence
        .bindings
    {
        let key = key_trust.resolve_ed25519_key(
            checkpoint,
            authority_role_signature_domain(binding.role),
            &binding.key_id,
            &binding.key_spki_sha256,
        )?;
        if ed25519_public_key_material_sha256(&key)
            != binding.key_material_sha256
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservationWindow {
    starts_at_unix_nanos: i64,
    ends_at_unix_nanos: i64,
    seal_deadline_unix_nanos: i64,
    minimum_duration_nanos: u64,
    first_ingress_sequence: u64,
    sampling_basis_points: u16,
    request_commitment_key_id: Sha256Digest,
    request_commitment_key_epoch: u64,
    maximum_evidence_age_nanos: u64,
    maximum_heartbeat_gap_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadinessThresholds {
    minimum_ingress_requests: u64,
    minimum_evaluated_observations: u64,
    minimum_comparable_responses: u64,
    minimum_ingress_requests_per_member: u64,
    minimum_evaluated_observations_per_member: u64,
    minimum_comparable_responses_per_member: u64,
    maximum_candidate_evaluation_p99_nanos: u64,
    maximum_shadow_total_p99_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompiledPolicySnapshotIdentity {
    policy_sha256: Sha256Digest,
    policy_sequence: u64,
    rollback_epoch: u64,
    compiled_snapshot_sha256: Sha256Digest,
    policy_compiler_binary_sha256: Sha256Digest,
    policy_compiler_configuration_sha256: Sha256Digest,
    policy_schema_sha256: Sha256Digest,
    adapter_schema_sha256: Sha256Digest,
    policy_semantic_model_sha256: Sha256Digest,
    policy_plan_schema_sha256: Sha256Digest,
}

impl CompiledPolicySnapshotIdentity {
    fn validate(&self) -> Result<(), ShadowError> {
        validate_positive(self.policy_sequence, "snapshot.policy_sequence")?;
        validate_positive(self.rollback_epoch, "snapshot.rollback_epoch")
    }

    #[allow(clippy::too_many_arguments)]
    fn matches_runtime_compilation(
        &self,
        policy_sha256: &Sha256Digest,
        policy_sequence: u64,
        rollback_epoch: u64,
        compiled_snapshot_sha256: &Sha256Digest,
        policy_compiler_binary_sha256: &Sha256Digest,
        policy_compiler_configuration_sha256: &Sha256Digest,
        policy_schema_sha256: &Sha256Digest,
        adapter_schema_sha256: &Sha256Digest,
        policy_semantic_model_sha256: &Sha256Digest,
        policy_plan_schema_sha256: &Sha256Digest,
    ) -> bool {
        self.policy_sha256 == *policy_sha256
            && self.policy_sequence == policy_sequence
            && self.rollback_epoch == rollback_epoch
            && self.compiled_snapshot_sha256
                == *compiled_snapshot_sha256
            && self.policy_compiler_binary_sha256
                == *policy_compiler_binary_sha256
            && self.policy_compiler_configuration_sha256
                == *policy_compiler_configuration_sha256
            && self.policy_schema_sha256 == *policy_schema_sha256
            && self.adapter_schema_sha256 == *adapter_schema_sha256
            && self.policy_semantic_model_sha256
                == *policy_semantic_model_sha256
            && self.policy_plan_schema_sha256
                == *policy_plan_schema_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AssignedSnapshotIdentities {
    active: CompiledPolicySnapshotIdentity,
    candidate: CompiledPolicySnapshotIdentity,
    request_facts_schema_sha256: Sha256Digest,
}

impl AssignedSnapshotIdentities {
    fn validate_against_policy(&self, policy: &PolicyIdentity) -> Result<(), ShadowError> {
        self.active.validate()?;
        self.candidate.validate()?;
        if self.active.policy_sha256 != policy.predecessor_policy_sha256
            || self.active.policy_sequence != policy.predecessor_policy_sequence
            || self.candidate.policy_sha256 != policy.candidate_policy_sha256
            || self.candidate.policy_sequence != policy.candidate_policy_sequence
            || self.active.rollback_epoch != policy.rollback_epoch
            || self.candidate.rollback_epoch != policy.rollback_epoch
            || self.active.policy_compiler_binary_sha256
                != policy.policy_compiler_binary_sha256
            || self.candidate.policy_compiler_binary_sha256
                != policy.policy_compiler_binary_sha256
            || self.active.policy_compiler_configuration_sha256
                != policy.policy_compiler_configuration_sha256
            || self.candidate.policy_compiler_configuration_sha256
                != policy.policy_compiler_configuration_sha256
            || self.active.policy_schema_sha256 != policy.policy_schema_sha256
            || self.candidate.policy_schema_sha256 != policy.policy_schema_sha256
            || self.active.policy_semantic_model_sha256
                != policy.policy_semantic_model_sha256
            || self.candidate.policy_semantic_model_sha256
                != policy.policy_semantic_model_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_runtime_compilation(
        &self,
        active_policy_sha256: &Sha256Digest,
        active_policy_sequence: u64,
        active_rollback_epoch: u64,
        active_compiled_snapshot_sha256: &Sha256Digest,
        candidate_policy_sha256: &Sha256Digest,
        candidate_policy_sequence: u64,
        candidate_rollback_epoch: u64,
        candidate_compiled_snapshot_sha256: &Sha256Digest,
        policy_compiler_binary_sha256: &Sha256Digest,
        policy_compiler_configuration_sha256: &Sha256Digest,
        policy_schema_sha256: &Sha256Digest,
        adapter_schema_sha256: &Sha256Digest,
        policy_semantic_model_sha256: &Sha256Digest,
        policy_plan_schema_sha256: &Sha256Digest,
        request_facts_schema_sha256: &Sha256Digest,
    ) -> bool {
        self.active.matches_runtime_compilation(
            active_policy_sha256,
            active_policy_sequence,
            active_rollback_epoch,
            active_compiled_snapshot_sha256,
            policy_compiler_binary_sha256,
            policy_compiler_configuration_sha256,
            policy_schema_sha256,
            adapter_schema_sha256,
            policy_semantic_model_sha256,
            policy_plan_schema_sha256,
        ) && self.candidate.matches_runtime_compilation(
            candidate_policy_sha256,
            candidate_policy_sequence,
            candidate_rollback_epoch,
            candidate_compiled_snapshot_sha256,
            policy_compiler_binary_sha256,
            policy_compiler_configuration_sha256,
            policy_schema_sha256,
            adapter_schema_sha256,
            policy_semantic_model_sha256,
            policy_plan_schema_sha256,
        ) && self.request_facts_schema_sha256
            == *request_facts_schema_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResponseValidationObligation {
    route_sha256: Sha256Digest,
    obligation_root_sha256: Sha256Digest,
    minimum_comparable_responses: u64,
}

impl ResponseValidationObligation {
    fn validate(&self) -> Result<(), ShadowError> {
        validate_positive(
            self.minimum_comparable_responses,
            "response_obligation.minimum_comparable_responses",
        )
    }
}

impl FleetAssignment {
    pub fn new(
        fleet_id: Sha256Digest,
        membership_revision: u64,
        membership_root_sha256: Sha256Digest,
        members: Vec<FleetMember>,
    ) -> Result<Self, ShadowError> {
        validate_positive(membership_revision, "membership_revision")?;
        validate_len("fleet.members", members.len(), 1, MAX_COLLECTION_ITEMS)?;
        Ok(Self {
            fleet_id,
            membership_revision,
            membership_root_sha256,
            members,
        })
    }

    pub fn members(&self) -> &[FleetMember] {
        &self.members
    }

    pub(crate) fn fleet_id(&self) -> &Sha256Digest {
        &self.fleet_id
    }

    pub(crate) fn membership_revision(&self) -> u64 {
        self.membership_revision
    }

    pub(crate) fn membership_root_sha256(&self) -> &Sha256Digest {
        &self.membership_root_sha256
    }
}

impl ObservationWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        starts_at_unix_nanos: i64,
        ends_at_unix_nanos: i64,
        seal_deadline_unix_nanos: i64,
        minimum_duration_nanos: u64,
        first_ingress_sequence: u64,
        sampling_basis_points: u16,
        request_commitment_key_id: Sha256Digest,
        request_commitment_key_epoch: u64,
        maximum_evidence_age_nanos: u64,
        maximum_heartbeat_gap_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_positive(minimum_duration_nanos, "minimum_duration_nanos")?;
        validate_positive(first_ingress_sequence, "first_ingress_sequence")?;
        validate_positive(request_commitment_key_epoch, "request_commitment_key_epoch")?;
        validate_positive(maximum_evidence_age_nanos, "maximum_evidence_age_nanos")?;
        validate_positive(
            maximum_heartbeat_gap_nanos,
            "maximum_heartbeat_gap_nanos",
        )?;
        if sampling_basis_points == 0
            || sampling_basis_points > 10_000
            || ends_at_unix_nanos <= starts_at_unix_nanos
            || seal_deadline_unix_nanos <= ends_at_unix_nanos
        {
            return Err(invalid("observation_window", "invalid bounds"));
        }
        Ok(Self {
            starts_at_unix_nanos,
            ends_at_unix_nanos,
            seal_deadline_unix_nanos,
            minimum_duration_nanos,
            first_ingress_sequence,
            sampling_basis_points,
            request_commitment_key_id,
            request_commitment_key_epoch,
            maximum_evidence_age_nanos,
            maximum_heartbeat_gap_nanos,
        })
    }
}

impl ReadinessThresholds {
    pub fn new(
        minimum_ingress_requests: u64,
        minimum_evaluated_observations: u64,
        minimum_comparable_responses: u64,
        minimum_ingress_requests_per_member: u64,
        minimum_evaluated_observations_per_member: u64,
        minimum_comparable_responses_per_member: u64,
        maximum_candidate_evaluation_p99_nanos: u64,
        maximum_shadow_total_p99_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_positive(minimum_ingress_requests, "minimum_ingress_requests")?;
        validate_positive(
            minimum_evaluated_observations,
            "minimum_evaluated_observations",
        )?;
        validate_unsigned(minimum_comparable_responses, "minimum_comparable_responses")?;
        validate_positive(
            minimum_ingress_requests_per_member,
            "minimum_ingress_requests_per_member",
        )?;
        validate_positive(
            minimum_evaluated_observations_per_member,
            "minimum_evaluated_observations_per_member",
        )?;
        validate_unsigned(
            minimum_comparable_responses_per_member,
            "minimum_comparable_responses_per_member",
        )?;
        validate_positive(
            maximum_candidate_evaluation_p99_nanos,
            "maximum_candidate_evaluation_p99_nanos",
        )?;
        validate_positive(
            maximum_shadow_total_p99_nanos,
            "maximum_shadow_total_p99_nanos",
        )?;
        Ok(Self {
            minimum_ingress_requests,
            minimum_evaluated_observations,
            minimum_comparable_responses,
            minimum_ingress_requests_per_member,
            minimum_evaluated_observations_per_member,
            minimum_comparable_responses_per_member,
            maximum_candidate_evaluation_p99_nanos,
            maximum_shadow_total_p99_nanos,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyShadowAssignmentPayload {
    assignment_id: Sha256Digest,
    canary_id: Sha256Digest,
    assignment_revision: u64,
    generation_epoch: u64,
    minimum_generation_tombstone_epoch: u64,
    policy_identity: PolicyIdentity,
    expected_loaded_snapshots: AssignedSnapshotIdentities,
    response_validation_obligations: Vec<ResponseValidationObligation>,
    response_validation_obligations_root_sha256: Sha256Digest,
    fleet: FleetAssignment,
    custody_authority: CustodyAuthority,
    authority_key_independence: AuthorityKeyIndependence,
    observation_window: ObservationWindow,
    readiness_thresholds: ReadinessThresholds,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl PolicyShadowAssignmentPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        assignment_id: Sha256Digest,
        canary_id: Sha256Digest,
        assignment_revision: u64,
        generation_epoch: u64,
        minimum_generation_tombstone_epoch: u64,
        policy_identity: PolicyIdentity,
        expected_loaded_snapshots: AssignedSnapshotIdentities,
        response_validation_obligations: Vec<ResponseValidationObligation>,
        response_validation_obligations_root_sha256: Sha256Digest,
        fleet: FleetAssignment,
        custody_authority: CustodyAuthority,
        authority_key_independence: AuthorityKeyIndependence,
        observation_window: ObservationWindow,
        readiness_thresholds: ReadinessThresholds,
        issued_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        let payload = Self {
            assignment_id,
            canary_id,
            assignment_revision,
            generation_epoch,
            minimum_generation_tombstone_epoch,
            policy_identity,
            expected_loaded_snapshots,
            response_validation_obligations,
            response_validation_obligations_root_sha256,
            fleet,
            custody_authority,
            authority_key_independence,
            observation_window,
            readiness_thresholds,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }

    pub fn assignment_revision(&self) -> u64 {
        self.assignment_revision
    }

    pub(crate) fn assignment_id(&self) -> &Sha256Digest {
        &self.assignment_id
    }

    pub(crate) fn canary_id(&self) -> &Sha256Digest {
        &self.canary_id
    }

    pub(crate) fn generation_epoch(&self) -> u64 {
        self.generation_epoch
    }

    pub(crate) fn minimum_generation_tombstone_epoch(&self) -> u64 {
        self.minimum_generation_tombstone_epoch
    }

    pub fn policy_identity(&self) -> &PolicyIdentity {
        &self.policy_identity
    }

    pub fn expected_loaded_snapshots(&self) -> &AssignedSnapshotIdentities {
        &self.expected_loaded_snapshots
    }

    pub fn fleet(&self) -> &FleetAssignment {
        &self.fleet
    }

    pub(crate) fn custody_authority(&self) -> &CustodyAuthority {
        &self.custody_authority
    }

    pub(crate) fn authority_key_independence(
        &self,
    ) -> &AuthorityKeyIndependence {
        &self.authority_key_independence
    }

    pub fn observation_window(&self) -> &ObservationWindow {
        &self.observation_window
    }
}

impl EnvelopePayload for PolicyShadowAssignmentPayload {
    const API_VERSION: &'static str = ASSIGNMENT_DOMAIN;
    const KIND: &'static str = "PolicyShadowAssignment";
    const SIGNATURE_DOMAIN: &'static str = ASSIGNMENT_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(self.generation_epoch, "generation_epoch")?;
        validate_positive(
            self.minimum_generation_tombstone_epoch,
            "minimum_generation_tombstone_epoch",
        )?;
        if self.minimum_generation_tombstone_epoch > self.generation_epoch {
            return Err(ShadowError::GenerationTombstoned);
        }
        self.policy_identity.validate()?;
        self.expected_loaded_snapshots
            .validate_against_policy(&self.policy_identity)?;
        validate_len(
            "response_validation_obligations",
            self.response_validation_obligations.len(),
            0,
            MAX_RESPONSE_OBLIGATIONS,
        )?;
        if self
            .response_validation_obligations
            .windows(2)
            .any(|pair| pair[0].route_sha256 >= pair[1].route_sha256)
        {
            return Err(invalid(
                "response_validation_obligations",
                "routes must be unique and sorted",
            ));
        }
        for obligation in &self.response_validation_obligations {
            obligation.validate()?;
        }
        let obligation_leaves = self
            .response_validation_obligations
            .iter()
            .enumerate()
            .map(|(index, obligation)| {
                Ok((
                    u64::try_from(index + 1).map_err(|_| ShadowError::CounterOverflow)?,
                    Sha256Digest::compute(&canonical_json_bytes(obligation)?),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        if merkle_root(&obligation_leaves)?
            != self.response_validation_obligations_root_sha256
        {
            return Err(ShadowError::MerkleRootMismatch);
        }
        validate_positive(self.fleet.membership_revision, "membership_revision")?;
        validate_len("fleet.members", self.fleet.members.len(), 1, MAX_COLLECTION_ITEMS)?;
        reject_duplicate_by(
            &self.fleet.members,
            |member| member.instance_id.as_str(),
            "fleet.members.instance_id",
        )?;
        reject_duplicate_by(
            &self.fleet.members,
            |member| member.spiffe_id.as_str(),
            "fleet.members.spiffe_id",
        )?;
        for member in &self.fleet.members {
            member.validate()?;
        }
        self.authority_key_independence.validate(
            &self.assignment_id,
            &self.fleet,
            &self.custody_authority,
        )?;
        let mut fleet_role_key_ids = BTreeSet::new();
        let mut fleet_role_key_spkis = BTreeSet::new();
        for member in &self.fleet.members {
            for key_id in [
                &member.tee_attestation_key_id,
                &member.ingress_signing_key_id,
                &member.active_decision_signing_key_id,
                &member.shadow_signing_key_id,
            ] {
                if !fleet_role_key_ids.insert(key_id) {
                    return Err(invalid(
                        "fleet.members.signing_key_ids",
                        "every role key must be independent across the assigned fleet",
                    ));
                }
            }
            for key_spki in [
                &member.tee_attestation_key_spki_sha256,
                &member.ingress_signing_key_spki_sha256,
                &member.active_decision_signing_key_spki_sha256,
                &member.shadow_signing_key_spki_sha256,
            ] {
                if !fleet_role_key_spkis.insert(key_spki) {
                    return Err(invalid(
                        "fleet.members.signing_key_spkis",
                        "every role SPKI must be independent across the assigned fleet",
                    ));
                }
            }
        }
        for key_id in [
            &self.custody_authority.ingress_admission_key_id,
            &self.custody_authority.unavailable_ingress_key_id,
            &self.custody_authority.dispatch_barrier_key_id,
            &self.custody_authority.active_effect_barrier_key_id,
            &self.custody_authority.active_effect_commit_key_id,
            &self.custody_authority.terminal_append_key_id,
            &self.custody_authority.ledger_append_key_id,
            &self.custody_authority.spool_compaction_key_id,
            &self
                .custody_authority
                .publication_reconciliation_key_id,
            &self.custody_authority.activation_publication_key_id,
            &self.custody_authority.result_envelope_key_id,
            &self.custody_authority.store_response_key_id,
            &self.custody_authority.signer_response_key_id,
            &self.custody_authority.retrieval_response_key_id,
            &self.custody_authority.trusted_time_response_key_id,
            &self.custody_authority.provider_response_key_id,
            &self.custody_authority.attestation_verifier_key_id,
            &self.custody_authority.supervisor_capability_key_id,
        ] {
            if !fleet_role_key_ids.insert(key_id) {
                return Err(invalid(
                    "custody_authority.signing_key_ids",
                    "custody and fleet role keys must be globally independent",
                ));
            }
        }
        for key_spki in [
            &self
                .custody_authority
                .ingress_admission_key_spki_sha256,
            &self
                .custody_authority
                .unavailable_ingress_key_spki_sha256,
            &self
                .custody_authority
                .dispatch_barrier_key_spki_sha256,
            &self
                .custody_authority
                .active_effect_barrier_key_spki_sha256,
            &self
                .custody_authority
                .active_effect_commit_key_spki_sha256,
            &self.custody_authority.terminal_append_key_spki_sha256,
            &self.custody_authority.ledger_append_key_spki_sha256,
            &self
                .custody_authority
                .spool_compaction_key_spki_sha256,
            &self
                .custody_authority
                .publication_reconciliation_key_spki_sha256,
            &self
                .custody_authority
                .activation_publication_key_spki_sha256,
            &self
                .custody_authority
                .result_envelope_key_spki_sha256,
            &self
                .custody_authority
                .store_response_key_spki_sha256,
            &self
                .custody_authority
                .signer_response_key_spki_sha256,
            &self
                .custody_authority
                .retrieval_response_key_spki_sha256,
            &self
                .custody_authority
                .trusted_time_response_key_spki_sha256,
            &self
                .custody_authority
                .provider_response_key_spki_sha256,
            &self
                .custody_authority
                .attestation_verifier_key_spki_sha256,
            &self
                .custody_authority
                .supervisor_capability_key_spki_sha256,
        ] {
            if !fleet_role_key_spkis.insert(key_spki) {
                return Err(invalid(
                    "custody_authority.signing_key_spkis",
                    "custody and fleet role SPKIs must be globally independent",
                ));
            }
        }
        let member_leaves: Vec<(u64, Sha256Digest)> = self
            .fleet
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                Ok((
                    u64::try_from(index + 1).map_err(|_| ShadowError::CounterOverflow)?,
                    Sha256Digest::compute(&canonical_json_bytes(member)?),
                ))
            })
            .collect::<Result<_, ShadowError>>()?;
        if merkle_root(&member_leaves)? != self.fleet.membership_root_sha256 {
            return Err(ShadowError::MerkleRootMismatch);
        }
        let window = &self.observation_window;
        validate_positive(window.minimum_duration_nanos, "minimum_duration_nanos")?;
        validate_positive(window.first_ingress_sequence, "first_ingress_sequence")?;
        validate_positive(
            window.request_commitment_key_epoch,
            "request_commitment_key_epoch",
        )?;
        validate_positive(
            window.maximum_evidence_age_nanos,
            "maximum_evidence_age_nanos",
        )?;
        validate_positive(
            window.maximum_heartbeat_gap_nanos,
            "maximum_heartbeat_gap_nanos",
        )?;
        if window.sampling_basis_points == 0 || window.sampling_basis_points > 10_000 {
            return Err(invalid("sampling_basis_points", "must be 1..=10000"));
        }
        let window_duration = window
            .ends_at_unix_nanos
            .checked_sub(window.starts_at_unix_nanos)
            .ok_or_else(|| invalid("observation_window", "duration overflow"))?;
        if window.ends_at_unix_nanos <= window.starts_at_unix_nanos
            || window.seal_deadline_unix_nanos <= window.ends_at_unix_nanos
            || window_duration
                < i64::try_from(window.minimum_duration_nanos)
                    .map_err(|_| invalid("minimum_duration_nanos", "out of range"))?
            || window_duration
                < i64::try_from(window.maximum_heartbeat_gap_nanos)
                    .map_err(|_| {
                        invalid("maximum_heartbeat_gap_nanos", "out of range")
                    })?
            || self.issued_at_unix_nanos > window.starts_at_unix_nanos
            || self.expires_at_unix_nanos < window.seal_deadline_unix_nanos
        {
            return Err(invalid("observation_window", "invalid bounded window"));
        }
        validate_positive(
            self.readiness_thresholds.minimum_ingress_requests,
            "minimum_ingress_requests",
        )?;
        validate_positive(
            self.readiness_thresholds.minimum_evaluated_observations,
            "minimum_evaluated_observations",
        )?;
        validate_positive(
            self.readiness_thresholds.minimum_ingress_requests_per_member,
            "minimum_ingress_requests_per_member",
        )?;
        validate_positive(
            self.readiness_thresholds
                .minimum_evaluated_observations_per_member,
            "minimum_evaluated_observations_per_member",
        )?;
        validate_positive(
            self.readiness_thresholds.maximum_candidate_evaluation_p99_nanos,
            "maximum_candidate_evaluation_p99_nanos",
        )?;
        validate_positive(
            self.readiness_thresholds.maximum_shadow_total_p99_nanos,
            "maximum_shadow_total_p99_nanos",
        )?;
        Ok(())
    }
}

pub(crate) type VerifiedAssignment = VerifiedSignedEnvelope<PolicyShadowAssignmentPayload>;

pub(crate) fn verify_assignment(
    wire: SignedEnvelope<PolicyShadowAssignmentPayload>,
    assignment_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedAssignment, ShadowError> {
    let assignment = verify_envelope(
        wire,
        assignment_signer,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    let mut roles = vec![(
        &assignment.envelope.signing_key_id,
        &assignment.envelope.signing_key_spki_sha256,
    )];
    roles.extend(
        assignment
            .payload()
            .authority_key_independence
            .bindings
            .iter()
            .map(|binding| {
                (&binding.key_id, &binding.key_spki_sha256)
            }),
    );
    enforce_cross_document_role_key_independence(roles)?;
    verify_assignment_authority_key_material(&assignment, key_trust)?;
    Ok(assignment)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LoadedSnapshots {
    active: CompiledPolicySnapshotIdentity,
    candidate: CompiledPolicySnapshotIdentity,
    request_facts_schema_sha256: Sha256Digest,
    effect_capabilities_exposed_to_candidate: bool,
}

impl LoadedSnapshots {
    pub fn new_side_effect_free(
        active: CompiledPolicySnapshotIdentity,
        candidate: CompiledPolicySnapshotIdentity,
        request_facts_schema_sha256: Sha256Digest,
    ) -> Self {
        Self {
            active,
            candidate,
            request_facts_schema_sha256,
            effect_capabilities_exposed_to_candidate: false,
        }
    }

    fn assigned_identities(&self) -> AssignedSnapshotIdentities {
        AssignedSnapshotIdentities {
            active: self.active.clone(),
            candidate: self.candidate.clone(),
            request_facts_schema_sha256: self.request_facts_schema_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyShadowLoadReceiptPayload {
    receipt_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    canary_id: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    generation_epoch: u64,
    generation_tombstone_epoch: u64,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    observation_interval_sha256: Sha256Digest,
    response_validation_obligations_root_sha256: Sha256Digest,
    custody_authority_sha256: Sha256Digest,
    authority_key_independence_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    authoritative_ledger_event_ordinal: u64,
    authoritative_ledger_head_sha256: Sha256Digest,
    authoritative_spool_root_sha256: Sha256Digest,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    loaded_snapshots: LoadedSnapshots,
    load_sequence: u64,
    loaded_at_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    status: String,
}

impl PolicyShadowLoadReceiptPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        receipt_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        canary_id: Sha256Digest,
        fleet_id: Sha256Digest,
        fleet_membership_revision: u64,
        generation_epoch: u64,
        generation_tombstone_epoch: u64,
        ingress_range_start_sequence: u64,
        ingress_range_predecessor_head_sha256: Sha256Digest,
        observation_interval_sha256: Sha256Digest,
        response_validation_obligations_root_sha256: Sha256Digest,
        custody_authority_sha256: Sha256Digest,
        authority_key_independence_sha256: Sha256Digest,
        publication_reconciliation_receipt_sha256: Sha256Digest,
        publication_revision: u64,
        authoritative_ledger_event_ordinal: u64,
        authoritative_ledger_head_sha256: Sha256Digest,
        authoritative_spool_root_sha256: Sha256Digest,
        policy_identity: PolicyIdentity,
        runtime_identity: RuntimeIdentity,
        loaded_snapshots: LoadedSnapshots,
        load_sequence: u64,
        loaded_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        let payload = Self {
            receipt_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            canary_id,
            fleet_id,
            fleet_membership_revision,
            generation_epoch,
            generation_tombstone_epoch,
            ingress_range_start_sequence,
            ingress_range_predecessor_head_sha256,
            observation_interval_sha256,
            response_validation_obligations_root_sha256,
            custody_authority_sha256,
            authority_key_independence_sha256,
            publication_reconciliation_receipt_sha256,
            publication_revision,
            authoritative_ledger_event_ordinal,
            authoritative_ledger_head_sha256,
            authoritative_spool_root_sha256,
            policy_identity,
            runtime_identity,
            loaded_snapshots,
            load_sequence,
            loaded_at_unix_nanos,
            issued_at_unix_nanos: loaded_at_unix_nanos,
            expires_at_unix_nanos,
            status: "loaded-side-effect-free".to_string(),
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }

    pub fn runtime_identity(&self) -> &RuntimeIdentity {
        &self.runtime_identity
    }

    pub fn load_sequence(&self) -> u64 {
        self.load_sequence
    }
}

impl EnvelopePayload for PolicyShadowLoadReceiptPayload {
    const API_VERSION: &'static str = LOAD_RECEIPT_DOMAIN;
    const KIND: &'static str = "PolicyShadowLoadReceipt";
    const SIGNATURE_DOMAIN: &'static str = LOAD_RECEIPT_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(
            self.fleet_membership_revision,
            "fleet_membership_revision",
        )?;
        validate_positive(self.load_sequence, "load_sequence")?;
        validate_positive(self.generation_epoch, "generation_epoch")?;
        validate_positive(
            self.generation_tombstone_epoch,
            "generation_tombstone_epoch",
        )?;
        validate_positive(
            self.ingress_range_start_sequence,
            "ingress_range_start_sequence",
        )?;
        validate_positive(
            self.publication_revision,
            "publication_revision",
        )?;
        validate_unsigned(
            self.authoritative_ledger_event_ordinal,
            "authoritative_ledger_event_ordinal",
        )?;
        if self.generation_tombstone_epoch > self.generation_epoch {
            return Err(ShadowError::GenerationTombstoned);
        }
        self.policy_identity.validate()?;
        self.loaded_snapshots
            .assigned_identities()
            .validate_against_policy(&self.policy_identity)?;
        if self.loaded_snapshots.effect_capabilities_exposed_to_candidate {
            return Err(ShadowError::CandidateCapabilityExposure);
        }
        if self.status != "loaded-side-effect-free"
            || self.loaded_at_unix_nanos != self.issued_at_unix_nanos
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err(invalid("load_receipt", "invalid load status or issuance"));
        }
        Ok(())
    }
}

pub(crate) type VerifiedLoadReceipt = VerifiedSignedEnvelope<PolicyShadowLoadReceiptPayload>;

/// TEE verification is deployment-specific. This trusted capability must
/// resolve `teeEvidenceSha256`, validate freshness and endorsement chains, and
/// bind the measured boot, SPIFFE identity, and both runtime signing keys to
/// the exact assigned member.
pub(crate) trait RuntimeAttestationVerification {
    fn verify_runtime_identity(
        &self,
        trust_checkpoint: &AtomicTrustCheckpoint,
        runtime: &RuntimeIdentity,
        assigned_member: &FleetMember,
        assignment_payload_sha256: &Sha256Digest,
        trusted_now_unix_nanos: i64,
    ) -> Result<(), ShadowError>;
}

pub(crate) fn verify_load_receipt(
    wire: SignedEnvelope<PolicyShadowLoadReceiptPayload>,
    assignment: &VerifiedAssignment,
    attestation: &dyn RuntimeAttestationVerification,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedLoadReceipt, ShadowError> {
    revalidate_verified_freshness(
        assignment,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    verify_assignment_authority_key_material(assignment, key_trust)?;
    let member = assignment
        .payload()
        .fleet
        .members
        .iter()
        .find(|member| member.instance_id == wire.payload.runtime_identity.instance_id)
        .ok_or(ShadowError::BindingDrift)?;
    let receipt = verify_envelope(
        wire,
        ExpectedSigner {
            key_id: &member.shadow_signing_key_id,
            key_spki_sha256: &member.shadow_signing_key_spki_sha256,
        },
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    verify_load_receipt_binding(&receipt, assignment)?;
    let trust_checkpoint = key_trust.current_checkpoint()?;
    attestation.verify_runtime_identity(
        &trust_checkpoint,
        &receipt.payload().runtime_identity,
        member,
        assignment.payload_sha256(),
        trusted_time.now_unix_nanos()?,
    )?;
    if key_trust.current_checkpoint()? != trust_checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(receipt)
}

pub(crate) fn verify_load_receipt_binding(
    receipt: &VerifiedLoadReceipt,
    assignment: &VerifiedAssignment,
) -> Result<(), ShadowError> {
    let receipt = receipt.payload();
    let assignment_payload = assignment.payload();
    let member = assignment_payload
        .fleet
        .members
        .iter()
        .find(|member| member.instance_id == receipt.runtime_identity.instance_id)
        .ok_or(ShadowError::BindingDrift)?;
    if receipt.assignment_sha256 != *assignment.envelope_sha256()
        || receipt.assignment_payload_sha256 != *assignment.payload_sha256()
        || receipt.assignment_revision != assignment_payload.assignment_revision
        || receipt.canary_id != assignment_payload.canary_id
        || receipt.fleet_id != assignment_payload.fleet.fleet_id
        || receipt.fleet_membership_revision != assignment_payload.fleet.membership_revision
        || receipt.generation_epoch != assignment_payload.generation_epoch
        || receipt.generation_tombstone_epoch
            < assignment_payload.minimum_generation_tombstone_epoch
        || receipt.generation_tombstone_epoch > receipt.generation_epoch
        || receipt.ingress_range_start_sequence
            != assignment_payload.observation_window.first_ingress_sequence
        || receipt.observation_interval_sha256
            != Sha256Digest::compute(&canonical_json_bytes(
                &assignment_payload.observation_window,
            )?)
        || receipt.response_validation_obligations_root_sha256
            != assignment_payload.response_validation_obligations_root_sha256
        || receipt.custody_authority_sha256
            != Sha256Digest::compute(&canonical_json_bytes(
                &assignment_payload.custody_authority,
            )?)
        || receipt.authority_key_independence_sha256
            != assignment_payload
                .authority_key_independence
                .independence_root_sha256
        || receipt.policy_identity != assignment_payload.policy_identity
        || receipt.loaded_snapshots.assigned_identities()
            != assignment_payload.expected_loaded_snapshots
        || !receipt.runtime_identity.matches_member(member)
        || receipt.loaded_at_unix_nanos < assignment_payload.observation_window.starts_at_unix_nanos
        || receipt.expires_at_unix_nanos > assignment_payload.expires_at_unix_nanos
    {
        return Err(ShadowError::BindingDrift);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShadowGenerationIdentity {
    generation_id: Sha256Digest,
    generation_epoch: u64,
    minimum_generation_tombstone_epoch: u64,
    generation_tombstone_epoch: u64,
    assignment_revision: u64,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    active_policy_sha256: Sha256Digest,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    active_compiled_snapshot_sha256: Sha256Digest,
    candidate_policy_sha256: Sha256Digest,
    candidate_policy_sequence: u64,
    candidate_rollback_epoch: u64,
    candidate_compiled_snapshot_sha256: Sha256Digest,
    runtime_boot_id_sha256: Sha256Digest,
    assignment_starts_at_unix_nanos: i64,
    assignment_ends_at_unix_nanos: i64,
    sampling_basis_points: u16,
    request_commitment_key_id: Sha256Digest,
    request_commitment_key_epoch: u64,
    request_facts_schema_sha256: Sha256Digest,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    observation_interval_sha256: Sha256Digest,
    response_validation_obligations_root_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    authoritative_ledger_event_ordinal: u64,
    authoritative_ledger_head_sha256: Sha256Digest,
    authoritative_spool_root_sha256: Sha256Digest,
}

impl ShadowGenerationIdentity {
    pub(crate) fn derive(
        assignment: &VerifiedAssignment,
        load_receipt: &VerifiedLoadReceipt,
    ) -> Result<Self, ShadowError> {
        verify_load_receipt_binding(load_receipt, assignment)?;
        let receipt = load_receipt.payload();
        let mut identity = Self {
            generation_id: Sha256Digest::compute(b"uninitialized"),
            generation_epoch: receipt.generation_epoch,
            minimum_generation_tombstone_epoch: assignment
                .payload()
                .minimum_generation_tombstone_epoch(),
            generation_tombstone_epoch: receipt.generation_tombstone_epoch,
            assignment_revision: assignment.payload().assignment_revision,
            assignment_sha256: assignment.envelope_sha256().clone(),
            assignment_payload_sha256: assignment.payload_sha256().clone(),
            load_receipt_sha256: load_receipt.envelope_sha256().clone(),
            load_receipt_payload_sha256: load_receipt.payload_sha256().clone(),
            active_policy_sha256: receipt.loaded_snapshots.active.policy_sha256.clone(),
            active_policy_sequence: receipt.loaded_snapshots.active.policy_sequence,
            active_rollback_epoch: receipt.loaded_snapshots.active.rollback_epoch,
            active_compiled_snapshot_sha256: receipt
                .loaded_snapshots
                .active
                .compiled_snapshot_sha256
                .clone(),
            candidate_policy_sha256: receipt
                .loaded_snapshots
                .candidate
                .policy_sha256
                .clone(),
            candidate_policy_sequence: receipt
                .loaded_snapshots
                .candidate
                .policy_sequence,
            candidate_rollback_epoch: receipt
                .loaded_snapshots
                .candidate
                .rollback_epoch,
            candidate_compiled_snapshot_sha256: receipt
                .loaded_snapshots
                .candidate
                .compiled_snapshot_sha256
                .clone(),
            runtime_boot_id_sha256: receipt.runtime_identity.boot_id_sha256.clone(),
            assignment_starts_at_unix_nanos: assignment
                .payload()
                .observation_window
                .starts_at_unix_nanos,
            assignment_ends_at_unix_nanos: assignment
                .payload()
                .observation_window
                .ends_at_unix_nanos,
            sampling_basis_points: assignment
                .payload()
                .observation_window
                .sampling_basis_points,
            request_commitment_key_id: assignment
                .payload()
                .observation_window
                .request_commitment_key_id
                .clone(),
            request_commitment_key_epoch: assignment
                .payload()
                .observation_window
                .request_commitment_key_epoch,
            request_facts_schema_sha256: assignment
                .payload()
                .expected_loaded_snapshots
                .request_facts_schema_sha256
                .clone(),
            ingress_range_start_sequence: receipt
                .ingress_range_start_sequence,
            ingress_range_predecessor_head_sha256: receipt
                .ingress_range_predecessor_head_sha256
                .clone(),
            observation_interval_sha256: receipt.observation_interval_sha256.clone(),
            response_validation_obligations_root_sha256: receipt
                .response_validation_obligations_root_sha256
                .clone(),
            publication_reconciliation_receipt_sha256: receipt
                .publication_reconciliation_receipt_sha256
                .clone(),
            publication_revision: receipt.publication_revision,
            authoritative_ledger_event_ordinal: receipt
                .authoritative_ledger_event_ordinal,
            authoritative_ledger_head_sha256: receipt
                .authoritative_ledger_head_sha256
                .clone(),
            authoritative_spool_root_sha256: receipt
                .authoritative_spool_root_sha256
                .clone(),
        };
        identity.generation_id = identity.recompute_id()?;
        identity.validate()?;
        Ok(identity)
    }

    fn recompute_id(&self) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyShadowGeneration/v1",
            &[
                &canonical_json_bytes(&serde_json::json!([
                    self.generation_epoch,
                    self.minimum_generation_tombstone_epoch,
                    self.generation_tombstone_epoch,
                    self.assignment_revision,
                    &self.assignment_sha256,
                    &self.assignment_payload_sha256,
                    &self.load_receipt_sha256,
                    &self.load_receipt_payload_sha256,
                    &self.active_policy_sha256,
                    self.active_policy_sequence,
                    self.active_rollback_epoch,
                    &self.active_compiled_snapshot_sha256,
                    &self.candidate_policy_sha256,
                    self.candidate_policy_sequence,
                    self.candidate_rollback_epoch,
                    &self.candidate_compiled_snapshot_sha256,
                    &self.runtime_boot_id_sha256,
                ]))?,
                &canonical_json_bytes(&(
                    self.assignment_starts_at_unix_nanos,
                    self.assignment_ends_at_unix_nanos,
                    self.sampling_basis_points,
                    &self.request_commitment_key_id,
                    self.request_commitment_key_epoch,
                    &self.request_facts_schema_sha256,
                    self.ingress_range_start_sequence,
                    &self.ingress_range_predecessor_head_sha256,
                    &self.observation_interval_sha256,
                    &self.response_validation_obligations_root_sha256,
                    &self.publication_reconciliation_receipt_sha256,
                    self.publication_revision,
                    self.authoritative_ledger_event_ordinal,
                    &self.authoritative_ledger_head_sha256,
                    &self.authoritative_spool_root_sha256,
                ))?,
            ],
        ))
    }

    fn validate(&self) -> Result<(), ShadowError> {
        validate_positive(self.generation_epoch, "generation.generation_epoch")?;
        validate_positive(
            self.minimum_generation_tombstone_epoch,
            "generation.minimum_generation_tombstone_epoch",
        )?;
        validate_positive(
            self.generation_tombstone_epoch,
            "generation.generation_tombstone_epoch",
        )?;
        validate_positive(self.assignment_revision, "generation.assignment_revision")?;
        validate_positive(
            self.active_policy_sequence,
            "generation.active_policy_sequence",
        )?;
        validate_positive(
            self.active_rollback_epoch,
            "generation.active_rollback_epoch",
        )?;
        validate_positive(
            self.candidate_policy_sequence,
            "generation.candidate_policy_sequence",
        )?;
        validate_positive(
            self.candidate_rollback_epoch,
            "generation.candidate_rollback_epoch",
        )?;
        validate_positive(
            self.request_commitment_key_epoch,
            "generation.request_commitment_key_epoch",
        )?;
        validate_positive(
            self.ingress_range_start_sequence,
            "generation.ingress_range_start_sequence",
        )?;
        validate_positive(
            self.publication_revision,
            "generation.publication_revision",
        )?;
        validate_unsigned(
            self.authoritative_ledger_event_ordinal,
            "generation.authoritative_ledger_event_ordinal",
        )?;
        if self.generation_tombstone_epoch > self.generation_epoch
            || self.generation_tombstone_epoch
                < self.minimum_generation_tombstone_epoch
            || self.assignment_starts_at_unix_nanos < 0
            || self.assignment_ends_at_unix_nanos
                <= self.assignment_starts_at_unix_nanos
            || !(1..=10_000).contains(&self.sampling_basis_points)
            || self.candidate_policy_sequence <= self.active_policy_sequence
            || self.candidate_policy_sha256 == self.active_policy_sha256
            || self.recompute_id()? != self.generation_id
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }

    pub(crate) fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    pub(crate) fn generation_epoch(&self) -> u64 {
        self.generation_epoch
    }

    pub(crate) fn generation_tombstone_epoch(&self) -> u64 {
        self.generation_tombstone_epoch
    }

    pub(crate) fn minimum_generation_tombstone_epoch(&self) -> u64 {
        self.minimum_generation_tombstone_epoch
    }

    pub(crate) fn active_compiled_snapshot_sha256(&self) -> &Sha256Digest {
        &self.active_compiled_snapshot_sha256
    }

    pub(crate) fn assignment_revision(&self) -> u64 {
        self.assignment_revision
    }

    pub(crate) fn assignment_sha256(&self) -> &Sha256Digest {
        &self.assignment_sha256
    }

    pub(crate) fn assignment_payload_sha256(&self) -> &Sha256Digest {
        &self.assignment_payload_sha256
    }

    pub(crate) fn load_receipt_sha256(&self) -> &Sha256Digest {
        &self.load_receipt_sha256
    }

    pub(crate) fn load_receipt_payload_sha256(&self) -> &Sha256Digest {
        &self.load_receipt_payload_sha256
    }

    pub(crate) fn active_policy_sha256(&self) -> &Sha256Digest {
        &self.active_policy_sha256
    }

    pub(crate) fn active_policy_sequence(&self) -> u64 {
        self.active_policy_sequence
    }

    pub(crate) fn active_rollback_epoch(&self) -> u64 {
        self.active_rollback_epoch
    }

    pub(crate) fn candidate_policy_sha256(&self) -> &Sha256Digest {
        &self.candidate_policy_sha256
    }

    pub(crate) fn candidate_policy_sequence(&self) -> u64 {
        self.candidate_policy_sequence
    }

    pub(crate) fn candidate_rollback_epoch(&self) -> u64 {
        self.candidate_rollback_epoch
    }

    pub(crate) fn candidate_compiled_snapshot_sha256(&self) -> &Sha256Digest {
        &self.candidate_compiled_snapshot_sha256
    }

    pub(crate) fn runtime_boot_id_sha256(&self) -> &Sha256Digest {
        &self.runtime_boot_id_sha256
    }

    pub(crate) fn assignment_window_unix_nanos(&self) -> (i64, i64) {
        (
            self.assignment_starts_at_unix_nanos,
            self.assignment_ends_at_unix_nanos,
        )
    }

    pub(crate) fn sampling_basis_points(&self) -> u16 {
        self.sampling_basis_points
    }

    pub(crate) fn request_commitment_key_binding(&self) -> (&Sha256Digest, u64) {
        (
            &self.request_commitment_key_id,
            self.request_commitment_key_epoch,
        )
    }

    pub(crate) fn request_facts_schema_sha256(&self) -> &Sha256Digest {
        &self.request_facts_schema_sha256
    }

    pub(crate) fn ingress_range_predecessor_head_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.ingress_range_predecessor_head_sha256
    }

    pub(crate) fn ingress_range_start_sequence(&self) -> u64 {
        self.ingress_range_start_sequence
    }

    pub(crate) fn response_validation_obligations_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.response_validation_obligations_root_sha256
    }

    pub(crate) fn observation_interval_sha256(&self) -> &Sha256Digest {
        &self.observation_interval_sha256
    }

    pub(crate) fn publication_reconciliation_receipt_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.publication_reconciliation_receipt_sha256
    }

    pub(crate) fn signed_publication_revision(&self) -> u64 {
        self.publication_revision
    }

    pub(crate) fn authoritative_ledger_event_ordinal(&self) -> u64 {
        self.authoritative_ledger_event_ordinal
    }

    pub(crate) fn authoritative_ledger_head_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.authoritative_ledger_head_sha256
    }

    pub(crate) fn authoritative_spool_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.authoritative_spool_root_sha256
    }

    pub(crate) fn matches_recovered_custody_state(
        &self,
        recovered: &VerifiedPublicationReconciliationReceipt,
    ) -> bool {
        let (ledger_event_ordinal, ledger_head_sha256, spool_root_sha256) =
            recovered.ledger_head();
        self.publication_reconciliation_receipt_sha256
                == *recovered.signed_receipt_sha256()
            && self.publication_revision == recovered.publication_revision()
            && self.authoritative_ledger_event_ordinal
                == ledger_event_ordinal
            && self.authoritative_ledger_head_sha256
                == *ledger_head_sha256
            && self.authoritative_spool_root_sha256 == *spool_root_sha256
    }
}

/// Every operation which can mutate custody state has one closed operation
/// class. A supervisor-issued call context is bound to exactly one class, so a
/// provider cannot reuse an operation id for a different mutation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PolicyShadowCustodyOperation {
    RecoverCurrentState,
    VerifyCheckpointSuccessor,
    VerifyCurrentCheckpointHead,
    VerifyObservationEvidence,
    PrepareGenerationPublication,
    CommitGenerationPublication,
    AbortGenerationPublication,
    BeginIngress,
    ReserveSpoolAppend,
    AppendSpoolEvent,
    CompactSpool,
    CommitRequest,
    AppendActiveEffectBarrier,
    CommitActiveEffect,
    ReconcileActiveEffect,
    AppendTerminal,
    ConsumeAndPublishActivation,
}

const MAX_PRODUCTION_CUSTODY_CLEANUP_NANOS: u64 = 5_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyOperationDeadline {
    supervisor_boot_id_sha256: Sha256Digest,
    opened_at_boottime_nanos: u64,
    operation_deadline_boottime_nanos: u64,
    cleanup_not_before_boottime_nanos: u64,
    cleanup_deadline_boottime_nanos: u64,
}

impl ProductionCustodyOperationDeadline {
    fn open(
        supervisor_boot_id_sha256: Sha256Digest,
        maximum_rpc_nanos: u64,
        cleanup_reserve_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_positive(maximum_rpc_nanos, "custody.maximum_rpc_nanos")?;
        validate_positive(
            cleanup_reserve_nanos,
            "custody.cleanup_reserve_nanos",
        )?;
        if cleanup_reserve_nanos > MAX_PRODUCTION_CUSTODY_CLEANUP_NANOS {
            return Err(ShadowError::CustodyUnavailable);
        }
        let opened_at_boottime_nanos =
            production_now_boottime_nanos()?;
        let operation_deadline_boottime_nanos =
            opened_at_boottime_nanos
                .checked_add(maximum_rpc_nanos)
                .ok_or(ShadowError::CounterOverflow)?;
        let cleanup_not_before_boottime_nanos =
            operation_deadline_boottime_nanos;
        let cleanup_deadline_boottime_nanos =
            operation_deadline_boottime_nanos
                .checked_add(cleanup_reserve_nanos)
                .ok_or(ShadowError::CounterOverflow)?;
        Ok(Self {
            supervisor_boot_id_sha256,
            opened_at_boottime_nanos,
            operation_deadline_boottime_nanos,
            cleanup_not_before_boottime_nanos,
            cleanup_deadline_boottime_nanos,
        })
    }

    fn validate_at(
        &self,
        now_boottime_nanos: u64,
        configuration: &ProductionCustodyConfiguration,
    ) -> Result<(), ShadowError> {
        if self.supervisor_boot_id_sha256
                != configuration.supervisor_boot_id_sha256
            || self.operation_deadline_boottime_nanos
                <= self.opened_at_boottime_nanos
            || self.cleanup_not_before_boottime_nanos
                != self.operation_deadline_boottime_nanos
            || self.cleanup_deadline_boottime_nanos
                <= self.operation_deadline_boottime_nanos
            || self
                .operation_deadline_boottime_nanos
                .checked_sub(self.opened_at_boottime_nanos)
                != Some(configuration.maximum_rpc_nanos)
            || self
                .cleanup_deadline_boottime_nanos
                .checked_sub(self.operation_deadline_boottime_nanos)
                != Some(configuration.cleanup_reserve_nanos)
            || now_boottime_nanos < self.opened_at_boottime_nanos
            || now_boottime_nanos
                >= self.operation_deadline_boottime_nanos
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn operation_deadline_boottime_nanos(
        &self,
    ) -> u64 {
        self.operation_deadline_boottime_nanos
    }

    pub(in crate::policy_shadow) fn supervisor_boot_id_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.supervisor_boot_id_sha256
    }

    pub(in crate::policy_shadow) fn opened_at_boottime_nanos(
        &self,
    ) -> u64 {
        self.opened_at_boottime_nanos
    }

    pub(in crate::policy_shadow) fn cleanup_not_before_boottime_nanos(
        &self,
    ) -> u64 {
        self.cleanup_not_before_boottime_nanos
    }

    pub(in crate::policy_shadow) fn cleanup_deadline_boottime_nanos(
        &self,
    ) -> u64 {
        self.cleanup_deadline_boottime_nanos
    }

    pub(in crate::policy_shadow) fn cleanup_interval(
        &self,
    ) -> (u64, u64) {
        (
            self.cleanup_not_before_boottime_nanos,
            self.cleanup_deadline_boottime_nanos,
        )
    }

    pub(in crate::policy_shadow) fn authorizes_operation_at(
        &self,
        now_boottime_nanos: u64,
    ) -> bool {
        now_boottime_nanos >= self.opened_at_boottime_nanos
            && now_boottime_nanos
                < self.operation_deadline_boottime_nanos
    }

    pub(in crate::policy_shadow) fn authorizes_cleanup_at(
        &self,
        now_boottime_nanos: u64,
    ) -> bool {
        now_boottime_nanos >= self.opened_at_boottime_nanos
            && now_boottime_nanos
                < self.cleanup_deadline_boottime_nanos
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn production_now_boottime_nanos() -> Result<u64, ShadowError> {
    policy_custody::boottime_now_nanos()
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn production_now_boottime_nanos() -> Result<u64, ShadowError> {
    Err(ShadowError::CustodyUnavailable)
}

/// This capability can only be issued by the configured RPC supervisor. The
/// supervisor owns an operation-id CAS, an isolated provider worker/transport,
/// and a termination fence. `finish_call` does not succeed until the provider
/// worker has exited or been killed and the fence rejects every late mutation.
/// It is intentionally not `Clone`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PolicyShadowCustodyCallContext {
    operation_id_sha256: Sha256Digest,
    request_binding_sha256: Sha256Digest,
    operation_deadline: ProductionCustodyOperationDeadline,
    operation: PolicyShadowCustodyOperation,
    supervisor_instance_sha256: Sha256Digest,
    termination_fence_sha256: Sha256Digest,
    operation_handle: policy_custody::OpaqueOperationHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyShadowCustodyCallCompletionBinding {
    operation_id_sha256: Sha256Digest,
    operation_deadline: ProductionCustodyOperationDeadline,
}

impl PolicyShadowCustodyCallContext {
    pub(crate) fn from_supervisor(
        operation_id_sha256: Sha256Digest,
        request_binding_sha256: Sha256Digest,
        operation_deadline: ProductionCustodyOperationDeadline,
        operation: PolicyShadowCustodyOperation,
        supervisor_instance_sha256: Sha256Digest,
        termination_fence_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        if !operation_deadline.authorizes_operation_at(
            production_now_boottime_nanos()?,
        ) {
            return Err(ShadowError::CustodyUnavailable);
        }
        let operation_handle =
            policy_custody::OpaqueOperationHandle::from_production_deadline(
                operation_id_sha256.clone(),
                &operation_deadline,
                termination_fence_sha256.clone(),
            )?;
        Ok(Self {
            operation_id_sha256,
            request_binding_sha256,
            operation_deadline,
            operation,
            supervisor_instance_sha256,
            termination_fence_sha256,
            operation_handle,
        })
    }

    pub(crate) fn operation_id_sha256(&self) -> &Sha256Digest {
        &self.operation_id_sha256
    }

    pub(crate) fn request_binding_sha256(&self) -> &Sha256Digest {
        &self.request_binding_sha256
    }

    pub(crate) fn completion_binding(
        &self,
    ) -> PolicyShadowCustodyCallCompletionBinding {
        PolicyShadowCustodyCallCompletionBinding {
            operation_id_sha256: self.operation_id_sha256.clone(),
            operation_deadline: self.operation_deadline.clone(),
        }
    }

    pub(in crate::policy_shadow) fn operation_deadline(
        &self,
    ) -> &ProductionCustodyOperationDeadline {
        &self.operation_deadline
    }

    pub(crate) fn authorizes(
        &self,
        operation: PolicyShadowCustodyOperation,
    ) -> bool {
        self.operation == operation
            && self.supervisor_instance_sha256.as_str().starts_with("sha256:")
            && self.termination_fence_sha256.as_str().starts_with("sha256:")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PolicyShadowCustodyCallCompletion {
    operation_id_sha256: Sha256Digest,
    terminal_cleanup_evidence:
        VerifiedProductionCustodyTerminalCleanupEvidence,
}

impl PolicyShadowCustodyCallCompletion {
    pub(crate) fn from_supervisor(
        operation_id_sha256: Sha256Digest,
        operation_deadline: &ProductionCustodyOperationDeadline,
        terminal_cleanup_evidence:
            VerifiedProductionCustodyTerminalCleanupEvidence,
    ) -> Result<Self, ShadowError> {
        if !terminal_cleanup_evidence.validates(
            &operation_id_sha256,
            operation_deadline,
        )
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(Self {
            operation_id_sha256,
            terminal_cleanup_evidence,
        })
    }

    pub(crate) fn validates(
        &self,
        operation_id_sha256: &Sha256Digest,
        operation_deadline: &ProductionCustodyOperationDeadline,
    ) -> bool {
        self.operation_id_sha256 == *operation_id_sha256
            && self
                .terminal_cleanup_evidence
                .validates(
                operation_id_sha256,
                operation_deadline,
            )
    }

    pub(crate) fn validates_binding(
        &self,
        binding: &PolicyShadowCustodyCallCompletionBinding,
    ) -> bool {
        self.validates(
            &binding.operation_id_sha256,
            &binding.operation_deadline,
        )
    }

    pub(crate) fn receipt_releasable(&self) -> bool {
        self.terminal_cleanup_evidence.result_disposition
            == ProductionCustodyResultDisposition::ResultCommitted
    }

    pub(crate) fn result_disposition(
        &self,
    ) -> ProductionCustodyResultDisposition {
        self.terminal_cleanup_evidence.result_disposition
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PublicationReconciliationState {
    Uninstalled,
    Prepared,
    Committed,
    Published,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PublicationReconciliationReceiptWire {
    state: PublicationReconciliationState,
    publication_revision: u64,
    predecessor_generation_sha256: Option<Sha256Digest>,
    committed_generation_sha256: Option<Sha256Digest>,
    published_generation_sha256: Option<Sha256Digest>,
    first_ingress_sequence: Option<u64>,
    last_ingress_sequence: Option<u64>,
    ledger_event_ordinal: u64,
    ledger_head_sha256: Sha256Digest,
    spool_root_sha256: Sha256Digest,
    prepared_publication_sha256: Option<Sha256Digest>,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signer_role: PolicyShadowCustodySignerRole,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl PublicationReconciliationReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        state: PublicationReconciliationState,
        publication_revision: u64,
        predecessor_generation_sha256: Option<Sha256Digest>,
        committed_generation_sha256: Option<Sha256Digest>,
        published_generation_sha256: Option<Sha256Digest>,
        first_ingress_sequence: Option<u64>,
        last_ingress_sequence: Option<u64>,
        ledger_event_ordinal: u64,
        ledger_head_sha256: Sha256Digest,
        spool_root_sha256: Sha256Digest,
        prepared_publication_sha256: Option<Sha256Digest>,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            publication_revision,
            "publication_reconciliation.publication_revision",
        )?;
        if trusted_observed_at_unix_nanos <= 0
            || first_ingress_sequence.is_some()
                != last_ingress_sequence.is_some()
            || first_ingress_sequence
                .zip(last_ingress_sequence)
                .is_some_and(|(first, last)| first == 0 || last < first)
            || matches!(
                state,
                PublicationReconciliationState::Committed
                    | PublicationReconciliationState::Published
            ) && committed_generation_sha256.is_none()
            || state == PublicationReconciliationState::Published
                && published_generation_sha256
                    != committed_generation_sha256
            || state != PublicationReconciliationState::Published
                && published_generation_sha256.is_some()
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let receipt = Self {
            state,
            publication_revision,
            predecessor_generation_sha256,
            committed_generation_sha256,
            published_generation_sha256,
            first_ingress_sequence,
            last_ingress_sequence,
            ledger_event_ordinal,
            ledger_head_sha256,
            spool_root_sha256,
            prepared_publication_sha256,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signer_role:
                PolicyShadowCustodySignerRole::PublicationReconciliation,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        };
        let canonical_payload = receipt.canonical_payload()?;
        let expected_signed_receipt = hash_domain_frames(
            b"serverware.policyShadowPublicationReconciliationReceipt/v1",
            &[
                canonical_payload.as_slice(),
                receipt.signature.0.as_bytes(),
            ],
        );
        if receipt.signed_receipt_sha256 != expected_signed_receipt {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(receipt)
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let reconstructed = Self::from_custody(
            self.state,
            self.publication_revision,
            self.predecessor_generation_sha256.clone(),
            self.committed_generation_sha256.clone(),
            self.published_generation_sha256.clone(),
            self.first_ingress_sequence,
            self.last_ingress_sequence,
            self.ledger_event_ordinal,
            self.ledger_head_sha256.clone(),
            self.spool_root_sha256.clone(),
            self.prepared_publication_sha256.clone(),
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            self.state,
            self.publication_revision,
            &self.predecessor_generation_sha256,
            &self.committed_generation_sha256,
            &self.published_generation_sha256,
            &self.first_ingress_sequence,
            &self.last_ingress_sequence,
            self.ledger_event_ordinal,
            &self.ledger_head_sha256,
            &self.spool_root_sha256,
            &self.prepared_publication_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            self.signer_role,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VerifiedPublicationReconciliationReceipt {
    wire: PublicationReconciliationReceiptWire,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[cfg(test)]
fn verify_publication_reconciliation_receipt(
    wire: PublicationReconciliationReceiptWire,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        wire.signer_role,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedPublicationReconciliationReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_publication_reconciliation_receipt(
    wire: PublicationReconciliationReceiptWire,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    let role = PolicyShadowCustodySignerRole::PublicationReconciliation;
    if wire.signer_role != role {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let canonical_payload = wire.canonical_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            role,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedPublicationReconciliationReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl VerifiedPublicationReconciliationReceipt {
    pub(crate) fn state(&self) -> PublicationReconciliationState {
        self.wire.state
    }

    pub(crate) fn publication_revision(&self) -> u64 {
        self.wire.publication_revision
    }

    pub(crate) fn predecessor_generation_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.wire.predecessor_generation_sha256.as_ref()
    }

    pub(crate) fn committed_generation_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.wire.committed_generation_sha256.as_ref()
    }

    pub(crate) fn published_generation_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.wire.published_generation_sha256.as_ref()
    }

    pub(crate) fn sequence_bounds(&self) -> Option<(u64, u64)> {
        self.wire
            .first_ingress_sequence
            .zip(self.wire.last_ingress_sequence)
    }

    pub(crate) fn ledger_head(
        &self,
    ) -> (u64, &Sha256Digest, &Sha256Digest) {
        (
            self.wire.ledger_event_ordinal,
            &self.wire.ledger_head_sha256,
            &self.wire.spool_root_sha256,
        )
    }

    pub(crate) fn prepared_publication_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.wire.prepared_publication_sha256.as_ref()
    }

    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.wire.signed_receipt_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActiveMutableEffectKind {
    JitGrantReserve,
    JitGrantDispatch,
    JitGrantComplete,
    JitGrantAbort,
    QuotaReserve,
    QuotaCommit,
    QuotaCancel,
    DurableBudgetReserve,
    DurableBudgetCommit,
    DurableBudgetCancel,
    CredentialLease,
    CredentialGeneration,
    CredentialDecrypt,
    CredentialInjection,
    OauthRefresh,
    OauthExchange,
    OauthMint,
    OauthRotation,
    ReleaseReserve,
    ReleaseDispatch,
    ReleaseComplete,
    ReleaseAbort,
    ProviderSend,
    GmailChildRegister,
    GmailChildInjecting,
    GmailChildInjected,
    GmailChildDispatch,
    GmailChildProviderOutcome,
    GmailChildFailed,
    GmailChildSucceeded,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActiveEffectCommitState {
    Committed,
    Aborted,
    OutcomeUnknown,
    ReconcileRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ActiveEffectPreparation {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    effect_id_sha256: Sha256Digest,
    effect_kind: ActiveMutableEffectKind,
    effect_intent_sha256: Sha256Digest,
    prepared_state_sha256: Sha256Digest,
}

impl ActiveEffectPreparation {
    pub(crate) fn new(
        generation_id: Sha256Digest,
        ingress_sequence: u64,
        effect_kind: ActiveMutableEffectKind,
        effect_intent_sha256: Sha256Digest,
        prepared_state_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            ingress_sequence,
            "active_effect_preparation.ingress_sequence",
        )?;
        let effect_id_sha256 = hash_domain_frames(
            b"serverware.policyShadowActiveEffectPreparation/v1",
            &[&canonical_json_bytes(&(
                &generation_id,
                ingress_sequence,
                effect_kind,
                &effect_intent_sha256,
                &prepared_state_sha256,
            ))?],
        );
        Ok(Self {
            generation_id,
            ingress_sequence,
            effect_id_sha256,
            effect_kind,
            effect_intent_sha256,
            prepared_state_sha256,
        })
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let reconstructed = Self::new(
            self.generation_id.clone(),
            self.ingress_sequence,
            self.effect_kind,
            self.effect_intent_sha256.clone(),
            self.prepared_state_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(crate) fn effect_id_sha256(&self) -> &Sha256Digest {
        &self.effect_id_sha256
    }

    pub(crate) fn effect_kind(&self) -> ActiveMutableEffectKind {
        self.effect_kind
    }

    pub(crate) fn reconciliation_identity(&self) -> (&Sha256Digest, u64) {
        (&self.generation_id, self.ingress_sequence)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            &self.generation_id,
            self.ingress_sequence,
            &self.effect_id_sha256,
            self.effect_kind,
            &self.effect_intent_sha256,
            &self.prepared_state_sha256,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ActiveEffectBarrierReceiptWire {
    preparation: ActiveEffectPreparation,
    barrier_ordinal: u64,
    predecessor_head_sha256: Sha256Digest,
    resulting_head_sha256: Sha256Digest,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl ActiveEffectBarrierReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        preparation: ActiveEffectPreparation,
        barrier_ordinal: u64,
        predecessor_head_sha256: Sha256Digest,
        resulting_head_sha256: Sha256Digest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            barrier_ordinal,
            "active_effect_barrier.barrier_ordinal",
        )?;
        if trusted_observed_at_unix_nanos <= 0 {
            return Err(ShadowError::TrustedTimeUnavailable);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let wire = Self {
            preparation,
            barrier_ordinal,
            predecessor_head_sha256,
            resulting_head_sha256,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        };
        let canonical_payload = wire.canonical_payload()?;
        let expected = hash_domain_frames(
            b"serverware.policyShadowActiveEffectBarrierReceipt/v1",
            &[
                canonical_payload.as_slice(),
                wire.signature.0.as_bytes(),
            ],
        );
        if expected != wire.signed_receipt_sha256 {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(wire)
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        self.preparation.validate_deserialized_invariants()?;
        let reconstructed = Self::from_custody(
            self.preparation.clone(),
            self.barrier_ordinal,
            self.predecessor_head_sha256.clone(),
            self.resulting_head_sha256.clone(),
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            &self.preparation,
            self.barrier_ordinal,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::ActiveEffectBarrier,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
    }
}

/// A one-use capability. It is neither cloneable nor deserializable and can
/// only be produced after the exact durable barrier wire receipt has been
/// verified. Serialization is restricted to the bounded custody request wire.
#[derive(Serialize)]
pub(crate) struct VerifiedActiveEffectPermit {
    wire: ActiveEffectBarrierReceiptWire,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[cfg(test)]
fn verify_active_effect_barrier(
    wire: ActiveEffectBarrierReceiptWire,
    expected_preparation: &ActiveEffectPreparation,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedActiveEffectPermit, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.preparation != *expected_preparation {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::ActiveEffectBarrier,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedActiveEffectPermit {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_active_effect_barrier(
    wire: ActiveEffectBarrierReceiptWire,
    expected_preparation: &ActiveEffectPreparation,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedActiveEffectPermit, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.preparation != *expected_preparation {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::ActiveEffectBarrier,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedActiveEffectPermit {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl VerifiedActiveEffectPermit {
    pub(crate) fn preparation(&self) -> &ActiveEffectPreparation {
        &self.wire.preparation
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.wire.signed_receipt_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ActiveEffectCommitReceiptWire {
    effect_id_sha256: Sha256Digest,
    barrier_receipt_sha256: Sha256Digest,
    terminal_state: ActiveEffectCommitState,
    result_sha256: Sha256Digest,
    reconcile_required: bool,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl ActiveEffectCommitReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        effect_id_sha256: Sha256Digest,
        barrier_receipt_sha256: Sha256Digest,
        terminal_state: ActiveEffectCommitState,
        result_sha256: Sha256Digest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        if trusted_observed_at_unix_nanos <= 0 {
            return Err(ShadowError::TrustedTimeUnavailable);
        }
        let reconcile_required = matches!(
            terminal_state,
            ActiveEffectCommitState::OutcomeUnknown
                | ActiveEffectCommitState::ReconcileRequired
        );
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let wire = Self {
            effect_id_sha256,
            barrier_receipt_sha256,
            terminal_state,
            result_sha256,
            reconcile_required,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        };
        let canonical_payload = wire.canonical_payload()?;
        let expected = hash_domain_frames(
            b"serverware.policyShadowActiveEffectCommitReceipt/v1",
            &[
                canonical_payload.as_slice(),
                wire.signature.0.as_bytes(),
            ],
        );
        if wire.signed_receipt_sha256 != expected {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(wire)
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let reconstructed = Self::from_custody(
            self.effect_id_sha256.clone(),
            self.barrier_receipt_sha256.clone(),
            self.terminal_state,
            self.result_sha256.clone(),
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            &self.effect_id_sha256,
            &self.barrier_receipt_sha256,
            self.terminal_state,
            &self.result_sha256,
            self.reconcile_required,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::ActiveEffectCommit,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
    }
}

pub(crate) struct VerifiedActiveEffectCommitReceipt {
    wire: ActiveEffectCommitReceiptWire,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

/// Fixed-size reference to an already verified OUTER effect receipt. This is
/// neither an execution permit nor evidence of which nested provider/cache
/// operations occurred. The custody store retains the signed wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct CompactActiveEffectCommitReceipt {
    digests: [[u8; 32]; 11],
    observed_at_unix_nanos: i64,
    terminal_state: ActiveEffectCommitState,
}

impl CompactActiveEffectCommitReceipt {
    pub(crate) fn terminal_state(&self) -> ActiveEffectCommitState {
        self.terminal_state
    }

    pub(crate) fn matches_result(&self, expected: &Sha256Digest) -> bool {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(&expected.as_str()[7..], &mut bytes).is_ok()
            && bytes == self.digests[2]
    }

    pub(crate) fn matches_preparation_and_barrier(&self, effect: &Sha256Digest, barrier: &Sha256Digest) -> bool {
        [effect, barrier].into_iter().zip(self.digests[..2].iter()).all(|(expected, actual)| {
            let mut bytes = [0_u8; 32];
            hex::decode_to_slice(&expected.as_str()[7..], &mut bytes).is_ok() && &bytes == actual
        })
    }
}

#[cfg(test)]
fn verify_active_effect_commit(
    wire: ActiveEffectCommitReceiptWire,
    permit: &VerifiedActiveEffectPermit,
    expected_state: ActiveEffectCommitState,
    expected_result_sha256: &Sha256Digest,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.effect_id_sha256
            != *permit.preparation().effect_id_sha256()
        || wire.barrier_receipt_sha256
            != *permit.signed_receipt_sha256()
        || wire.terminal_state != expected_state
        || wire.result_sha256 != *expected_result_sha256
        || wire.reconcile_required
            != matches!(
                expected_state,
                ActiveEffectCommitState::OutcomeUnknown
                    | ActiveEffectCommitState::ReconcileRequired
            )
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::ActiveEffectCommit,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedActiveEffectCommitReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::policy_shadow) fn verify_production_active_effect_commit(
    wire: ActiveEffectCommitReceiptWire,
    permit: &VerifiedActiveEffectPermit,
    expected_state: ActiveEffectCommitState,
    expected_result_sha256: &Sha256Digest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.effect_id_sha256
            != *permit.preparation().effect_id_sha256()
        || wire.barrier_receipt_sha256
            != *permit.signed_receipt_sha256()
        || wire.terminal_state != expected_state
        || wire.result_sha256 != *expected_result_sha256
        || wire.reconcile_required
            != matches!(
                expected_state,
                ActiveEffectCommitState::OutcomeUnknown
                    | ActiveEffectCommitState::ReconcileRequired
            )
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::ActiveEffectCommit,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedActiveEffectCommitReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_reconciled_active_effect_commit(
    wire: ActiveEffectCommitReceiptWire,
    expected_effect_id_sha256: &Sha256Digest,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.effect_id_sha256 != *expected_effect_id_sha256
        || !wire.reconcile_required
        || !matches!(
            wire.terminal_state,
            ActiveEffectCommitState::OutcomeUnknown
                | ActiveEffectCommitState::ReconcileRequired
        )
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::ActiveEffectCommit,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedActiveEffectCommitReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_reconciled_active_effect_commit(
    wire: ActiveEffectCommitReceiptWire,
    expected_effect_id_sha256: &Sha256Digest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.effect_id_sha256 != *expected_effect_id_sha256
        || !wire.reconcile_required
        || !matches!(
            wire.terminal_state,
            ActiveEffectCommitState::OutcomeUnknown
                | ActiveEffectCommitState::ReconcileRequired
        )
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::ActiveEffectCommit,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedActiveEffectCommitReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl VerifiedActiveEffectCommitReceipt {
    pub(crate) fn compact_for(
        &self,
        preparation: &ActiveEffectPreparation,
        barrier_receipt_sha256: &Sha256Digest,
        expected_state: ActiveEffectCommitState,
        expected_result_sha256: &Sha256Digest,
    ) -> Result<CompactActiveEffectCommitReceipt, ShadowError> {
        preparation.validate_deserialized_invariants()?;
        if self.wire.effect_id_sha256 != *preparation.effect_id_sha256()
            || self.wire.barrier_receipt_sha256 != *barrier_receipt_sha256
            || self.wire.terminal_state != expected_state
            || self.wire.result_sha256 != *expected_result_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        let mut digests = [[0_u8; 32]; 11];
        for (target, source) in digests.iter_mut().zip([
            &self.wire.effect_id_sha256,
            &self.wire.barrier_receipt_sha256,
            &self.wire.result_sha256,
            &self.wire.signed_receipt_sha256,
            &self.canonical_payload_sha256,
            &self.verified_trust_checkpoint.checkpoint_id,
            &self.wire.persistence_receipt_sha256,
            &self.wire.retrieval_id_sha256,
            &self.wire.retrieval_proof_sha256,
            &self.wire.signing_key_id,
            &self.wire.signing_key_spki_sha256,
        ]) {
            hex::decode_to_slice(&source.as_str()[7..], target)
                .map_err(|_| ShadowError::PayloadDigestMismatch)?;
        }
        Ok(CompactActiveEffectCommitReceipt {
            digests,
            observed_at_unix_nanos: self.wire.trusted_observed_at_unix_nanos,
            terminal_state: expected_state,
        })
    }

    pub(crate) fn effect_id_sha256(&self) -> &Sha256Digest {
        &self.wire.effect_id_sha256
    }

    pub(crate) fn terminal_state(&self) -> ActiveEffectCommitState {
        self.wire.terminal_state
    }

    pub(crate) fn result_sha256(&self) -> &Sha256Digest {
        &self.wire.result_sha256
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.wire.signed_receipt_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TerminalSlotAppendRequest {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    terminal_event_sha256: Sha256Digest,
    terminal_event: ShadowSpoolEvent,
}

impl TerminalSlotAppendRequest {
    pub(crate) fn new(
        terminal_event: ShadowSpoolEvent,
    ) -> Result<Self, ShadowError> {
        if !matches!(
            terminal_event.phase(),
            ShadowSpoolPhase::PreDispatchTerminal
                | ShadowSpoolPhase::PostDispatchTerminal
        ) {
            return Err(ShadowError::ActiveEnforcementEvidenceMismatch);
        }
        Ok(Self {
            generation_id: terminal_event.generation_id().clone(),
            ingress_sequence: terminal_event.ingress_sequence(),
            terminal_event_sha256: terminal_event.event_sha256().clone(),
            terminal_event,
        })
    }

    pub(crate) fn terminal_event(&self) -> &ShadowSpoolEvent {
        &self.terminal_event
    }
}

pub(crate) enum TerminalSlotAppendOutcome {
    Committed(VerifiedShadowSpillReceipt),
    Existing(VerifiedShadowSpillReceipt),
    Fork(VerifiedShadowSpillReceipt),
}

/// Untrusted transport representation. The outcome tag is bound by the
/// enclosing exact production dispatch response; it grants no authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "receipt",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(in crate::policy_shadow) enum TerminalSlotAppendOutcomeWire {
    Committed(SignedShadowSpillReceipt),
    Existing(SignedShadowSpillReceipt),
    Fork(SignedShadowSpillReceipt),
}

impl TerminalSlotAppendOutcomeWire {
    fn receipt_and_expected_event(
        self,
        request: &TerminalSlotAppendRequest,
    ) -> Result<(Self, ShadowSpoolEvent), ShadowError> {
        let (receipt, fork) = match &self {
            Self::Committed(receipt) | Self::Existing(receipt) => (receipt, false),
            Self::Fork(receipt) => (receipt, true),
        };
        receipt.validate_deserialized_invariants()?;
        let requested = request.terminal_event();
        if receipt.disposition != ShadowSpoolDisposition::Appended
            || receipt.generation_id != requested.generation_id
            || receipt.ingress_sequence != requested.ingress_sequence
            || receipt.request_binding_sha256 != requested.request_binding_sha256
            || receipt.request_commitment_sha256 != requested.request_commitment_sha256
            || !matches!(
                receipt.event_phase,
                ShadowSpoolPhase::PreDispatchTerminal
                    | ShadowSpoolPhase::PostDispatchTerminal
            )
            || (fork && receipt.event_sha256 == requested.event_sha256)
            || (!fork && !receipt.matches_event(requested))
        {
            return Err(ShadowError::BindingDrift);
        }
        // A fork authenticates the stored conflicting event, not the bytes of
        // the attempted replacement. The caller still receives Fork, never a
        // successful terminal receipt for that replacement.
        let expected = ShadowSpoolEvent::new(
            receipt.generation_id.clone(),
            receipt.ingress_sequence,
            receipt.request_binding_sha256.clone(),
            receipt.request_commitment_sha256.clone(),
            receipt.event_phase,
            receipt.event_sha256.clone(),
            receipt.canonical_event_bytes.clone(),
        )?;
        Ok((self, expected))
    }
}

pub(in crate::policy_shadow) fn verify_production_terminal_slot_append_outcome(
    wire: TerminalSlotAppendOutcomeWire,
    request: &TerminalSlotAppendRequest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<TerminalSlotAppendOutcome, ShadowError> {
    let (wire, event) = wire.receipt_and_expected_event(request)?;
    match wire {
        TerminalSlotAppendOutcomeWire::Committed(receipt) => {
            Ok(TerminalSlotAppendOutcome::Committed(
                verify_production_shadow_spill_receipt(
                    receipt, &event, configuration, key_trust,
                    trusted_time, proof_verifier,
                )?,
            ))
        }
        TerminalSlotAppendOutcomeWire::Existing(receipt) => {
            Ok(TerminalSlotAppendOutcome::Existing(
                verify_production_shadow_spill_receipt(
                    receipt, &event, configuration, key_trust,
                    trusted_time, proof_verifier,
                )?,
            ))
        }
        TerminalSlotAppendOutcomeWire::Fork(receipt) => {
            Ok(TerminalSlotAppendOutcome::Fork(
                verify_production_shadow_spill_receipt(
                    receipt, &event, configuration, key_trust,
                    trusted_time, proof_verifier,
                )?,
            ))
        }
    }
}

const PRODUCTION_CUSTODY_AUTHORITY_ROLES: [AuthorityRole; 18] = [
    AuthorityRole::CustodyIngressAdmission,
    AuthorityRole::CustodyUnavailableIngress,
    AuthorityRole::CustodyDispatchBarrier,
    AuthorityRole::CustodyTerminalAppend,
    AuthorityRole::CustodyLedgerAppend,
    AuthorityRole::CustodySpoolCompaction,
    AuthorityRole::CustodyActiveEffectBarrier,
    AuthorityRole::CustodyActiveEffectCommit,
    AuthorityRole::CustodyPublicationReconciliation,
    AuthorityRole::CustodyActivationPublication,
    AuthorityRole::CustodyResultEnvelope,
    AuthorityRole::CustodyStoreResponse,
    AuthorityRole::CustodySignerResponse,
    AuthorityRole::CustodyRetrievalResponse,
    AuthorityRole::CustodyTrustedTimeResponse,
    AuthorityRole::CustodyProviderResponse,
    AuthorityRole::CustodyAttestationVerifier,
    AuthorityRole::CustodySupervisorCapability,
];

pub(crate) fn authority_role_for_custody_signer(
    role: PolicyShadowCustodySignerRole,
) -> AuthorityRole {
    match role {
        PolicyShadowCustodySignerRole::IngressAdmission => {
            AuthorityRole::CustodyIngressAdmission
        }
        PolicyShadowCustodySignerRole::UnavailableIngress => {
            AuthorityRole::CustodyUnavailableIngress
        }
        PolicyShadowCustodySignerRole::DispatchBarrier => {
            AuthorityRole::CustodyDispatchBarrier
        }
        PolicyShadowCustodySignerRole::ActiveEffectBarrier => {
            AuthorityRole::CustodyActiveEffectBarrier
        }
        PolicyShadowCustodySignerRole::ActiveEffectCommit => {
            AuthorityRole::CustodyActiveEffectCommit
        }
        PolicyShadowCustodySignerRole::TerminalAppend => {
            AuthorityRole::CustodyTerminalAppend
        }
        PolicyShadowCustodySignerRole::LedgerAppend => {
            AuthorityRole::CustodyLedgerAppend
        }
        PolicyShadowCustodySignerRole::SpoolCompaction => {
            AuthorityRole::CustodySpoolCompaction
        }
        PolicyShadowCustodySignerRole::PublicationReconciliation => {
            AuthorityRole::CustodyPublicationReconciliation
        }
        PolicyShadowCustodySignerRole::ActivationPublication => {
            AuthorityRole::CustodyActivationPublication
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProductionCustodyKeyBinding {
    role: AuthorityRole,
    key_id: Sha256Digest,
    key_spki_sha256: Sha256Digest,
    key_material_sha256: Sha256Digest,
}

impl ProductionCustodyKeyBinding {
    pub(crate) fn role(&self) -> AuthorityRole {
        self.role
    }

    pub(crate) fn key_id(&self) -> &Sha256Digest {
        &self.key_id
    }

    pub(crate) fn key_spki_sha256(&self) -> &Sha256Digest {
        &self.key_spki_sha256
    }

    pub(crate) fn key_material_sha256(&self) -> &Sha256Digest {
        &self.key_material_sha256
    }
}

pub(in crate::policy_shadow) struct ProductionCustodySignerAuthority<'a> {
    role: PolicyShadowCustodySignerRole,
    binding: &'a ProductionCustodyKeyBinding,
    proof_scope: &'a ProductionCustodyProofScope,
    _not_constructible: PhantomData<fn() -> ()>,
}

impl ProductionCustodySignerAuthority<'_> {
    pub(in crate::policy_shadow) fn role(&self) -> PolicyShadowCustodySignerRole {
        self.role
    }

    pub(in crate::policy_shadow) fn key_id(&self) -> &Sha256Digest {
        self.binding.key_id()
    }

    pub(in crate::policy_shadow) fn key_spki_sha256(&self) -> &Sha256Digest {
        self.binding.key_spki_sha256()
    }

    pub(in crate::policy_shadow) fn key_material_sha256(&self) -> &Sha256Digest {
        self.binding.key_material_sha256()
    }

    pub(in crate::policy_shadow) fn proof_scope(&self) -> &ProductionCustodyProofScope {
        self.proof_scope
    }

    /// This is the exact payload the independent signer/HSM signs for a
    /// production receipt. The ordinary receipt payload remains available to
    /// legacy verification, but is never a production signing preimage.
    pub(in crate::policy_shadow) fn assignment_bound_canonical_payload(
        &self,
        canonical_receipt_payload: &[u8],
    ) -> Result<Vec<u8>, ShadowError> {
        self.proof_scope.assignment_bound_canonical_payload(
            self.role,
            canonical_receipt_payload,
        )
    }

    pub(in crate::policy_shadow) fn assignment_bound_signature_preimage(
        &self,
        canonical_receipt_payload: &[u8],
    ) -> Result<Vec<u8>, ShadowError> {
        Ok(signature_preimage(
            self.role.signature_domain(),
            &self.assignment_bound_canonical_payload(
                canonical_receipt_payload,
            )?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct CustodyTeeAttestationVerifierResultWire {
    platform: TeePlatform,
    quote_sha256: Sha256Digest,
    endorsement_evidence_sha256: Sha256Digest,
    endorsement_root_sha256: Sha256Digest,
    collateral_policy_sha256: Sha256Digest,
    revocation_source_sha256: Sha256Digest,
    collateral_revocation_generation: u64,
    collateral_revocation_root_sha256: Sha256Digest,
    measurement_sha256: Sha256Digest,
    production_configuration_binding_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    quote_bound_custody_key_set_root_sha256: Sha256Digest,
    verified_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    trust_checkpoint_id: Sha256Digest,
    trust_revocation_generation: u64,
    trust_revocation_root_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
}

impl CustodyTeeAttestationVerifierResultWire {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verifier(
        _platform: TeePlatform,
        _quote_sha256: Sha256Digest,
        _endorsement_evidence_sha256: Sha256Digest,
        _endorsement_root_sha256: Sha256Digest,
        _collateral_policy_sha256: Sha256Digest,
        _revocation_source_sha256: Sha256Digest,
        _collateral_revocation_generation: u64,
        _collateral_revocation_root_sha256: Sha256Digest,
        _measurement_sha256: Sha256Digest,
        _production_configuration_binding_sha256: Sha256Digest,
        _worker_executable_sha256: Sha256Digest,
        _quote_bound_custody_key_set_root_sha256: Sha256Digest,
        _verified_at_unix_nanos: i64,
        _expires_at_unix_nanos: i64,
        _trust_checkpoint_id: Sha256Digest,
        _trust_revocation_generation: u64,
        _trust_revocation_root_sha256: Sha256Digest,
        _signing_key_id: Sha256Digest,
        _signing_key_spki_sha256: Sha256Digest,
        _signature: String,
    ) -> Result<Self, ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verifier_with_execution_closure(
        platform: TeePlatform,
        quote_sha256: Sha256Digest,
        endorsement_evidence_sha256: Sha256Digest,
        endorsement_root_sha256: Sha256Digest,
        collateral_policy_sha256: Sha256Digest,
        revocation_source_sha256: Sha256Digest,
        collateral_revocation_generation: u64,
        collateral_revocation_root_sha256: Sha256Digest,
        measurement_sha256: Sha256Digest,
        production_configuration_binding_sha256: Sha256Digest,
        worker_executable_sha256: Sha256Digest,
        execution_closure_manifest_sha256: Sha256Digest,
        structurally_verified_seccomp_policy_sha256: Sha256Digest,
        quote_bound_custody_key_set_root_sha256: Sha256Digest,
        verified_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
        trust_checkpoint_id: Sha256Digest,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            collateral_revocation_generation,
            "custody_attestation.collateral_revocation_generation",
        )?;
        validate_positive(
            trust_revocation_generation,
            "custody_attestation.trust_revocation_generation",
        )?;
        if verified_at_unix_nanos <= 0
            || expires_at_unix_nanos <= verified_at_unix_nanos
        {
            return Err(ShadowError::EvidenceTooOld);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        Ok(Self {
            platform,
            quote_sha256,
            endorsement_evidence_sha256,
            endorsement_root_sha256,
            collateral_policy_sha256,
            revocation_source_sha256,
            collateral_revocation_generation,
            collateral_revocation_root_sha256,
            measurement_sha256,
            production_configuration_binding_sha256,
            worker_executable_sha256,
            execution_closure_manifest_sha256,
            structurally_verified_seccomp_policy_sha256,
            quote_bound_custody_key_set_root_sha256,
            verified_at_unix_nanos,
            expires_at_unix_nanos,
            trust_checkpoint_id,
            trust_revocation_generation,
            trust_revocation_root_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
        })
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            "serverware.policyShadowCustodyTeeAttestationResult/v1",
            &(
                self.platform,
                &self.quote_sha256,
                &self.endorsement_evidence_sha256,
                &self.endorsement_root_sha256,
                &self.collateral_policy_sha256,
                &self.revocation_source_sha256,
                self.collateral_revocation_generation,
                &self.collateral_revocation_root_sha256,
                &self.measurement_sha256,
            ),
            &(
                &self.production_configuration_binding_sha256,
                &self.worker_executable_sha256,
                &self.execution_closure_manifest_sha256,
                &self.structurally_verified_seccomp_policy_sha256,
                &self.quote_bound_custody_key_set_root_sha256,
                self.verified_at_unix_nanos,
                self.expires_at_unix_nanos,
                &self.trust_checkpoint_id,
                self.trust_revocation_generation,
                &self.trust_revocation_root_sha256,
                &self.signing_key_id,
                &self.signing_key_spki_sha256,
            ),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct CustodyTrustedHostVerifierResultWire {
    host_evidence_sha256: Sha256Digest,
    host_evidence_profile_sha256: Sha256Digest,
    host_evidence_policy_sha256: Sha256Digest,
    host_measurement_sha256: Sha256Digest,
    production_configuration_binding_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    asserted_custody_key_set_root_sha256: Sha256Digest,
    verified_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    trust_checkpoint_id: Sha256Digest,
    trust_revocation_generation: u64,
    trust_revocation_root_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
}

impl CustodyTrustedHostVerifierResultWire {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verifier(
        _host_evidence_sha256: Sha256Digest,
        _host_evidence_profile_sha256: Sha256Digest,
        _host_evidence_policy_sha256: Sha256Digest,
        _host_measurement_sha256: Sha256Digest,
        _production_configuration_binding_sha256: Sha256Digest,
        _worker_executable_sha256: Sha256Digest,
        _asserted_custody_key_set_root_sha256: Sha256Digest,
        _verified_at_unix_nanos: i64,
        _expires_at_unix_nanos: i64,
        _trust_checkpoint_id: Sha256Digest,
        _trust_revocation_generation: u64,
        _trust_revocation_root_sha256: Sha256Digest,
        _signing_key_id: Sha256Digest,
        _signing_key_spki_sha256: Sha256Digest,
        _signature: String,
    ) -> Result<Self, ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verifier_with_execution_closure(
        host_evidence_sha256: Sha256Digest,
        host_evidence_profile_sha256: Sha256Digest,
        host_evidence_policy_sha256: Sha256Digest,
        host_measurement_sha256: Sha256Digest,
        production_configuration_binding_sha256: Sha256Digest,
        worker_executable_sha256: Sha256Digest,
        execution_closure_manifest_sha256: Sha256Digest,
        structurally_verified_seccomp_policy_sha256: Sha256Digest,
        asserted_custody_key_set_root_sha256: Sha256Digest,
        verified_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
        trust_checkpoint_id: Sha256Digest,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            trust_revocation_generation,
            "custody_host_evidence.trust_revocation_generation",
        )?;
        if verified_at_unix_nanos <= 0
            || expires_at_unix_nanos <= verified_at_unix_nanos
        {
            return Err(ShadowError::EvidenceTooOld);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        Ok(Self {
            host_evidence_sha256,
            host_evidence_profile_sha256,
            host_evidence_policy_sha256,
            host_measurement_sha256,
            production_configuration_binding_sha256,
            worker_executable_sha256,
            execution_closure_manifest_sha256,
            structurally_verified_seccomp_policy_sha256,
            asserted_custody_key_set_root_sha256,
            verified_at_unix_nanos,
            expires_at_unix_nanos,
            trust_checkpoint_id,
            trust_revocation_generation,
            trust_revocation_root_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
        })
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            "serverware.policyShadowCustodyTrustedHostResult/v1",
            &self.host_evidence_sha256,
            &self.host_evidence_profile_sha256,
            &self.host_evidence_policy_sha256,
            &self.host_measurement_sha256,
            &self.production_configuration_binding_sha256,
            &self.worker_executable_sha256,
            &self.execution_closure_manifest_sha256,
            &self.structurally_verified_seccomp_policy_sha256,
            &self.asserted_custody_key_set_root_sha256,
            self.verified_at_unix_nanos,
            self.expires_at_unix_nanos,
            &self.trust_checkpoint_id,
            self.trust_revocation_generation,
            &self.trust_revocation_root_sha256,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifiedCustodyAttestationKind {
    Tee {
        platform: TeePlatform,
        quote_sha256: Sha256Digest,
        endorsement_evidence_sha256: Sha256Digest,
        collateral_revocation_generation: u64,
        collateral_revocation_root_sha256: Sha256Digest,
        measurement_sha256: Sha256Digest,
    },
    TrustedHost {
        host_evidence_sha256: Sha256Digest,
        host_measurement_sha256: Sha256Digest,
    },
}

/// Non-serializable evidence capability. It is produced only by canonical
/// verification of an assignment-selected attestation-verifier response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct VerifiedCustodyAttestation {
    kind: VerifiedCustodyAttestationKind,
    production_configuration_binding_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    asserted_custody_key_set_root_sha256: Sha256Digest,
    verified_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
    _not_constructible: PhantomData<fn() -> ()>,
}

impl VerifiedCustodyAttestation {
    pub(in crate::policy_shadow) fn is_tee(&self) -> bool {
        matches!(&self.kind, VerifiedCustodyAttestationKind::Tee { .. })
    }

    pub(in crate::policy_shadow) fn production_configuration_binding_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.production_configuration_binding_sha256
    }

    pub(in crate::policy_shadow) fn asserted_custody_key_set_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.asserted_custody_key_set_root_sha256
    }

    pub(in crate::policy_shadow) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }
}

fn production_custody_key_set_root(
    bindings: &BTreeMap<AuthorityRole, ProductionCustodyKeyBinding>,
) -> Result<Sha256Digest, ShadowError> {
    let leaves = bindings
        .values()
        .enumerate()
        .map(|(index, binding)| {
            Ok((
                u64::try_from(index + 1)
                    .map_err(|_| ShadowError::CounterOverflow)?,
                hash_domain_frames(
                    b"serverware.policyShadowCustodyAssertedKey/v1",
                    &[&canonical_json_bytes(&(
                        binding.role,
                        &binding.key_id,
                        &binding.key_spki_sha256,
                        &binding.key_material_sha256,
                    ))?],
                ),
            ))
        })
        .collect::<Result<Vec<_>, ShadowError>>()?;
    merkle_root(&leaves)
}

pub(in crate::policy_shadow) const
    PRODUCTION_CUSTODY_DISPATCH_CONTRACT_VERSION: &str =
    "serverware.policyShadowCustodyDispatch/v2";
pub(in crate::policy_shadow) const
    MAX_PRODUCTION_CUSTODY_DISPATCH_REQUEST_BYTES: u64 =
    8 * 1024 * 1024;
pub(in crate::policy_shadow) const
    MAX_PRODUCTION_CUSTODY_DISPATCH_RESPONSE_BYTES: u64 =
    8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct ExactCanonicalReceiptBytes {
    bytes: Arc<[u8]>,
    sha256: Sha256Digest,
}

impl ExactCanonicalReceiptBytes {
    pub(in crate::policy_shadow) fn decode<T>(
        bytes: &[u8],
        maximum_bytes: u64,
    ) -> Result<(Self, T), ShadowError>
    where
        T: DeserializeOwned + Serialize,
    {
        if bytes.is_empty()
            || u64::try_from(bytes.len())
                .ok()
                .is_none_or(|length| length > maximum_bytes)
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = T::deserialize(&mut deserializer)
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        deserializer
            .end()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if canonical_json_bytes(&value)? != bytes {
            return Err(ShadowError::CanonicalizationFailure(
                "external custody receipt is not exact canonical JSON",
            ));
        }
        Ok((
            Self {
                bytes: Arc::from(bytes),
                sha256: Sha256Digest::compute(bytes),
            },
            value,
        ))
    }

    pub(in crate::policy_shadow) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(in crate::policy_shadow) fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

fn production_custody_operation_coverage_root(
) -> Result<Sha256Digest, ShadowError> {
    let operations = [
        PolicyShadowCustodyOperation::RecoverCurrentState,
        PolicyShadowCustodyOperation::VerifyCheckpointSuccessor,
        PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead,
        PolicyShadowCustodyOperation::VerifyObservationEvidence,
        PolicyShadowCustodyOperation::PrepareGenerationPublication,
        PolicyShadowCustodyOperation::CommitGenerationPublication,
        PolicyShadowCustodyOperation::AbortGenerationPublication,
        PolicyShadowCustodyOperation::BeginIngress,
        PolicyShadowCustodyOperation::ReserveSpoolAppend,
        PolicyShadowCustodyOperation::AppendSpoolEvent,
        PolicyShadowCustodyOperation::CompactSpool,
        PolicyShadowCustodyOperation::CommitRequest,
        PolicyShadowCustodyOperation::AppendActiveEffectBarrier,
        PolicyShadowCustodyOperation::CommitActiveEffect,
        PolicyShadowCustodyOperation::ReconcileActiveEffect,
        PolicyShadowCustodyOperation::AppendTerminal,
        PolicyShadowCustodyOperation::ConsumeAndPublishActivation,
    ];
    Ok(hash_domain_frames(
        b"serverware.policyShadowCustodyOperationCoverage/v1",
        &[&canonical_json_bytes(&operations)?],
    ))
}

/// Identity measured from kernel-retained pidfd and cgroup descriptors. The
/// extracted launcher constructs this only after descriptor identity has been
/// re-read from the kernel; serialized process ids are not sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyKernelDriverIdentity {
    driver_instance_sha256: Sha256Digest,
    driver_executable_sha256: Sha256Digest,
    supervisor_boot_id_sha256: Sha256Digest,
    process_start_time_ticks: u64,
    pidfd_inode: u64,
    cgroup_id: u64,
    cgroup_mount_id: u64,
    cgroup_inode: u64,
    retained_descriptor_manifest_sha256: Sha256Digest,
    verified_at_boottime_nanos: u64,
    identity_sha256: Sha256Digest,
}

impl ProductionCustodyKernelDriverIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verified_kernel_descriptors(
        driver_instance_sha256: Sha256Digest,
        driver_executable_sha256: Sha256Digest,
        supervisor_boot_id_sha256: Sha256Digest,
        process_start_time_ticks: u64,
        pidfd_inode: u64,
        cgroup_id: u64,
        cgroup_mount_id: u64,
        cgroup_inode: u64,
        retained_descriptor_manifest_sha256: Sha256Digest,
        verified_at_boottime_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            process_start_time_ticks,
            "custody.driver.process_start_time_ticks",
        )?;
        validate_positive(pidfd_inode, "custody.driver.pidfd_inode")?;
        validate_positive(cgroup_id, "custody.driver.cgroup_id")?;
        validate_positive(
            cgroup_mount_id,
            "custody.driver.cgroup_mount_id",
        )?;
        validate_positive(cgroup_inode, "custody.driver.cgroup_inode")?;
        validate_positive(
            verified_at_boottime_nanos,
            "custody.driver.verified_at_boottime_nanos",
        )?;
        let identity_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
            &[&canonical_json_bytes(&(
                &driver_instance_sha256,
                &driver_executable_sha256,
                &supervisor_boot_id_sha256,
                process_start_time_ticks,
                pidfd_inode,
                cgroup_id,
                cgroup_mount_id,
                cgroup_inode,
                &retained_descriptor_manifest_sha256,
                verified_at_boottime_nanos,
            ))?],
        );
        Ok(Self {
            driver_instance_sha256,
            driver_executable_sha256,
            supervisor_boot_id_sha256,
            process_start_time_ticks,
            pidfd_inode,
            cgroup_id,
            cgroup_mount_id,
            cgroup_inode,
            retained_descriptor_manifest_sha256,
            verified_at_boottime_nanos,
            identity_sha256,
        })
    }

    fn validate(
        &self,
        expected_worker_executable_sha256: &Sha256Digest,
        expected_supervisor_boot_id_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        let rebuilt = Self::from_verified_kernel_descriptors(
            self.driver_instance_sha256.clone(),
            self.driver_executable_sha256.clone(),
            self.supervisor_boot_id_sha256.clone(),
            self.process_start_time_ticks,
            self.pidfd_inode,
            self.cgroup_id,
            self.cgroup_mount_id,
            self.cgroup_inode,
            self.retained_descriptor_manifest_sha256.clone(),
            self.verified_at_boottime_nanos,
        )?;
        if rebuilt.identity_sha256 != self.identity_sha256
            || self.driver_executable_sha256
                != *expected_worker_executable_sha256
            || self.supervisor_boot_id_sha256
                != *expected_supervisor_boot_id_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn identity_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.identity_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyStableReaperIdentity {
    reaper_instance_sha256: Sha256Digest,
    reaper_executable_sha256: Sha256Digest,
    supervisor_instance_sha256: Sha256Digest,
    supervisor_boot_id_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    subreaper_process_start_time_ticks: u64,
    pidfd_namespace_sha256: Sha256Digest,
    retained_descriptor_set_sha256: Sha256Digest,
    ownership_epoch: u64,
    independent_restart_forbidden: bool,
    identity_sha256: Sha256Digest,
}

impl ProductionCustodyStableReaperIdentity {
    pub(in crate::policy_shadow) fn identity_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.identity_sha256
    }

    fn validate(
        &self,
        configuration: &ProductionCustodyConfiguration,
        driver: &ProductionCustodyKernelDriverIdentity,
    ) -> Result<(), ShadowError> {
        let expected = hash_domain_frames(
            b"serverware.policyShadowCustodyStableReaper/v1",
            &[&canonical_json_bytes(&(
                &self.reaper_instance_sha256,
                &self.reaper_executable_sha256,
                &self.supervisor_instance_sha256,
                &self.supervisor_boot_id_sha256,
                &self.kernel_driver_identity_sha256,
                self.subreaper_process_start_time_ticks,
                &self.pidfd_namespace_sha256,
                &self.retained_descriptor_set_sha256,
                self.ownership_epoch,
                self.independent_restart_forbidden,
            ))?],
        );
        if self.identity_sha256 != expected
            || self.supervisor_instance_sha256
                != configuration.supervisor_instance_sha256
            || self.supervisor_boot_id_sha256
                != configuration.supervisor_boot_id_sha256
            || self.kernel_driver_identity_sha256
                != *driver.identity_sha256()
            || self.subreaper_process_start_time_ticks == 0
            || self.ownership_epoch == 0
            || !self.independent_restart_forbidden
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }
}

/// Immutable production hooks which identify the killable custody worker and
/// its independent signer, append-only persistence, and retrieval-proof
/// implementations. Construction is deliberately crate-private; the runtime
/// will not accept a supervisor which cannot expose this binding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetainedProductionCustodyClosure {
    Legacy(ProductionCustodyExecutionClosureManifest),
    #[cfg(target_os = "linux")]
    Native(native_custody_closure::NativeCustodyClosureOwner),
}
impl RetainedProductionCustodyClosure {
    fn validate(&self)->Result<(),ShadowError> {match self {
        Self::Legacy(v)=>v.validate(),
        #[cfg(target_os="linux")] Self::Native(v)=>v.check(),
    }}
    fn manifest_sha256(&self)->&Sha256Digest {match self {
        Self::Legacy(v)=>v.manifest_sha256(),
        #[cfg(target_os="linux")] Self::Native(v)=>v.manifest_sha256(),
    }}
    fn seccomp_policy_sha256(&self)->&Sha256Digest {match self {
        Self::Legacy(v)=>v.seccomp_policy_sha256(),
        #[cfg(target_os="linux")] Self::Native(v)=>v.seccomp_policy_sha256(),
    }}
    fn worker_executable_sha256(&self)->&Sha256Digest {match self {
        Self::Legacy(v)=>v.worker_executable_sha256(),
        #[cfg(target_os="linux")] Self::Native(v)=>v.worker_executable_sha256(),
    }}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionCustodyConfiguration {
    retained_verified_assignment: VerifiedAssignment,
    assignment_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_id: Sha256Digest,
    storage_realm_sha256: Sha256Digest,
    retrieval_namespace_sha256: Sha256Digest,
    authority_key_independence_sha256: Sha256Digest,
    authority_trust_checkpoint: AtomicTrustCheckpoint,
    maximum_authority_evidence_age_nanos: i64,
    attestation_mode: CustodyAttestationMode,
    authority_bindings: BTreeMap<AuthorityRole, ProductionCustodyKeyBinding>,
    supervisor_instance_sha256: Sha256Digest,
    supervisor_boot_id_sha256: Sha256Digest,
    execution_closure_manifest: RetainedProductionCustodyClosure,
    execution_closure_manifest_sha256: Sha256Digest,
    structurally_verified_seccomp_policy_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    signer_backend_sha256: Sha256Digest,
    persistence_backend_sha256: Sha256Digest,
    retrieval_backend_sha256: Sha256Digest,
    maximum_rpc_nanos: u64,
    cleanup_reserve_nanos: u64,
    maximum_in_flight_calls: u16,
    operation_coverage_root_sha256: Sha256Digest,
    dispatcher_protocol_set_sha256: Sha256Digest,
    kernel_retained_driver_identity_sha256: Sha256Digest,
    maximum_async_durability_nanos: u64,
    production_configuration_binding_sha256: Sha256Digest,
    asserted_custody_key_set_root_sha256: Sha256Digest,
    proof_scope: ProductionCustodyProofScope,
    verified_attestation: Option<VerifiedCustodyAttestation>,
}

impl ProductionCustodyConfiguration {
    /// Retained only as a fail-closed compatibility surface for process code
    /// which has not yet supplied a verified assignment and current authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        _supervisor_instance_sha256: Sha256Digest,
        _worker_executable_sha256: Sha256Digest,
        _signer_backend_sha256: Sha256Digest,
        _persistence_backend_sha256: Sha256Digest,
        _retrieval_backend_sha256: Sha256Digest,
        _maximum_rpc_nanos: u64,
        _maximum_in_flight_calls: u16,
    ) -> Result<Self, ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_assignment(
        _assignment: &VerifiedAssignment,
        _key_trust: &dyn EnvelopeKeyTrust,
        _trusted_time: &dyn TrustedTime,
        _supervisor_instance_sha256: Sha256Digest,
        _worker_executable_sha256: Sha256Digest,
        _signer_backend_sha256: Sha256Digest,
        _persistence_backend_sha256: Sha256Digest,
        _retrieval_backend_sha256: Sha256Digest,
        _maximum_rpc_nanos: u64,
        _maximum_in_flight_calls: u16,
    ) -> Result<Self, ShadowError> {
        Err(ShadowError::CustodyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_verified_assignment_with_settlement_authority(
        assignment: &VerifiedAssignment,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
        supervisor_instance_sha256: Sha256Digest,
        supervisor_boot_id_sha256: Sha256Digest,
        execution_closure_manifest:
            ProductionCustodyExecutionClosureManifest,
        signer_backend_sha256: Sha256Digest,
        persistence_backend_sha256: Sha256Digest,
        retrieval_backend_sha256: Sha256Digest,
        dispatcher_protocol_set_sha256: Sha256Digest,
        kernel_retained_driver_identity:
            ProductionCustodyKernelDriverIdentity,
        maximum_rpc_nanos: u64,
        cleanup_reserve_nanos: u64,
        maximum_in_flight_calls: u16,
        maximum_async_durability_nanos: u64,
    ) -> Result<Self, ShadowError> {
        Self::from_retained_closure_with_settlement_authority(assignment,key_trust,trusted_time,
            supervisor_instance_sha256,supervisor_boot_id_sha256,
            RetainedProductionCustodyClosure::Legacy(execution_closure_manifest),signer_backend_sha256,
            persistence_backend_sha256,retrieval_backend_sha256,dispatcher_protocol_set_sha256,
            kernel_retained_driver_identity,maximum_rpc_nanos,cleanup_reserve_nanos,maximum_in_flight_calls,
            maximum_async_durability_nanos)
    }

    /// An actual native owner is necessary, but never sufficient, for admission.
    /// The existing real settlement driver and independently verified TEE result
    /// remain mandatory. There is no DTO/native-ready constructor.
    #[cfg(target_os="linux")]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_native_closure_with_settlement_authority(
        assignment:&VerifiedAssignment,key_trust:&dyn EnvelopeKeyTrust,trusted_time:&dyn TrustedTime,
        supervisor_instance_sha256:Sha256Digest,supervisor_boot_id_sha256:Sha256Digest,
        closure:native_custody_closure::NativeCustodyClosureOwner,
        signer_backend_sha256:Sha256Digest,persistence_backend_sha256:Sha256Digest,retrieval_backend_sha256:Sha256Digest,
        dispatcher_protocol_set_sha256:Sha256Digest,kernel_retained_driver_identity:ProductionCustodyKernelDriverIdentity,
        maximum_rpc_nanos:u64,cleanup_reserve_nanos:u64,maximum_in_flight_calls:u16,maximum_async_durability_nanos:u64,
    )->Result<Self,ShadowError> {
        closure.require_assignment(assignment,key_trust,trusted_time,&supervisor_instance_sha256,&supervisor_boot_id_sha256)?;
        Self::from_retained_closure_with_settlement_authority(assignment,key_trust,trusted_time,
            supervisor_instance_sha256,supervisor_boot_id_sha256,RetainedProductionCustodyClosure::Native(closure),
            signer_backend_sha256,persistence_backend_sha256,retrieval_backend_sha256,dispatcher_protocol_set_sha256,
            kernel_retained_driver_identity,maximum_rpc_nanos,cleanup_reserve_nanos,maximum_in_flight_calls,
            maximum_async_durability_nanos)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_retained_closure_with_settlement_authority(
        assignment:&VerifiedAssignment,key_trust:&dyn EnvelopeKeyTrust,trusted_time:&dyn TrustedTime,
        supervisor_instance_sha256:Sha256Digest,supervisor_boot_id_sha256:Sha256Digest,
        execution_closure_manifest:RetainedProductionCustodyClosure,
        signer_backend_sha256:Sha256Digest,persistence_backend_sha256:Sha256Digest,retrieval_backend_sha256:Sha256Digest,
        dispatcher_protocol_set_sha256:Sha256Digest,kernel_retained_driver_identity:ProductionCustodyKernelDriverIdentity,
        maximum_rpc_nanos:u64,cleanup_reserve_nanos:u64,maximum_in_flight_calls:u16,maximum_async_durability_nanos:u64,
    )->Result<Self,ShadowError> {
        validate_positive(maximum_rpc_nanos, "custody.maximum_rpc_nanos")?;
        validate_positive(
            cleanup_reserve_nanos,
            "custody.cleanup_reserve_nanos",
        )?;
        if maximum_rpc_nanos < 250_000_000
            || maximum_in_flight_calls == 0
            || maximum_in_flight_calls > 64
            || maximum_rpc_nanos > 1_000_000_000
            || cleanup_reserve_nanos > MAX_PRODUCTION_CUSTODY_CLEANUP_NANOS
            || maximum_async_durability_nanos == 0
            || maximum_async_durability_nanos > maximum_rpc_nanos
        {
            return Err(invalid(
                "production_custody",
                "operation and cleanup intervals exceed production bounds",
            ));
        }
        execution_closure_manifest.validate()?;
        let execution_closure_manifest_sha256 =
            execution_closure_manifest.manifest_sha256().clone();
        let structurally_verified_seccomp_policy_sha256 =
            execution_closure_manifest
                .seccomp_policy_sha256()
                .clone();
        let worker_executable_sha256 = execution_closure_manifest
            .worker_executable_sha256()
            .clone();
        kernel_retained_driver_identity.validate(
            &worker_executable_sha256,
            &supervisor_boot_id_sha256,
        )?;
        let kernel_retained_driver_identity_sha256 =
            kernel_retained_driver_identity.identity_sha256().clone();
        let operation_coverage_root_sha256 =
            production_custody_operation_coverage_root()?;
        revalidate_verified_freshness(
            assignment,
            key_trust,
            trusted_time,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        let checkpoint = key_trust.current_checkpoint()?;
        revalidate_verified_at_checkpoint(
            assignment,
            &checkpoint,
            key_trust,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        let payload = assignment.payload();
        if payload
                .custody_authority
                .execution_closure_manifest_sha256
                != execution_closure_manifest_sha256
            || payload
                .custody_authority
                .structurally_verified_seccomp_policy_sha256
                != structurally_verified_seccomp_policy_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        payload.authority_key_independence.validate(
            &payload.assignment_id,
            &payload.fleet,
            &payload.custody_authority,
        )?;
        verify_assignment_authority_key_material_at_checkpoint(
            assignment,
            &checkpoint,
            key_trust,
        )?;
        let mut authority_bindings = BTreeMap::new();
        for role in PRODUCTION_CUSTODY_AUTHORITY_ROLES {
            let binding = payload
                .authority_key_independence
                .binding(role, &payload.assignment_id)?;
            if authority_bindings
                .insert(
                    role,
                    ProductionCustodyKeyBinding {
                        role,
                        key_id: binding.key_id.clone(),
                        key_spki_sha256:
                            binding.key_spki_sha256.clone(),
                        key_material_sha256:
                            binding.key_material_sha256.clone(),
                    },
                )
                .is_some()
            {
                return Err(ShadowError::SignerBindingMismatch);
            }
        }
        if authority_bindings.len()
            != PRODUCTION_CUSTODY_AUTHORITY_ROLES.len()
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        validate_freshness(
            assignment.payload().issued_at_unix_nanos(),
            assignment.payload().expires_at_unix_nanos(),
            trusted_time.now_unix_nanos()?,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        if key_trust.current_checkpoint()? != checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        let maximum_authority_evidence_age_nanos = i64::try_from(
            payload.observation_window.maximum_evidence_age_nanos,
        )
        .map_err(|_| ShadowError::EvidenceTooOld)?;
        let asserted_custody_key_set_root_sha256 =
            production_custody_key_set_root(&authority_bindings)?;
        let store_response_authority = authority_bindings
            .get(&AuthorityRole::CustodyStoreResponse)
            .cloned()
            .ok_or(ShadowError::SignerBindingMismatch)?;
        let retrieval_response_authority = authority_bindings
            .get(&AuthorityRole::CustodyRetrievalResponse)
            .cloned()
            .ok_or(ShadowError::SignerBindingMismatch)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct ConfigurationBinding<'a> {
            assignment_id: &'a Sha256Digest,
            assignment_payload_sha256: &'a Sha256Digest,
            assignment_revision: u64,
            authority_id: &'a Sha256Digest,
            storage_realm_sha256: &'a Sha256Digest,
            retrieval_namespace_sha256: &'a Sha256Digest,
            authority_key_independence_sha256: &'a Sha256Digest,
            attestation_mode: &'a CustodyAttestationMode,
            supervisor_instance_sha256: &'a Sha256Digest,
            supervisor_boot_id_sha256: &'a Sha256Digest,
            execution_closure_manifest_sha256: &'a Sha256Digest,
            structurally_verified_seccomp_policy_sha256:
                &'a Sha256Digest,
            worker_executable_sha256: &'a Sha256Digest,
            signer_backend_sha256: &'a Sha256Digest,
            persistence_backend_sha256: &'a Sha256Digest,
            retrieval_backend_sha256: &'a Sha256Digest,
            maximum_rpc_nanos: u64,
            cleanup_reserve_nanos: u64,
            maximum_in_flight_calls: u16,
            operation_coverage_root_sha256: &'a Sha256Digest,
            dispatcher_protocol_set_sha256: &'a Sha256Digest,
            kernel_retained_driver_identity_sha256: &'a Sha256Digest,
            maximum_async_durability_nanos: u64,
            asserted_custody_key_set_root_sha256: &'a Sha256Digest,
        }
        let configuration_binding = ConfigurationBinding {
            assignment_id: &payload.assignment_id,
            assignment_payload_sha256: assignment.payload_sha256(),
            assignment_revision: payload.assignment_revision,
            authority_id: &payload.custody_authority.authority_id,
            storage_realm_sha256:
                &payload.custody_authority.storage_realm_sha256,
            retrieval_namespace_sha256:
                &payload.custody_authority.retrieval_namespace_sha256,
            authority_key_independence_sha256: &payload
                .authority_key_independence
                .independence_root_sha256,
            attestation_mode:
                &payload.custody_authority.attestation_mode,
            supervisor_instance_sha256: &supervisor_instance_sha256,
            supervisor_boot_id_sha256: &supervisor_boot_id_sha256,
            execution_closure_manifest_sha256:
                &execution_closure_manifest_sha256,
            structurally_verified_seccomp_policy_sha256:
                &structurally_verified_seccomp_policy_sha256,
            worker_executable_sha256: &worker_executable_sha256,
            signer_backend_sha256: &signer_backend_sha256,
            persistence_backend_sha256: &persistence_backend_sha256,
            retrieval_backend_sha256: &retrieval_backend_sha256,
            maximum_rpc_nanos,
            cleanup_reserve_nanos,
            maximum_in_flight_calls,
            operation_coverage_root_sha256:
                &operation_coverage_root_sha256,
            dispatcher_protocol_set_sha256:
                &dispatcher_protocol_set_sha256,
            kernel_retained_driver_identity_sha256:
                &kernel_retained_driver_identity_sha256,
            maximum_async_durability_nanos,
            asserted_custody_key_set_root_sha256:
                &asserted_custody_key_set_root_sha256,
        };
        let production_configuration_binding_sha256 = hash_domain_frames(
            b"serverware.policyShadowProductionCustodyConfiguration/v1",
            &[&canonical_json_bytes(&configuration_binding)?],
        );
        let proof_scope_binding_sha256 = hash_domain_frames(
            b"serverware.policyShadowProductionCustodyProofScope/v1",
            &[&canonical_json_bytes(&(
                &payload.assignment_id,
                assignment.payload_sha256(),
                payload.assignment_revision,
                &payload.custody_authority.authority_id,
                &payload.custody_authority.storage_realm_sha256,
                &payload.custody_authority.retrieval_namespace_sha256,
                &payload
                    .authority_key_independence
                    .independence_root_sha256,
                &production_configuration_binding_sha256,
                &asserted_custody_key_set_root_sha256,
                &execution_closure_manifest_sha256,
                &structurally_verified_seccomp_policy_sha256,
            ))?],
        );
        let proof_scope = ProductionCustodyProofScope {
            assignment_id: payload.assignment_id.clone(),
            assignment_payload_sha256:
                assignment.payload_sha256().clone(),
            assignment_revision: payload.assignment_revision,
            authority_id: payload.custody_authority.authority_id.clone(),
            storage_realm_sha256:
                payload.custody_authority.storage_realm_sha256.clone(),
            retrieval_namespace_sha256: payload
                .custody_authority
                .retrieval_namespace_sha256
                .clone(),
            authority_key_independence_sha256: payload
                .authority_key_independence
                .independence_root_sha256
                .clone(),
            production_configuration_binding_sha256:
                production_configuration_binding_sha256.clone(),
            asserted_custody_key_set_root_sha256:
                asserted_custody_key_set_root_sha256.clone(),
            execution_closure_manifest_sha256:
                execution_closure_manifest_sha256.clone(),
            structurally_verified_seccomp_policy_sha256:
                structurally_verified_seccomp_policy_sha256.clone(),
            store_response_authority,
            retrieval_response_authority,
            binding_sha256: proof_scope_binding_sha256,
        };
        validate_freshness(
            assignment.payload().issued_at_unix_nanos(),
            assignment.payload().expires_at_unix_nanos(),
            trusted_time.now_unix_nanos()?,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        if key_trust.current_checkpoint()? != checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(Self {
            retained_verified_assignment: assignment.clone(),
            assignment_id: payload.assignment_id.clone(),
            assignment_payload_sha256:
                assignment.payload_sha256().clone(),
            assignment_revision: payload.assignment_revision,
            authority_id: payload.custody_authority.authority_id.clone(),
            storage_realm_sha256:
                payload.custody_authority.storage_realm_sha256.clone(),
            retrieval_namespace_sha256: payload
                .custody_authority
                .retrieval_namespace_sha256
                .clone(),
            authority_key_independence_sha256: payload
                .authority_key_independence
                .independence_root_sha256
                .clone(),
            authority_trust_checkpoint: checkpoint,
            maximum_authority_evidence_age_nanos,
            attestation_mode:
                payload.custody_authority.attestation_mode.clone(),
            authority_bindings,
            supervisor_instance_sha256,
            supervisor_boot_id_sha256,
            execution_closure_manifest,
            execution_closure_manifest_sha256,
            structurally_verified_seccomp_policy_sha256,
            worker_executable_sha256,
            signer_backend_sha256,
            persistence_backend_sha256,
            retrieval_backend_sha256,
            maximum_rpc_nanos,
            cleanup_reserve_nanos,
            maximum_in_flight_calls,
            operation_coverage_root_sha256,
            dispatcher_protocol_set_sha256,
            kernel_retained_driver_identity_sha256,
            maximum_async_durability_nanos,
            production_configuration_binding_sha256,
            asserted_custody_key_set_root_sha256,
            proof_scope,
            verified_attestation: None,
        })
    }

    pub(crate) fn assignment_id(&self) -> &Sha256Digest {
        &self.assignment_id
    }

    pub(crate) fn assignment_payload_sha256(&self) -> &Sha256Digest {
        &self.assignment_payload_sha256
    }

    pub(crate) fn assignment_revision(&self) -> u64 {
        self.assignment_revision
    }

    pub(crate) fn authority_id(&self) -> &Sha256Digest {
        &self.authority_id
    }

    pub(crate) fn storage_realm_sha256(&self) -> &Sha256Digest {
        &self.storage_realm_sha256
    }

    pub(crate) fn retrieval_namespace_sha256(&self) -> &Sha256Digest {
        &self.retrieval_namespace_sha256
    }

    pub(crate) fn authority_key_independence_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.authority_key_independence_sha256
    }

    pub(crate) fn authority_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.authority_trust_checkpoint
    }

    pub(crate) fn maximum_authority_evidence_age_nanos(&self) -> i64 {
        self.maximum_authority_evidence_age_nanos
    }

    pub(crate) fn attestation_mode(&self) -> &CustodyAttestationMode {
        &self.attestation_mode
    }

    pub(crate) fn authority_binding(
        &self,
        role: AuthorityRole,
    ) -> Result<&ProductionCustodyKeyBinding, ShadowError> {
        self.authority_bindings
            .get(&role)
            .ok_or(ShadowError::SignerBindingMismatch)
    }

    fn custody_signer_binding(
        &self,
        role: PolicyShadowCustodySignerRole,
    ) -> Result<&ProductionCustodyKeyBinding, ShadowError> {
        self.authority_binding(authority_role_for_custody_signer(role))
    }

    pub(in crate::policy_shadow) fn signer_authority(
        &self,
        role: PolicyShadowCustodySignerRole,
    ) -> Result<ProductionCustodySignerAuthority<'_>, ShadowError> {
        let binding = self.custody_signer_binding(role)?;
        Ok(ProductionCustodySignerAuthority {
            role,
            binding,
            proof_scope: &self.proof_scope,
            _not_constructible: PhantomData,
        })
    }

    pub(crate) fn authority_bindings(
        &self,
    ) -> impl Iterator<Item = &ProductionCustodyKeyBinding> {
        self.authority_bindings.values()
    }

    pub(crate) fn production_configuration_binding_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.production_configuration_binding_sha256
    }

    pub(in crate::policy_shadow) fn operation_coverage_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.operation_coverage_root_sha256
    }

    pub(in crate::policy_shadow) fn dispatcher_protocol_set_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.dispatcher_protocol_set_sha256
    }

    pub(in crate::policy_shadow) fn kernel_retained_driver_identity_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.kernel_retained_driver_identity_sha256
    }

    pub(in crate::policy_shadow) fn maximum_async_durability_nanos(
        &self,
    ) -> u64 {
        self.maximum_async_durability_nanos
    }

    pub(crate) fn asserted_custody_key_set_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.asserted_custody_key_set_root_sha256
    }

    pub(in crate::policy_shadow) fn supervisor_capability_authority(
        &self,
    ) -> Result<&ProductionCustodyKeyBinding, ShadowError> {
        self.authority_binding(
            AuthorityRole::CustodySupervisorCapability,
        )
    }

    pub(in crate::policy_shadow) fn execution_closure_manifest(
        &self,
    ) -> Result<&ProductionCustodyExecutionClosureManifest,ShadowError> {
        // No production callers existed for this legacy-only accessor. Keep
        // its meaning explicit: a native owner cannot yield an IMA manifest.
        match &self.execution_closure_manifest {
            RetainedProductionCustodyClosure::Legacy(value)=>Ok(value),
            #[cfg(target_os="linux")]
            RetainedProductionCustodyClosure::Native(_)=>Err(ShadowError::CustodyUnavailable),
        }
    }

    #[cfg(target_os="linux")]
    pub(in crate::policy_shadow) fn native_execution_closure(
        &self,
    )->Option<&native_custody_closure::NativeCustodyClosureOwner> {
        match &self.execution_closure_manifest {
            RetainedProductionCustodyClosure::Native(value)=>Some(value),
            RetainedProductionCustodyClosure::Legacy(_)=>None,
        }
    }

    pub(in crate::policy_shadow) fn execution_closure_manifest_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.execution_closure_manifest_sha256
    }

    pub(in crate::policy_shadow) fn structurally_verified_seccomp_policy_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.structurally_verified_seccomp_policy_sha256
    }

    pub(in crate::policy_shadow) fn supervisor_boot_id_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.supervisor_boot_id_sha256
    }

    pub(crate) fn proof_scope(&self) -> &ProductionCustodyProofScope {
        &self.proof_scope
    }

    fn validate_retained_assignment_binding(
        &self,
    ) -> Result<(), ShadowError> {
        let assignment = &self.retained_verified_assignment;
        let payload = assignment.payload();
        if assignment.payload_sha256() != &self.assignment_payload_sha256
            || payload.assignment_id != self.assignment_id
            || payload.assignment_revision != self.assignment_revision
            || payload.custody_authority.authority_id != self.authority_id
            || payload.custody_authority.storage_realm_sha256
                != self.storage_realm_sha256
            || payload.custody_authority.retrieval_namespace_sha256
                != self.retrieval_namespace_sha256
            || payload
                .custody_authority
                .execution_closure_manifest_sha256
                != self.execution_closure_manifest_sha256
            || payload
                .custody_authority
                .structurally_verified_seccomp_policy_sha256
                != self.structurally_verified_seccomp_policy_sha256
            || payload
                .authority_key_independence
                .independence_root_sha256
                != self.authority_key_independence_sha256
            || payload.custody_authority.attestation_mode
                != self.attestation_mode
            || self.proof_scope.assignment_id != self.assignment_id
            || self.proof_scope.assignment_payload_sha256
                != self.assignment_payload_sha256
            || self.proof_scope.assignment_revision
                != self.assignment_revision
            || self.proof_scope.authority_id != self.authority_id
            || self.proof_scope.storage_realm_sha256
                != self.storage_realm_sha256
            || self.proof_scope.retrieval_namespace_sha256
                != self.retrieval_namespace_sha256
            || self.proof_scope.authority_key_independence_sha256
                != self.authority_key_independence_sha256
            || self
                .proof_scope
                .production_configuration_binding_sha256
                != self.production_configuration_binding_sha256
            || self.proof_scope.asserted_custody_key_set_root_sha256
                != self.asserted_custody_key_set_root_sha256
            || self.proof_scope.execution_closure_manifest_sha256
                != self.execution_closure_manifest_sha256
            || self
                .proof_scope
                .structurally_verified_seccomp_policy_sha256
                != self.structurally_verified_seccomp_policy_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        self.execution_closure_manifest.validate()?;
        if self.execution_closure_manifest.manifest_sha256()
                != &self.execution_closure_manifest_sha256
            || self
                .execution_closure_manifest
                .seccomp_policy_sha256()
                != &self.structurally_verified_seccomp_policy_sha256
            || self.execution_closure_manifest.worker_executable_sha256()
                != &self.worker_executable_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        payload.authority_key_independence.validate(
            &payload.assignment_id,
            &payload.fleet,
            &payload.custody_authority,
        )?;
        if self.authority_bindings.len()
            != PRODUCTION_CUSTODY_AUTHORITY_ROLES.len()
            || production_custody_key_set_root(&self.authority_bindings)?
                != self.asserted_custody_key_set_root_sha256
            || production_custody_operation_coverage_root()?
                != self.operation_coverage_root_sha256
            || self.maximum_async_durability_nanos == 0
            || self.maximum_async_durability_nanos
                > self.maximum_rpc_nanos
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        for role in PRODUCTION_CUSTODY_AUTHORITY_ROLES {
            let retained = payload
                .authority_key_independence
                .binding(role, &payload.assignment_id)?;
            let configured = self.authority_binding(role)?;
            if configured.role != role
                || configured.key_id != retained.key_id
                || configured.key_spki_sha256
                    != retained.key_spki_sha256
                || configured.key_material_sha256
                    != retained.key_material_sha256
            {
                return Err(ShadowError::SignerBindingMismatch);
            }
        }
        if self.proof_scope.store_response_authority()
                != self.authority_binding(
                    AuthorityRole::CustodyStoreResponse,
                )?
            || self.proof_scope.retrieval_response_authority()
                != self.authority_binding(
                    AuthorityRole::CustodyRetrievalResponse,
                )?
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        Ok(())
    }

    fn revalidate_retained_assignment_at_checkpoint(
        &self,
        checkpoint: &AtomicTrustCheckpoint,
        key_trust: &dyn EnvelopeKeyTrust,
    ) -> Result<(), ShadowError> {
        self.validate_retained_assignment_binding()?;
        #[cfg(target_os="linux")]
        if let Some(closure)=self.native_execution_closure() {
            closure.verify_current(&self.retained_verified_assignment,checkpoint,key_trust)?;
        }
        if !self
            .retained_verified_assignment
            .trust_checkpoint
            .permits_successor(checkpoint)
            || !self
                .authority_trust_checkpoint
                .permits_successor(checkpoint)
        {
            return Err(ShadowError::TrustResolutionFailed);
        }
        revalidate_verified_at_checkpoint(
            &self.retained_verified_assignment,
            checkpoint,
            key_trust,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        verify_assignment_authority_key_material_at_checkpoint(
            &self.retained_verified_assignment,
            checkpoint,
            key_trust,
        )?;
        if key_trust.current_checkpoint()? != *checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(())
    }

    fn validate_attestation_binding_at_checkpoint(
        &self,
        attestation: &VerifiedCustodyAttestation,
        expected_checkpoint: &AtomicTrustCheckpoint,
    ) -> Result<(), ShadowError> {
        if attestation.production_configuration_binding_sha256
                != self.production_configuration_binding_sha256
            || attestation.worker_executable_sha256
                != self.worker_executable_sha256
            || attestation.execution_closure_manifest_sha256
                != self.execution_closure_manifest_sha256
            || attestation
                .structurally_verified_seccomp_policy_sha256
                != self.structurally_verified_seccomp_policy_sha256
            || attestation.asserted_custody_key_set_root_sha256
                != self.asserted_custody_key_set_root_sha256
            || attestation.verified_trust_checkpoint
                != *expected_checkpoint
        {
            return Err(ShadowError::BindingDrift);
        }
        match (&self.attestation_mode, &attestation.kind) {
            (
                CustodyAttestationMode::Tee {
                    platform,
                    expected_measurement_sha256,
                    ..
                },
                VerifiedCustodyAttestationKind::Tee {
                    platform: verified_platform,
                    measurement_sha256,
                    ..
                },
            ) if platform == verified_platform
                && expected_measurement_sha256 == measurement_sha256 => {}
            (
                CustodyAttestationMode::TrustedHost { .. },
                VerifiedCustodyAttestationKind::TrustedHost { .. },
            ) => {}
            _ => return Err(ShadowError::BindingDrift),
        }
        Ok(())
    }

    fn revalidate_attestation_at_checkpoint(
        &self,
        attestation: &VerifiedCustodyAttestation,
        checkpoint: &AtomicTrustCheckpoint,
        key_trust: &dyn EnvelopeKeyTrust,
    ) -> Result<(), ShadowError> {
        self.validate_attestation_binding_at_checkpoint(
            attestation,
            checkpoint,
        )?;
        if key_trust.current_checkpoint()? != *checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        let verifier = self.authority_binding(
            AuthorityRole::CustodyAttestationVerifier,
        )?;
        let key = key_trust.resolve_ed25519_key(
            checkpoint,
            authority_role_signature_domain(
                AuthorityRole::CustodyAttestationVerifier,
            ),
            verifier.key_id(),
            verifier.key_spki_sha256(),
        )?;
        if ed25519_public_key_material_sha256(&key)
            != *verifier.key_material_sha256()
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        if key_trust.current_checkpoint()? != *checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(())
    }

    fn revalidate_active_attestation_at_checkpoint(
        &self,
        checkpoint: &AtomicTrustCheckpoint,
        key_trust: &dyn EnvelopeKeyTrust,
    ) -> Result<&VerifiedCustodyAttestation, ShadowError> {
        let attestation = self.require_active_attestation()?;
        self.revalidate_attestation_at_checkpoint(
            attestation,
            checkpoint,
            key_trust,
        )?;
        Ok(attestation)
    }

    fn validate_authority_evidence_freshness_at(
        &self,
        trusted_now_unix_nanos: i64,
    ) -> Result<(), ShadowError> {
        #[cfg(target_os="linux")]
        if let Some(closure)=self.native_execution_closure() {closure.freshness(trusted_now_unix_nanos)?;}
        validate_freshness(
            self.retained_verified_assignment
                .payload()
                .issued_at_unix_nanos(),
            self.retained_verified_assignment
                .payload()
                .expires_at_unix_nanos(),
            trusted_now_unix_nanos,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        let attestation = self.require_active_attestation()?;
        validate_freshness(
            attestation.verified_at_unix_nanos,
            attestation.expires_at_unix_nanos,
            trusted_now_unix_nanos,
            self.maximum_authority_evidence_age_nanos,
        )
    }

    pub(in crate::policy_shadow) fn activate_with_verified_attestation(
        mut self,
        attestation: VerifiedCustodyAttestation,
    ) -> Result<Self, ShadowError> {
        #[cfg(target_os="linux")]
        if let Some(closure)=self.native_execution_closure() {closure.check()?;}
        self.validate_attestation_binding_at_checkpoint(
            &attestation,
            &self.authority_trust_checkpoint,
        )?;
        self.verified_attestation = Some(attestation);
        Ok(self)
    }

    pub(in crate::policy_shadow) fn require_active_attestation(
        &self,
    ) -> Result<&VerifiedCustodyAttestation, ShadowError> {
        self.verified_attestation
            .as_ref()
            .ok_or(ShadowError::CustodyUnavailable)
    }

    pub(in crate::policy_shadow) fn revalidate_active_attestation(
        &self,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<&VerifiedCustodyAttestation, ShadowError> {
        let checkpoint = key_trust.current_checkpoint()?;
        let attestation = self.revalidate_active_attestation_at_checkpoint(
            &checkpoint,
            key_trust,
        )?;
        self.revalidate_retained_assignment_at_checkpoint(
            &checkpoint,
            key_trust,
        )?;
        let now = trusted_time.now_unix_nanos()?;
        self.validate_authority_evidence_freshness_at(now)?;
        if key_trust.current_checkpoint()? != checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(attestation)
    }

    /// Copy-on-success transition to a newly verified attestation at a
    /// monotonic successor checkpoint. Any failure leaves the existing
    /// configuration unchanged and hard-unready at the new checkpoint.
    pub(in crate::policy_shadow) fn refresh_for_successor_checkpoint(
        &self,
        successor_attestation: VerifiedCustodyAttestation,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<Self, ShadowError> {
        let previous_attestation = self.require_active_attestation()?;
        self.validate_attestation_binding_at_checkpoint(
            previous_attestation,
            &self.authority_trust_checkpoint,
        )?;
        let successor = key_trust.current_checkpoint()?;
        if successor == self.authority_trust_checkpoint
            || !self
                .authority_trust_checkpoint
                .permits_successor(&successor)
        {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        self.revalidate_retained_assignment_at_checkpoint(
            &successor,
            key_trust,
        )?;
        self.revalidate_attestation_at_checkpoint(
            &successor_attestation,
            &successor,
            key_trust,
        )?;
        let now = trusted_time.now_unix_nanos()?;
        #[cfg(target_os="linux")]
        if let Some(closure)=self.native_execution_closure() {closure.freshness(now)?;}
        validate_freshness(
            self.retained_verified_assignment
                .payload()
                .issued_at_unix_nanos(),
            self.retained_verified_assignment
                .payload()
                .expires_at_unix_nanos(),
            now,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        validate_freshness(
            successor_attestation.verified_at_unix_nanos,
            successor_attestation.expires_at_unix_nanos,
            now,
            self.maximum_authority_evidence_age_nanos,
        )?;
        if key_trust.current_checkpoint()? != successor {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        let mut refreshed = self.clone();
        refreshed.authority_trust_checkpoint = successor;
        refreshed.verified_attestation = Some(successor_attestation);
        Ok(refreshed)
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_custody_attestation_verifier_result(
    configuration: &ProductionCustodyConfiguration,
    verified_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    trust_checkpoint_id: &Sha256Digest,
    trust_revocation_generation: u64,
    trust_revocation_root_sha256: &Sha256Digest,
    signing_key_id: &Sha256Digest,
    signing_key_spki_sha256: &Sha256Digest,
    signature: &CanonicalEd25519Signature,
    canonical_payload: &[u8],
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<AtomicTrustCheckpoint, ShadowError> {
    let now = trusted_time.now_unix_nanos()?;
    validate_freshness(
        verified_at_unix_nanos,
        expires_at_unix_nanos,
        now,
        configuration.maximum_authority_evidence_age_nanos,
    )?;
    let checkpoint = key_trust.current_checkpoint()?;
    #[cfg(target_os="linux")]
    if let Some(closure)=configuration.native_execution_closure() {
        closure.verify_current(&configuration.retained_verified_assignment,&checkpoint,key_trust)?;
        closure.freshness(now)?;
    }
    if checkpoint.checkpoint_id != *trust_checkpoint_id
        || checkpoint.revocation_generation != trust_revocation_generation
        || checkpoint.revocation_root_sha256
            != *trust_revocation_root_sha256
    {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let expected = configuration.authority_binding(
        AuthorityRole::CustodyAttestationVerifier,
    )?;
    if signing_key_id != expected.key_id()
        || signing_key_spki_sha256 != expected.key_spki_sha256()
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let key = key_trust.resolve_ed25519_key(
        &checkpoint,
        authority_role_signature_domain(
            AuthorityRole::CustodyAttestationVerifier,
        ),
        signing_key_id,
        signing_key_spki_sha256,
    )?;
    if &ed25519_public_key_material_sha256(&key)
        != expected.key_material_sha256()
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    key.verify_strict(
        &signature_preimage(
            authority_role_signature_domain(
                AuthorityRole::CustodyAttestationVerifier,
            ),
            canonical_payload,
        ),
        &Signature::from_bytes(&signature.decode()?),
    )
    .map_err(|_| ShadowError::SignatureInvalid)?;
    let final_now = trusted_time.now_unix_nanos()?;
    if final_now < now {
        return Err(ShadowError::TrustedTimeUnavailable);
    }
    #[cfg(target_os="linux")]
    if let Some(closure)=configuration.native_execution_closure() {closure.freshness(final_now)?;}
    validate_freshness(
        verified_at_unix_nanos,
        expires_at_unix_nanos,
        final_now,
        configuration.maximum_authority_evidence_age_nanos,
    )?;
    if key_trust.current_checkpoint()? != checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(checkpoint)
}

pub(in crate::policy_shadow) fn verify_production_custody_tee_attestation(
    configuration: &ProductionCustodyConfiguration,
    wire: CustodyTeeAttestationVerifierResultWire,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedCustodyAttestation, ShadowError> {
    let CustodyAttestationMode::Tee {
        platform,
        expected_measurement_sha256,
        endorsement_root_sha256,
        collateral_policy_sha256,
        revocation_source_sha256,
    } = configuration.attestation_mode()
    else {
        return Err(ShadowError::BindingDrift);
    };
    if wire.platform != *platform
        || wire.measurement_sha256 != *expected_measurement_sha256
        || wire.endorsement_root_sha256 != *endorsement_root_sha256
        || wire.collateral_policy_sha256 != *collateral_policy_sha256
        || wire.revocation_source_sha256 != *revocation_source_sha256
        || wire.production_configuration_binding_sha256
            != configuration.production_configuration_binding_sha256
        || wire.worker_executable_sha256
            != configuration.worker_executable_sha256
        || wire.execution_closure_manifest_sha256
            != configuration.execution_closure_manifest_sha256
        || wire.structurally_verified_seccomp_policy_sha256
            != configuration
                .structurally_verified_seccomp_policy_sha256
        || wire.quote_bound_custody_key_set_root_sha256
            != configuration.asserted_custody_key_set_root_sha256
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint =
        verify_custody_attestation_verifier_result(
            configuration,
            wire.verified_at_unix_nanos,
            wire.expires_at_unix_nanos,
            &wire.trust_checkpoint_id,
            wire.trust_revocation_generation,
            &wire.trust_revocation_root_sha256,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            &canonical_payload,
            key_trust,
            trusted_time,
        )?;
    Ok(VerifiedCustodyAttestation {
        kind: VerifiedCustodyAttestationKind::Tee {
            platform: wire.platform,
            quote_sha256: wire.quote_sha256,
            endorsement_evidence_sha256:
                wire.endorsement_evidence_sha256,
            collateral_revocation_generation:
                wire.collateral_revocation_generation,
            collateral_revocation_root_sha256:
                wire.collateral_revocation_root_sha256,
            measurement_sha256: wire.measurement_sha256,
        },
        production_configuration_binding_sha256:
            wire.production_configuration_binding_sha256,
        worker_executable_sha256: wire.worker_executable_sha256,
        execution_closure_manifest_sha256:
            wire.execution_closure_manifest_sha256,
        structurally_verified_seccomp_policy_sha256:
            wire.structurally_verified_seccomp_policy_sha256,
        asserted_custody_key_set_root_sha256:
            wire.quote_bound_custody_key_set_root_sha256,
        verified_at_unix_nanos: wire.verified_at_unix_nanos,
        expires_at_unix_nanos: wire.expires_at_unix_nanos,
        verified_trust_checkpoint,
        _not_constructible: PhantomData,
    })
}

pub(in crate::policy_shadow) fn verify_production_custody_trusted_host_attestation(
    configuration: &ProductionCustodyConfiguration,
    wire: CustodyTrustedHostVerifierResultWire,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedCustodyAttestation, ShadowError> {
    let CustodyAttestationMode::TrustedHost {
        host_evidence_profile_sha256,
        host_evidence_policy_sha256,
    } = configuration.attestation_mode()
    else {
        return Err(ShadowError::BindingDrift);
    };
    if wire.host_evidence_profile_sha256
            != *host_evidence_profile_sha256
        || wire.host_evidence_policy_sha256
            != *host_evidence_policy_sha256
        || wire.production_configuration_binding_sha256
            != configuration.production_configuration_binding_sha256
        || wire.worker_executable_sha256
            != configuration.worker_executable_sha256
        || wire.execution_closure_manifest_sha256
            != configuration.execution_closure_manifest_sha256
        || wire.structurally_verified_seccomp_policy_sha256
            != configuration
                .structurally_verified_seccomp_policy_sha256
        || wire.asserted_custody_key_set_root_sha256
            != configuration.asserted_custody_key_set_root_sha256
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint =
        verify_custody_attestation_verifier_result(
            configuration,
            wire.verified_at_unix_nanos,
            wire.expires_at_unix_nanos,
            &wire.trust_checkpoint_id,
            wire.trust_revocation_generation,
            &wire.trust_revocation_root_sha256,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            &canonical_payload,
            key_trust,
            trusted_time,
        )?;
    Ok(VerifiedCustodyAttestation {
        kind: VerifiedCustodyAttestationKind::TrustedHost {
            host_evidence_sha256: wire.host_evidence_sha256,
            host_measurement_sha256: wire.host_measurement_sha256,
        },
        production_configuration_binding_sha256:
            wire.production_configuration_binding_sha256,
        worker_executable_sha256: wire.worker_executable_sha256,
        execution_closure_manifest_sha256:
            wire.execution_closure_manifest_sha256,
        structurally_verified_seccomp_policy_sha256:
            wire.structurally_verified_seccomp_policy_sha256,
        asserted_custody_key_set_root_sha256:
            wire.asserted_custody_key_set_root_sha256,
        verified_at_unix_nanos: wire.verified_at_unix_nanos,
        expires_at_unix_nanos: wire.expires_at_unix_nanos,
        verified_trust_checkpoint,
        _not_constructible: PhantomData,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_production_custody_receipt_authority(
    configuration: &ProductionCustodyConfiguration,
    role: PolicyShadowCustodySignerRole,
    signing_key_id: &Sha256Digest,
    signing_key_spki_sha256: &Sha256Digest,
    signature: &CanonicalEd25519Signature,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: &Sha256Digest,
    persistence_receipt_sha256: &Sha256Digest,
    retrieval_id_sha256: &Sha256Digest,
    retrieval_proof_sha256: &Sha256Digest,
    canonical_payload: &[u8],
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<AtomicTrustCheckpoint, ShadowError> {
    configuration.revalidate_active_attestation(
        key_trust,
        trusted_time,
    )?;
    let authority = configuration.signer_authority(role)?;
    verify_custody_receipt_authority_inner(
        role,
        signing_key_id,
        signing_key_spki_sha256,
        signature,
        trusted_observed_at_unix_nanos,
        trusted_time_checkpoint_sha256,
        persistence_receipt_sha256,
        retrieval_id_sha256,
        retrieval_proof_sha256,
        canonical_payload,
        CustodyReceiptVerificationAuthority::Production {
            configuration,
            authority,
        },
        key_trust,
        trusted_time,
        proof_verifier,
        configuration.maximum_authority_evidence_age_nanos,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionCustodyTerminationProof {
    operation_id_sha256: Sha256Digest,
    termination_fence_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    kernel_retained_descriptor_set_sha256: Sha256Digest,
    driver_generation_receipt_sha256: Sha256Digest,
    worker_terminated_at_unix_nanos: i64,
    worker_terminated_at_boottime_nanos: u64,
    process_reaped: VerifiedProcessReaped,
    late_mutation_fence_closed: VerifiedLateMutationFenceClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedProcessReaped;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedLateMutationFenceClosed;

impl ProductionCustodyTerminationProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_process_supervisor(
        operation_id_sha256: Sha256Digest,
        termination_fence_sha256: Sha256Digest,
        worker_executable_sha256: Sha256Digest,
        kernel_driver_identity_sha256: Sha256Digest,
        kernel_retained_descriptor_set_sha256: Sha256Digest,
        driver_generation_receipt_sha256: Sha256Digest,
        worker_terminated_at_unix_nanos: i64,
        worker_terminated_at_boottime_nanos: u64,
        process_reaped: bool,
        late_mutation_fence_closed: bool,
    ) -> Result<Self, ShadowError> {
        if worker_terminated_at_unix_nanos <= 0
            || worker_terminated_at_boottime_nanos == 0
            || !process_reaped
            || !late_mutation_fence_closed
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(Self {
            operation_id_sha256,
            termination_fence_sha256,
            worker_executable_sha256,
            kernel_driver_identity_sha256,
            kernel_retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
            worker_terminated_at_unix_nanos,
            worker_terminated_at_boottime_nanos,
            process_reaped: VerifiedProcessReaped,
            late_mutation_fence_closed:
                VerifiedLateMutationFenceClosed,
        })
    }

    fn validate_against(
        &self,
        operation_id_sha256: &Sha256Digest,
        termination_fence_sha256: &Sha256Digest,
        worker_executable_sha256: &Sha256Digest,
        kernel_driver_identity_sha256: &Sha256Digest,
        cleanup_deadline_boottime_nanos: u64,
    ) -> Result<(), ShadowError> {
        if self.operation_id_sha256 != *operation_id_sha256
            || self.termination_fence_sha256
                != *termination_fence_sha256
            || self.worker_executable_sha256
                != *worker_executable_sha256
            || self.kernel_driver_identity_sha256
                != *kernel_driver_identity_sha256
            || self.kernel_retained_descriptor_set_sha256
                .as_str()
                .is_empty()
            || self.driver_generation_receipt_sha256
                .as_str()
                .is_empty()
            || self.worker_terminated_at_unix_nanos <= 0
            || self.worker_terminated_at_boottime_nanos == 0
            || self.worker_terminated_at_boottime_nanos
                >= cleanup_deadline_boottime_nanos
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let _ = (
            self.process_reaped,
            self.late_mutation_fence_closed,
        );
        Ok(())
    }
}

/// Every production mutation receives this non-cloneable fence capability.
/// Closing the shared fence is allocation-free and immediately makes a late
/// worker response unable to authorize persistence or signing.
pub(crate) struct ProductionCustodyMutationPermit {
    operation_id_sha256: Sha256Digest,
    operation: PolicyShadowCustodyOperation,
    request_sha256: Sha256Digest,
    durable_request_sha256: Sha256Digest,
    termination_fence_sha256: Sha256Digest,
    operation_deadline: ProductionCustodyOperationDeadline,
    authorization_deadline:
        policy_custody::boottime::BoottimeDeadline,
    fence_open: Arc<AtomicBool>,
}

impl ProductionCustodyMutationPermit {
    pub(crate) fn authorize(
        &self,
        operation: PolicyShadowCustodyOperation,
        operation_id_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        if self.operation != operation
            || self.operation_id_sha256 != *operation_id_sha256
            || !self.fence_open.load(Ordering::Acquire)
            || !self.authorization_deadline.is_live()
            || !self.operation_deadline.authorizes_operation_at(
                production_now_boottime_nanos()?,
            )
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn authorize_cleanup(
        &self,
        operation: PolicyShadowCustodyOperation,
        operation_id_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        if self.operation != operation
            || self.operation_id_sha256 != *operation_id_sha256
            || self.fence_open.load(Ordering::Acquire)
            || !self.authorization_deadline.is_live()
            || !self.operation_deadline.authorizes_cleanup_at(
                production_now_boottime_nanos()?,
            )
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn operation_id_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.operation_id_sha256
    }

    pub(in crate::policy_shadow) fn operation(
        &self,
    ) -> PolicyShadowCustodyOperation {
        self.operation
    }

    pub(in crate::policy_shadow) fn request_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.request_sha256
    }

    pub(in crate::policy_shadow) fn durable_request_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.durable_request_sha256
    }

    pub(in crate::policy_shadow) fn operation_deadline(
        &self,
    ) -> &ProductionCustodyOperationDeadline {
        &self.operation_deadline
    }

    pub(in crate::policy_shadow) fn termination_fence_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.termination_fence_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct ProductionCustodyDispatchManifest {
    operation_coverage_root_sha256: Sha256Digest,
    five_service_protocol_set_sha256: Sha256Digest,
    kernel_driver_identity: ProductionCustodyKernelDriverIdentity,
    stable_reaper_identity: ProductionCustodyStableReaperIdentity,
    worker_executable_sha256: Sha256Digest,
    signer_backend_sha256: Sha256Digest,
    persistence_backend_sha256: Sha256Digest,
    retrieval_backend_sha256: Sha256Digest,
    maximum_request_bytes: u64,
    maximum_response_bytes: u64,
    maximum_async_durability_nanos: u64,
    terminal_cleanup_signing_key_id: Sha256Digest,
    terminal_cleanup_signing_key_spki_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
}

impl ProductionCustodyDispatchManifest {
    pub(in crate::policy_shadow) fn from_verified_external_dispatcher(
        configuration: &ProductionCustodyConfiguration,
        kernel_driver_identity: ProductionCustodyKernelDriverIdentity,
        stable_reaper_identity: ProductionCustodyStableReaperIdentity,
        five_service_protocol_set_sha256: Sha256Digest,
        maximum_request_bytes: u64,
        maximum_response_bytes: u64,
        maximum_async_durability_nanos: u64,
    ) -> Result<Self, ShadowError> {
        kernel_driver_identity.validate(
            &configuration.worker_executable_sha256,
            &configuration.supervisor_boot_id_sha256,
        )?;
        stable_reaper_identity.validate(
            configuration,
            &kernel_driver_identity,
        )?;
        let cleanup_authority = configuration
            .authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        let mut manifest = Self {
            operation_coverage_root_sha256:
                production_custody_operation_coverage_root()?,
            five_service_protocol_set_sha256,
            kernel_driver_identity,
            stable_reaper_identity,
            worker_executable_sha256:
                configuration.worker_executable_sha256.clone(),
            signer_backend_sha256:
                configuration.signer_backend_sha256.clone(),
            persistence_backend_sha256:
                configuration.persistence_backend_sha256.clone(),
            retrieval_backend_sha256:
                configuration.retrieval_backend_sha256.clone(),
            maximum_request_bytes,
            maximum_response_bytes,
            maximum_async_durability_nanos,
            terminal_cleanup_signing_key_id:
                cleanup_authority.key_id().clone(),
            terminal_cleanup_signing_key_spki_sha256:
                cleanup_authority.key_spki_sha256().clone(),
            manifest_sha256: Sha256Digest::compute(b"uninitialized"),
        };
        manifest.manifest_sha256 = manifest.recompute_sha256()?;
        manifest.validate(configuration)?;
        Ok(manifest)
    }

    fn recompute_sha256(&self) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyShadowCustodyDispatchManifest/v1",
            &[&canonical_json_bytes(&(
                PRODUCTION_CUSTODY_DISPATCH_CONTRACT_VERSION,
                &self.operation_coverage_root_sha256,
                &self.five_service_protocol_set_sha256,
                self.kernel_driver_identity.identity_sha256(),
                self.stable_reaper_identity.identity_sha256(),
                &self.worker_executable_sha256,
                &self.signer_backend_sha256,
                &self.persistence_backend_sha256,
                &self.retrieval_backend_sha256,
                self.maximum_request_bytes,
                self.maximum_response_bytes,
                self.maximum_async_durability_nanos,
                &self.terminal_cleanup_signing_key_id,
                &self.terminal_cleanup_signing_key_spki_sha256,
            ))?],
        ))
    }

    fn validate(
        &self,
        configuration: &ProductionCustodyConfiguration,
    ) -> Result<(), ShadowError> {
        self.kernel_driver_identity.validate(
            &configuration.worker_executable_sha256,
            &configuration.supervisor_boot_id_sha256,
        )?;
        self.stable_reaper_identity.validate(
            configuration,
            &self.kernel_driver_identity,
        )?;
        let cleanup_authority = configuration
            .authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        if self.operation_coverage_root_sha256
                != *configuration.operation_coverage_root_sha256()
            || self.five_service_protocol_set_sha256
                != *configuration.dispatcher_protocol_set_sha256()
            || self.kernel_driver_identity.identity_sha256()
                != configuration.kernel_retained_driver_identity_sha256()
            || self.worker_executable_sha256
                != configuration.worker_executable_sha256
            || self.signer_backend_sha256
                != configuration.signer_backend_sha256
            || self.persistence_backend_sha256
                != configuration.persistence_backend_sha256
            || self.retrieval_backend_sha256
                != configuration.retrieval_backend_sha256
            || self.maximum_request_bytes == 0
            || self.maximum_request_bytes
                > MAX_PRODUCTION_CUSTODY_DISPATCH_REQUEST_BYTES
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes
                > MAX_PRODUCTION_CUSTODY_DISPATCH_RESPONSE_BYTES
            || self.maximum_async_durability_nanos
                != configuration.maximum_async_durability_nanos()
            || self.terminal_cleanup_signing_key_id
                != *cleanup_authority.key_id()
            || self.terminal_cleanup_signing_key_spki_sha256
                != *cleanup_authority.key_spki_sha256()
            || self.recompute_sha256()? != self.manifest_sha256
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }

    pub(in crate::policy_shadow) fn manifest_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub(in crate::policy_shadow) fn stable_reaper_identity(
        &self,
    ) -> &ProductionCustodyStableReaperIdentity {
        &self.stable_reaper_identity
    }
}

pub(in crate::policy_shadow) enum ProductionCustodyDispatchRequest {
    RecoverCurrentState,
    VerifyCheckpointSuccessor {
        generation: ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        previous_checkpoint_sha256: Sha256Digest,
        checkpoint_payload_sha256: Sha256Digest,
    },
    VerifyCurrentCheckpointHead {
        generation: ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        checkpoint_sha256: Sha256Digest,
    },
    VerifyObservationEvidence {
        evidence: CustodyEvidenceBinding,
        ingress: IngressEvidencePayload,
        active_decision: ActiveDecisionReceiptPayload,
    },
    PrepareGenerationPublication {
        recovered: VerifiedPublicationReconciliationReceipt,
        previous: Option<ShadowGenerationIdentity>,
        successor: ShadowGenerationIdentity,
    },
    CommitGenerationPublication {
        prepared: PreparedGenerationPublication,
    },
    AbortGenerationPublication {
        prepared: PreparedGenerationPublication,
    },
    BeginIngress {
        request_binding_sha256: Sha256Digest,
    },
    ReserveSpoolAppend {
        event: ShadowSpoolEvent,
    },
    AppendSpoolEvent {
        reservation: VerifiedSpoolAppendReservation,
        event: ShadowSpoolEvent,
    },
    CompactSpool {
        request: AuthenticatedSpoolCompactionRequest,
    },
    CommitRequest {
        facts: ProtectedRequestFacts,
        context: RequestCommitmentContext,
    },
    AppendActiveEffectBarrier {
        preparation: ActiveEffectPreparation,
    },
    CommitActiveEffect {
        effect_permit: VerifiedActiveEffectPermit,
        terminal_state: ActiveEffectCommitState,
        result_sha256: Sha256Digest,
    },
    ReconcileActiveEffect {
        generation_id: Sha256Digest,
        ingress_sequence: u64,
        effect_id_sha256: Sha256Digest,
    },
    AppendTerminal {
        request: TerminalSlotAppendRequest,
    },
    ConsumeAndPublishActivation {
        transaction: ActivationPublicationTransaction,
    },
}

impl ProductionCustodyDispatchRequest {
    pub(in crate::policy_shadow) fn operation(
        &self,
    ) -> PolicyShadowCustodyOperation {
        match self {
            Self::RecoverCurrentState => {
                PolicyShadowCustodyOperation::RecoverCurrentState
            }
            Self::VerifyCheckpointSuccessor { .. } => {
                PolicyShadowCustodyOperation::VerifyCheckpointSuccessor
            }
            Self::VerifyCurrentCheckpointHead { .. } => {
                PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead
            }
            Self::VerifyObservationEvidence { .. } => {
                PolicyShadowCustodyOperation::VerifyObservationEvidence
            }
            Self::PrepareGenerationPublication { .. } => {
                PolicyShadowCustodyOperation::PrepareGenerationPublication
            }
            Self::CommitGenerationPublication { .. } => {
                PolicyShadowCustodyOperation::CommitGenerationPublication
            }
            Self::AbortGenerationPublication { .. } => {
                PolicyShadowCustodyOperation::AbortGenerationPublication
            }
            Self::BeginIngress { .. } => {
                PolicyShadowCustodyOperation::BeginIngress
            }
            Self::ReserveSpoolAppend { .. } => {
                PolicyShadowCustodyOperation::ReserveSpoolAppend
            }
            Self::AppendSpoolEvent { .. } => {
                PolicyShadowCustodyOperation::AppendSpoolEvent
            }
            Self::CompactSpool { .. } => {
                PolicyShadowCustodyOperation::CompactSpool
            }
            Self::CommitRequest { .. } => {
                PolicyShadowCustodyOperation::CommitRequest
            }
            Self::AppendActiveEffectBarrier { .. } => {
                PolicyShadowCustodyOperation::AppendActiveEffectBarrier
            }
            Self::CommitActiveEffect { .. } => {
                PolicyShadowCustodyOperation::CommitActiveEffect
            }
            Self::ReconcileActiveEffect { .. } => {
                PolicyShadowCustodyOperation::ReconcileActiveEffect
            }
            Self::AppendTerminal { .. } => {
                PolicyShadowCustodyOperation::AppendTerminal
            }
            Self::ConsumeAndPublishActivation { .. } => {
                PolicyShadowCustodyOperation::ConsumeAndPublishActivation
            }
        }
    }
}

pub(in crate::policy_shadow) enum ProductionCustodyDispatchResponse {
    CurrentStateRecovered(VerifiedPublicationReconciliationReceipt),
    CheckpointSuccessorVerified,
    CurrentCheckpointHeadVerified,
    ObservationEvidenceVerified,
    GenerationPublicationPrepared(PreparedGenerationPublication),
    GenerationPublicationCommitted(
        VerifiedPublicationReconciliationReceipt,
    ),
    GenerationPublicationAborted,
    IngressBegun(IngressCustodyAdmission),
    SpoolAppendReserved(SpoolAppendReservationOutcome),
    SpoolEventAppended(VerifiedShadowSpillReceipt),
    SpoolCompacted(VerifiedSpoolCompactionReceipt),
    RequestCommitted(RequestCommitment),
    ActiveEffectBarrierAppended(VerifiedActiveEffectPermit),
    ActiveEffectCommitted(VerifiedActiveEffectCommitReceipt),
    ActiveEffectReconciled(VerifiedActiveEffectCommitReceipt),
    TerminalAppended(TerminalSlotAppendOutcome),
    ActivationConsumedAndPublished(VerifiedActivationPublicationReceipt),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodyResultDisposition {
    ResultCommitted,
    ResultAborted,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(in crate::policy_shadow) enum ProductionCustodyDurabilityMode {
    Synchronous,
    BoundedAsync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyDurabilitySettlement {
    mode: ProductionCustodyDurabilityMode,
    accepted_at_boottime_nanos: u64,
    durable_at_boottime_nanos: u64,
    durability_deadline_boottime_nanos: u64,
    maximum_async_wait_nanos: u64,
    durability_receipt_sha256: Sha256Digest,
    service_settlement_root_sha256: Sha256Digest,
}

impl ProductionCustodyDurabilitySettlement {
    fn validate(
        &self,
        operation_deadline_boottime_nanos: u64,
        cleanup_deadline_boottime_nanos: u64,
        result_disposition: ProductionCustodyResultDisposition,
        maximum_async_durability_nanos: u64,
        five_service_receipts_root_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        let expected_deadline = match result_disposition {
            ProductionCustodyResultDisposition::ResultCommitted => {
                operation_deadline_boottime_nanos
            }
            ProductionCustodyResultDisposition::ResultAborted => {
                cleanup_deadline_boottime_nanos
            }
        };
        if self.accepted_at_boottime_nanos == 0
            || self.durable_at_boottime_nanos
                < self.accepted_at_boottime_nanos
            || self.durability_deadline_boottime_nanos
                != expected_deadline
            || self.durable_at_boottime_nanos
                >= self.durability_deadline_boottime_nanos
            || self.service_settlement_root_sha256
                != *five_service_receipts_root_sha256
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        match self.mode {
            ProductionCustodyDurabilityMode::Synchronous
                if self.maximum_async_wait_nanos == 0
                    && self.durable_at_boottime_nanos
                        == self.accepted_at_boottime_nanos => {}
            ProductionCustodyDurabilityMode::BoundedAsync
                if self.maximum_async_wait_nanos > 0
                    && self.maximum_async_wait_nanos
                        <= maximum_async_durability_nanos
                    && self
                        .durable_at_boottime_nanos
                        .checked_sub(self.accepted_at_boottime_nanos)
                        .is_some_and(|elapsed| {
                            elapsed <= self.maximum_async_wait_nanos
                        }) => {}
            _ => return Err(ShadowError::CustodyUnavailable),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct ProductionCustodyKeyHistoryState {
    current_key_epoch: u64,
    oldest_retained_key_epoch: u64,
    current_key_set_root_sha256: Sha256Digest,
    predecessor_historical_key_chain_root_sha256:
        Option<Sha256Digest>,
    historical_key_chain_root_sha256: Sha256Digest,
    rotation_continuity_receipt_sha256: Sha256Digest,
    trust_checkpoint_sha256: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl ProductionCustodyKeyHistoryState {
    fn validate(
        &self,
        configuration: &ProductionCustodyConfiguration,
        checkpoint: &AtomicTrustCheckpoint,
    ) -> Result<(), ShadowError> {
        validate_positive(
            self.current_key_epoch,
            "custody.key_history.current_key_epoch",
        )?;
        validate_positive(
            self.oldest_retained_key_epoch,
            "custody.key_history.oldest_retained_key_epoch",
        )?;
        if self.oldest_retained_key_epoch > self.current_key_epoch
            || self.current_key_set_root_sha256
                != *configuration.asserted_custody_key_set_root_sha256()
            || self.trust_checkpoint_sha256 != checkpoint.checkpoint_id
            || self.revocation_generation
                != checkpoint.revocation_generation
            || self.revocation_root_sha256
                != checkpoint.revocation_root_sha256
        {
            return Err(ShadowError::TrustResolutionFailed);
        }
        Ok(())
    }

    fn validate_successor(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), ShadowError> {
        match previous {
            None
                if self
                    .predecessor_historical_key_chain_root_sha256
                    .is_none() => Ok(()),
            Some(previous)
                if self.current_key_epoch
                        > previous.current_key_epoch
                    && self.oldest_retained_key_epoch
                        <= previous.oldest_retained_key_epoch
                    && self
                        .predecessor_historical_key_chain_root_sha256
                        .as_ref()
                        == Some(
                            &previous
                                .historical_key_chain_root_sha256,
                        )
                    && self.historical_key_chain_root_sha256
                        != previous.historical_key_chain_root_sha256 => {
                            Ok(())
                        }
            _ => Err(ShadowError::TrustResolutionFailed),
        }
    }
}

fn production_custody_five_service_receipts_root(
    durable_recovery_store_receipt_sha256: &Sha256Digest,
    cleanup_authorization_receipt_sha256: &Sha256Digest,
    recovery_target_receipt_sha256: &Sha256Digest,
    bounded_cleanup_receipt_sha256: &Sha256Digest,
    current_signature_receipt_sha256: &Sha256Digest,
) -> Result<Sha256Digest, ShadowError> {
    Ok(hash_domain_frames(
        b"serverware.policyShadowCustodyFiveServiceSettlement/v1",
        &[&canonical_json_bytes(&(
            durable_recovery_store_receipt_sha256,
            cleanup_authorization_receipt_sha256,
            recovery_target_receipt_sha256,
            bounded_cleanup_receipt_sha256,
            current_signature_receipt_sha256,
        ))?],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct
    ProductionCustodyGenerationTransitionPreparation
{
    transition_id_sha256: Sha256Digest,
    previous_configuration_binding_sha256: Option<Sha256Digest>,
    successor_configuration_binding_sha256: Sha256Digest,
    dispatch_manifest_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    kernel_retained_descriptor_set_sha256: Sha256Digest,
    driver_generation_receipt_sha256: Sha256Digest,
    durable_recovery_store_prepare_receipt_sha256: Sha256Digest,
    cleanup_authorization_prepare_receipt_sha256: Sha256Digest,
    recovery_target_prepare_receipt_sha256: Sha256Digest,
    bounded_cleanup_prepare_receipt_sha256: Sha256Digest,
    current_signature_prepare_receipt_sha256: Sha256Digest,
    five_service_preparation_receipts_root_sha256: Sha256Digest,
    durable_intent_receipt_sha256: Sha256Digest,
    prepared_at_boottime_nanos: u64,
    commit_deadline_boottime_nanos: u64,
}

impl ProductionCustodyGenerationTransitionPreparation {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_shadow) fn from_external_preparation(
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        manifest: &ProductionCustodyDispatchManifest,
        driver_generation_receipt_sha256: Sha256Digest,
        durable_recovery_store_prepare_receipt_sha256: Sha256Digest,
        cleanup_authorization_prepare_receipt_sha256: Sha256Digest,
        recovery_target_prepare_receipt_sha256: Sha256Digest,
        bounded_cleanup_prepare_receipt_sha256: Sha256Digest,
        current_signature_prepare_receipt_sha256: Sha256Digest,
        durable_intent_receipt_sha256: Sha256Digest,
        prepared_at_boottime_nanos: u64,
        commit_deadline_boottime_nanos: u64,
    ) -> Result<Self, ShadowError> {
        let previous_configuration_binding_sha256 =
            previous.map(|configuration| {
                configuration
                    .production_configuration_binding_sha256
                    .clone()
            });
        let five_service_preparation_receipts_root_sha256 =
            production_custody_five_service_receipts_root(
                &durable_recovery_store_prepare_receipt_sha256,
                &cleanup_authorization_prepare_receipt_sha256,
                &recovery_target_prepare_receipt_sha256,
                &bounded_cleanup_prepare_receipt_sha256,
                &current_signature_prepare_receipt_sha256,
            )?;
        let kernel_retained_descriptor_set_sha256 = manifest
            .kernel_driver_identity
            .retained_descriptor_manifest_sha256
            .clone();
        let transition_id_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyGenerationTransition/v1",
            &[&canonical_json_bytes(&(
                &previous_configuration_binding_sha256,
                successor.production_configuration_binding_sha256(),
                manifest.manifest_sha256(),
                manifest.kernel_driver_identity.identity_sha256(),
                &kernel_retained_descriptor_set_sha256,
                &driver_generation_receipt_sha256,
                &five_service_preparation_receipts_root_sha256,
                &durable_intent_receipt_sha256,
                prepared_at_boottime_nanos,
                commit_deadline_boottime_nanos,
            ))?],
        );
        let preparation = Self {
            transition_id_sha256,
            previous_configuration_binding_sha256,
            successor_configuration_binding_sha256: successor
                .production_configuration_binding_sha256
                .clone(),
            dispatch_manifest_sha256:
                manifest.manifest_sha256().clone(),
            kernel_driver_identity_sha256: manifest
                .kernel_driver_identity
                .identity_sha256()
                .clone(),
            kernel_retained_descriptor_set_sha256,
            driver_generation_receipt_sha256,
            durable_recovery_store_prepare_receipt_sha256,
            cleanup_authorization_prepare_receipt_sha256,
            recovery_target_prepare_receipt_sha256,
            bounded_cleanup_prepare_receipt_sha256,
            current_signature_prepare_receipt_sha256,
            five_service_preparation_receipts_root_sha256,
            durable_intent_receipt_sha256,
            prepared_at_boottime_nanos,
            commit_deadline_boottime_nanos,
        };
        preparation.validate(previous, successor, manifest)?;
        Ok(preparation)
    }

    fn validate(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        manifest: &ProductionCustodyDispatchManifest,
    ) -> Result<(), ShadowError> {
        let expected_previous = previous.map(|configuration| {
            configuration
                .production_configuration_binding_sha256
                .clone()
        });
        let expected_root =
            production_custody_five_service_receipts_root(
                &self.durable_recovery_store_prepare_receipt_sha256,
                &self.cleanup_authorization_prepare_receipt_sha256,
                &self.recovery_target_prepare_receipt_sha256,
                &self.bounded_cleanup_prepare_receipt_sha256,
                &self.current_signature_prepare_receipt_sha256,
            )?;
        if self.previous_configuration_binding_sha256
                != expected_previous
            || self.successor_configuration_binding_sha256
                != *successor
                    .production_configuration_binding_sha256()
            || self.dispatch_manifest_sha256
                != *manifest.manifest_sha256()
            || self.kernel_driver_identity_sha256
                != *manifest.kernel_driver_identity.identity_sha256()
            || self.kernel_retained_descriptor_set_sha256
                != manifest
                    .kernel_driver_identity
                    .retained_descriptor_manifest_sha256
            || self.five_service_preparation_receipts_root_sha256
                != expected_root
            || self.prepared_at_boottime_nanos == 0
            || self.commit_deadline_boottime_nanos
                <= self.prepared_at_boottime_nanos
            || self
                .commit_deadline_boottime_nanos
                .checked_sub(self.prepared_at_boottime_nanos)
                != Some(successor.maximum_rpc_nanos)
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }

    fn authorize_commit(&self) -> Result<(), ShadowError> {
        let now = production_now_boottime_nanos()?;
        if now < self.prepared_at_boottime_nanos
            || now >= self.commit_deadline_boottime_nanos
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }

    fn receipt_sha256(&self) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyShadowCustodyGenerationPreparationReceipt/v1",
            &[&canonical_json_bytes(&(
                &self.transition_id_sha256,
                &self.five_service_preparation_receipts_root_sha256,
                &self.durable_intent_receipt_sha256,
                &self.driver_generation_receipt_sha256,
                self.prepared_at_boottime_nanos,
                self.commit_deadline_boottime_nanos,
            ))?],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct
    ProductionCustodyGenerationInstallReceiptPayload
{
    transition_id_sha256: Sha256Digest,
    preparation_receipt_sha256: Sha256Digest,
    previous_configuration_binding_sha256: Option<Sha256Digest>,
    successor_configuration_binding_sha256: Sha256Digest,
    assignment_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    dispatch_manifest_sha256: Sha256Digest,
    operation_coverage_root_sha256: Sha256Digest,
    five_service_protocol_set_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    kernel_retained_descriptor_set_sha256: Sha256Digest,
    driver_generation_receipt_sha256: Sha256Digest,
    five_service_preparation_receipts_root_sha256: Sha256Digest,
    durable_commit_receipt_sha256: Sha256Digest,
    key_history: ProductionCustodyKeyHistoryState,
    durable_recovery_store_receipt_sha256: Sha256Digest,
    cleanup_authorization_receipt_sha256: Sha256Digest,
    recovery_target_receipt_sha256: Sha256Digest,
    bounded_cleanup_receipt_sha256: Sha256Digest,
    current_signature_receipt_sha256: Sha256Digest,
    five_service_receipts_root_sha256: Sha256Digest,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl ProductionCustodyGenerationInstallReceiptPayload {
    fn validate_against(
        &self,
        preparation:
            &ProductionCustodyGenerationTransitionPreparation,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        manifest: &ProductionCustodyDispatchManifest,
        checkpoint: &AtomicTrustCheckpoint,
        previous_key_history:
            Option<&ProductionCustodyKeyHistoryState>,
    ) -> Result<(), ShadowError> {
        self.key_history.validate(successor, checkpoint)?;
        self.key_history
            .validate_successor(previous_key_history)?;
        let expected_previous = previous.map(|configuration| {
            configuration
                .production_configuration_binding_sha256
                .clone()
        });
        preparation.validate(previous, successor, manifest)?;
        if self.transition_id_sha256
                != preparation.transition_id_sha256
            || self.preparation_receipt_sha256
                != preparation.receipt_sha256()?
            || self.previous_configuration_binding_sha256
                != expected_previous
            || self.successor_configuration_binding_sha256
                != successor.production_configuration_binding_sha256
            || self.assignment_id != successor.assignment_id
            || self.assignment_payload_sha256
                != successor.assignment_payload_sha256
            || self.assignment_revision != successor.assignment_revision
            || self.dispatch_manifest_sha256
                != *manifest.manifest_sha256()
            || self.operation_coverage_root_sha256
                != successor.operation_coverage_root_sha256
            || self.five_service_protocol_set_sha256
                != successor.dispatcher_protocol_set_sha256
            || self.kernel_driver_identity_sha256
                != successor.kernel_retained_driver_identity_sha256
            || self.kernel_retained_descriptor_set_sha256
                != preparation.kernel_retained_descriptor_set_sha256
            || self.driver_generation_receipt_sha256
                != preparation.driver_generation_receipt_sha256
            || self.five_service_preparation_receipts_root_sha256
                != preparation
                    .five_service_preparation_receipts_root_sha256
            || self.durable_commit_receipt_sha256
                != hash_domain_frames(
                    b"serverware.policyShadowCustodyGenerationCommit/v1",
                    &[&canonical_json_bytes(&(
                        &preparation.transition_id_sha256,
                        preparation.receipt_sha256()?,
                        &self.five_service_receipts_root_sha256,
                        &self.key_history.historical_key_chain_root_sha256,
                    ))?],
                )
            || self.five_service_receipts_root_sha256
                != production_custody_five_service_receipts_root(
                    &self.durable_recovery_store_receipt_sha256,
                    &self.cleanup_authorization_receipt_sha256,
                    &self.recovery_target_receipt_sha256,
                    &self.bounded_cleanup_receipt_sha256,
                    &self.current_signature_receipt_sha256,
                )?
        {
            return Err(ShadowError::BindingDrift);
        }
        Ok(())
    }
}

impl EnvelopePayload for ProductionCustodyGenerationInstallReceiptPayload {
    const API_VERSION: &'static str =
        "serverware.policyShadowCustodyGenerationInstall/v1";
    const KIND: &'static str =
        "ProductionPolicyShadowCustodyGenerationInstall";
    const SIGNATURE_DOMAIN: &'static str =
        "serverware.policyShadowCustodyResultEnvelope/v1";

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(
            self.assignment_revision,
            "custody.generation_install.assignment_revision",
        )?;
        if self.issued_at_unix_nanos <= 0
            || self.expires_at_unix_nanos
                <= self.issued_at_unix_nanos
            || self.five_service_receipts_root_sha256
                != production_custody_five_service_receipts_root(
                    &self.durable_recovery_store_receipt_sha256,
                    &self.cleanup_authorization_receipt_sha256,
                    &self.recovery_target_receipt_sha256,
                    &self.bounded_cleanup_receipt_sha256,
                    &self.current_signature_receipt_sha256,
                )?
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }
}

pub(in crate::policy_shadow) struct
    ProductionCustodyGenerationInstallAttestation
{
    manifest: ProductionCustodyDispatchManifest,
    signed_receipt:
        SignedEnvelope<ProductionCustodyGenerationInstallReceiptPayload>,
}

impl ProductionCustodyGenerationInstallAttestation {
    pub(in crate::policy_shadow) fn from_external_installation(
        manifest: ProductionCustodyDispatchManifest,
        signed_receipt:
            SignedEnvelope<ProductionCustodyGenerationInstallReceiptPayload>,
    ) -> Self {
        Self {
            manifest,
            signed_receipt,
        }
    }

    fn verify(
        self,
        preparation:
            &ProductionCustodyGenerationTransitionPreparation,
        previous: Option<&ProductionCustodyConfiguration>,
        previous_key_history:
            Option<&ProductionCustodyKeyHistoryState>,
        successor: &ProductionCustodyConfiguration,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<
        (
            ProductionCustodyDispatchManifest,
            ProductionCustodyKeyHistoryState,
        ),
        ShadowError,
    > {
        self.manifest.validate(successor)?;
        let authority = successor
            .authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        let verified = verify_envelope(
            self.signed_receipt,
            ExpectedSigner {
                key_id: authority.key_id(),
                key_spki_sha256: authority.key_spki_sha256(),
            },
            key_trust,
            trusted_time,
            successor.maximum_authority_evidence_age_nanos(),
        )?;
        verified.payload().validate_against(
            preparation,
            previous,
            successor,
            &self.manifest,
            &verified.trust_checkpoint,
            previous_key_history,
        )?;
        if key_trust.current_checkpoint()?
            != verified.trust_checkpoint
        {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok((self.manifest, verified.payload().key_history.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct
    ProductionCustodyTerminalCleanupReceiptPayload
{
    assignment_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    production_configuration_binding_sha256: Sha256Digest,
    dispatch_manifest_sha256: Sha256Digest,
    operation_id_sha256: Sha256Digest,
    operation: PolicyShadowCustodyOperation,
    request_sha256: Sha256Digest,
    durable_request_sha256: Sha256Digest,
    supervisor_boot_id_sha256: Sha256Digest,
    opened_at_boottime_nanos: u64,
    operation_deadline_boottime_nanos: u64,
    cleanup_not_before_boottime_nanos: u64,
    cleanup_deadline_boottime_nanos: u64,
    termination_fence_sha256: Sha256Digest,
    worker_executable_sha256: Sha256Digest,
    kernel_driver_identity_sha256: Sha256Digest,
    kernel_retained_descriptor_set_sha256: Sha256Digest,
    driver_generation_receipt_sha256: Sha256Digest,
    result_disposition: ProductionCustodyResultDisposition,
    result_envelope_sha256: Option<Sha256Digest>,
    result_persistence_receipt_sha256: Option<Sha256Digest>,
    abort_evidence_sha256: Option<Sha256Digest>,
    result_disposition_binding_sha256: Sha256Digest,
    durability: ProductionCustodyDurabilitySettlement,
    key_history: ProductionCustodyKeyHistoryState,
    durable_recovery_store_receipt_sha256: Sha256Digest,
    cleanup_authorization_receipt_sha256: Sha256Digest,
    recovery_target_receipt_sha256: Sha256Digest,
    bounded_cleanup_receipt_sha256: Sha256Digest,
    current_signature_receipt_sha256: Sha256Digest,
    five_service_receipts_root_sha256: Sha256Digest,
    worker_terminated_at_unix_nanos: i64,
    worker_terminated_at_boottime_nanos: u64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl ProductionCustodyTerminalCleanupReceiptPayload {
    fn disposition_binding_sha256(
        operation_id_sha256: &Sha256Digest,
        operation: PolicyShadowCustodyOperation,
        request_sha256: &Sha256Digest,
        durable_request_sha256: &Sha256Digest,
        result_disposition: ProductionCustodyResultDisposition,
        result_envelope_sha256: Option<&Sha256Digest>,
        result_persistence_receipt_sha256: Option<&Sha256Digest>,
        abort_evidence_sha256: Option<&Sha256Digest>,
        five_service_receipts_root_sha256: &Sha256Digest,
    ) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyShadowCustodyResultDisposition/v1",
            &[&canonical_json_bytes(&(
                operation_id_sha256,
                operation,
                request_sha256,
                durable_request_sha256,
                result_disposition,
                result_envelope_sha256,
                result_persistence_receipt_sha256,
                abort_evidence_sha256,
                five_service_receipts_root_sha256,
            ))?],
        ))
    }

    fn five_service_receipts_root_sha256(
        &self,
    ) -> Result<Sha256Digest, ShadowError> {
        production_custody_five_service_receipts_root(
            &self.durable_recovery_store_receipt_sha256,
            &self.cleanup_authorization_receipt_sha256,
            &self.recovery_target_receipt_sha256,
            &self.bounded_cleanup_receipt_sha256,
            &self.current_signature_receipt_sha256,
        )
    }

    fn validate_against(
        &self,
        permit: &ProductionCustodyMutationPermit,
        result_disposition: ProductionCustodyResultDisposition,
        configuration: &ProductionCustodyConfiguration,
        manifest: &ProductionCustodyDispatchManifest,
        checkpoint: &AtomicTrustCheckpoint,
        expected_key_history: &ProductionCustodyKeyHistoryState,
        termination_proof: &ProductionCustodyTerminationProof,
    ) -> Result<(), ShadowError> {
        let deadline = permit.operation_deadline();
        self.key_history.validate(configuration, checkpoint)?;
        self.durability.validate(
            deadline.operation_deadline_boottime_nanos(),
            deadline.cleanup_deadline_boottime_nanos(),
            result_disposition,
            configuration.maximum_async_durability_nanos(),
            &self.five_service_receipts_root_sha256,
        )?;
        termination_proof.validate_against(
            permit.operation_id_sha256(),
            permit.termination_fence_sha256(),
            &configuration.worker_executable_sha256,
            configuration
                .kernel_retained_driver_identity_sha256(),
            deadline.cleanup_deadline_boottime_nanos(),
        )?;
        let disposition_evidence_is_exact = match result_disposition {
            ProductionCustodyResultDisposition::ResultCommitted => {
                self.result_envelope_sha256.is_some()
                    && self
                        .result_persistence_receipt_sha256
                        .is_some()
                    && self.abort_evidence_sha256.is_none()
            }
            ProductionCustodyResultDisposition::ResultAborted => {
                self.result_envelope_sha256.is_none()
                    && self
                        .result_persistence_receipt_sha256
                        .is_none()
                    && self.abort_evidence_sha256.is_some()
            }
        };
        if self.assignment_id != *configuration.assignment_id()
            || self.assignment_payload_sha256
                != *configuration.assignment_payload_sha256()
            || self.assignment_revision
                != configuration.assignment_revision()
            || self.production_configuration_binding_sha256
                != *configuration
                    .production_configuration_binding_sha256()
            || self.dispatch_manifest_sha256
                != *manifest.manifest_sha256()
            || self.operation_id_sha256
                != *permit.operation_id_sha256()
            || self.operation != permit.operation()
            || self.request_sha256 != *permit.request_sha256()
            || self.durable_request_sha256
                != *permit.durable_request_sha256()
            || self.supervisor_boot_id_sha256
                != *deadline.supervisor_boot_id_sha256()
            || self.opened_at_boottime_nanos
                != deadline.opened_at_boottime_nanos()
            || self.operation_deadline_boottime_nanos
                != deadline.operation_deadline_boottime_nanos()
            || self.cleanup_not_before_boottime_nanos
                != deadline.cleanup_not_before_boottime_nanos()
            || self.cleanup_deadline_boottime_nanos
                != deadline.cleanup_deadline_boottime_nanos()
            || self.termination_fence_sha256
                != *permit.termination_fence_sha256()
            || self.worker_executable_sha256
                != configuration.worker_executable_sha256
            || self.kernel_driver_identity_sha256
                != *configuration
                    .kernel_retained_driver_identity_sha256()
            || self.kernel_retained_descriptor_set_sha256
                != termination_proof
                    .kernel_retained_descriptor_set_sha256
            || self.driver_generation_receipt_sha256
                != termination_proof
                    .driver_generation_receipt_sha256
            || self.result_disposition != result_disposition
            || !disposition_evidence_is_exact
            || self.key_history != *expected_key_history
            || self.result_disposition_binding_sha256
                != Self::disposition_binding_sha256(
                    permit.operation_id_sha256(),
                    permit.operation(),
                    permit.request_sha256(),
                    permit.durable_request_sha256(),
                    result_disposition,
                    self.result_envelope_sha256.as_ref(),
                    self.result_persistence_receipt_sha256.as_ref(),
                    self.abort_evidence_sha256.as_ref(),
                    &self.five_service_receipts_root_sha256,
                )?
            || self.five_service_receipts_root_sha256
                != self.five_service_receipts_root_sha256()?
            || self.worker_terminated_at_unix_nanos
                != termination_proof.worker_terminated_at_unix_nanos
            || self.worker_terminated_at_boottime_nanos
                != termination_proof.worker_terminated_at_boottime_nanos
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }
}

impl EnvelopePayload for ProductionCustodyTerminalCleanupReceiptPayload {
    const API_VERSION: &'static str =
        "serverware.policyShadowCustodyTerminalCleanup/v1";
    const KIND: &'static str =
        "ProductionPolicyShadowCustodyTerminalCleanup";
    const SIGNATURE_DOMAIN: &'static str =
        "serverware.policyShadowCustodyResultEnvelope/v1";

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(
            self.assignment_revision,
            "custody.cleanup.assignment_revision",
        )?;
        let disposition_evidence_is_exact = match self.result_disposition {
            ProductionCustodyResultDisposition::ResultCommitted => {
                self.result_envelope_sha256.is_some()
                    && self
                        .result_persistence_receipt_sha256
                        .is_some()
                    && self.abort_evidence_sha256.is_none()
            }
            ProductionCustodyResultDisposition::ResultAborted => {
                self.result_envelope_sha256.is_none()
                    && self
                        .result_persistence_receipt_sha256
                        .is_none()
                    && self.abort_evidence_sha256.is_some()
            }
        };
        if self.worker_terminated_at_unix_nanos <= 0
            || self.worker_terminated_at_boottime_nanos == 0
            || self.issued_at_unix_nanos <= 0
            || self.expires_at_unix_nanos
                <= self.issued_at_unix_nanos
            || self.five_service_receipts_root_sha256
                != self.five_service_receipts_root_sha256()?
            || self.durability.service_settlement_root_sha256
                != self.five_service_receipts_root_sha256
            || !disposition_evidence_is_exact
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(())
    }
}

pub(in crate::policy_shadow) struct
    ProductionCustodyTerminalCleanupAttestation
{
    process_termination: ProductionCustodyTerminationProof,
    signed_settlement:
        SignedEnvelope<ProductionCustodyTerminalCleanupReceiptPayload>,
}

impl ProductionCustodyTerminalCleanupAttestation {
    pub(in crate::policy_shadow) fn from_external_settlement(
        process_termination: ProductionCustodyTerminationProof,
        signed_settlement:
            SignedEnvelope<ProductionCustodyTerminalCleanupReceiptPayload>,
    ) -> Self {
        Self {
            process_termination,
            signed_settlement,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct VerifiedProductionCustodyTerminalCleanupEvidence {
    operation_id_sha256: Sha256Digest,
    result_disposition: ProductionCustodyResultDisposition,
    completed_at_boottime_nanos: u64,
    signed_settlement_sha256: Sha256Digest,
}

impl VerifiedProductionCustodyTerminalCleanupEvidence {
    #[allow(clippy::too_many_arguments)]
    fn verify(
        attestation: ProductionCustodyTerminalCleanupAttestation,
        permit: &ProductionCustodyMutationPermit,
        result_disposition: ProductionCustodyResultDisposition,
        configuration: &ProductionCustodyConfiguration,
        manifest: &ProductionCustodyDispatchManifest,
        expected_key_history: &ProductionCustodyKeyHistoryState,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<Self, ShadowError> {
        configuration.revalidate_active_attestation(
            key_trust,
            trusted_time,
        )?;
        manifest.validate(configuration)?;
        let cleanup_authority = configuration
            .authority_binding(AuthorityRole::CustodyResultEnvelope)?;
        let verified = verify_envelope(
            attestation.signed_settlement,
            ExpectedSigner {
                key_id: cleanup_authority.key_id(),
                key_spki_sha256:
                    cleanup_authority.key_spki_sha256(),
            },
            key_trust,
            trusted_time,
            configuration.maximum_authority_evidence_age_nanos(),
        )?;
        verified.payload().validate_against(
            permit,
            result_disposition,
            configuration,
            manifest,
            &verified.trust_checkpoint,
            expected_key_history,
            &attestation.process_termination,
        )?;
        let current_checkpoint = key_trust.current_checkpoint()?;
        if current_checkpoint != verified.trust_checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(Self {
            operation_id_sha256:
                permit.operation_id_sha256().clone(),
            result_disposition,
            completed_at_boottime_nanos: verified
                .payload()
                .worker_terminated_at_boottime_nanos,
            signed_settlement_sha256:
                verified.envelope_sha256().clone(),
        })
    }

    fn validates(
        &self,
        operation_id_sha256: &Sha256Digest,
        operation_deadline: &ProductionCustodyOperationDeadline,
    ) -> bool {
        self.operation_id_sha256 == *operation_id_sha256
            && self.completed_at_boottime_nanos
                >= operation_deadline.opened_at_boottime_nanos()
            && self.completed_at_boottime_nanos
                < operation_deadline
                    .cleanup_deadline_boottime_nanos()
            && self
                .signed_settlement_sha256
                .as_str()
                .starts_with("sha256:")
    }
}

/// Process-facing hooks. Implementations must perform signer and persistence
/// work in the isolated worker identified by the configuration. The supervisor
/// executes each hook on a disposable host thread, waits only to the hard
/// deadline, closes the mutation fence on timeout, and requests process
/// termination without waiting on the active proxy thread.
pub(crate) trait ProductionPolicyShadowCustodyProcess: Send + Sync {
    fn dispatch_manifest(
        &self,
    ) -> Result<ProductionCustodyDispatchManifest, ShadowError>;

    /// Recovers a previously committed exact transition. A different
    /// transition for the same successor is a permanent conflict.
    fn recover_generation_configuration(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<
        Option<(
            ProductionCustodyGenerationTransitionPreparation,
            ProductionCustodyGenerationInstallAttestation,
        )>,
        ShadowError,
    >;

    /// Durably prepares all five isolated services without exposing the
    /// successor to dispatch.
    fn prepare_generation_configuration(
        &self,
        previous: Option<&ProductionCustodyConfiguration>,
        successor: &ProductionCustodyConfiguration,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
    ) -> Result<
        ProductionCustodyGenerationTransitionPreparation,
        ShadowError,
    >;

    /// Atomically commits one previously verified preparation and returns the
    /// signed five-service installation result.
    fn commit_generation_configuration(
        &self,
        preparation:
            &ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<
        ProductionCustodyGenerationInstallAttestation,
        ShadowError,
    >;

    /// Idempotently aborts and durably settles all five service preparations.
    fn abort_generation_configuration(
        &self,
        preparation: ProductionCustodyGenerationTransitionPreparation,
    ) -> Result<Sha256Digest, ShadowError>;

    fn validate_production_configuration(
        &self,
        configuration: &ProductionCustodyConfiguration,
    ) -> Result<(), ShadowError>;

    fn persistence_proof_verifier(
        &self,
    ) -> &dyn PolicyShadowPersistenceProofVerifier;

    fn request_worker_termination(
        &self,
        operation_id_sha256: &Sha256Digest,
        termination_fence_sha256: &Sha256Digest,
    );

    /// Reaps the disposable worker, closes the kernel-enforced late-mutation
    /// fence, durably settles all five services, and returns the exact signed
    /// cleanup artifact. A host-only process-exit assertion is insufficient.
    fn terminate_reap_fence_and_settle(
        &self,
        permit: &ProductionCustodyMutationPermit,
        result_disposition: ProductionCustodyResultDisposition,
    ) -> Result<ProductionCustodyTerminalCleanupAttestation, ShadowError>;

    /// Closed mutation surface. The request operation must equal the
    /// supervisor-issued permit, and the response variant must be the exact
    /// counterpart for that operation. Unknown protocol operations cannot be
    /// represented by this contract.
    fn dispatch(
        &self,
        permit: &ProductionCustodyMutationPermit,
        request: ProductionCustodyDispatchRequest,
    ) -> Result<ProductionCustodyDispatchResponse, ShadowError>;
}

struct ProductionCustodyActiveCall {
    operation_id_sha256: Sha256Digest,
    request_binding_sha256: Sha256Digest,
    durable_request_sha256: Sha256Digest,
    operation: PolicyShadowCustodyOperation,
    operation_deadline: ProductionCustodyOperationDeadline,
    termination_fence_sha256: Sha256Digest,
    operation_handle: policy_custody::OpaqueOperationHandle,
    fence_open: Arc<AtomicBool>,
    invoked: AtomicBool,
    terminal_cleanup_evidence:
        Mutex<Option<VerifiedProductionCustodyTerminalCleanupEvidence>>,
}

#[derive(Clone)]
struct ProductionCustodyInstalledGeneration {
    configuration: ProductionCustodyConfiguration,
    key_history: ProductionCustodyKeyHistoryState,
}

pub(crate) struct ProductionPolicyShadowCustodyRpcSupervisor {
    installed_generation: RwLock<ProductionCustodyInstalledGeneration>,
    process: Arc<dyn ProductionPolicyShadowCustodyProcess>,
    key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
    trusted_time: Arc<dyn TrustedTime + Send + Sync>,
    active_calls: Mutex<BTreeMap<String, Arc<ProductionCustodyActiveCall>>>,
    hard_unready: Arc<AtomicBool>,
}

impl ProductionPolicyShadowCustodyRpcSupervisor {
    pub(crate) fn install(
        configuration: ProductionCustodyConfiguration,
        process: Arc<dyn ProductionPolicyShadowCustodyProcess>,
        key_trust: Arc<dyn EnvelopeKeyTrust + Send + Sync>,
        trusted_time: Arc<dyn TrustedTime + Send + Sync>,
    ) -> Result<Arc<Self>, ShadowError> {
        configuration.require_active_attestation()?;
        configuration.revalidate_active_attestation(
            key_trust.as_ref(),
            trusted_time.as_ref(),
        )?;
        let manifest = process.dispatch_manifest()?;
        manifest.validate(&configuration)?;
        let recovered = process.recover_generation_configuration(
            None,
            &configuration,
            key_trust.as_ref(),
            trusted_time.as_ref(),
        )?;
        let (preparation, installation) =
            if let Some(recovered) = recovered {
                recovered
            } else {
                let preparation =
                    process.prepare_generation_configuration(
                        None,
                        &configuration,
                        key_trust.as_ref(),
                        trusted_time.as_ref(),
                    )?;
                preparation.validate(
                    None,
                    &configuration,
                    &manifest,
                )?;
                preparation.authorize_commit()?;
                let installation =
                    match process.commit_generation_configuration(
                        &preparation,
                    ) {
                        Ok(installation) => installation,
                        Err(error) => {
                            process.abort_generation_configuration(
                                preparation,
                            )?;
                            return Err(error);
                        }
                    };
                (preparation, installation)
            };
        let (installed_manifest, key_history) = installation.verify(
            &preparation,
            None,
            None,
            &configuration,
            key_trust.as_ref(),
            trusted_time.as_ref(),
        )?;
        if installed_manifest != manifest {
            process.abort_generation_configuration(preparation)?;
            return Err(ShadowError::BindingDrift);
        }
        process.validate_production_configuration(&configuration)?;
        Ok(Arc::new(Self {
            installed_generation: RwLock::new(
                ProductionCustodyInstalledGeneration {
                    configuration,
                    key_history,
                },
            ),
            process,
            key_trust,
            trusted_time,
            active_calls: Mutex::new(BTreeMap::new()),
            hard_unready: Arc::new(AtomicBool::new(false)),
        }))
    }

    pub(in crate::policy_shadow) fn install_verified_generation_configuration(
        &self,
        successor: ProductionCustodyConfiguration,
    ) -> Result<(), ShadowError> {
        if self.hard_unready.load(Ordering::Acquire) {
            return Err(ShadowError::CustodyUnavailable);
        }
        successor.revalidate_active_attestation(
            self.key_trust.as_ref(),
            self.trusted_time.as_ref(),
        )?;
        let calls = self
            .active_calls
            .try_lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if !calls.is_empty() {
            return Err(ShadowError::CustodyUnavailable);
        }
        let current_installed = self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .clone();
        let current = current_installed.configuration;
        let current_key_history = current_installed.key_history;
        if successor.assignment_revision <= current.assignment_revision
            || !current
                .authority_trust_checkpoint
                .permits_successor(
                    &successor.authority_trust_checkpoint,
                )
            || successor.supervisor_instance_sha256
                != current.supervisor_instance_sha256
            || successor.supervisor_boot_id_sha256
                != current.supervisor_boot_id_sha256
            || successor.execution_closure_manifest_sha256
                != current.execution_closure_manifest_sha256
            || successor.structurally_verified_seccomp_policy_sha256
                != current.structurally_verified_seccomp_policy_sha256
            || successor.worker_executable_sha256
                != current.worker_executable_sha256
            || successor.signer_backend_sha256
                != current.signer_backend_sha256
            || successor.persistence_backend_sha256
                != current.persistence_backend_sha256
            || successor.retrieval_backend_sha256
                != current.retrieval_backend_sha256
            || successor.maximum_rpc_nanos
                != current.maximum_rpc_nanos
            || successor.cleanup_reserve_nanos
                != current.cleanup_reserve_nanos
            || successor.maximum_in_flight_calls
                != current.maximum_in_flight_calls
            || successor.operation_coverage_root_sha256
                != current.operation_coverage_root_sha256
            || successor.dispatcher_protocol_set_sha256
                != current.dispatcher_protocol_set_sha256
            || successor.kernel_retained_driver_identity_sha256
                != current.kernel_retained_driver_identity_sha256
            || successor.maximum_async_durability_nanos
                != current.maximum_async_durability_nanos
        {
            return Err(ShadowError::BindingDrift);
        }
        let manifest = self.process.dispatch_manifest()?;
        manifest.validate(&successor)?;
        let recovered = self
            .process
            .recover_generation_configuration(
                Some(&current),
                &successor,
                self.key_trust.as_ref(),
                self.trusted_time.as_ref(),
            )?;
        let (preparation, installation) =
            if let Some(recovered) = recovered {
                recovered
            } else {
                let preparation = self
                    .process
                    .prepare_generation_configuration(
                        Some(&current),
                        &successor,
                        self.key_trust.as_ref(),
                        self.trusted_time.as_ref(),
                    )?;
                preparation.validate(
                    Some(&current),
                    &successor,
                    &manifest,
                )?;
                preparation.authorize_commit()?;
                let installation = match self
                    .process
                    .commit_generation_configuration(&preparation)
                {
                    Ok(installation) => installation,
                    Err(error) => {
                        self.process
                            .abort_generation_configuration(
                                preparation,
                            )?;
                        self.hard_unready
                            .store(true, Ordering::Release);
                        return Err(error);
                    }
                };
                (preparation, installation)
            };
        let (installed_manifest, successor_key_history) =
            installation.verify(
            &preparation,
            Some(&current),
            Some(&current_key_history),
            &successor,
            self.key_trust.as_ref(),
            self.trusted_time.as_ref(),
        )?;
        if installed_manifest != manifest {
            self.hard_unready.store(true, Ordering::Release);
            self.process
                .abort_generation_configuration(preparation)?;
            return Err(ShadowError::BindingDrift);
        }
        self.process
            .validate_production_configuration(&successor)?;
        let mut installed = match self.installed_generation.write() {
            Ok(installed) => installed,
            Err(_) => {
                self.hard_unready.store(true, Ordering::Release);
                return Err(ShadowError::CustodyUnavailable);
            }
        };
        *installed = ProductionCustodyInstalledGeneration {
                configuration: successor,
                key_history: successor_key_history,
            };
        Ok(())
    }

    fn active_call(
        &self,
        context: &PolicyShadowCustodyCallContext,
        operation: PolicyShadowCustodyOperation,
    ) -> Result<Arc<ProductionCustodyActiveCall>, ShadowError> {
        let configuration = self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .configuration
            .clone();
        let configuration_binding_sha256 =
            configuration
                .production_configuration_binding_sha256
                .clone();
        if self.hard_unready.load(Ordering::Acquire)
            || !context.authorizes(operation)
            || context.supervisor_instance_sha256
                != configuration.supervisor_instance_sha256
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let calls = self
            .active_calls
            .try_lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if self.hard_unready.load(Ordering::Acquire)
            || self
                .installed_generation
                .try_read()
                .map_err(|_| ShadowError::CustodyUnavailable)?
                .configuration
                .production_configuration_binding_sha256
                != configuration_binding_sha256
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let call = calls
            .get(context.operation_id_sha256.as_str())
            .cloned()
            .ok_or(ShadowError::CustodyUnavailable)?;
        if call.operation != operation
            || call.operation_id_sha256 != context.operation_id_sha256
            || call.request_binding_sha256
                != context.request_binding_sha256
            || call.operation_deadline != context.operation_deadline
            || call.termination_fence_sha256
                != context.termination_fence_sha256
            || call
                .invoked
                .compare_exchange(
                    false,
                    true,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        Ok(call)
    }

    fn invoke<T, F>(
        &self,
        context: &PolicyShadowCustodyCallContext,
        operation: PolicyShadowCustodyOperation,
        invoke: F,
    ) -> Result<T, ShadowError>
    where
        T: Send + 'static,
        F: FnOnce(
                Arc<dyn ProductionPolicyShadowCustodyProcess>,
                ProductionCustodyMutationPermit,
            ) -> Result<T, ShadowError>
            + Send
            + 'static,
    {
        let call = self.active_call(context, operation)?;
        let completion = Arc::new(
            policy_custody::BoottimeCompletion::new(
                call.operation_handle.operation_deadline(),
            )?,
        );
        let permit = ProductionCustodyMutationPermit {
            operation_id_sha256: call.operation_id_sha256.clone(),
            operation,
            request_sha256:
                call.request_binding_sha256.clone(),
            durable_request_sha256:
                call.durable_request_sha256.clone(),
            termination_fence_sha256:
                call.termination_fence_sha256.clone(),
            operation_deadline: call.operation_deadline.clone(),
            authorization_deadline:
                call.operation_handle.operation_deadline(),
            fence_open: Arc::clone(&call.fence_open),
        };
        let process = Arc::clone(&self.process);
        let worker_process = Arc::clone(&self.process);
        let worker_call = Arc::clone(&call);
        let worker_hard_unready = Arc::clone(&self.hard_unready);
        let worker_completion = Arc::clone(&completion);
        let worker_installed = self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .clone();
        let worker_configuration =
            worker_installed.configuration;
        let worker_key_history = worker_installed.key_history;
        let worker_manifest = self.process.dispatch_manifest()?;
        worker_manifest.validate(&worker_configuration)?;
        let worker_key_trust = Arc::clone(&self.key_trust);
        let worker_trusted_time = Arc::clone(&self.trusted_time);
        let spawned = thread::Builder::new()
            .name("policy-shadow-custody-rpc".to_string())
            .spawn(move || {
                let result = permit
                    .authorize(
                        operation,
                        &worker_call.operation_id_sha256,
                    )
                    .and_then(|_| invoke(process, permit));
                let result_disposition = if result.is_ok() {
                    ProductionCustodyResultDisposition::ResultCommitted
                } else {
                    ProductionCustodyResultDisposition::ResultAborted
                };
                worker_call.fence_open.store(false, Ordering::Release);
                let cleanup_permit =
                    ProductionCustodyMutationPermit {
                        operation_id_sha256:
                            worker_call.operation_id_sha256.clone(),
                        operation: worker_call.operation,
                        request_sha256:
                            worker_call.request_binding_sha256.clone(),
                        durable_request_sha256:
                            worker_call.durable_request_sha256.clone(),
                        termination_fence_sha256:
                            worker_call.termination_fence_sha256.clone(),
                        operation_deadline:
                            worker_call.operation_deadline.clone(),
                        authorization_deadline:
                            worker_call.operation_handle.cleanup_deadline(),
                        fence_open:
                            Arc::clone(&worker_call.fence_open),
                    };
                let terminal_evidence = cleanup_permit
                    .authorize_cleanup(
                        worker_call.operation,
                        &worker_call.operation_id_sha256,
                    )
                    .and_then(|_| {
                        worker_process
                            .terminate_reap_fence_and_settle(
                                &cleanup_permit,
                                result_disposition,
                            )
                    })
                    .and_then(|attestation| {
                        VerifiedProductionCustodyTerminalCleanupEvidence::
                            verify(
                                attestation,
                                &cleanup_permit,
                                result_disposition,
                                &worker_configuration,
                                &worker_manifest,
                                &worker_key_history,
                                worker_key_trust.as_ref(),
                                worker_trusted_time.as_ref(),
                            )
                    });
                let completed_result = match terminal_evidence {
                    Ok(evidence) => {
                        match worker_call
                            .terminal_cleanup_evidence
                            .lock()
                        {
                            Ok(mut slot) if slot.is_none() => {
                                *slot = Some(evidence);
                                result
                            }
                            _ => {
                                worker_hard_unready
                                    .store(true, Ordering::Release);
                                Err(ShadowError::CustodyUnavailable)
                            }
                        }
                    }
                    Err(_) => {
                        worker_hard_unready
                            .store(true, Ordering::Release);
                        Err(ShadowError::CustodyUnavailable)
                    }
                };
                if worker_completion.complete(completed_result).is_err() {
                    worker_hard_unready.store(true, Ordering::Release);
                }
            });
        if spawned.is_err() {
            call.fence_open.store(false, Ordering::Release);
            self.hard_unready.store(true, Ordering::Release);
            self.process.request_worker_termination(
                &call.operation_id_sha256,
                &call.termination_fence_sha256,
            );
            return Err(ShadowError::CustodyUnavailable);
        }
        match completion.wait() {
            Ok(result) => result,
            Err(error) => {
                call.fence_open.store(false, Ordering::Release);
                self.hard_unready.store(true, Ordering::Release);
                self.process.request_worker_termination(
                    &call.operation_id_sha256,
                    &call.termination_fence_sha256,
                );
                Err(error)
            }
        }
    }
}

fn open_verified_custody_call(
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    _trusted_time: &dyn TrustedTime,
    operation: PolicyShadowCustodyOperation,
    binding: &Sha256Digest,
) -> Result<PolicyShadowCustodyCallContext, ShadowError> {
    let opened_at_boottime_nanos = production_now_boottime_nanos()?;
    let operation_id_sha256 = hash_domain_frames(
        b"serverware.policyShadowVerifiedCustodyRpc/v2",
        &[
            binding.as_str().as_bytes(),
            &opened_at_boottime_nanos.to_be_bytes(),
            &[operation as u8],
        ],
    );
    let context = custody.open_bound_call(
        operation_id_sha256,
        operation,
        binding.clone(),
    )?;
    if !context.authorizes(operation)
        || !context.operation_deadline().authorizes_operation_at(
            production_now_boottime_nanos()?,
        )
    {
        return Err(ShadowError::CustodyUnavailable);
    }
    Ok(context)
}

fn finish_verified_custody_call(
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    context: PolicyShadowCustodyCallContext,
) -> Result<(), ShadowError> {
    let operation_id_sha256 = context.operation_id_sha256().clone();
    let operation_deadline = context.operation_deadline().clone();
    let completion = custody.finish_call(context)?;
    if !completion.validates(
        &operation_id_sha256,
        &operation_deadline,
    ) {
        return Err(ShadowError::CustodyUnavailable);
    }
    Ok(())
}

/// One production custody RPC supervisor owns every monotonic or
/// signing-sensitive transition. `open_call` performs an operation-id CAS and
/// starts an isolated killable worker/transport. Every operation below is
/// bounded by the context deadline. `finish_call` must kill/join that worker
/// and close its late-mutation fence before returning success. The runtime
/// remains hard-unready while no supervisor is installed.
pub(crate) trait PolicyShadowCustodyRpcSupervisor: Send + Sync {
    fn production_configuration_binding_sha256(
        &self,
    ) -> Option<Sha256Digest> {
        None
    }

    fn persistence_proof_verifier(
        &self,
    ) -> Option<&dyn PolicyShadowPersistenceProofVerifier> {
        None
    }

    fn open_call(
        &self,
        operation_id_sha256: Sha256Digest,
        operation: PolicyShadowCustodyOperation,
    ) -> Result<PolicyShadowCustodyCallContext, ShadowError>;

    fn open_bound_call(
        &self,
        operation_id_sha256: Sha256Digest,
        operation: PolicyShadowCustodyOperation,
        request_binding_sha256: Sha256Digest,
    ) -> Result<PolicyShadowCustodyCallContext, ShadowError> {
        let _ = request_binding_sha256;
        self.open_call(operation_id_sha256, operation)
    }

    fn finish_call(
        &self,
        context: PolicyShadowCustodyCallContext,
    ) -> Result<PolicyShadowCustodyCallCompletion, ShadowError>;

    fn verify_checkpoint_successor(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation: &ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        previous_checkpoint_sha256: &Sha256Digest,
        checkpoint_payload_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError>;

    fn verify_current_sealed_checkpoint_head(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation: &ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        checkpoint_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError>;

    /// Idempotently returns the authoritative durable publication, sequence,
    /// ledger and spool state. Runtime remains unavailable until this receipt
    /// has been reconciled; a blank local process state is never authoritative.
    fn recover_current_state(
        &self,
        context: &PolicyShadowCustodyCallContext,
    ) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError>;

    fn prepare_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        recovered: &VerifiedPublicationReconciliationReceipt,
        previous: Option<&ShadowGenerationIdentity>,
        successor: &ShadowGenerationIdentity,
    ) -> Result<PreparedGenerationPublication, ShadowError>;

    fn commit_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        prepared: &PreparedGenerationPublication,
    ) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError>;

    fn abort_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        prepared: PreparedGenerationPublication,
    ) -> Result<(), ShadowError>;

    /// Atomically allocates the next durable ingress sequence and appends its
    /// opening spool record, or durably records and returns a signed
    /// custody-unavailable record.
    /// Runtime contention, sequence exhaustion, and spool backpressure are
    /// represented by `Unavailable`; this operation has no evidence-free
    /// error return.
    fn begin_ingress(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request_binding_sha256: &Sha256Digest,
    ) -> Result<IngressCustodyAdmission, ShadowError>;

    /// Reserves one position from custody's single authoritative ordered
    /// ledger. Implementations may shard reservation contention internally,
    /// but the returned ordinal and predecessor are globally contiguous for
    /// the generation.
    fn reserve_spool_append(
        &self,
        context: &PolicyShadowCustodyCallContext,
        event: &ShadowSpoolEvent,
    ) -> Result<SpoolAppendReservationOutcome, ShadowError>;

    /// Appends before acknowledging. A returned `Unavailable` disposition is
    /// itself a durable, signed, sequence-bound failure record.
    fn append_spool_event(
        &self,
        context: &PolicyShadowCustodyCallContext,
        reservation: VerifiedSpoolAppendReservation,
        event: &ShadowSpoolEvent,
    ) -> Result<VerifiedShadowSpillReceipt, ShadowError>;

    fn compact_spool(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request: &AuthenticatedSpoolCompactionRequest,
    ) -> Result<VerifiedSpoolCompactionReceipt, ShadowError>;

    /// Resolves every immutable receipt referenced by one observation, verifies
    /// its pinned role/key/current revocation state, and recomputes the exact
    /// admitted/unavailable, dispatch, active-effect barrier/commit, terminal,
    /// spill, persistence, retrieval, compaction and publication roots.
    /// Digest-only observation assertions are never sufficient.
    fn verify_observation_custody_evidence(
        &self,
        context: &PolicyShadowCustodyCallContext,
        evidence: &CustodyEvidenceBinding,
        ingress: &IngressEvidencePayload,
        active_decision: &ActiveDecisionReceiptPayload,
    ) -> Result<(), ShadowError>;

    fn commit_request(
        &self,
        call_context: &PolicyShadowCustodyCallContext,
        facts: &ProtectedRequestFacts,
        context: &RequestCommitmentContext,
    ) -> Result<RequestCommitment, ShadowError>;

    fn append_active_effect_barrier(
        &self,
        context: &PolicyShadowCustodyCallContext,
        preparation: &ActiveEffectPreparation,
    ) -> Result<VerifiedActiveEffectPermit, ShadowError>;

    fn commit_active_effect(
        &self,
        context: &PolicyShadowCustodyCallContext,
        permit: VerifiedActiveEffectPermit,
        terminal_state: ActiveEffectCommitState,
        result_sha256: &Sha256Digest,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError>;

    fn reconcile_active_effect(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation_id: &Sha256Digest,
        ingress_sequence: u64,
        effect_id_sha256: &Sha256Digest,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError>;

    /// Custody owns one atomic terminal slot per generation and ingress. The
    /// same digest is idempotent; a different digest is a signed fork.
    fn append_terminal(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request: &TerminalSlotAppendRequest,
    ) -> Result<TerminalSlotAppendOutcome, ShadowError>;

    fn consume_recheck_and_publish(
        &self,
        context: &PolicyShadowCustodyCallContext,
        transaction: ActivationPublicationTransaction,
    ) -> Result<VerifiedActivationPublicationReceipt, ShadowError>;
}

impl PolicyShadowCustodyRpcSupervisor
    for ProductionPolicyShadowCustodyRpcSupervisor
{
    fn production_configuration_binding_sha256(
        &self,
    ) -> Option<Sha256Digest> {
        self.installed_generation
            .try_read()
            .ok()
            .map(|installed| {
                installed
                    .configuration
                    .production_configuration_binding_sha256
                    .clone()
            })
    }

    fn persistence_proof_verifier(
        &self,
    ) -> Option<&dyn PolicyShadowPersistenceProofVerifier> {
        Some(self.process.persistence_proof_verifier())
    }

    fn open_call(
        &self,
        operation_id_sha256: Sha256Digest,
        operation: PolicyShadowCustodyOperation,
    ) -> Result<PolicyShadowCustodyCallContext, ShadowError> {
        self.open_bound_call(
            operation_id_sha256.clone(),
            operation,
            operation_id_sha256,
        )
    }

    fn open_bound_call(
        &self,
        operation_id_sha256: Sha256Digest,
        operation: PolicyShadowCustodyOperation,
        request_binding_sha256: Sha256Digest,
    ) -> Result<PolicyShadowCustodyCallContext, ShadowError> {
        if self.hard_unready.load(Ordering::Acquire) {
            return Err(ShadowError::CustodyUnavailable);
        }
        let configuration = self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .configuration
            .clone();
        let configuration_binding_sha256 =
            configuration
                .production_configuration_binding_sha256
                .clone();
        let operation_deadline = ProductionCustodyOperationDeadline::open(
            configuration.supervisor_boot_id_sha256.clone(),
            configuration.maximum_rpc_nanos,
            configuration.cleanup_reserve_nanos,
        )?;
        let termination_fence_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyTerminationFence/v2",
            &[
                configuration
                    .supervisor_instance_sha256
                    .as_str()
                    .as_bytes(),
                operation_id_sha256.as_str().as_bytes(),
                &canonical_json_bytes(&operation_deadline)?,
            ],
        );
        let durable_request_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyDurableRequest/v1",
            &[
                configuration_binding_sha256.as_str().as_bytes(),
                operation_id_sha256.as_str().as_bytes(),
                request_binding_sha256.as_str().as_bytes(),
                &[operation as u8],
            ],
        );
        let context = PolicyShadowCustodyCallContext::from_supervisor(
            operation_id_sha256.clone(),
            request_binding_sha256.clone(),
            operation_deadline.clone(),
            operation,
            configuration.supervisor_instance_sha256.clone(),
            termination_fence_sha256.clone(),
        )?;
        let call = Arc::new(ProductionCustodyActiveCall {
            operation_id_sha256: operation_id_sha256.clone(),
            request_binding_sha256,
            durable_request_sha256,
            operation,
            operation_deadline: operation_deadline.clone(),
            termination_fence_sha256:
                termination_fence_sha256.clone(),
            operation_handle: context.operation_handle.clone(),
            fence_open: Arc::new(AtomicBool::new(true)),
            invoked: AtomicBool::new(false),
            terminal_cleanup_evidence: Mutex::new(None),
        });
        let mut calls = self
            .active_calls
            .try_lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?;
        if self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .configuration
            .production_configuration_binding_sha256
            != configuration_binding_sha256
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let activation_is_active = calls.values().any(|call| {
            call.operation
                == PolicyShadowCustodyOperation::ConsumeAndPublishActivation
        });
        let activation_would_reenter = operation
            == PolicyShadowCustodyOperation::ConsumeAndPublishActivation
            && !calls.is_empty();
        let ordinary_call_would_reenter_activation = operation
            != PolicyShadowCustodyOperation::ConsumeAndPublishActivation
            && activation_is_active;
        if calls.len()
            >= usize::from(
                configuration.maximum_in_flight_calls,
            )
            || self.hard_unready.load(Ordering::Acquire)
            || calls.contains_key(operation_id_sha256.as_str())
            || activation_would_reenter
            || ordinary_call_would_reenter_activation
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        calls.insert(operation_id_sha256.as_str().to_string(), call);
        drop(calls);
        Ok(context)
    }

    fn finish_call(
        &self,
        context: PolicyShadowCustodyCallContext,
    ) -> Result<PolicyShadowCustodyCallCompletion, ShadowError> {
        if !context
            .termination_fence_sha256
            .as_str()
            .starts_with("sha256:")
        {
            self.hard_unready.store(true, Ordering::Release);
            return Err(ShadowError::CustodyUnavailable);
        }
        let configuration = self
            .installed_generation
            .try_read()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .configuration
            .clone();
        let call = {
            let mut calls = self
                .active_calls
                .try_lock()
                .map_err(|_| ShadowError::CustodyUnavailable)?;
            let call = calls
                .get(context.operation_id_sha256.as_str())
                .cloned()
                .ok_or(ShadowError::CustodyUnavailable)?;
            if call.operation_id_sha256 != context.operation_id_sha256
                || call.request_binding_sha256
                    != context.request_binding_sha256
                || call.operation != context.operation
                || call.operation_deadline
                    != context.operation_deadline
                || call.termination_fence_sha256
                    != context.termination_fence_sha256
                || context.supervisor_instance_sha256
                    != configuration.supervisor_instance_sha256
                || call
                    .terminal_cleanup_evidence
                    .lock()
                    .map_or(true, |slot| slot.is_none())
                || call.fence_open.load(Ordering::Acquire)
            {
                call.fence_open.store(false, Ordering::Release);
                self.hard_unready.store(true, Ordering::Release);
                let operation_id_sha256 = call.operation_id_sha256.clone();
                let termination_fence_sha256 =
                    call.termination_fence_sha256.clone();
                drop(calls);
                self.process.request_worker_termination(
                    &operation_id_sha256,
                    &termination_fence_sha256,
                );
                return Err(ShadowError::CustodyUnavailable);
            }
            calls.remove(context.operation_id_sha256.as_str());
            call
        };
        let terminal_cleanup_evidence = call
            .terminal_cleanup_evidence
            .lock()
            .map_err(|_| ShadowError::CustodyUnavailable)?
            .take()
            .ok_or(ShadowError::CustodyUnavailable)?;
        PolicyShadowCustodyCallCompletion::from_supervisor(
            context.operation_id_sha256,
            &context.operation_deadline,
            terminal_cleanup_evidence,
        )
    }

    fn verify_checkpoint_successor(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation: &ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        previous_checkpoint_sha256: &Sha256Digest,
        checkpoint_payload_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        let generation = generation.clone();
        let previous = previous_checkpoint_sha256.clone();
        let payload = checkpoint_payload_sha256.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::VerifyCheckpointSuccessor,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        VerifyCheckpointSuccessor {
                    generation,
                    checkpoint_sequence,
                    previous_checkpoint_sha256: previous,
                    checkpoint_payload_sha256: payload,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        CheckpointSuccessorVerified => Ok(()),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn verify_current_sealed_checkpoint_head(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation: &ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        checkpoint_sha256: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        let generation = generation.clone();
        let checkpoint = checkpoint_sha256.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        VerifyCurrentCheckpointHead {
                    generation,
                    checkpoint_sequence,
                    checkpoint_sha256: checkpoint,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        CurrentCheckpointHeadVerified => Ok(()),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn recover_current_state(
        &self,
        context: &PolicyShadowCustodyCallContext,
    ) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError> {
        self.invoke(
            context,
            PolicyShadowCustodyOperation::RecoverCurrentState,
            |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        RecoverCurrentState;
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        CurrentStateRecovered(receipt) => Ok(receipt),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn prepare_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        recovered: &VerifiedPublicationReconciliationReceipt,
        previous: Option<&ShadowGenerationIdentity>,
        successor: &ShadowGenerationIdentity,
    ) -> Result<PreparedGenerationPublication, ShadowError> {
        let recovered = recovered.clone();
        let previous = previous.cloned();
        let successor = successor.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::PrepareGenerationPublication,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        PrepareGenerationPublication {
                    recovered,
                    previous,
                    successor,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        GenerationPublicationPrepared(prepared) => {
                            Ok(prepared)
                        }
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn commit_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        prepared: &PreparedGenerationPublication,
    ) -> Result<VerifiedPublicationReconciliationReceipt, ShadowError> {
        let prepared = prepared.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::CommitGenerationPublication,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        CommitGenerationPublication { prepared };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        GenerationPublicationCommitted(receipt) => {
                            Ok(receipt)
                        }
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn abort_generation_publication(
        &self,
        context: &PolicyShadowCustodyCallContext,
        prepared: PreparedGenerationPublication,
    ) -> Result<(), ShadowError> {
        self.invoke(
            context,
            PolicyShadowCustodyOperation::AbortGenerationPublication,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        AbortGenerationPublication { prepared };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        GenerationPublicationAborted => Ok(()),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn begin_ingress(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request_binding_sha256: &Sha256Digest,
    ) -> Result<IngressCustodyAdmission, ShadowError> {
        let binding = request_binding_sha256.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::BeginIngress,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::BeginIngress {
                        request_binding_sha256: binding,
                    };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::IngressBegun(
                        admission,
                    ) => Ok(admission),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn reserve_spool_append(
        &self,
        context: &PolicyShadowCustodyCallContext,
        event: &ShadowSpoolEvent,
    ) -> Result<SpoolAppendReservationOutcome, ShadowError> {
        let event = event.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::ReserveSpoolAppend,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        ReserveSpoolAppend { event };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        SpoolAppendReserved(outcome) => Ok(outcome),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn append_spool_event(
        &self,
        context: &PolicyShadowCustodyCallContext,
        reservation: VerifiedSpoolAppendReservation,
        event: &ShadowSpoolEvent,
    ) -> Result<VerifiedShadowSpillReceipt, ShadowError> {
        let event = event.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::AppendSpoolEvent,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::AppendSpoolEvent {
                    reservation,
                    event,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        SpoolEventAppended(receipt) => Ok(receipt),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn compact_spool(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request: &AuthenticatedSpoolCompactionRequest,
    ) -> Result<VerifiedSpoolCompactionReceipt, ShadowError> {
        let request = request.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::CompactSpool,
            move |process, permit| {
                let dispatch_request =
                    ProductionCustodyDispatchRequest::CompactSpool {
                        request,
                    };
                if dispatch_request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, dispatch_request)? {
                    ProductionCustodyDispatchResponse::SpoolCompacted(
                        receipt,
                    ) => Ok(receipt),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn verify_observation_custody_evidence(
        &self,
        context: &PolicyShadowCustodyCallContext,
        evidence: &CustodyEvidenceBinding,
        ingress: &IngressEvidencePayload,
        active_decision: &ActiveDecisionReceiptPayload,
    ) -> Result<(), ShadowError> {
        let evidence = evidence.clone();
        let ingress = ingress.clone();
        let active_decision = active_decision.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::VerifyObservationEvidence,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        VerifyObservationEvidence {
                    evidence,
                    ingress,
                    active_decision,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        ObservationEvidenceVerified => Ok(()),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn commit_request(
        &self,
        context: &PolicyShadowCustodyCallContext,
        facts: &ProtectedRequestFacts,
        commitment_context: &RequestCommitmentContext,
    ) -> Result<RequestCommitment, ShadowError> {
        let facts = facts.clone();
        let commitment_context = commitment_context.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::CommitRequest,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::CommitRequest {
                    facts,
                    context: commitment_context,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::RequestCommitted(
                        commitment,
                    ) => Ok(commitment),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn append_active_effect_barrier(
        &self,
        context: &PolicyShadowCustodyCallContext,
        preparation: &ActiveEffectPreparation,
    ) -> Result<VerifiedActiveEffectPermit, ShadowError> {
        let preparation = preparation.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::AppendActiveEffectBarrier,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        AppendActiveEffectBarrier { preparation };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        ActiveEffectBarrierAppended(effect_permit) => {
                            Ok(effect_permit)
                        }
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn commit_active_effect(
        &self,
        context: &PolicyShadowCustodyCallContext,
        permit: VerifiedActiveEffectPermit,
        terminal_state: ActiveEffectCommitState,
        result_sha256: &Sha256Digest,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
        let result_sha256 = result_sha256.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::CommitActiveEffect,
            move |process, custody_permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        CommitActiveEffect {
                    effect_permit: permit,
                    terminal_state,
                    result_sha256,
                };
                if request.operation() != custody_permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&custody_permit, request)? {
                    ProductionCustodyDispatchResponse::
                        ActiveEffectCommitted(receipt) => Ok(receipt),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn reconcile_active_effect(
        &self,
        context: &PolicyShadowCustodyCallContext,
        generation_id: &Sha256Digest,
        ingress_sequence: u64,
        effect_id_sha256: &Sha256Digest,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
        let generation_id = generation_id.clone();
        let effect_id_sha256 = effect_id_sha256.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::ReconcileActiveEffect,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        ReconcileActiveEffect {
                    generation_id,
                    ingress_sequence,
                    effect_id_sha256,
                };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        ActiveEffectReconciled(receipt) => Ok(receipt),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn append_terminal(
        &self,
        context: &PolicyShadowCustodyCallContext,
        request: &TerminalSlotAppendRequest,
    ) -> Result<TerminalSlotAppendOutcome, ShadowError> {
        let request = request.clone();
        self.invoke(
            context,
            PolicyShadowCustodyOperation::AppendTerminal,
            move |process, permit| {
                let dispatch_request =
                    ProductionCustodyDispatchRequest::AppendTerminal {
                        request,
                    };
                if dispatch_request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, dispatch_request)? {
                    ProductionCustodyDispatchResponse::TerminalAppended(
                        outcome,
                    ) => Ok(outcome),
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }

    fn consume_recheck_and_publish(
        &self,
        context: &PolicyShadowCustodyCallContext,
        transaction: ActivationPublicationTransaction,
    ) -> Result<VerifiedActivationPublicationReceipt, ShadowError> {
        self.invoke(
            context,
            PolicyShadowCustodyOperation::ConsumeAndPublishActivation,
            move |process, permit| {
                let request =
                    ProductionCustodyDispatchRequest::
                        ConsumeAndPublishActivation { transaction };
                if request.operation() != permit.operation() {
                    return Err(ShadowError::CustodyUnavailable);
                }
                match process.dispatch(&permit, request)? {
                    ProductionCustodyDispatchResponse::
                        ActivationConsumedAndPublished(receipt) => {
                            Ok(receipt)
                        }
                    _ => Err(ShadowError::CustodyUnavailable),
                }
            },
        )
    }
}

#[derive(Serialize)]
pub(crate) struct VerifiedSpoolAppendReservation {
    wire: SpoolAppendReservationReceiptWire,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SpoolAppendReservationReceiptWire {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    lane: u16,
    event_ordinal: u64,
    predecessor_event_ordinal: u64,
    predecessor_head_sha256: Sha256Digest,
    event_sha256: Sha256Digest,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

pub(crate) enum SpoolAppendReservationOutcome {
    Reserved(VerifiedSpoolAppendReservation),
    Unavailable(VerifiedShadowSpillReceipt),
}

impl SpoolAppendReservationReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        generation_id: Sha256Digest,
        ingress_sequence: u64,
        lane: u16,
        event_ordinal: u64,
        predecessor_event_ordinal: u64,
        predecessor_head_sha256: Sha256Digest,
        event_sha256: Sha256Digest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(ingress_sequence, "spool.ingress_sequence")?;
        validate_positive(event_ordinal, "spool.event_ordinal")?;
        if event_ordinal
            != predecessor_event_ordinal
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?
            || lane >= 64
            || trusted_observed_at_unix_nanos <= 0
        {
            return Err(ShadowError::NonContiguousObservationSequence);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let receipt = Self {
            generation_id,
            ingress_sequence,
            lane,
            event_ordinal,
            predecessor_event_ordinal,
            predecessor_head_sha256,
            event_sha256,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        };
        let canonical_payload = receipt.canonical_signature_payload()?;
        let expected_signed_receipt = hash_domain_frames(
            b"serverware.policyShadowSpoolAppendReservationReceipt/v1",
            &[
                canonical_payload.as_slice(),
                receipt.signature.0.as_bytes(),
            ],
        );
        if receipt.signed_receipt_sha256 != expected_signed_receipt {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(receipt)
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let reconstructed = Self::from_custody(
            self.generation_id.clone(),
            self.ingress_sequence,
            self.lane,
            self.event_ordinal,
            self.predecessor_event_ordinal,
            self.predecessor_head_sha256.clone(),
            self.event_sha256.clone(),
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    fn canonical_signature_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&(
            &self.generation_id,
            self.ingress_sequence,
            self.lane,
            self.event_ordinal,
            self.predecessor_event_ordinal,
            &self.predecessor_head_sha256,
            &self.event_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::LedgerAppend,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ))
    }
}

#[cfg(test)]
fn verify_spool_append_reservation_receipt(
    wire: SpoolAppendReservationReceiptWire,
    event: &ShadowSpoolEvent,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedSpoolAppendReservation, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.generation_id != event.generation_id
        || wire.ingress_sequence != event.ingress_sequence
        || wire.event_sha256 != event.event_sha256
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::LedgerAppend,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedSpoolAppendReservation {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_spool_append_reservation_receipt(
    wire: SpoolAppendReservationReceiptWire,
    event: &ShadowSpoolEvent,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedSpoolAppendReservation, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.generation_id != event.generation_id
        || wire.ingress_sequence != event.ingress_sequence
        || wire.event_sha256 != event.event_sha256
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::LedgerAppend,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedSpoolAppendReservation {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl VerifiedSpoolAppendReservation {
    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }

    pub(crate) fn matches_event(
        &self,
        event: &ShadowSpoolEvent,
    ) -> bool {
        self.wire.generation_id == event.generation_id
            && self.wire.ingress_sequence == event.ingress_sequence
            && self.wire.event_sha256 == event.event_sha256
            && self.wire.event_ordinal > 0
            && self.wire.lane < 64
            && self.wire.signed_receipt_sha256.as_str().starts_with("sha256:")
            && self.wire.retrieval_id_sha256.as_str().starts_with("sha256:")
            && self
                .verified_trust_checkpoint
                .checkpoint_id
                .as_str()
                .starts_with("sha256:")
    }

    pub(crate) fn predecessor(
        &self,
    ) -> (u64, &Sha256Digest) {
        (
            self.wire.predecessor_event_ordinal,
            &self.wire.predecessor_head_sha256,
        )
    }

    pub(crate) fn event_ordinal(&self) -> u64 {
        self.wire.event_ordinal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedGenerationPublication {
    expected_predecessor_generation_sha256: Option<Sha256Digest>,
    successor_generation_sha256: Sha256Digest,
    generation_epoch: u64,
    generation_tombstone_epoch: u64,
    assignment_revision: u64,
    active_policy_sequence: u64,
    active_rollback_epoch: u64,
    first_ingress_sequence: u64,
    last_ingress_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    spill_predecessor_event_ordinal: u64,
    spill_predecessor_head_sha256: Sha256Digest,
    persisted_sequence_range_sha256: Sha256Digest,
    durable_spool_sha256: Sha256Digest,
    preparation_receipt_sha256: Sha256Digest,
}

impl PreparedGenerationPublication {
    pub(in crate::policy_shadow) fn validate_for_successor(
        &self,
        predecessor: Option<&Sha256Digest>,
        successor: &ShadowGenerationIdentity,
    ) -> Result<(), ShadowError> {
        successor.validate()?;
        validate_positive(self.first_ingress_sequence, "custody.first_ingress_sequence")?;
        validate_positive(self.last_ingress_sequence, "custody.last_ingress_sequence")?;
        if !self.matches_recovered(predecessor, successor)
            || self.last_ingress_sequence < self.first_ingress_sequence
            || self.last_ingress_sequence == u64::MAX
            || self.persisted_sequence_range_sha256 != hash_domain_frames(
                b"serverware.policyShadowPersistedSequenceRange/v1",
                &[&canonical_json_bytes(&(
                    successor.generation_id(), self.first_ingress_sequence,
                    self.last_ingress_sequence, &successor.ingress_range_predecessor_head_sha256,
                ))?],
            )
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        previous: Option<&ShadowGenerationIdentity>,
        successor: &ShadowGenerationIdentity,
        first_ingress_sequence: u64,
        last_ingress_sequence: u64,
        spill_predecessor_event_ordinal: u64,
        spill_predecessor_head_sha256: Sha256Digest,
        persisted_sequence_range_sha256: Sha256Digest,
        durable_spool_sha256: Sha256Digest,
        preparation_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(first_ingress_sequence, "custody.first_ingress_sequence")?;
        validate_positive(last_ingress_sequence, "custody.last_ingress_sequence")?;
        if first_ingress_sequence != successor.ingress_range_start_sequence
            || last_ingress_sequence < first_ingress_sequence
            || last_ingress_sequence == u64::MAX
        {
            return Err(ShadowError::NonContiguousIngressSequence);
        }
        let expected_range = hash_domain_frames(
            b"serverware.policyShadowPersistedSequenceRange/v1",
            &[&canonical_json_bytes(&(
                &successor.generation_id,
                first_ingress_sequence,
                last_ingress_sequence,
                &successor.ingress_range_predecessor_head_sha256,
            ))?],
        );
        if persisted_sequence_range_sha256 != expected_range {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        Ok(Self {
            expected_predecessor_generation_sha256: previous
                .map(|generation| generation.generation_id.clone()),
            successor_generation_sha256: successor.generation_id.clone(),
            generation_epoch: successor.generation_epoch,
            generation_tombstone_epoch: successor.generation_tombstone_epoch,
            assignment_revision: successor.assignment_revision,
            active_policy_sequence: successor.active_policy_sequence,
            active_rollback_epoch: successor.active_rollback_epoch,
            first_ingress_sequence,
            last_ingress_sequence,
            ingress_range_predecessor_head_sha256: successor
                .ingress_range_predecessor_head_sha256
                .clone(),
            spill_predecessor_event_ordinal,
            spill_predecessor_head_sha256,
            persisted_sequence_range_sha256,
            durable_spool_sha256,
            preparation_receipt_sha256,
        })
    }

    pub(crate) fn matches(
        &self,
        previous: Option<&ShadowGenerationIdentity>,
        successor: &ShadowGenerationIdentity,
    ) -> bool {
        self.expected_predecessor_generation_sha256
            == previous.map(|generation| generation.generation_id.clone())
            && self.successor_generation_sha256 == successor.generation_id
            && self.generation_epoch == successor.generation_epoch
            && self.generation_tombstone_epoch
                == successor.generation_tombstone_epoch
            && self.assignment_revision == successor.assignment_revision
            && self.active_policy_sequence == successor.active_policy_sequence
            && self.active_rollback_epoch == successor.active_rollback_epoch
            && self.first_ingress_sequence
                == successor.ingress_range_start_sequence
            && self.ingress_range_predecessor_head_sha256
                == successor.ingress_range_predecessor_head_sha256
    }

    pub(crate) fn matches_recovered(
        &self,
        recovered_predecessor: Option<&Sha256Digest>,
        successor: &ShadowGenerationIdentity,
    ) -> bool {
        self.expected_predecessor_generation_sha256.as_ref()
            == recovered_predecessor
            && self.successor_generation_sha256 == successor.generation_id
            && self.generation_epoch == successor.generation_epoch
            && self.generation_tombstone_epoch
                == successor.generation_tombstone_epoch
            && self.assignment_revision == successor.assignment_revision
            && self.active_policy_sequence == successor.active_policy_sequence
            && self.active_rollback_epoch == successor.active_rollback_epoch
            && self.first_ingress_sequence
                == successor.ingress_range_start_sequence
            && self.ingress_range_predecessor_head_sha256
                == successor.ingress_range_predecessor_head_sha256
    }

    pub(crate) fn sequence_bounds(&self) -> (u64, u64) {
        (self.first_ingress_sequence, self.last_ingress_sequence)
    }

    pub(crate) fn spill_predecessor(&self) -> (u64, &Sha256Digest) {
        (
            self.spill_predecessor_event_ordinal,
            &self.spill_predecessor_head_sha256,
        )
    }

    pub(crate) fn persisted_sequence_range_sha256(&self) -> &Sha256Digest {
        &self.persisted_sequence_range_sha256
    }

    pub(crate) fn durable_spool_sha256(&self) -> &Sha256Digest {
        &self.durable_spool_sha256
    }

    pub(crate) fn preparation_receipt_sha256(&self) -> &Sha256Digest {
        &self.preparation_receipt_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CustodyUnavailableReason {
    NoInstalledGeneration,
    GenerationReconciling,
    SequenceRangeExhausted,
    DurableSpoolBackpressure,
    CustodyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnavailableGenerationInstallState {
    Uninstalled,
    Reconciling,
    Installed,
    Retired,
    SequenceRangeExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedUnavailableGenerationReceipt {
    request_binding_sha256: Sha256Digest,
    request_commitment_sha256: Sha256Digest,
    generation_id: Option<Sha256Digest>,
    generation_install_state: UnavailableGenerationInstallState,
    reason: CustodyUnavailableReason,
    event_ordinal: u64,
    predecessor_event_ordinal: u64,
    predecessor_head_sha256: Sha256Digest,
    resulting_head_sha256: Sha256Digest,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl SignedUnavailableGenerationReceipt {
    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        Self::from_custody(
            self.request_binding_sha256.clone(), self.request_commitment_sha256.clone(),
            self.generation_id.clone(), self.generation_install_state, self.reason,
            self.event_ordinal, self.predecessor_event_ordinal,
            self.predecessor_head_sha256.clone(), self.resulting_head_sha256.clone(),
            self.trusted_observed_at_unix_nanos, self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(), self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(), self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(), self.signature.0.clone(), self.signed_receipt_sha256.clone(),
        ).map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        request_binding_sha256: Sha256Digest,
        request_commitment_sha256: Sha256Digest,
        generation_id: Option<Sha256Digest>,
        generation_install_state: UnavailableGenerationInstallState,
        reason: CustodyUnavailableReason,
        event_ordinal: u64,
        predecessor_event_ordinal: u64,
        predecessor_head_sha256: Sha256Digest,
        resulting_head_sha256: Sha256Digest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(event_ordinal, "custody_unavailable.event_ordinal")?;
        if event_ordinal
            != predecessor_event_ordinal
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?
            || trusted_observed_at_unix_nanos <= 0
        {
            return Err(ShadowError::NonContiguousIngressSequence);
        }
        if matches!(
            reason,
            CustodyUnavailableReason::SequenceRangeExhausted
                | CustodyUnavailableReason::DurableSpoolBackpressure
        ) && generation_id.is_none()
        {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        let state_matches_reason = matches!(
            (generation_install_state, reason),
            (
                UnavailableGenerationInstallState::Uninstalled,
                CustodyUnavailableReason::NoInstalledGeneration
                    | CustodyUnavailableReason::CustodyUnavailable
            ) | (
                UnavailableGenerationInstallState::Reconciling,
                CustodyUnavailableReason::GenerationReconciling
            ) | (
                UnavailableGenerationInstallState::Installed,
                CustodyUnavailableReason::DurableSpoolBackpressure
            ) | (
                UnavailableGenerationInstallState::Retired,
                CustodyUnavailableReason::GenerationReconciling
            ) | (
                UnavailableGenerationInstallState::SequenceRangeExhausted,
                CustodyUnavailableReason::SequenceRangeExhausted
            )
        );
        if !state_matches_reason {
            return Err(ShadowError::GenerationIdentityMismatch);
        }
        let record_sha256 = hash_domain_frames(
            b"serverware.policyShadowUnavailableGenerationRecord/v1",
            &[&canonical_json_bytes(&(
                &request_binding_sha256,
                &request_commitment_sha256,
                &generation_id,
                generation_install_state,
                reason,
                event_ordinal,
                predecessor_event_ordinal,
                &predecessor_head_sha256,
                trusted_observed_at_unix_nanos,
                &trusted_time_checkpoint_sha256,
                &persistence_receipt_sha256,
                &retrieval_id_sha256,
                &retrieval_proof_sha256,
            ))?],
        );
        let expected_resulting_head = hash_domain_frames(
            b"serverware.policyShadowUnavailableGenerationHead/v1",
            &[&canonical_json_bytes(&(
                predecessor_event_ordinal,
                &predecessor_head_sha256,
                event_ordinal,
                &record_sha256,
            ))?],
        );
        if resulting_head_sha256 != expected_resulting_head {
            return Err(ShadowError::PreviousObservationHashMismatch);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let expected_signed_receipt = hash_domain_frames(
            b"serverware.policyShadowUnavailableGenerationReceipt/v1",
            &[&canonical_json_bytes(&(
                &record_sha256,
                &resulting_head_sha256,
                &signing_key_id,
                &signing_key_spki_sha256,
                &signature,
            ))?],
        );
        if signed_receipt_sha256 != expected_signed_receipt {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(Self {
            request_binding_sha256,
            request_commitment_sha256,
            generation_id,
            generation_install_state,
            reason,
            event_ordinal,
            predecessor_event_ordinal,
            predecessor_head_sha256,
            resulting_head_sha256,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        })
    }

    pub(crate) fn request_binding_sha256(&self) -> &Sha256Digest {
        &self.request_binding_sha256
    }

    pub(crate) fn generation_id(&self) -> Option<&Sha256Digest> {
        self.generation_id.as_ref()
    }

    pub(crate) fn event_ordinal(&self) -> u64 {
        self.event_ordinal
    }

    pub(crate) fn predecessor_event_ordinal(&self) -> u64 {
        self.predecessor_event_ordinal
    }

    pub(crate) fn predecessor_head_sha256(&self) -> &Sha256Digest {
        &self.predecessor_head_sha256
    }

    pub(crate) fn resulting_head_sha256(&self) -> &Sha256Digest {
        &self.resulting_head_sha256
    }

    pub(crate) fn retrieval_id_sha256(&self) -> &Sha256Digest {
        &self.retrieval_id_sha256
    }

    pub(crate) fn retrieval_proof_sha256(&self) -> &Sha256Digest {
        &self.retrieval_proof_sha256
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.signed_receipt_sha256
    }

    fn canonical_signature_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            &self.request_binding_sha256,
            &self.request_commitment_sha256,
            &self.generation_id,
            self.generation_install_state,
            self.reason,
            self.event_ordinal,
            self.predecessor_event_ordinal,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::UnavailableIngress,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedUnavailableGenerationReceipt {
    wire: SignedUnavailableGenerationReceipt,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[cfg(test)]
fn verify_unavailable_generation_receipt(
    wire: SignedUnavailableGenerationReceipt,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedUnavailableGenerationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    let canonical_payload = wire.canonical_signature_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::UnavailableIngress,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedUnavailableGenerationReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_unavailable_generation_receipt(
    wire: SignedUnavailableGenerationReceipt,
    expected_request_binding_sha256: &Sha256Digest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedUnavailableGenerationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.request_binding_sha256 != *expected_request_binding_sha256 {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::UnavailableIngress,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedUnavailableGenerationReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl Deref for VerifiedUnavailableGenerationReceipt {
    type Target = SignedUnavailableGenerationReceipt;

    fn deref(&self) -> &Self::Target {
        &self.wire
    }
}

impl VerifiedUnavailableGenerationReceipt {
    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }

    pub(crate) fn canonical_payload_length(
        &self,
    ) -> Result<usize, ShadowError> {
        Ok(self.wire.canonical_signature_payload()?.len())
    }
}

#[derive(Clone)]
pub(crate) struct PersistedIngressAdmission {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    request_binding_sha256: Sha256Digest,
    request_commitment_sha256: Sha256Digest,
    observed_at_unix_nanos: i64,
    sampling: CustodySamplingAuthorization,
    opening_spill_receipt: VerifiedShadowSpillReceipt,
}

impl PersistedIngressAdmission {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        generation: &ShadowGenerationIdentity,
        ingress_sequence: u64,
        request_binding_sha256: Sha256Digest,
        observed_at_unix_nanos: i64,
        sampling: CustodySamplingAuthorization,
        opening_spill_receipt: VerifiedShadowSpillReceipt,
    ) -> Result<Self, ShadowError> {
        validate_positive(ingress_sequence, "custody.ingress_sequence")?;
        if ingress_sequence < generation.ingress_range_start_sequence
            || observed_at_unix_nanos < generation.assignment_starts_at_unix_nanos
            || observed_at_unix_nanos >= generation.assignment_ends_at_unix_nanos
            || !sampling.matches(
                generation.generation_id.as_str(),
                request_binding_sha256.as_str(),
                ingress_sequence,
                generation.sampling_basis_points,
            )
            || !opening_spill_receipt.matches_opening(
                &generation.generation_id,
                ingress_sequence,
                &request_binding_sha256,
            )
            || opening_spill_receipt.request_commitment_sha256()
                != sampling.request_commitment_sha256()
            || opening_spill_receipt.trusted_observed_at_unix_nanos()
                != observed_at_unix_nanos
        {
            return Err(ShadowError::BindingDrift);
        }
        let request_commitment_sha256 =
            sampling.request_commitment_sha256().clone();
        Ok(Self {
            generation_id: generation.generation_id.clone(),
            ingress_sequence,
            request_binding_sha256,
            request_commitment_sha256,
            observed_at_unix_nanos,
            sampling,
            opening_spill_receipt,
        })
    }

    pub(crate) fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    pub(crate) fn ingress_sequence(&self) -> u64 {
        self.ingress_sequence
    }

    pub(crate) fn request_binding_sha256(&self) -> &Sha256Digest {
        &self.request_binding_sha256
    }

    pub(crate) fn request_commitment_sha256(&self) -> &Sha256Digest {
        &self.request_commitment_sha256
    }

    pub(crate) fn observed_at_unix_nanos(&self) -> i64 {
        self.observed_at_unix_nanos
    }

    pub(crate) fn sampling(&self) -> &CustodySamplingAuthorization {
        &self.sampling
    }

    pub(crate) fn opening_spill_receipt(&self) -> &VerifiedShadowSpillReceipt {
        &self.opening_spill_receipt
    }
}

#[derive(Clone)]
pub(crate) enum IngressCustodyAdmission {
    Assigned(PersistedIngressAdmission),
    Unavailable(VerifiedUnavailableGenerationReceipt),
}

/// This wire deliberately contains no deserializable verified receipt or
/// response-supplied generation. Assigned responses use the immutable locally
/// retained identity of the authenticated publication captured at dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    content = "receipt",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(in crate::policy_shadow) enum IngressCustodyAdmissionWire {
    Assigned(PersistedIngressAdmissionWire),
    Unavailable(SignedUnavailableGenerationReceipt),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct PersistedIngressAdmissionWire {
    observed_at_unix_nanos: i64,
    sampling: CustodySamplingAuthorizationWire,
    opening_spill_receipt: SignedShadowSpillReceipt,
}

impl IngressCustodyAdmissionWire {
    fn validate_expected_binding(
        &self,
        expected_generation: Option<&ShadowGenerationIdentity>,
        expected_sequence_bounds: Option<(u64, u64)>,
        request_binding: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        match self {
            Self::Assigned(wire) => {
                let generation = expected_generation
                    .ok_or(ShadowError::GenerationIdentityMismatch)?;
                let (first, last) = expected_sequence_bounds
                    .ok_or(ShadowError::GenerationIdentityMismatch)?;
                if wire.sampling.request_binding_sha256 != *request_binding {
                    return Err(ShadowError::BindingDrift);
                }
                if first != generation.ingress_range_start_sequence
                    || last < first
                    || wire.sampling.ingress_sequence < first
                    || wire.sampling.ingress_sequence > last
                {
                    return Err(ShadowError::NonContiguousIngressSequence);
                }
            }
            Self::Unavailable(wire) => {
                wire.validate_deserialized_invariants()?;
                if wire.request_binding_sha256 != *request_binding {
                    return Err(ShadowError::BindingDrift);
                }
                if let (Some(expected), Some(actual)) =
                    (expected_generation, wire.generation_id.as_ref())
                {
                    if expected.generation_id() != actual {
                        return Err(ShadowError::GenerationIdentityMismatch);
                    }
                }
            }
        }
        Ok(())
    }
}

pub(in crate::policy_shadow) fn verify_production_ingress_custody_admission(
    wire: IngressCustodyAdmissionWire,
    expected_generation: Option<&ShadowGenerationIdentity>,
    expected_sequence_bounds: Option<(u64, u64)>,
    expected_request_binding_sha256: &Sha256Digest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<IngressCustodyAdmission, ShadowError> {
    wire.validate_expected_binding(
        expected_generation,
        expected_sequence_bounds,
        expected_request_binding_sha256,
    )?;
    match wire {
        IngressCustodyAdmissionWire::Assigned(wire) => {
            let generation = expected_generation
                .ok_or(ShadowError::GenerationIdentityMismatch)?;
            Ok(IngressCustodyAdmission::Assigned(
                verify_production_persisted_ingress_admission(
                    generation,
                    expected_request_binding_sha256,
                    wire.observed_at_unix_nanos,
                    wire.sampling,
                    wire.opening_spill_receipt,
                    configuration,
                    key_trust,
                    trusted_time,
                    proof_verifier,
                )?,
            ))
        }
        IngressCustodyAdmissionWire::Unavailable(wire) => {
            Ok(IngressCustodyAdmission::Unavailable(
                verify_production_unavailable_generation_receipt(
                    wire,
                    expected_request_binding_sha256,
                    configuration,
                    key_trust,
                    trusted_time,
                    proof_verifier,
                )?,
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ShadowSpoolPhase {
    IngressOpen,
    Capture,
    Decision,
    PreDispatchTerminal,
    DispatchBarrier,
    PostDispatchTerminal,
    Response,
    Candidate,
    RangeClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ShadowSpoolDisposition {
    Appended,
    Unavailable,
}

pub(crate) fn custody_signer_role_for_spool_phase(
    phase: ShadowSpoolPhase,
) -> PolicyShadowCustodySignerRole {
    match phase {
        ShadowSpoolPhase::IngressOpen => {
            PolicyShadowCustodySignerRole::IngressAdmission
        }
        ShadowSpoolPhase::DispatchBarrier => {
            PolicyShadowCustodySignerRole::DispatchBarrier
        }
        ShadowSpoolPhase::PreDispatchTerminal
        | ShadowSpoolPhase::PostDispatchTerminal => {
            PolicyShadowCustodySignerRole::TerminalAppend
        }
        _ => PolicyShadowCustodySignerRole::LedgerAppend,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ShadowSpoolEvent {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    request_binding_sha256: Sha256Digest,
    request_commitment_sha256: Sha256Digest,
    phase: ShadowSpoolPhase,
    event_sha256: Sha256Digest,
    canonical_event_bytes: Vec<u8>,
}

impl ShadowSpoolEvent {
    const MAX_CANONICAL_EVENT_BYTES: usize = 256 * 1024;

    pub(crate) fn new(
        generation_id: Sha256Digest,
        ingress_sequence: u64,
        request_binding_sha256: Sha256Digest,
        request_commitment_sha256: Sha256Digest,
        phase: ShadowSpoolPhase,
        event_sha256: Sha256Digest,
        canonical_event_bytes: Vec<u8>,
    ) -> Result<Self, ShadowError> {
        validate_positive(ingress_sequence, "spool.ingress_sequence")?;
        if canonical_event_bytes.is_empty()
            || canonical_event_bytes.len() > Self::MAX_CANONICAL_EVENT_BYTES
            || Sha256Digest::compute(&canonical_event_bytes) != event_sha256
        {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(Self {
            generation_id,
            ingress_sequence,
            request_binding_sha256,
            request_commitment_sha256,
            phase,
            event_sha256,
            canonical_event_bytes,
        })
    }

    pub(crate) fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    pub(crate) fn ingress_sequence(&self) -> u64 {
        self.ingress_sequence
    }

    pub(crate) fn event_sha256(&self) -> &Sha256Digest {
        &self.event_sha256
    }

    pub(crate) fn request_commitment_sha256(&self) -> &Sha256Digest {
        &self.request_commitment_sha256
    }

    pub(crate) fn canonical_event_bytes(&self) -> &[u8] {
        &self.canonical_event_bytes
    }

    pub(crate) fn phase(&self) -> ShadowSpoolPhase {
        self.phase
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedShadowSpillReceipt {
    generation_id: Sha256Digest,
    ingress_sequence: u64,
    request_binding_sha256: Sha256Digest,
    request_commitment_sha256: Sha256Digest,
    event_ordinal: u64,
    event_phase: ShadowSpoolPhase,
    disposition: ShadowSpoolDisposition,
    event_sha256: Sha256Digest,
    canonical_event_bytes: Vec<u8>,
    predecessor_event_ordinal: u64,
    predecessor_head_sha256: Sha256Digest,
    resulting_head_sha256: Sha256Digest,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl SignedShadowSpillReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        event: &ShadowSpoolEvent,
        event_ordinal: u64,
        disposition: ShadowSpoolDisposition,
        predecessor_event_ordinal: u64,
        predecessor_head_sha256: Sha256Digest,
        resulting_head_sha256: Sha256Digest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(event_ordinal, "spool.event_ordinal")?;
        if event_ordinal
            != predecessor_event_ordinal
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?
        {
            return Err(ShadowError::NonContiguousObservationSequence);
        }
        if trusted_observed_at_unix_nanos <= 0 {
            return Err(ShadowError::TrustedTimeUnavailable);
        }
        let record_sha256 = hash_domain_frames(
            b"serverware.policyShadowSpoolRecord/v1",
            &[&canonical_json_bytes(&(
                &event.generation_id,
                event.ingress_sequence,
                &event.request_binding_sha256,
                &event.request_commitment_sha256,
                event.phase,
                disposition,
                &event.event_sha256,
                &event.canonical_event_bytes,
                event_ordinal,
                predecessor_event_ordinal,
                &predecessor_head_sha256,
                trusted_observed_at_unix_nanos,
                &trusted_time_checkpoint_sha256,
                &persistence_receipt_sha256,
                &retrieval_id_sha256,
                &retrieval_proof_sha256,
            ))?],
        );
        let expected_resulting_head = hash_domain_frames(
            b"serverware.policyShadowSpoolHead/v1",
            &[&canonical_json_bytes(&(
                predecessor_event_ordinal,
                &predecessor_head_sha256,
                event_ordinal,
                &record_sha256,
            ))?],
        );
        if resulting_head_sha256 != expected_resulting_head {
            return Err(ShadowError::PreviousObservationHashMismatch);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let expected_signed_receipt = hash_domain_frames(
            b"serverware.policyShadowSpillReceipt/v1",
            &[&canonical_json_bytes(&(
                &record_sha256,
                &resulting_head_sha256,
                &signing_key_id,
                &signing_key_spki_sha256,
                &signature,
            ))?],
        );
        if signed_receipt_sha256 != expected_signed_receipt {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(Self {
            generation_id: event.generation_id.clone(),
            ingress_sequence: event.ingress_sequence,
            request_binding_sha256: event.request_binding_sha256.clone(),
            request_commitment_sha256:
                event.request_commitment_sha256.clone(),
            event_ordinal,
            event_phase: event.phase,
            disposition,
            event_sha256: event.event_sha256.clone(),
            canonical_event_bytes: event.canonical_event_bytes.clone(),
            predecessor_event_ordinal,
            predecessor_head_sha256,
            resulting_head_sha256,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        })
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let event = ShadowSpoolEvent::new(
            self.generation_id.clone(),
            self.ingress_sequence,
            self.request_binding_sha256.clone(),
            self.request_commitment_sha256.clone(),
            self.event_phase,
            self.event_sha256.clone(),
            self.canonical_event_bytes.clone(),
        )?;
        let reconstructed = Self::from_custody(
            &event,
            self.event_ordinal,
            self.disposition,
            self.predecessor_event_ordinal,
            self.predecessor_head_sha256.clone(),
            self.resulting_head_sha256.clone(),
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(crate) fn matches_opening(
        &self,
        generation_id: &Sha256Digest,
        ingress_sequence: u64,
        request_binding_sha256: &Sha256Digest,
    ) -> bool {
        self.generation_id == *generation_id
            && self.ingress_sequence == ingress_sequence
            && self.request_binding_sha256 == *request_binding_sha256
            && self.event_phase == ShadowSpoolPhase::IngressOpen
            && self.disposition == ShadowSpoolDisposition::Appended
    }

    pub(crate) fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    pub(crate) fn ingress_sequence(&self) -> u64 {
        self.ingress_sequence
    }

    pub(crate) fn request_commitment_sha256(&self) -> &Sha256Digest {
        &self.request_commitment_sha256
    }

    pub(crate) fn event_ordinal(&self) -> u64 {
        self.event_ordinal
    }

    pub(crate) fn event_sha256(&self) -> &Sha256Digest {
        &self.event_sha256
    }

    pub(crate) fn canonical_event_bytes(&self) -> &[u8] {
        &self.canonical_event_bytes
    }

    pub(crate) fn predecessor_event_ordinal(&self) -> u64 {
        self.predecessor_event_ordinal
    }

    pub(crate) fn predecessor_head_sha256(&self) -> &Sha256Digest {
        &self.predecessor_head_sha256
    }

    pub(crate) fn resulting_head_sha256(&self) -> &Sha256Digest {
        &self.resulting_head_sha256
    }

    pub(crate) fn trusted_observed_at_unix_nanos(&self) -> i64 {
        self.trusted_observed_at_unix_nanos
    }

    pub(crate) fn trusted_time_checkpoint_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.trusted_time_checkpoint_sha256
    }

    pub(crate) fn retrieval_id_sha256(&self) -> &Sha256Digest {
        &self.retrieval_id_sha256
    }

    pub(crate) fn retrieval_proof_sha256(&self) -> &Sha256Digest {
        &self.retrieval_proof_sha256
    }

    pub(crate) fn disposition(&self) -> ShadowSpoolDisposition {
        self.disposition
    }

    pub(crate) fn matches_event(&self, event: &ShadowSpoolEvent) -> bool {
        self.generation_id == event.generation_id
            && self.ingress_sequence == event.ingress_sequence
            && self.request_binding_sha256 == event.request_binding_sha256
            && self.request_commitment_sha256
                == event.request_commitment_sha256
            && self.event_phase == event.phase
            && self.event_sha256 == event.event_sha256
            && self.canonical_event_bytes == event.canonical_event_bytes
    }

    pub(crate) fn matches_event_and_predecessor(
        &self,
        event: &ShadowSpoolEvent,
        predecessor_event_ordinal: u64,
        predecessor_head_sha256: &Sha256Digest,
    ) -> bool {
        self.matches_event(event)
            && self.predecessor_event_ordinal == predecessor_event_ordinal
            && self.predecessor_head_sha256 == *predecessor_head_sha256
            && predecessor_event_ordinal
                .checked_add(1)
                .is_some_and(|next| self.event_ordinal == next)
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.signed_receipt_sha256
    }

    fn signer_role(&self) -> PolicyShadowCustodySignerRole {
        custody_signer_role_for_spool_phase(self.event_phase)
    }

    fn canonical_signature_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            &self.generation_id,
            self.ingress_sequence,
            &self.request_binding_sha256,
            &self.request_commitment_sha256,
            self.event_ordinal,
            self.event_phase,
            self.disposition,
            &self.event_sha256,
            &self.canonical_event_bytes,
            self.predecessor_event_ordinal,
            &self.predecessor_head_sha256,
            &self.resulting_head_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            self.signer_role(),
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedShadowSpillReceipt {
    wire: SignedShadowSpillReceipt,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[cfg(test)]
fn verify_shadow_spill_receipt(
    wire: SignedShadowSpillReceipt,
    expected_event: &ShadowSpoolEvent,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedShadowSpillReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if !wire.matches_event(expected_event) {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        wire.signer_role(),
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedShadowSpillReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_shadow_spill_receipt(
    wire: SignedShadowSpillReceipt,
    expected_event: &ShadowSpoolEvent,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedShadowSpillReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if !wire.matches_event(expected_event) {
        return Err(ShadowError::BindingDrift);
    }
    let role = custody_signer_role_for_spool_phase(
        expected_event.phase(),
    );
    if wire.signer_role() != role {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            role,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedShadowSpillReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl Deref for VerifiedShadowSpillReceipt {
    type Target = SignedShadowSpillReceipt;

    fn deref(&self) -> &Self::Target {
        &self.wire
    }
}

impl VerifiedShadowSpillReceipt {
    pub(crate) fn request_binding_sha256(&self)->&Sha256Digest {
        &self.wire.request_binding_sha256
    }

    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AuthenticatedSpoolCompactionRequest {
    generation_id: Sha256Digest,
    old_spool_head_sha256: Sha256Digest,
    compacted_first_event_ordinal: u64,
    compacted_last_event_ordinal: u64,
    compacted_ordered_range_root_sha256: Sha256Digest,
    compacted_record_count: u64,
    compacted_through_spill_receipt_sha256: Sha256Digest,
    retained_successor_event_ordinal: Option<u64>,
    retained_successor_head_sha256: Option<Sha256Digest>,
    expected_new_spool_root_sha256: Sha256Digest,
}

impl AuthenticatedSpoolCompactionRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation_id: Sha256Digest,
        old_spool_head_sha256: Sha256Digest,
        compacted_first_event_ordinal: u64,
        compacted_last_event_ordinal: u64,
        compacted_ordered_range_root_sha256: Sha256Digest,
        compacted_record_count: u64,
        compacted_through_spill_receipt_sha256: Sha256Digest,
        retained_successor_event_ordinal: Option<u64>,
        retained_successor_head_sha256: Option<Sha256Digest>,
        expected_new_spool_root_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(compacted_first_event_ordinal, "spool.compacted_first_event_ordinal")?;
        validate_positive(compacted_last_event_ordinal, "spool.compacted_last_event_ordinal")?;
        validate_positive(compacted_record_count, "spool.compacted_record_count")?;
        let expected_count = compacted_last_event_ordinal
            .checked_sub(compacted_first_event_ordinal)
            .and_then(|delta| delta.checked_add(1))
            .ok_or(ShadowError::CounterOverflow)?;
        if compacted_record_count != expected_count
            || retained_successor_event_ordinal.is_some()
                != retained_successor_head_sha256.is_some()
            || retained_successor_event_ordinal.is_some_and(|ordinal| {
                compacted_last_event_ordinal
                    .checked_add(1)
                    .is_none_or(|next| ordinal != next)
            })
        {
            return Err(ShadowError::NonContiguousObservationSequence);
        }
        Ok(Self {
            generation_id,
            old_spool_head_sha256,
            compacted_first_event_ordinal,
            compacted_last_event_ordinal,
            compacted_ordered_range_root_sha256,
            compacted_record_count,
            compacted_through_spill_receipt_sha256,
            retained_successor_event_ordinal,
            retained_successor_head_sha256,
            expected_new_spool_root_sha256,
        })
    }

    pub(crate) fn old_spool_head_sha256(&self) -> &Sha256Digest {
        &self.old_spool_head_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthenticatedSpoolCompactionReceipt {
    generation_id: Sha256Digest,
    old_spool_head_sha256: Sha256Digest,
    compacted_first_event_ordinal: u64,
    compacted_last_event_ordinal: u64,
    compacted_ordered_range_root_sha256: Sha256Digest,
    compacted_record_count: u64,
    compacted_through_spill_receipt_sha256: Sha256Digest,
    retained_successor_event_ordinal: Option<u64>,
    retained_successor_head_sha256: Option<Sha256Digest>,
    new_spool_root_sha256: Sha256Digest,
    trusted_observed_at_unix_nanos: i64,
    trusted_time_checkpoint_sha256: Sha256Digest,
    persistence_receipt_sha256: Sha256Digest,
    retrieval_id_sha256: Sha256Digest,
    retrieval_proof_sha256: Sha256Digest,
    signing_key_id: Sha256Digest,
    signing_key_spki_sha256: Sha256Digest,
    signature: CanonicalEd25519Signature,
    signed_receipt_sha256: Sha256Digest,
}

impl AuthenticatedSpoolCompactionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        request: &AuthenticatedSpoolCompactionRequest,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        if trusted_observed_at_unix_nanos <= 0 {
            return Err(ShadowError::TrustedTimeUnavailable);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let expected_signed_receipt = hash_domain_frames(
            b"serverware.policyShadowSpoolCompactionReceipt/v1",
            &[&canonical_json_bytes(&serde_json::json!([
                &request.generation_id,
                &request.old_spool_head_sha256,
                request.compacted_first_event_ordinal,
                request.compacted_last_event_ordinal,
                &request.compacted_ordered_range_root_sha256,
                request.compacted_record_count,
                &request.compacted_through_spill_receipt_sha256,
                &request.retained_successor_event_ordinal,
                &request.retained_successor_head_sha256,
                &request.expected_new_spool_root_sha256,
                trusted_observed_at_unix_nanos,
                &trusted_time_checkpoint_sha256,
                &persistence_receipt_sha256,
                &retrieval_id_sha256,
                &retrieval_proof_sha256,
                &signing_key_id,
                &signing_key_spki_sha256,
                &signature,
            ]))?],
        );
        if signed_receipt_sha256 != expected_signed_receipt {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(Self {
            generation_id: request.generation_id.clone(),
            old_spool_head_sha256: request.old_spool_head_sha256.clone(),
            compacted_first_event_ordinal: request.compacted_first_event_ordinal,
            compacted_last_event_ordinal: request.compacted_last_event_ordinal,
            compacted_ordered_range_root_sha256: request
                .compacted_ordered_range_root_sha256
                .clone(),
            compacted_record_count: request.compacted_record_count,
            compacted_through_spill_receipt_sha256: request
                .compacted_through_spill_receipt_sha256
                .clone(),
            retained_successor_event_ordinal: request
                .retained_successor_event_ordinal,
            retained_successor_head_sha256: request
                .retained_successor_head_sha256
                .clone(),
            new_spool_root_sha256: request
                .expected_new_spool_root_sha256
                .clone(),
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        })
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let request = AuthenticatedSpoolCompactionRequest::new(
            self.generation_id.clone(),
            self.old_spool_head_sha256.clone(),
            self.compacted_first_event_ordinal,
            self.compacted_last_event_ordinal,
            self.compacted_ordered_range_root_sha256.clone(),
            self.compacted_record_count,
            self.compacted_through_spill_receipt_sha256.clone(),
            self.retained_successor_event_ordinal,
            self.retained_successor_head_sha256.clone(),
            self.new_spool_root_sha256.clone(),
        )?;
        let reconstructed = Self::from_custody(
            &request,
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(crate) fn generation_id(&self) -> &Sha256Digest {
        &self.generation_id
    }

    pub(crate) fn compacted_through_event_ordinal(&self) -> u64 {
        self.compacted_last_event_ordinal
    }

    pub(crate) fn compacted_through_spill_receipt_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.compacted_through_spill_receipt_sha256
    }

    pub(crate) fn matches_request(
        &self,
        request: &AuthenticatedSpoolCompactionRequest,
    ) -> bool {
        self.generation_id == request.generation_id
            && self.old_spool_head_sha256 == request.old_spool_head_sha256
            && self.compacted_first_event_ordinal
                == request.compacted_first_event_ordinal
            && self.compacted_last_event_ordinal
                == request.compacted_last_event_ordinal
            && self.compacted_ordered_range_root_sha256
                == request.compacted_ordered_range_root_sha256
            && self.compacted_record_count == request.compacted_record_count
            && self.compacted_through_spill_receipt_sha256
                == request.compacted_through_spill_receipt_sha256
            && self.retained_successor_event_ordinal
                == request.retained_successor_event_ordinal
            && self.retained_successor_head_sha256
                == request.retained_successor_head_sha256
            && self.new_spool_root_sha256
                == request.expected_new_spool_root_sha256
    }

    pub(crate) fn compacted_first_event_ordinal(&self) -> u64 {
        self.compacted_first_event_ordinal
    }

    pub(crate) fn compacted_record_count(&self) -> u64 {
        self.compacted_record_count
    }

    pub(crate) fn compacted_ordered_range_root_sha256(
        &self,
    ) -> &Sha256Digest {
        &self.compacted_ordered_range_root_sha256
    }

    pub(crate) fn old_spool_head_sha256(&self) -> &Sha256Digest {
        &self.old_spool_head_sha256
    }

    pub(crate) fn retained_successor(
        &self,
    ) -> (Option<u64>, Option<&Sha256Digest>) {
        (
            self.retained_successor_event_ordinal,
            self.retained_successor_head_sha256.as_ref(),
        )
    }

    pub(crate) fn new_spool_root_sha256(&self) -> &Sha256Digest {
        &self.new_spool_root_sha256
    }

    pub(crate) fn retrieval_id_sha256(&self) -> &Sha256Digest {
        &self.retrieval_id_sha256
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.signed_receipt_sha256
    }

    fn canonical_signature_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            &self.generation_id,
            &self.old_spool_head_sha256,
            self.compacted_first_event_ordinal,
            self.compacted_last_event_ordinal,
            &self.compacted_ordered_range_root_sha256,
            self.compacted_record_count,
            &self.compacted_through_spill_receipt_sha256,
            &self.retained_successor_event_ordinal,
            &self.retained_successor_head_sha256,
            &self.new_spool_root_sha256,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::SpoolCompaction,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedSpoolCompactionReceipt {
    wire: AuthenticatedSpoolCompactionReceipt,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[cfg(test)]
fn verify_spool_compaction_receipt(
    wire: AuthenticatedSpoolCompactionReceipt,
    expected_request: &AuthenticatedSpoolCompactionRequest,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedSpoolCompactionReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if !wire.matches_request(expected_request) {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::SpoolCompaction,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedSpoolCompactionReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

pub(in crate::policy_shadow) fn verify_production_spool_compaction_receipt(
    wire: AuthenticatedSpoolCompactionReceipt,
    expected_request: &AuthenticatedSpoolCompactionRequest,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedSpoolCompactionReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if !wire.matches_request(expected_request) {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_payload = wire.canonical_signature_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::SpoolCompaction,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedSpoolCompactionReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl Deref for VerifiedSpoolCompactionReceipt {
    type Target = AuthenticatedSpoolCompactionReceipt;

    fn deref(&self) -> &Self::Target {
        &self.wire
    }
}

impl VerifiedSpoolCompactionReceipt {
    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RequestScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperationClass {
    Read,
    Search,
    Write,
    Publish,
    Delete,
    Administrative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProtectedRequestFacts {
    method: Identifier,
    scheme: RequestScheme,
    authority: Identifier,
    path_commitment: Identifier,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    query_commitment: Option<Identifier>,
    header_commitments: Vec<Identifier>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    body_commitment: Option<Identifier>,
    principal_commitment: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    credential_commitment: Option<Sha256Digest>,
    route_sha256: Sha256Digest,
    compiled_semantic_profile_sha256: Sha256Digest,
    operation: OperationClass,
}

impl ProtectedRequestFacts {
    /// `route_sha256`, `compiled_semantic_profile_sha256`, and `operation` are
    /// emitted by the compiled route/provider classifier, never request input.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        method: Identifier,
        scheme: RequestScheme,
        authority: Identifier,
        path_commitment: Identifier,
        query_commitment: Option<Identifier>,
        header_commitments: Vec<Identifier>,
        body_commitment: Option<Identifier>,
        principal_commitment: Sha256Digest,
        credential_commitment: Option<Sha256Digest>,
        route_sha256: Sha256Digest,
        compiled_semantic_profile_sha256: Sha256Digest,
        operation: OperationClass,
    ) -> Result<Self, ShadowError> {
        let facts = Self {
            method,
            scheme,
            authority,
            path_commitment,
            query_commitment,
            header_commitments,
            body_commitment,
            principal_commitment,
            credential_commitment,
            route_sha256,
            compiled_semantic_profile_sha256,
            operation,
        };
        facts.validate()?;
        Ok(facts)
    }

    fn validate(&self) -> Result<(), ShadowError> {
        validate_len(
            "protected_facts.header_commitments",
            self.header_commitments.len(),
            0,
            MAX_PLAN_ITEMS,
        )?;
        let bytes = canonical_json_bytes(self)?;
        if bytes.len() > MAX_PROTECTED_FACTS_BYTES {
            return Err(invalid("protected_facts", "canonical facts exceed limit"));
        }
        Ok(())
    }

    pub(crate) fn operation(&self) -> OperationClass {
        self.operation
    }

    pub(crate) fn route_sha256(&self) -> &Sha256Digest {
        &self.route_sha256
    }

    pub(crate) fn compiled_semantic_profile_sha256(&self) -> &Sha256Digest {
        &self.compiled_semantic_profile_sha256
    }
}

pub(crate) struct RequestCommitmentKey {
    key_id: Sha256Digest,
    key_epoch: u64,
    key: hmac::Key,
}

impl RequestCommitmentKey {
    pub(crate) fn from_secret(
        key_id: Sha256Digest,
        key_epoch: u64,
        secret: &[u8],
    ) -> Result<Self, ShadowError> {
        validate_positive(key_epoch, "request_commitment.key_epoch")?;
        if secret.len() < 32 {
            return Err(invalid("request_commitment.secret", "at least 32 bytes required"));
        }
        Ok(Self {
            key_id,
            key_epoch,
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestCommitment {
    algorithm: String,
    domain: String,
    key_id: Sha256Digest,
    key_epoch: u64,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    boot_id_sha256: Sha256Digest,
    ingress_sequence: u64,
    observed_at_unix_nanos: i64,
    commitment: HmacSha256Digest,
}

impl RequestCommitment {
    pub(crate) fn from_custody_hmac(
        key_id: Sha256Digest,
        key_epoch: u64,
        context: &RequestCommitmentContext,
        tag: &[u8],
    ) -> Result<Self, ShadowError> {
        validate_positive(key_epoch, "request_commitment.key_epoch")?;
        if tag.len() != 32 {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        Ok(Self {
            algorithm: "HMAC-SHA-256".to_string(),
            domain: REQUEST_COMMITMENT_DOMAIN_TEXT.to_string(),
            key_id,
            key_epoch,
            assignment_payload_sha256: context.assignment_payload_sha256.clone(),
            assignment_revision: context.assignment_revision,
            boot_id_sha256: context.boot_id_sha256.clone(),
            ingress_sequence: context.ingress_sequence,
            observed_at_unix_nanos: context.observed_at_unix_nanos,
            commitment: HmacSha256Digest(format!("hmac-sha256:{}", hex::encode(tag))),
        })
    }

    fn validate_binding(
        &self,
        assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity,
        ingress_sequence: u64,
        observed_at_unix_nanos: i64,
    ) -> Result<(), ShadowError> {
        let assignment_payload = assignment.payload();
        if self.algorithm != "HMAC-SHA-256"
            || self.domain.as_bytes() != REQUEST_COMMITMENT_DOMAIN
            || self.key_id
                != assignment_payload
                    .observation_window
                    .request_commitment_key_id
            || self.key_epoch
                != assignment_payload
                    .observation_window
                    .request_commitment_key_epoch
            || self.assignment_payload_sha256 != *assignment.payload_sha256()
            || self.assignment_revision != assignment_payload.assignment_revision
            || self.boot_id_sha256 != runtime.boot_id_sha256
            || self.ingress_sequence != ingress_sequence
            || self.observed_at_unix_nanos != observed_at_unix_nanos
        {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        validate_positive(self.key_epoch, "request_commitment.key_epoch")?;
        validate_positive(
            self.assignment_revision,
            "request_commitment.assignment_revision",
        )?;
        validate_positive(self.ingress_sequence, "request_commitment.ingress_sequence")
    }

    pub(crate) fn key_id(&self) -> &Sha256Digest {
        &self.key_id
    }

    pub(crate) fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    fn sampling_decision(
        &self,
        sampling_basis_points: u16,
    ) -> Result<SamplingDecision, ShadowError> {
        keyed_sampling_decision(&self.commitment, sampling_basis_points)
    }
}

pub(crate) fn keyed_sampling_decision(
    commitment: &HmacSha256Digest,
    sampling_basis_points: u16,
) -> Result<SamplingDecision, ShadowError> {
        if sampling_basis_points == 0 || sampling_basis_points > 10_000 {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        let commitment = commitment.raw_bytes()?;
        let sample = u64::from_be_bytes(
            commitment[..8]
                .try_into()
                .map_err(|_| ShadowError::RequestCommitmentMismatch)?,
        ) % 10_000;
        Ok(if sample < u64::from(sampling_basis_points) {
            SamplingDecision::Included
        } else {
            SamplingDecision::ExcludedByAssignment
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CustodySamplingAuthorizationWire {
    generation_id: Sha256Digest,
    request_binding_sha256: Sha256Digest,
    ingress_sequence: u64,
    sampling_basis_points: u16,
    request_commitment_sha256: Sha256Digest,
    decision: SamplingDecision,
}

impl CustodySamplingAuthorizationWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation_id: Sha256Digest,
        request_binding_sha256: Sha256Digest,
        ingress_sequence: u64,
        sampling_basis_points: u16,
        request_commitment_sha256: Sha256Digest,
        decision: SamplingDecision,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            ingress_sequence,
            "custody_sampling.ingress_sequence",
        )?;
        if sampling_basis_points == 0 || sampling_basis_points > 10_000 {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        Ok(Self {
            generation_id,
            request_binding_sha256,
            ingress_sequence,
            sampling_basis_points,
            request_commitment_sha256,
            decision,
        })
    }
}

fn canonical_ingress_admission_event_bytes(
    generation: &ShadowGenerationIdentity,
    observed_at_unix_nanos: i64,
    sampling: &CustodySamplingAuthorizationWire,
) -> Result<Vec<u8>, ShadowError> {
    canonical_json_bytes(&(
        "serverware.policyShadowIngressAdmissionEvent/v1",
        generation,
        observed_at_unix_nanos,
        sampling,
    ))
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_persisted_ingress_admission(
    generation: &ShadowGenerationIdentity,
    observed_at_unix_nanos: i64,
    sampling_wire: CustodySamplingAuthorizationWire,
    opening_spill_wire: SignedShadowSpillReceipt,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<PersistedIngressAdmission, ShadowError> {
    if observed_at_unix_nanos <= 0
        || sampling_wire.generation_id != generation.generation_id
        || sampling_wire.ingress_sequence
            < generation.ingress_range_start_sequence
        || sampling_wire.sampling_basis_points
            != generation.sampling_basis_points
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_event_bytes = canonical_ingress_admission_event_bytes(
        generation,
        observed_at_unix_nanos,
        &sampling_wire,
    )?;
    let opening_event = ShadowSpoolEvent::new(
        sampling_wire.generation_id.clone(),
        sampling_wire.ingress_sequence,
        sampling_wire.request_binding_sha256.clone(),
        sampling_wire.request_commitment_sha256.clone(),
        ShadowSpoolPhase::IngressOpen,
        Sha256Digest::compute(&canonical_event_bytes),
        canonical_event_bytes,
    )?;
    let opening_spill_receipt = verify_shadow_spill_receipt(
        opening_spill_wire,
        &opening_event,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    let sampling = CustodySamplingAuthorization {
        generation_id: sampling_wire.generation_id,
        request_binding_sha256:
            sampling_wire.request_binding_sha256.clone(),
        ingress_sequence: sampling_wire.ingress_sequence,
        sampling_basis_points: sampling_wire.sampling_basis_points,
        request_commitment_sha256:
            sampling_wire.request_commitment_sha256,
        decision: sampling_wire.decision,
    };
    PersistedIngressAdmission::from_custody(
        generation,
        sampling_wire.ingress_sequence,
        sampling_wire.request_binding_sha256,
        observed_at_unix_nanos,
        sampling,
        opening_spill_receipt,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::policy_shadow) fn verify_production_persisted_ingress_admission(
    generation: &ShadowGenerationIdentity,
    expected_request_binding_sha256: &Sha256Digest,
    observed_at_unix_nanos: i64,
    sampling_wire: CustodySamplingAuthorizationWire,
    opening_spill_wire: SignedShadowSpillReceipt,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<PersistedIngressAdmission, ShadowError> {
    if observed_at_unix_nanos <= 0
        || sampling_wire.request_binding_sha256
            != *expected_request_binding_sha256
        || sampling_wire.generation_id != generation.generation_id
        || sampling_wire.ingress_sequence
            < generation.ingress_range_start_sequence
        || sampling_wire.sampling_basis_points
            != generation.sampling_basis_points
    {
        return Err(ShadowError::BindingDrift);
    }
    let canonical_event_bytes = canonical_ingress_admission_event_bytes(
        generation,
        observed_at_unix_nanos,
        &sampling_wire,
    )?;
    let opening_event = ShadowSpoolEvent::new(
        sampling_wire.generation_id.clone(),
        sampling_wire.ingress_sequence,
        sampling_wire.request_binding_sha256.clone(),
        sampling_wire.request_commitment_sha256.clone(),
        ShadowSpoolPhase::IngressOpen,
        Sha256Digest::compute(&canonical_event_bytes),
        canonical_event_bytes,
    )?;
    let opening_spill_receipt =
        verify_production_shadow_spill_receipt(
            opening_spill_wire,
            &opening_event,
            configuration,
            key_trust,
            trusted_time,
            proof_verifier,
        )?;
    let sampling = CustodySamplingAuthorization {
        generation_id: sampling_wire.generation_id,
        request_binding_sha256:
            sampling_wire.request_binding_sha256.clone(),
        ingress_sequence: sampling_wire.ingress_sequence,
        sampling_basis_points: sampling_wire.sampling_basis_points,
        request_commitment_sha256:
            sampling_wire.request_commitment_sha256,
        decision: sampling_wire.decision,
    };
    PersistedIngressAdmission::from_custody(
        generation,
        sampling_wire.ingress_sequence,
        sampling_wire.request_binding_sha256,
        observed_at_unix_nanos,
        sampling,
        opening_spill_receipt,
    )
}

/// Non-deserializable authority returned only after custody HMAC verification
/// or verification of a signed, immutable ingress-admission event.
/// Runtime and signed observation verification consume the same 64-bit sample
/// reduction from the exact request commitment.
#[derive(Clone)]
pub(crate) struct CustodySamplingAuthorization {
    generation_id: Sha256Digest,
    request_binding_sha256: Sha256Digest,
    ingress_sequence: u64,
    sampling_basis_points: u16,
    request_commitment_sha256: Sha256Digest,
    decision: SamplingDecision,
}

impl CustodySamplingAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_request_commitment(
        generation: &ShadowGenerationIdentity,
        request_binding_sha256: Sha256Digest,
        request_commitment: &RequestCommitment,
        protected_facts: &ProtectedRequestFacts,
        assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity,
        ingress_sequence: u64,
        observed_at_unix_nanos: i64,
        verifier: &dyn RequestCommitmentVerification,
    ) -> Result<Self, ShadowError> {
        request_commitment.validate_binding(
            assignment,
            runtime,
            ingress_sequence,
            observed_at_unix_nanos,
        )?;
        verifier.verify(
            request_commitment,
            protected_facts,
            assignment,
            runtime,
            ingress_sequence,
            observed_at_unix_nanos,
        )?;
        let sampling_basis_points = assignment
            .payload()
            .observation_window
            .sampling_basis_points;
        if generation.assignment_payload_sha256()
                != assignment.payload_sha256()
            || generation.runtime_boot_id_sha256()
                != &runtime.boot_id_sha256
            || generation.sampling_basis_points() != sampling_basis_points
        {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        Ok(Self {
            generation_id: generation.generation_id().clone(),
            request_binding_sha256,
            ingress_sequence,
            sampling_basis_points,
            request_commitment_sha256: Sha256Digest::compute(
                &canonical_json_bytes(request_commitment)?,
            ),
            decision: request_commitment
                .sampling_decision(sampling_basis_points)?,
        })
    }

    pub(crate) fn matches(
        &self,
        generation_id: &str,
        request_binding_sha256: &str,
        ingress_sequence: u64,
        sampling_basis_points: u16,
    ) -> bool {
        self.generation_id.as_str() == generation_id
            && self.request_binding_sha256.as_str()
                == request_binding_sha256
            && self.ingress_sequence == ingress_sequence
            && self.sampling_basis_points == sampling_basis_points
    }

    pub(crate) fn decision(&self) -> SamplingDecision {
        self.decision
    }

    pub(crate) fn request_commitment_sha256(&self) -> &Sha256Digest {
        &self.request_commitment_sha256
    }
}

pub(crate) fn commit_protected_request_facts(
    facts: &ProtectedRequestFacts,
    assignment: &VerifiedAssignment,
    runtime: &RuntimeIdentity,
    ingress_sequence: u64,
    observed_at_unix_nanos: i64,
    key: &RequestCommitmentKey,
) -> Result<RequestCommitment, ShadowError> {
    facts.validate()?;
    validate_positive(ingress_sequence, "ingress_sequence")?;
    let payload = assignment.payload();
    if key.key_id != payload.observation_window.request_commitment_key_id
        || key.key_epoch != payload.observation_window.request_commitment_key_epoch
        || observed_at_unix_nanos < payload.observation_window.starts_at_unix_nanos
        || observed_at_unix_nanos >= payload.observation_window.ends_at_unix_nanos
    {
        return Err(ShadowError::RequestCommitmentMismatch);
    }
    let facts_bytes = canonical_json_bytes(facts)?;
    let mut preimage = Vec::new();
    append_frame(&mut preimage, REQUEST_COMMITMENT_DOMAIN);
    append_frame(&mut preimage, &facts_bytes);
    append_frame(
        &mut preimage,
        &assignment.payload_sha256().raw_bytes()?,
    );
    append_frame(&mut preimage, &payload.assignment_revision.to_be_bytes());
    append_frame(&mut preimage, &runtime.boot_id_sha256.raw_bytes()?);
    append_frame(&mut preimage, &ingress_sequence.to_be_bytes());
    append_frame(&mut preimage, &key.key_epoch.to_be_bytes());
    append_frame(&mut preimage, &observed_at_unix_nanos.to_be_bytes());
    let tag = hmac::sign(&key.key, &preimage);
    let context = RequestCommitmentContext::from_verified_binding(
        assignment,
        runtime,
        ingress_sequence,
        observed_at_unix_nanos,
    )?;
    RequestCommitment::from_custody_hmac(
        key.key_id.clone(),
        key.key_epoch,
        &context,
        tag.as_ref(),
    )
}

/// Secret-free, validated inputs to the fixed custody HMAC operation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RequestCommitmentContext {
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    boot_id_sha256: Sha256Digest,
    ingress_sequence: u64,
    observed_at_unix_nanos: i64,
}

impl RequestCommitmentContext {
    pub(crate) fn from_verified_binding(
        assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity,
        ingress_sequence: u64,
        observed_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        validate_positive(ingress_sequence, "ingress_sequence")?;
        let window = &assignment.payload().observation_window;
        if observed_at_unix_nanos < window.starts_at_unix_nanos
            || observed_at_unix_nanos >= window.ends_at_unix_nanos
        {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        Ok(Self {
            assignment_payload_sha256: assignment.payload_sha256().clone(),
            assignment_revision: assignment.payload().assignment_revision,
            boot_id_sha256: runtime.boot_id_sha256.clone(),
            ingress_sequence,
            observed_at_unix_nanos,
        })
    }

    pub(crate) fn assignment_payload_sha256(&self) -> &Sha256Digest {
        &self.assignment_payload_sha256
    }

    pub(crate) fn assignment_revision(&self) -> u64 {
        self.assignment_revision
    }

    pub(crate) fn boot_id_sha256(&self) -> &Sha256Digest {
        &self.boot_id_sha256
    }

    pub(crate) fn ingress_sequence(&self) -> u64 {
        self.ingress_sequence
    }

    pub(crate) fn observed_at_unix_nanos(&self) -> i64 {
        self.observed_at_unix_nanos
    }
}

fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutcomeClass {
    Deny,
    Permit,
    Conditional,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PolicyOutcome {
    Deny { reason: Identifier },
    Permit,
    Conditional { reason: Identifier },
    Indeterminate { reason: Identifier },
}

impl PolicyOutcome {
    pub fn class(&self) -> OutcomeClass {
        match self {
            Self::Deny { .. } => OutcomeClass::Deny,
            Self::Permit => OutcomeClass::Permit,
            Self::Conditional { .. } => OutcomeClass::Conditional,
            Self::Indeterminate { .. } => OutcomeClass::Indeterminate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ActiveEffectIntent {
    MaterializeCredential {
        credential_slot_sha256: Sha256Digest,
        destination: Identifier,
    },
    RequireGmailPriorSearchProof {
        route_sha256: Sha256Digest,
        gmail_user_sha256: Sha256Digest,
        message_id_sha256: Sha256Digest,
        maximum_age_days: u64,
    },
    ResolveGmailMetadataFanout {
        route_sha256: Sha256Digest,
        maximum_age_days: u64,
        maximum_messages: u64,
    },
    ResolveCredentialVersion {
        credential_slot_sha256: Sha256Digest,
        credential_claim_sha256: Sha256Digest,
    },
    RefreshOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    ExchangeOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    MintOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    AcquireCredentialLease {
        credential_slot_sha256: Sha256Digest,
        lease_policy_sha256: Sha256Digest,
    },
    DecryptCredential {
        credential_slot_sha256: Sha256Digest,
        decryption_context_sha256: Sha256Digest,
    },
    InjectCredential {
        credential_slot_sha256: Sha256Digest,
        injection_commitment_sha256: Sha256Digest,
    },
    BindIdempotencyKey {
        idempotency_commitment_sha256: Sha256Digest,
    },
    ResolveRecoveryState {
        recovery_commitment_sha256: Sha256Digest,
    },
    RequireJitApproval {
        approval_policy_sha256: Sha256Digest,
    },
    ReserveQuota {
        counter_sha256: Sha256Digest,
        claim_sha256: Sha256Digest,
        weighted_units: u64,
    },
    ReserveDurableBudget {
        budget_sha256: Sha256Digest,
        claim_sha256: Sha256Digest,
        weighted_units: u64,
    },
}

/// Candidate intents are descriptive evidence only. There is intentionally no
/// conversion to `ActiveEffectIntent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CandidateEffectIntent {
    WouldMaterializeCredential {
        credential_slot_sha256: Sha256Digest,
        destination: Identifier,
    },
    WouldRequireGmailPriorSearchProof {
        route_sha256: Sha256Digest,
        gmail_user_sha256: Sha256Digest,
        message_id_sha256: Sha256Digest,
        maximum_age_days: u64,
    },
    WouldUseActiveGmailMetadataEvidence {
        route_sha256: Sha256Digest,
        maximum_age_days: u64,
        maximum_messages: u64,
    },
    WouldResolveCredentialVersion {
        credential_slot_sha256: Sha256Digest,
        credential_claim_sha256: Sha256Digest,
    },
    WouldRefreshOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    WouldExchangeOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    WouldMintOauthCredential {
        credential_slot_sha256: Sha256Digest,
        oauth_authority_sha256: Sha256Digest,
    },
    WouldAcquireCredentialLease {
        credential_slot_sha256: Sha256Digest,
        lease_policy_sha256: Sha256Digest,
    },
    WouldDecryptCredential {
        credential_slot_sha256: Sha256Digest,
        decryption_context_sha256: Sha256Digest,
    },
    WouldInjectCredential {
        credential_slot_sha256: Sha256Digest,
        injection_commitment_sha256: Sha256Digest,
    },
    WouldBindIdempotencyKey {
        idempotency_commitment_sha256: Sha256Digest,
    },
    WouldResolveRecoveryState {
        recovery_commitment_sha256: Sha256Digest,
    },
    WouldRequireJitApproval {
        approval_policy_sha256: Sha256Digest,
    },
    WouldReserveQuota {
        counter_sha256: Sha256Digest,
        claim_sha256: Sha256Digest,
        weighted_units: u64,
    },
    WouldReserveDurableBudget {
        budget_sha256: Sha256Digest,
        claim_sha256: Sha256Digest,
        weighted_units: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivePolicyPlan {
    outcome: PolicyOutcome,
    request_rewrite_commitments: Vec<Sha256Digest>,
    response_validation_commitments: Vec<Sha256Digest>,
    effect_intents: Vec<ActiveEffectIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CandidatePolicyPlan {
    outcome: PolicyOutcome,
    request_rewrite_commitments: Vec<Sha256Digest>,
    response_validation_commitments: Vec<Sha256Digest>,
    effect_intents: Vec<CandidateEffectIntent>,
    evaluation_purpose: String,
    effect_capabilities_available: bool,
    effect_intents_executed: bool,
}

impl ActivePolicyPlan {
    pub fn new(
        outcome: PolicyOutcome,
        request_rewrite_commitments: Vec<Sha256Digest>,
        response_validation_commitments: Vec<Sha256Digest>,
        effect_intents: Vec<ActiveEffectIntent>,
    ) -> Result<Self, ShadowError> {
        let plan = Self {
            outcome,
            request_rewrite_commitments,
            response_validation_commitments,
            effect_intents,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), ShadowError> {
        validate_plan_lengths(
            &self.request_rewrite_commitments,
            &self.response_validation_commitments,
            self.effect_intents.len(),
        )?;
        reject_digest_duplicates(
            &self.request_rewrite_commitments,
            "active_plan.request_rewrites",
        )?;
        reject_digest_duplicates(
            &self.response_validation_commitments,
            "active_plan.response_validations",
        )?;
        for effect in &self.effect_intents {
            match effect {
                ActiveEffectIntent::ReserveQuota { weighted_units, .. }
                | ActiveEffectIntent::ReserveDurableBudget {
                    weighted_units, ..
                } => {
                    validate_positive(
                        *weighted_units,
                        "active_plan.effect.weighted_units",
                    )?
                }
                ActiveEffectIntent::RequireGmailPriorSearchProof {
                    maximum_age_days,
                    ..
                } => validate_positive(
                    *maximum_age_days,
                    "active_plan.effect.maximum_age_days",
                )?,
                ActiveEffectIntent::ResolveGmailMetadataFanout {
                    maximum_age_days,
                    maximum_messages,
                    ..
                } => {
                    validate_positive(
                        *maximum_age_days,
                        "active_plan.effect.maximum_age_days",
                    )?;
                    validate_positive(
                        *maximum_messages,
                        "active_plan.effect.maximum_messages",
                    )?;
                }
                _ => {}
            }
        }
        let has_condition = self.effect_intents.iter().any(|effect| {
            matches!(
                effect,
                ActiveEffectIntent::ResolveCredentialVersion { .. }
                    | ActiveEffectIntent::RefreshOauthCredential { .. }
                    | ActiveEffectIntent::ExchangeOauthCredential { .. }
                    | ActiveEffectIntent::MintOauthCredential { .. }
                    | ActiveEffectIntent::ResolveRecoveryState { .. }
                    | ActiveEffectIntent::RequireGmailPriorSearchProof { .. }
                    | ActiveEffectIntent::ResolveGmailMetadataFanout { .. }
                    | ActiveEffectIntent::RequireJitApproval { .. }
                    | ActiveEffectIntent::ReserveQuota { .. }
                    | ActiveEffectIntent::ReserveDurableBudget { .. }
            )
        });
        if (matches!(&self.outcome, PolicyOutcome::Conditional { .. }) && !has_condition)
            || (matches!(&self.outcome, PolicyOutcome::Permit) && has_condition)
        {
            return Err(invalid("active_plan", "outcome/effect mismatch"));
        }
        if matches!(
            &self.outcome,
            PolicyOutcome::Deny { .. } | PolicyOutcome::Indeterminate { .. }
        ) && (!self.request_rewrite_commitments.is_empty()
            || !self.response_validation_commitments.is_empty()
            || !self.effect_intents.is_empty())
        {
            return Err(invalid("active_plan", "non-dispatchable plan has intents"));
        }
        Ok(())
    }

    pub fn outcome(&self) -> &PolicyOutcome {
        &self.outcome
    }

    pub fn request_rewrite_commitments(&self) -> &[Sha256Digest] {
        &self.request_rewrite_commitments
    }

    pub fn response_validation_commitments(&self) -> &[Sha256Digest] {
        &self.response_validation_commitments
    }

    pub fn effect_intents(&self) -> &[ActiveEffectIntent] {
        &self.effect_intents
    }

    pub(crate) fn effect_intents_commitment(
        &self,
    ) -> Result<Sha256Digest, ShadowError> {
        self.validate()?;
        Ok(hash_domain_frames(
            b"serverware.activeEffectIntents/v1",
            &[&canonical_json_bytes(&self.effect_intents)?],
        ))
    }

    pub fn semantic_commitment(&self) -> Result<Sha256Digest, ShadowError> {
        self.validate()?;
        let canonical = canonical_json_bytes(self)?;
        Ok(hash_domain_frames(
            b"serverware.activePolicyPlan/v1",
            &[canonical.as_slice()],
        ))
    }
}

impl CandidatePolicyPlan {
    pub fn new_shadow_only(
        outcome: PolicyOutcome,
        request_rewrite_commitments: Vec<Sha256Digest>,
        response_validation_commitments: Vec<Sha256Digest>,
        effect_intents: Vec<CandidateEffectIntent>,
    ) -> Result<Self, ShadowError> {
        let plan = Self {
            outcome,
            request_rewrite_commitments,
            response_validation_commitments,
            effect_intents,
            evaluation_purpose: "candidate-shadow".to_string(),
            effect_capabilities_available: false,
            effect_intents_executed: false,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), ShadowError> {
        validate_plan_lengths(
            &self.request_rewrite_commitments,
            &self.response_validation_commitments,
            self.effect_intents.len(),
        )?;
        reject_digest_duplicates(
            &self.request_rewrite_commitments,
            "candidate_plan.request_rewrites",
        )?;
        reject_digest_duplicates(
            &self.response_validation_commitments,
            "candidate_plan.response_validations",
        )?;
        for effect in &self.effect_intents {
            match effect {
                CandidateEffectIntent::WouldReserveQuota {
                    weighted_units, ..
                }
                | CandidateEffectIntent::WouldReserveDurableBudget {
                    weighted_units, ..
                } => {
                    validate_positive(
                        *weighted_units,
                        "candidate_plan.effect.weighted_units",
                    )?
                }
                CandidateEffectIntent::WouldRequireGmailPriorSearchProof {
                    maximum_age_days,
                    ..
                } => validate_positive(
                    *maximum_age_days,
                    "candidate_plan.effect.maximum_age_days",
                )?,
                CandidateEffectIntent::WouldUseActiveGmailMetadataEvidence {
                    maximum_age_days,
                    maximum_messages,
                    ..
                } => {
                    validate_positive(
                        *maximum_age_days,
                        "candidate_plan.effect.maximum_age_days",
                    )?;
                    validate_positive(
                        *maximum_messages,
                        "candidate_plan.effect.maximum_messages",
                    )?;
                }
                _ => {}
            }
        }
        let has_condition = self.effect_intents.iter().any(|effect| {
            matches!(
                effect,
                CandidateEffectIntent::WouldResolveCredentialVersion { .. }
                    | CandidateEffectIntent::WouldRefreshOauthCredential { .. }
                    | CandidateEffectIntent::WouldExchangeOauthCredential { .. }
                    | CandidateEffectIntent::WouldMintOauthCredential { .. }
                    | CandidateEffectIntent::WouldResolveRecoveryState { .. }
                    | CandidateEffectIntent::WouldRequireGmailPriorSearchProof { .. }
                    | CandidateEffectIntent::WouldUseActiveGmailMetadataEvidence { .. }
                    | CandidateEffectIntent::WouldRequireJitApproval { .. }
                    | CandidateEffectIntent::WouldReserveQuota { .. }
                    | CandidateEffectIntent::WouldReserveDurableBudget { .. }
            )
        });
        if (matches!(&self.outcome, PolicyOutcome::Conditional { .. }) && !has_condition)
            || (matches!(&self.outcome, PolicyOutcome::Permit) && has_condition)
        {
            return Err(invalid("candidate_plan", "outcome/effect mismatch"));
        }
        if self.evaluation_purpose != "candidate-shadow"
            || self.effect_capabilities_available
            || self.effect_intents_executed
        {
            return Err(ShadowError::CandidateCapabilityExposure);
        }
        if matches!(
            &self.outcome,
            PolicyOutcome::Deny { .. } | PolicyOutcome::Indeterminate { .. }
        ) && (!self.request_rewrite_commitments.is_empty()
            || !self.response_validation_commitments.is_empty()
            || !self.effect_intents.is_empty())
        {
            return Err(invalid(
                "candidate_plan",
                "non-dispatchable plan has intents",
            ));
        }
        Ok(())
    }

    pub fn outcome(&self) -> &PolicyOutcome {
        &self.outcome
    }

    pub fn request_rewrite_commitments(&self) -> &[Sha256Digest] {
        &self.request_rewrite_commitments
    }

    pub fn response_validation_commitments(&self) -> &[Sha256Digest] {
        &self.response_validation_commitments
    }

    pub fn effect_intents(&self) -> &[CandidateEffectIntent] {
        &self.effect_intents
    }

    pub fn semantic_commitment(&self) -> Result<Sha256Digest, ShadowError> {
        self.validate()?;
        let canonical = canonical_json_bytes(self)?;
        Ok(hash_domain_frames(
            b"serverware.candidatePolicyPlan/v1",
            &[canonical.as_slice()],
        ))
    }
}

/// A pure policy-core analysis product. It owns already separated active and
/// candidate representations and can only be consumed into both plan types.
/// No `CandidatePolicyPlan -> ActivePolicyPlan` conversion exists.
pub(crate) struct ValidatedPolicyAnalysis {
    active_plan: ActivePolicyPlan,
    candidate_plan: CandidatePolicyPlan,
}

impl ValidatedPolicyAnalysis {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_outcome: PolicyOutcome,
        active_request_rewrite_commitments: Vec<Sha256Digest>,
        active_response_validation_commitments: Vec<Sha256Digest>,
        active_effect_intents: Vec<ActiveEffectIntent>,
        candidate_outcome: PolicyOutcome,
        candidate_request_rewrite_commitments: Vec<Sha256Digest>,
        candidate_response_validation_commitments: Vec<Sha256Digest>,
        candidate_effect_intents: Vec<CandidateEffectIntent>,
    ) -> Result<Self, ShadowError> {
        Ok(Self {
            active_plan: ActivePolicyPlan::new(
                active_outcome,
                active_request_rewrite_commitments,
                active_response_validation_commitments,
                active_effect_intents,
            )?,
            candidate_plan: CandidatePolicyPlan::new_shadow_only(
                candidate_outcome,
                candidate_request_rewrite_commitments,
                candidate_response_validation_commitments,
                candidate_effect_intents,
            )?,
        })
    }

    pub fn into_separate_plans(self) -> (ActivePolicyPlan, CandidatePolicyPlan) {
        (self.active_plan, self.candidate_plan)
    }
}

fn validate_plan_lengths(
    rewrites: &[Sha256Digest],
    validations: &[Sha256Digest],
    effects: usize,
) -> Result<(), ShadowError> {
    validate_len("plan.rewrites", rewrites.len(), 0, MAX_PLAN_ITEMS)?;
    validate_len("plan.validations", validations.len(), 0, MAX_PLAN_ITEMS)?;
    validate_len("plan.effects", effects, 0, MAX_PLAN_ITEMS)
}

fn reject_digest_duplicates(
    values: &[Sha256Digest],
    field: &'static str,
) -> Result<(), ShadowError> {
    let unique: BTreeSet<&Sha256Digest> = values.iter().collect();
    if unique.len() != values.len() {
        return Err(invalid(field, "duplicates are forbidden"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EvaluationSummary {
    outcome: OutcomeClass,
    policy_plan: ActivePolicyPlan,
    policy_plan_sha256: Sha256Digest,
    reason_set_sha256: Sha256Digest,
    obligations_sha256: Sha256Digest,
    effect_intents_sha256: Sha256Digest,
    dispatch_commitment_sha256: Sha256Digest,
    effect_requirements: ActiveEffectRequirements,
    evaluation_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CandidateEvaluationSummary {
    outcome: OutcomeClass,
    policy_plan_sha256: Sha256Digest,
    reason_set_sha256: Sha256Digest,
    obligations_sha256: Sha256Digest,
    effect_intents_sha256: Sha256Digest,
    dispatch_commitment_sha256: Sha256Digest,
    evaluation_nanos: u64,
    evaluation_purpose: String,
    effect_capabilities_available: bool,
    effect_intents_executed: bool,
}

impl EvaluationSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_plan: &ActivePolicyPlan,
        policy_plan_sha256: Sha256Digest,
        reason_set_sha256: Sha256Digest,
        obligations_sha256: Sha256Digest,
        effect_intents_sha256: Sha256Digest,
        dispatch_commitment_sha256: Sha256Digest,
        evaluation_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_unsigned(evaluation_nanos, "evaluation_nanos")?;
        active_plan.validate()?;
        if active_plan.semantic_commitment()? != policy_plan_sha256
            || active_plan.effect_intents_commitment()?
                != effect_intents_sha256
        {
            return Err(ShadowError::ActiveDecisionEvidenceMismatch);
        }
        Ok(Self {
            outcome: active_plan.outcome().class(),
            policy_plan: active_plan.clone(),
            policy_plan_sha256,
            reason_set_sha256,
            obligations_sha256,
            effect_intents_sha256,
            dispatch_commitment_sha256,
            effect_requirements: ActiveEffectRequirements::from_plan(active_plan),
            evaluation_nanos,
        })
    }

    pub fn outcome(&self) -> OutcomeClass {
        self.outcome
    }

    pub fn policy_plan_sha256(&self) -> &Sha256Digest {
        &self.policy_plan_sha256
    }

    pub(crate) fn policy_plan(&self) -> &ActivePolicyPlan {
        &self.policy_plan
    }

    pub fn dispatch_commitment_sha256(&self) -> &Sha256Digest {
        &self.dispatch_commitment_sha256
    }

    pub fn evaluation_nanos(&self) -> u64 {
        self.evaluation_nanos
    }

    pub(crate) fn effect_requirements(&self) -> &ActiveEffectRequirements {
        &self.effect_requirements
    }
}

impl CandidateEvaluationSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new_shadow_only(
        outcome: OutcomeClass,
        policy_plan_sha256: Sha256Digest,
        reason_set_sha256: Sha256Digest,
        obligations_sha256: Sha256Digest,
        effect_intents_sha256: Sha256Digest,
        dispatch_commitment_sha256: Sha256Digest,
        evaluation_nanos: u64,
    ) -> Result<Self, ShadowError> {
        validate_unsigned(evaluation_nanos, "candidate_evaluation_nanos")?;
        Ok(Self {
            outcome,
            policy_plan_sha256,
            reason_set_sha256,
            obligations_sha256,
            effect_intents_sha256,
            dispatch_commitment_sha256,
            evaluation_nanos,
            evaluation_purpose: "candidate-shadow".to_string(),
            effect_capabilities_available: false,
            effect_intents_executed: false,
        })
    }

    pub fn outcome(&self) -> OutcomeClass {
        self.outcome
    }

    pub fn policy_plan_sha256(&self) -> &Sha256Digest {
        &self.policy_plan_sha256
    }

    pub fn dispatch_commitment_sha256(&self) -> &Sha256Digest {
        &self.dispatch_commitment_sha256
    }

    pub fn evaluation_nanos(&self) -> u64 {
        self.evaluation_nanos
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RequestAuthorityClass {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SemanticExpansionCell {
    cell_sha256: Sha256Digest,
    authority_expansion: AuthorityExpansionCell,
    route_sha256: Sha256Digest,
    operation: OperationClass,
    compiled_semantic_profile_sha256: Sha256Digest,
    request_authority_class: RequestAuthorityClass,
    active_outcome: OutcomeClass,
    candidate_outcome: OutcomeClass,
    route_authority_root_sha256: Sha256Digest,
    operation_authority_root_sha256: Sha256Digest,
    pilot_principal_set_root_sha256: Sha256Digest,
    pilot_route_set_root_sha256: Sha256Digest,
    maximum_requests: u64,
    maximum_write_requests: u64,
}

impl SemanticExpansionCell {
    fn validate(&self) -> Result<(), ShadowError> {
        let derived_authority_class = match self.operation {
            OperationClass::Read | OperationClass::Search => {
                RequestAuthorityClass::Read
            }
            OperationClass::Write
            | OperationClass::Publish
            | OperationClass::Delete
            | OperationClass::Administrative => {
                RequestAuthorityClass::Write
            }
        };
        if self.request_authority_class != derived_authority_class
            || (self.authority_expansion
                == AuthorityExpansionCell::WriteMethodEnabled
                && derived_authority_class != RequestAuthorityClass::Write)
        {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        let transition_matches = match self.authority_expansion {
            AuthorityExpansionCell::ActiveDenyToConditional => {
                self.active_outcome == OutcomeClass::Deny
                    && self.candidate_outcome == OutcomeClass::Conditional
            }
            AuthorityExpansionCell::ActiveDenyToPermit => {
                self.active_outcome == OutcomeClass::Deny
                    && self.candidate_outcome == OutcomeClass::Permit
            }
            AuthorityExpansionCell::ActiveConditionalToPermit => {
                self.active_outcome == OutcomeClass::Conditional
                    && self.candidate_outcome == OutcomeClass::Permit
            }
            AuthorityExpansionCell::ActiveIndeterminateToConditional => {
                self.active_outcome == OutcomeClass::Indeterminate
                    && self.candidate_outcome == OutcomeClass::Conditional
            }
            AuthorityExpansionCell::ActiveIndeterminateToPermit => {
                self.active_outcome == OutcomeClass::Indeterminate
                    && self.candidate_outcome == OutcomeClass::Permit
            }
            AuthorityExpansionCell::EndpointAdded => {
                matches!(
                    self.active_outcome,
                    OutcomeClass::Deny | OutcomeClass::Indeterminate
                ) && matches!(
                    self.candidate_outcome,
                    OutcomeClass::Conditional | OutcomeClass::Permit
                )
            }
            AuthorityExpansionCell::CredentialScopeAdded
            | AuthorityExpansionCell::WriteMethodEnabled
            | AuthorityExpansionCell::QuotaIncreased
            | AuthorityExpansionCell::BudgetIncreased
            | AuthorityExpansionCell::ResponseFieldExposureAdded
            | AuthorityExpansionCell::ResponseValidationRelaxed
            | AuthorityExpansionCell::ResponseFilterReduced
            | AuthorityExpansionCell::OtherCompilerDeclared => {
                matches!(
                    self.candidate_outcome,
                    OutcomeClass::Conditional | OutcomeClass::Permit
                ) && !matches!(self.active_outcome, OutcomeClass::Indeterminate)
            }
        };
        if !transition_matches {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        validate_positive(
            self.maximum_requests,
            "semantic_expansion_cell.maximum_requests",
        )?;
        validate_unsigned(
            self.maximum_write_requests,
            "semantic_expansion_cell.maximum_write_requests",
        )?;
        if self.maximum_write_requests > self.maximum_requests
            || (self.request_authority_class == RequestAuthorityClass::Read
                && self.maximum_write_requests != 0)
        {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        let expected = hash_domain_frames(
            b"serverware.policySemanticExpansionCell/v1",
            &[&canonical_json_bytes(&(
                &self.route_sha256,
                self.operation,
                self.authority_expansion,
                &self.compiled_semantic_profile_sha256,
                self.request_authority_class,
                self.active_outcome,
                self.candidate_outcome,
                &self.route_authority_root_sha256,
                &self.operation_authority_root_sha256,
                &self.pilot_principal_set_root_sha256,
                &self.pilot_route_set_root_sha256,
                self.maximum_requests,
                self.maximum_write_requests,
            ))?],
        );
        if expected != self.cell_sha256 {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveDecisionReceiptPayload {
    receipt_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    generation_id: Sha256Digest,
    ingress_evidence_sha256: Sha256Digest,
    ingress_sequence: u64,
    captured_at_unix_nanos: i64,
    decision_at_unix_nanos: i64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    dispatch_barrier_receipt_sha256: Option<Sha256Digest>,
    terminal_spill_receipt_sha256: Sha256Digest,
    result: ActiveDecisionResult,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FinalEnforcementOutcome {
    Allow,
    Deny,
    Conditional,
    Error,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActiveEffectRequirement {
    TrustFreshness,
    GmailPriorSearchProof,
    GmailMetadataFanout,
    JitGrant,
    QuotaReserve,
    QuotaTerminal,
    DurableBudgetReserve,
    DurableBudgetTerminal,
    CredentialVersion,
    CredentialLease,
    CredentialDecrypt,
    CredentialInjection,
    OauthRefresh,
    OauthExchange,
    OauthMint,
    IdempotencyBinding,
    RecoveryResolution,
    FinalRequest,
    DispatchAuthorization,
    DispatchTerminal,
    ResponseValidation,
    TerminalResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveEffectRequirements {
    requirements: Vec<ActiveEffectRequirement>,
}

impl ActiveEffectRequirements {
    pub(crate) fn from_plan(plan: &ActivePolicyPlan) -> Self {
        let mut requirements = BTreeSet::from([
            ActiveEffectRequirement::TrustFreshness,
            ActiveEffectRequirement::FinalRequest,
            ActiveEffectRequirement::TerminalResponse,
        ]);
        for intent in plan.effect_intents() {
            let required = match intent {
                ActiveEffectIntent::RequireGmailPriorSearchProof { .. } => {
                    &[ActiveEffectRequirement::GmailPriorSearchProof][..]
                }
                ActiveEffectIntent::ResolveGmailMetadataFanout { .. } => {
                    &[ActiveEffectRequirement::GmailMetadataFanout][..]
                }
                ActiveEffectIntent::RequireJitApproval { .. } => {
                    &[ActiveEffectRequirement::JitGrant][..]
                }
                ActiveEffectIntent::ReserveQuota { .. } => &[
                    ActiveEffectRequirement::QuotaReserve,
                    ActiveEffectRequirement::QuotaTerminal,
                ][..],
                ActiveEffectIntent::ReserveDurableBudget { .. } => &[
                    ActiveEffectRequirement::DurableBudgetReserve,
                    ActiveEffectRequirement::DurableBudgetTerminal,
                ][..],
                ActiveEffectIntent::ResolveCredentialVersion { .. } => {
                    &[ActiveEffectRequirement::CredentialVersion][..]
                }
                ActiveEffectIntent::MaterializeCredential { .. } => &[
                    ActiveEffectRequirement::CredentialLease,
                    ActiveEffectRequirement::CredentialDecrypt,
                    ActiveEffectRequirement::CredentialInjection,
                ][..],
                ActiveEffectIntent::AcquireCredentialLease { .. } => {
                    &[ActiveEffectRequirement::CredentialLease][..]
                }
                ActiveEffectIntent::DecryptCredential { .. } => {
                    &[ActiveEffectRequirement::CredentialDecrypt][..]
                }
                ActiveEffectIntent::InjectCredential { .. } => {
                    &[ActiveEffectRequirement::CredentialInjection][..]
                }
                ActiveEffectIntent::RefreshOauthCredential { .. } => {
                    &[ActiveEffectRequirement::OauthRefresh][..]
                }
                ActiveEffectIntent::ExchangeOauthCredential { .. } => {
                    &[ActiveEffectRequirement::OauthExchange][..]
                }
                ActiveEffectIntent::MintOauthCredential { .. } => {
                    &[ActiveEffectRequirement::OauthMint][..]
                }
                ActiveEffectIntent::BindIdempotencyKey { .. } => {
                    &[ActiveEffectRequirement::IdempotencyBinding][..]
                }
                ActiveEffectIntent::ResolveRecoveryState { .. } => {
                    &[ActiveEffectRequirement::RecoveryResolution][..]
                }
            };
            requirements.extend(required.iter().copied());
        }
        if matches!(
            plan.outcome(),
            PolicyOutcome::Permit | PolicyOutcome::Conditional { .. }
        ) {
            requirements.insert(ActiveEffectRequirement::DispatchAuthorization);
            requirements.insert(ActiveEffectRequirement::DispatchTerminal);
        }
        if !plan.response_validation_commitments().is_empty() {
            requirements.insert(ActiveEffectRequirement::ResponseValidation);
        }
        Self {
            requirements: requirements.into_iter().collect(),
        }
    }

    pub(crate) fn requires(&self, requirement: ActiveEffectRequirement) -> bool {
        self.requirements.binary_search(&requirement).is_ok()
    }

    pub(crate) fn as_slice(&self) -> &[ActiveEffectRequirement] {
        &self.requirements
    }

    pub(crate) fn gmail_prior_search_proof(&self) -> bool {
        self.requires(ActiveEffectRequirement::GmailPriorSearchProof)
    }

    pub(crate) fn jit_grant(&self) -> bool {
        self.requires(ActiveEffectRequirement::JitGrant)
    }

    pub(crate) fn quota_reservation(&self) -> bool {
        self.requires(ActiveEffectRequirement::QuotaReserve)
    }

    pub(crate) fn durable_budget_reservation(&self) -> bool {
        self.requires(ActiveEffectRequirement::DurableBudgetReserve)
    }

    pub(crate) fn credential_materialization(&self) -> bool {
        self.requires(ActiveEffectRequirement::CredentialLease)
            || self.requires(ActiveEffectRequirement::CredentialDecrypt)
            || self.requires(ActiveEffectRequirement::CredentialInjection)
    }

    pub(crate) fn upstream_dispatch(&self) -> bool {
        self.requires(ActiveEffectRequirement::DispatchTerminal)
    }

    pub(crate) fn response_validation(&self) -> bool {
        self.requires(ActiveEffectRequirement::ResponseValidation)
    }

    pub(crate) fn gmail_metadata_fanout(&self) -> bool {
        self.requires(ActiveEffectRequirement::GmailMetadataFanout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActiveEffectTerminalState {
    Completed,
    Denied,
    Failed,
    Cancelled,
    ProviderOutcomeUnknown,
    RecoveryRequired,
    NotReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveEffectTerminalEvidence {
    requirement: ActiveEffectRequirement,
    terminal_state: ActiveEffectTerminalState,
    result_sha256: Sha256Digest,
}

impl ActiveEffectTerminalEvidence {
    pub(crate) fn from_active_executor(
        requirement: ActiveEffectRequirement,
        terminal_state: ActiveEffectTerminalState,
        result_sha256: Sha256Digest,
    ) -> Self {
        Self {
            requirement,
            terminal_state,
            result_sha256,
        }
    }

    pub(crate) fn requirement(&self) -> ActiveEffectRequirement {
        self.requirement
    }

    pub(crate) fn terminal_state(&self) -> ActiveEffectTerminalState {
        self.terminal_state
    }

    pub(crate) fn result_sha256(&self) -> &Sha256Digest {
        &self.result_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActiveEffectResolutionSummary {
    finalization_binding_sha256: Sha256Digest,
    resolved_effect_intents_sha256: Sha256Digest,
    effect_requirements: ActiveEffectRequirements,
    terminal_evidence: Vec<ActiveEffectTerminalEvidence>,
    effect_result_commitments_root_sha256: Sha256Digest,
    final_outcome: FinalEnforcementOutcome,
    returned_http_status: u16,
    upstream_dispatch_authorized: bool,
    finalized_at_unix_nanos: i64,
}

/// A request-plan result has no evidence authority until every effect owned by
/// the active path has reached an authoritative terminal state. This type is
/// deliberately neither serializable nor an `EnvelopePayload`.
pub(crate) struct ProvisionalActiveDecisionReceipt {
    receipt_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    generation_id: Sha256Digest,
    ingress_evidence_sha256: Sha256Digest,
    ingress_sequence: u64,
    captured_at_unix_nanos: i64,
    planned_evaluation: EvaluationSummary,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl ProvisionalActiveDecisionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        receipt_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        authority_key_independence_sha256: Sha256Digest,
        policy_authority_analysis_sha256: Sha256Digest,
        policy_authority_analysis_payload_sha256: Sha256Digest,
        custody_receipt_evidence_requirements_sha256: Sha256Digest,
        load_receipt_sha256: Sha256Digest,
        load_receipt_payload_sha256: Sha256Digest,
        canary_id: Sha256Digest,
        policy_identity: PolicyIdentity,
        runtime_identity: RuntimeIdentity,
        generation_id: Sha256Digest,
        ingress_evidence_sha256: Sha256Digest,
        ingress_sequence: u64,
        captured_at_unix_nanos: i64,
        planned_evaluation: EvaluationSummary,
        issued_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        validate_positive(assignment_revision, "active_decision.assignment_revision")?;
        validate_positive(ingress_sequence, "active_decision.ingress_sequence")?;
        policy_identity.validate()?;
        if expires_at_unix_nanos <= issued_at_unix_nanos {
            return Err(ShadowError::ActiveDecisionEvidenceMismatch);
        }
        Ok(Self {
            receipt_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            authority_key_independence_sha256,
            policy_authority_analysis_sha256,
            policy_authority_analysis_payload_sha256,
            custody_receipt_evidence_requirements_sha256,
            load_receipt_sha256,
            load_receipt_payload_sha256,
            canary_id,
            policy_identity,
            runtime_identity,
            generation_id,
            ingress_evidence_sha256,
            ingress_sequence,
            captured_at_unix_nanos,
            planned_evaluation,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
        })
    }

    /// The caller must hold the crate-private active-effect completion token
    /// emitted after Gmail proof, JIT, quota, credential, and dispatch checks.
    pub(crate) fn finalization_binding_sha256(
        &self,
    ) -> Result<Sha256Digest, ShadowError> {
        active_finalization_binding_sha256(
            &self.assignment_sha256,
            &self.assignment_payload_sha256,
            self.assignment_revision,
            &self.authority_key_independence_sha256,
            &self.policy_authority_analysis_sha256,
            &self.policy_authority_analysis_payload_sha256,
            &self.custody_receipt_evidence_requirements_sha256,
            &self.load_receipt_sha256,
            &self.load_receipt_payload_sha256,
            &self.canary_id,
            &self.policy_identity,
            &self.runtime_identity,
            &self.generation_id,
            &self.ingress_evidence_sha256,
            self.ingress_sequence,
            self.captured_at_unix_nanos,
            &self.planned_evaluation,
        )
    }

    pub(crate) fn finalize(
        self,
        completion: FinalizedActiveEffects,
    ) -> Result<ActiveDecisionReceiptPayload, ShadowError> {
        if completion.summary.finalized_at_unix_nanos < self.issued_at_unix_nanos
            || completion.summary.finalized_at_unix_nanos >= self.expires_at_unix_nanos
            || completion.summary.resolved_effect_intents_sha256
                != self.planned_evaluation.effect_intents_sha256
            || completion.summary.effect_requirements
                != self.planned_evaluation.effect_requirements
            || completion.summary.finalization_binding_sha256
                != self.finalization_binding_sha256()?
            || completion.summary.finalized_at_unix_nanos < self.captured_at_unix_nanos
        {
            return Err(ShadowError::ActiveDecisionEvidenceMismatch);
        }
        let payload = ActiveDecisionReceiptPayload {
            receipt_id: self.receipt_id,
            assignment_sha256: self.assignment_sha256,
            assignment_payload_sha256: self.assignment_payload_sha256,
            assignment_revision: self.assignment_revision,
            authority_key_independence_sha256:
                self.authority_key_independence_sha256,
            policy_authority_analysis_sha256:
                self.policy_authority_analysis_sha256,
            policy_authority_analysis_payload_sha256:
                self.policy_authority_analysis_payload_sha256,
            custody_receipt_evidence_requirements_sha256:
                self.custody_receipt_evidence_requirements_sha256,
            load_receipt_sha256: self.load_receipt_sha256,
            load_receipt_payload_sha256: self.load_receipt_payload_sha256,
            canary_id: self.canary_id,
            policy_identity: self.policy_identity,
            runtime_identity: self.runtime_identity,
            generation_id: self.generation_id,
            ingress_evidence_sha256: self.ingress_evidence_sha256,
            ingress_sequence: self.ingress_sequence,
            captured_at_unix_nanos: self.captured_at_unix_nanos,
            decision_at_unix_nanos: completion.summary.finalized_at_unix_nanos,
            dispatch_barrier_receipt_sha256: completion
                .dispatch_barrier_receipt_sha256,
            terminal_spill_receipt_sha256: completion
                .terminal_spill_receipt_sha256,
            result: ActiveDecisionResult::Finalized {
                pure_active_evaluation: self.planned_evaluation,
                effect_resolution: completion.summary,
            },
            issued_at_unix_nanos: self.issued_at_unix_nanos,
            expires_at_unix_nanos: self.expires_at_unix_nanos,
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }
}

/// Non-deserializable proof that the active path, not the pure planner, resolved
/// all effects. Constructors stay in the crate so wire callers cannot mint it.
pub(crate) struct FinalizedActiveEffects {
    summary: ActiveEffectResolutionSummary,
    dispatch_barrier_receipt_sha256: Option<Sha256Digest>,
    terminal_spill_receipt_sha256: Sha256Digest,
}

impl FinalizedActiveEffects {
    pub(crate) fn from_authoritative_completion(
        finalization_binding_sha256: Sha256Digest,
        resolved_effect_intents_sha256: Sha256Digest,
        active_plan: &ActivePolicyPlan,
        terminal_evidence: Vec<ActiveEffectTerminalEvidence>,
        effect_result_commitments_root_sha256: Sha256Digest,
        final_outcome: FinalEnforcementOutcome,
        returned_http_status: u16,
        upstream_dispatch_authorized: bool,
        dispatch_barrier_receipt_sha256: Option<Sha256Digest>,
        terminal_spill_receipt_sha256: Sha256Digest,
        finalized_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        active_plan.validate()?;
        let effect_requirements = ActiveEffectRequirements::from_plan(active_plan);
        validate_len(
            "active_effects.terminal_evidence",
            terminal_evidence.len(),
            1,
            MAX_PLAN_ITEMS,
        )?;
        let observed_requirements = terminal_evidence
            .iter()
            .map(|evidence| evidence.requirement)
            .collect::<Vec<_>>();
        if observed_requirements != effect_requirements.requirements
            || observed_requirements.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ShadowError::ActiveEnforcementEvidenceMismatch);
        }
        let effect_leaves = terminal_evidence
            .iter()
            .enumerate()
            .map(|(index, evidence)| {
                Ok((
                    u64::try_from(index + 1)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                    Sha256Digest::compute(&canonical_json_bytes(evidence)?),
                ))
            })
            .collect::<Result<Vec<_>, ShadowError>>()?;
        if merkle_root(&effect_leaves)? != effect_result_commitments_root_sha256 {
            return Err(ShadowError::ActiveEnforcementEvidenceMismatch);
        }
        let terminal_state = |requirement| {
            terminal_evidence
                .iter()
                .find(|evidence| evidence.requirement == requirement)
                .map(|evidence| evidence.terminal_state)
        };
        let outcome_consistent = (200..=599).contains(&returned_http_status)
            && !matches!(
                terminal_state(ActiveEffectRequirement::TrustFreshness),
                Some(ActiveEffectTerminalState::NotReached)
            )
            && !matches!(
                terminal_state(ActiveEffectRequirement::FinalRequest),
                Some(ActiveEffectTerminalState::NotReached)
            )
            && !matches!(
                terminal_state(ActiveEffectRequirement::TerminalResponse),
                Some(ActiveEffectTerminalState::NotReached)
            )
            && (!matches!(final_outcome, FinalEnforcementOutcome::Allow)
                || (upstream_dispatch_authorized
                    && terminal_evidence.iter().all(|evidence| {
                        evidence.terminal_state
                            == ActiveEffectTerminalState::Completed
                    })
                    && terminal_state(ActiveEffectRequirement::DispatchTerminal)
                        == Some(ActiveEffectTerminalState::Completed)
                    && (!effect_requirements
                        .requires(ActiveEffectRequirement::ResponseValidation)
                        || terminal_state(ActiveEffectRequirement::ResponseValidation)
                            == Some(ActiveEffectTerminalState::Completed))));
        if !outcome_consistent
            || upstream_dispatch_authorized
                != dispatch_barrier_receipt_sha256.is_some()
        {
            return Err(ShadowError::ActiveEnforcementEvidenceMismatch);
        }
        Ok(Self {
            summary: ActiveEffectResolutionSummary {
                finalization_binding_sha256,
                resolved_effect_intents_sha256,
                effect_requirements,
                terminal_evidence,
                effect_result_commitments_root_sha256,
                final_outcome,
                returned_http_status,
                upstream_dispatch_authorized,
                finalized_at_unix_nanos,
            },
            dispatch_barrier_receipt_sha256,
            terminal_spill_receipt_sha256,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn active_finalization_binding_sha256(
    assignment_sha256: &Sha256Digest,
    assignment_payload_sha256: &Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: &Sha256Digest,
    policy_authority_analysis_sha256: &Sha256Digest,
    policy_authority_analysis_payload_sha256: &Sha256Digest,
    custody_receipt_evidence_requirements_sha256: &Sha256Digest,
    load_receipt_sha256: &Sha256Digest,
    load_receipt_payload_sha256: &Sha256Digest,
    canary_id: &Sha256Digest,
    policy_identity: &PolicyIdentity,
    runtime_identity: &RuntimeIdentity,
    generation_id: &Sha256Digest,
    ingress_evidence_sha256: &Sha256Digest,
    ingress_sequence: u64,
    captured_at_unix_nanos: i64,
    pure_active_evaluation: &EvaluationSummary,
) -> Result<Sha256Digest, ShadowError> {
    Ok(hash_domain_frames(
        b"serverware.policyShadowActiveFinalizationBinding/v1",
        &[&canonical_json_bytes(&serde_json::json!([
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            authority_key_independence_sha256,
            policy_authority_analysis_sha256,
            policy_authority_analysis_payload_sha256,
            custody_receipt_evidence_requirements_sha256,
            load_receipt_sha256,
            load_receipt_payload_sha256,
            canary_id,
            policy_identity,
            runtime_identity,
            generation_id,
            ingress_evidence_sha256,
            ingress_sequence,
            captured_at_unix_nanos,
            &pure_active_evaluation.policy_plan_sha256,
            &pure_active_evaluation.effect_intents_sha256,
            &pure_active_evaluation.dispatch_commitment_sha256,
        ]))?],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ActiveDecisionResult {
    Finalized {
        pure_active_evaluation: EvaluationSummary,
        effect_resolution: ActiveEffectResolutionSummary,
    },
    SampledOut {
        accounting_record_sha256: Sha256Digest,
    },
    CandidateDropped {
        pure_active_evaluation: EvaluationSummary,
        effect_resolution: ActiveEffectResolutionSummary,
        reason: DropReason,
        unavailable_marker_sha256: Sha256Digest,
    },
    TransportExcluded {
        accounting_record_sha256: Sha256Digest,
    },
    CaptureFailed {
        terminal_reason: PolicyShadowTerminalReason,
        unavailable_marker_sha256: Sha256Digest,
    },
    NotEvaluated {
        terminal_reason: PolicyShadowTerminalReason,
        unavailable_marker_sha256: Sha256Digest,
    },
}

impl ActiveDecisionResult {
    fn finalized_parts(
        &self,
    ) -> Option<(&EvaluationSummary, &ActiveEffectResolutionSummary)> {
        match self {
            Self::Finalized {
                pure_active_evaluation,
                effect_resolution,
            }
            | Self::CandidateDropped {
                pure_active_evaluation,
                effect_resolution,
                ..
            } => Some((pure_active_evaluation, effect_resolution)),
            _ => None,
        }
    }
}

impl EnvelopePayload for ActiveDecisionReceiptPayload {
    const API_VERSION: &'static str = ACTIVE_DECISION_DOMAIN;
    const KIND: &'static str = "PolicyShadowActiveDecision";
    const SIGNATURE_DOMAIN: &'static str = ACTIVE_DECISION_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "active_decision.assignment_revision")?;
        validate_positive(self.ingress_sequence, "active_decision.ingress_sequence")?;
        self.policy_identity.validate()?;
        if let Some((pure_active_evaluation, effect_resolution)) =
            self.result.finalized_parts()
        {
            pure_active_evaluation.policy_plan.validate()?;
            if pure_active_evaluation.policy_plan.semantic_commitment()?
                != pure_active_evaluation.policy_plan_sha256
                || pure_active_evaluation
                    .policy_plan
                    .effect_intents_commitment()?
                    != pure_active_evaluation.effect_intents_sha256
                || pure_active_evaluation.outcome
                    != pure_active_evaluation.policy_plan.outcome().class()
                || pure_active_evaluation.effect_requirements
                    != ActiveEffectRequirements::from_plan(
                        &pure_active_evaluation.policy_plan,
                    )
            {
                return Err(ShadowError::ActiveDecisionEvidenceMismatch);
            }
            validate_unsigned(
                pure_active_evaluation.evaluation_nanos,
                "active_decision.evaluation_nanos",
            )?;
            let effect_leaves = effect_resolution
                .terminal_evidence
                .iter()
                .enumerate()
                .map(|(index, evidence)| {
                    Ok((
                        u64::try_from(index + 1)
                            .map_err(|_| ShadowError::CounterOverflow)?,
                        Sha256Digest::compute(&canonical_json_bytes(evidence)?),
                    ))
                })
                .collect::<Result<Vec<_>, ShadowError>>()?;
            let requirements = &effect_resolution.effect_requirements;
            let observed_requirements = effect_resolution
                .terminal_evidence
                .iter()
                .map(|evidence| evidence.requirement)
                .collect::<Vec<_>>();
            let final_outcome_consistent =
                (200..=599).contains(&effect_resolution.returned_http_status)
                && (!matches!(
                    effect_resolution.final_outcome,
                    FinalEnforcementOutcome::Allow
                ) || effect_resolution.upstream_dispatch_authorized)
                && effect_resolution.effect_requirements
                    == pure_active_evaluation.effect_requirements;
            if !final_outcome_consistent
                || observed_requirements != requirements.requirements
                || observed_requirements.windows(2).any(|pair| pair[0] >= pair[1])
                || effect_resolution.finalization_binding_sha256
                    != active_finalization_binding_sha256(
                        &self.assignment_sha256,
                        &self.assignment_payload_sha256,
                        self.assignment_revision,
                        &self.authority_key_independence_sha256,
                        &self.policy_authority_analysis_sha256,
                        &self.policy_authority_analysis_payload_sha256,
                        &self.custody_receipt_evidence_requirements_sha256,
                        &self.load_receipt_sha256,
                        &self.load_receipt_payload_sha256,
                        &self.canary_id,
                        &self.policy_identity,
                        &self.runtime_identity,
                        &self.generation_id,
                        &self.ingress_evidence_sha256,
                        self.ingress_sequence,
                        self.captured_at_unix_nanos,
                        pure_active_evaluation,
                    )?
                || merkle_root(&effect_leaves)?
                    != effect_resolution.effect_result_commitments_root_sha256
                || effect_resolution.finalized_at_unix_nanos
                    != self.decision_at_unix_nanos
                || self.captured_at_unix_nanos > self.decision_at_unix_nanos
                || self.decision_at_unix_nanos < self.issued_at_unix_nanos
                || effect_resolution.finalized_at_unix_nanos >= self.expires_at_unix_nanos
                || effect_resolution.resolved_effect_intents_sha256
                    != pure_active_evaluation.effect_intents_sha256
                || effect_resolution.upstream_dispatch_authorized
                    != self.dispatch_barrier_receipt_sha256.is_some()
            {
                return Err(ShadowError::ActiveDecisionEvidenceMismatch);
            }
        }
        match &self.result {
            ActiveDecisionResult::CaptureFailed {
                terminal_reason,
                ..
            } => {
                if *terminal_reason
                    != PolicyShadowTerminalReason::FactsCaptureError
                {
                    return Err(ShadowError::ActiveDecisionEvidenceMismatch);
                }
            }
            ActiveDecisionResult::NotEvaluated {
                terminal_reason,
                ..
            } => {
                if !terminal_reason.is_active_not_evaluated() {
                    return Err(ShadowError::ActiveDecisionEvidenceMismatch);
                }
            }
            _ => {}
        }
        if self.expires_at_unix_nanos <= self.issued_at_unix_nanos
            || self.captured_at_unix_nanos > self.issued_at_unix_nanos
            || self.decision_at_unix_nanos < self.captured_at_unix_nanos
        {
            return Err(ShadowError::ActiveDecisionEvidenceMismatch);
        }
        Ok(())
    }
}

pub(crate) type VerifiedActiveDecision =
    VerifiedSignedEnvelope<ActiveDecisionReceiptPayload>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResponseComparisonClass {
    ComparableIdentical,
    ComparableValidationMatch,
    ComparableValidationDivergence,
    NotApplicableActiveNotDispatched,
    NotComparableCandidateNotDispatchable,
    NotComparableDispatchCommitmentMismatch,
    NotComparableActiveResponseUnavailable,
    NotComparableCandidateValidatorUnavailable,
    NotApplicableBothDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResponseCaptureMode {
    BoundedExact,
    StreamingUnavailable,
    NotDispatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PhysicalResponseFraming {
    NoBody,
    ContentLength,
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResponseValidationOutcome {
    Accepted,
    Rejected,
    Indeterminate,
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BoundResponseValidation {
    policy_snapshot_sha256: Sha256Digest,
    response_constraints_root_sha256: Sha256Digest,
    exact_response_commitment_sha256: Sha256Digest,
    outcome: ResponseValidationOutcome,
    validation_result_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResponseComparison {
    classification: ResponseComparisonClass,
    capture_mode: ResponseCaptureMode,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    upstream_status: Option<u16>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    exact_response_body_bytes: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    exact_response_body_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    physical_response_header_count: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    physical_response_headers_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    exact_response_commitment_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    active_validation: Option<BoundResponseValidation>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    candidate_validation: Option<BoundResponseValidation>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    unavailable_marker_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    transport_capture_receipt_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    runtime_attestation_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    peer_identity_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    physical_response_framing: Option<PhysicalResponseFraming>,
    response_proof_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "disposition",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ResponseObligationBinding {
    Applied {
        route_sha256: Sha256Digest,
        obligation_root_sha256: Sha256Digest,
        active_constraints_root_sha256: Sha256Digest,
        candidate_constraints_root_sha256: Sha256Digest,
        exact_response_commitment_sha256: Sha256Digest,
        applied_obligations_root_sha256: Sha256Digest,
    },
    NotApplicableActiveNotDispatched {
        route_sha256: Sha256Digest,
        obligation_root_sha256: Sha256Digest,
        active_outcome: OutcomeClass,
        candidate_outcome: OutcomeClass,
        not_applicable_sha256: Sha256Digest,
    },
}

impl ResponseObligationBinding {
    fn route_sha256(&self) -> &Sha256Digest {
        match self {
            Self::Applied { route_sha256, .. }
            | Self::NotApplicableActiveNotDispatched { route_sha256, .. } => {
                route_sha256
            }
        }
    }

    fn obligation_root_sha256(&self) -> &Sha256Digest {
        match self {
            Self::Applied {
                obligation_root_sha256,
                ..
            }
            | Self::NotApplicableActiveNotDispatched {
                obligation_root_sha256,
                ..
            } => obligation_root_sha256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MerkleSiblingSide {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MerkleProofStep {
    sibling_side: MerkleSiblingSide,
    sibling_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PilotMembershipEvidence {
    principal_leaf_sha256: Sha256Digest,
    principal_proof: Vec<MerkleProofStep>,
    route_leaf_sha256: Sha256Digest,
    route_proof: Vec<MerkleProofStep>,
}

impl ResponseComparison {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_bounded_exact(
        classification: ResponseComparisonClass,
        upstream_status: u16,
        exact_response_body_bytes: u64,
        exact_response_body_sha256: Sha256Digest,
        physical_response_header_count: u64,
        physical_response_headers_sha256: Sha256Digest,
        exact_response_commitment_sha256: Sha256Digest,
        active_validation: BoundResponseValidation,
        candidate_validation: BoundResponseValidation,
        transport_capture_receipt_sha256: Sha256Digest,
        runtime_attestation_sha256: Sha256Digest,
        peer_identity_sha256: Sha256Digest,
        physical_response_framing: PhysicalResponseFraming,
        response_proof_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        let comparison = Self {
            classification,
            capture_mode: ResponseCaptureMode::BoundedExact,
            upstream_status: Some(upstream_status),
            exact_response_body_bytes: Some(exact_response_body_bytes),
            exact_response_body_sha256: Some(exact_response_body_sha256),
            physical_response_header_count: Some(physical_response_header_count),
            physical_response_headers_sha256: Some(physical_response_headers_sha256),
            exact_response_commitment_sha256: Some(exact_response_commitment_sha256),
            active_validation: Some(active_validation),
            candidate_validation: Some(candidate_validation),
            unavailable_marker_sha256: None,
            transport_capture_receipt_sha256:
                Some(transport_capture_receipt_sha256),
            runtime_attestation_sha256: Some(runtime_attestation_sha256),
            peer_identity_sha256: Some(peer_identity_sha256),
            physical_response_framing: Some(physical_response_framing),
            response_proof_sha256,
        };
        comparison.validate()?;
        Ok(comparison)
    }

    pub(crate) fn new_unavailable(
        classification: ResponseComparisonClass,
        capture_mode: ResponseCaptureMode,
        unavailable_marker_sha256: Sha256Digest,
        response_proof_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        let comparison = Self {
            classification,
            capture_mode,
            upstream_status: None,
            exact_response_body_bytes: None,
            exact_response_body_sha256: None,
            physical_response_header_count: None,
            physical_response_headers_sha256: None,
            exact_response_commitment_sha256: None,
            active_validation: None,
            candidate_validation: None,
            unavailable_marker_sha256: Some(unavailable_marker_sha256),
            transport_capture_receipt_sha256: None,
            runtime_attestation_sha256: None,
            peer_identity_sha256: None,
            physical_response_framing: None,
            response_proof_sha256,
        };
        comparison.validate()?;
        Ok(comparison)
    }

    pub(crate) fn classification(&self) -> ResponseComparisonClass {
        self.classification
    }

    fn validate(&self) -> Result<(), ShadowError> {
        match self.capture_mode {
            ResponseCaptureMode::BoundedExact => {
                let status = self
                    .upstream_status
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let body_bytes = self
                    .exact_response_body_bytes
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let body_sha256 = self
                    .exact_response_body_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let header_count = self
                    .physical_response_header_count
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let headers_sha256 = self
                    .physical_response_headers_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let response_commitment = self
                    .exact_response_commitment_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let active = self
                    .active_validation
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let candidate = self
                    .candidate_validation
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let receipt = self
                    .transport_capture_receipt_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let runtime_attestation = self
                    .runtime_attestation_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let peer_identity = self
                    .peer_identity_sha256
                    .as_ref()
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                let framing = self
                    .physical_response_framing
                    .ok_or(ShadowError::ResponseEvidenceMismatch)?;
                if !(200..=599).contains(&status)
                    || self.unavailable_marker_sha256.is_some()
                    || active.exact_response_commitment_sha256
                        != *response_commitment
                    || candidate.exact_response_commitment_sha256
                        != *response_commitment
                    || self.response_proof_sha256
                        != hash_domain_frames(
                            b"serverware.policyShadowAuthenticatedResponseProof/v1",
                            &[&canonical_json_bytes(&(
                                response_commitment,
                                receipt,
                                runtime_attestation,
                                peer_identity,
                                framing,
                            ))?],
                        )
                {
                    return Err(ShadowError::ResponseEvidenceMismatch);
                }
                validate_unsigned(
                    body_bytes,
                    "response_comparison.exact_response_body_bytes",
                )?;
                validate_unsigned(
                    header_count,
                    "response_comparison.physical_response_header_count",
                )?;
                let expected_response_commitment = hash_domain_frames(
                    b"serverware.policyShadowExactResponse/v1",
                    &[&canonical_json_bytes(&(
                        status,
                        body_bytes,
                        body_sha256,
                        header_count,
                        headers_sha256,
                    ))?],
                );
                if expected_response_commitment != *response_commitment {
                    return Err(ShadowError::ResponseEvidenceMismatch);
                }
                let classification_consistent = match self.classification {
                    ResponseComparisonClass::ComparableIdentical => {
                        active.outcome == candidate.outcome
                            && active.validation_result_sha256
                                == candidate.validation_result_sha256
                            && !matches!(
                                active.outcome,
                                ResponseValidationOutcome::Indeterminate
                                    | ResponseValidationOutcome::NotEvaluated
                            )
                    }
                    ResponseComparisonClass::ComparableValidationMatch => {
                        active.outcome == candidate.outcome
                            && active.validation_result_sha256
                                != candidate.validation_result_sha256
                            && !matches!(
                                active.outcome,
                                ResponseValidationOutcome::Indeterminate
                                    | ResponseValidationOutcome::NotEvaluated
                            )
                    }
                    ResponseComparisonClass::ComparableValidationDivergence => {
                        active.outcome != candidate.outcome
                            && !matches!(
                                active.outcome,
                                ResponseValidationOutcome::Indeterminate
                                    | ResponseValidationOutcome::NotEvaluated
                            )
                            && !matches!(
                                candidate.outcome,
                                ResponseValidationOutcome::Indeterminate
                                    | ResponseValidationOutcome::NotEvaluated
                            )
                    }
                    ResponseComparisonClass::NotComparableCandidateValidatorUnavailable => {
                        matches!(
                            candidate.outcome,
                            ResponseValidationOutcome::Indeterminate
                                | ResponseValidationOutcome::NotEvaluated
                        )
                    }
                    ResponseComparisonClass::NotComparableCandidateNotDispatchable
                    | ResponseComparisonClass::NotComparableDispatchCommitmentMismatch => {
                        candidate.outcome
                            == ResponseValidationOutcome::NotEvaluated
                    }
                    ResponseComparisonClass::NotComparableActiveResponseUnavailable
                    | ResponseComparisonClass::NotApplicableActiveNotDispatched
                    | ResponseComparisonClass::NotApplicableBothDeny => false,
                };
                if !classification_consistent {
                    return Err(ShadowError::ResponseEvidenceMismatch);
                }
            }
            ResponseCaptureMode::StreamingUnavailable => {
                if self.classification
                    != ResponseComparisonClass::NotComparableActiveResponseUnavailable
                    || self.unavailable_marker_sha256.is_none()
                    || self.upstream_status.is_some()
                    || self.exact_response_body_bytes.is_some()
                    || self.exact_response_body_sha256.is_some()
                    || self.physical_response_header_count.is_some()
                    || self.physical_response_headers_sha256.is_some()
                    || self.exact_response_commitment_sha256.is_some()
                    || self.active_validation.is_some()
                    || self.candidate_validation.is_some()
                    || self.transport_capture_receipt_sha256.is_some()
                    || self.runtime_attestation_sha256.is_some()
                    || self.peer_identity_sha256.is_some()
                    || self.physical_response_framing.is_some()
                {
                    return Err(ShadowError::ResponseEvidenceMismatch);
                }
            }
            ResponseCaptureMode::NotDispatched => {
                if !matches!(
                    self.classification,
                    ResponseComparisonClass::NotApplicableActiveNotDispatched
                        | ResponseComparisonClass::NotComparableCandidateNotDispatchable
                        | ResponseComparisonClass::NotComparableDispatchCommitmentMismatch
                        | ResponseComparisonClass::NotApplicableBothDeny
                ) || self.unavailable_marker_sha256.is_none()
                    || self.upstream_status.is_some()
                    || self.exact_response_body_bytes.is_some()
                    || self.exact_response_body_sha256.is_some()
                    || self.physical_response_header_count.is_some()
                    || self.physical_response_headers_sha256.is_some()
                    || self.exact_response_commitment_sha256.is_some()
                    || self.active_validation.is_some()
                    || self.candidate_validation.is_some()
                    || self.transport_capture_receipt_sha256.is_some()
                    || self.runtime_attestation_sha256.is_some()
                    || self.peer_identity_sha256.is_some()
                    || self.physical_response_framing.is_some()
                {
                    return Err(ShadowError::ResponseEvidenceMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SamplingDecision {
    Included,
    ExcludedByAssignment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnavailableReason {
    FactsCaptureFailed,
    CommitmentUnavailable,
    RuntimeShuttingDown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum IngressFactsState {
    Captured {
        request_commitment: RequestCommitment,
    },
    Unavailable {
        reason: UnavailableReason,
        unavailable_marker_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DropReason {
    QueueFull,
    WorkerUnavailable,
    DeadlineExceeded,
    FactsUnsupported,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PolicyShadowTerminalReason {
    FactsCaptureError,
    ActiveEvaluationError,
    CandidateEvaluationError,
    ResponseValidationError,
    CommitmentError,
    InternalError,
    ResponsePolicyRejected,
    ResponseEvidenceInvalid,
    CredentialReflectionBlocked,
    RawTransportCaptureUnavailableAfterRelease,
    RawTransportCaptureUnavailableAfterBlock,
    BufferedLocalTerminal,
    UpstreamOutcomeUnknown,
    StreamingUpstreamOutcomeUnknown,
    InterceptedStreamOutcomeUnknown,
    ResponseQueueFull,
    ResponseWorkerUnavailable,
    WorkerLost,
    StreamingResponseNotBoundedExact,
    ActiveResponseValidationUnavailable,
    UpstreamResponseNotObserved,
    RequiredActiveResponseValidationUnavailable,
    RequiredGmailMetadataEvidenceUnavailable,
    GenerationChangedBeforeTerminal,
    PreDispatchTerminalHttpStatusInvalid,
    PostDispatchTerminalHttpStatusInvalid,
    TerminalOutcomeInvalid,
    DecisionTimePlanBindingMismatch,
    DuplicateTerminalFinalization,
    TerminalStateContention,
    CandidateEnqueueFailed,
    PostDispatchTypedCompletionRequired,
    EarlyLocalTerminalEvidenceUnavailable,
    DispatchBarrierNonAllow,
    DispatchBarrierEvidenceUnavailable,
    DispatchBarrierStateContention,
    DuplicateDispatchBarrier,
    PreDispatchResponseParseUnavailable,
    PreDispatchResponseStatusInvalid,
    PreDispatchFinalizationFailed,
    PostDispatchActiveDecisionUnavailable,
    PostDispatchResponseParseUnavailable,
    PostDispatchFinalizationFailed,
    AccountingCustodyUnavailable,
    AccountingLedgerContention,
    AccountingSerializationFailed,
    AccountingQueueFull,
    AccountingQueueDisconnected,
    AccountingOversize,
    AccountingGenerationTombstoned,
}

impl PolicyShadowTerminalReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::FactsCaptureError => "facts-capture-error",
            Self::ActiveEvaluationError => "active-evaluation-error",
            Self::CandidateEvaluationError => "candidate-evaluation-error",
            Self::ResponseValidationError => "response-validation-error",
            Self::CommitmentError => "commitment-error",
            Self::InternalError => "internal-error",
            Self::ResponsePolicyRejected => "response-policy-rejected",
            Self::ResponseEvidenceInvalid => "response-evidence-invalid",
            Self::CredentialReflectionBlocked => "credential-reflection-blocked",
            Self::RawTransportCaptureUnavailableAfterRelease => {
                "raw-transport-capture-unavailable-after-release"
            }
            Self::RawTransportCaptureUnavailableAfterBlock => {
                "raw-transport-capture-unavailable-after-block"
            }
            Self::BufferedLocalTerminal => "buffered-local-terminal",
            Self::UpstreamOutcomeUnknown => "upstream-outcome-unknown",
            Self::StreamingUpstreamOutcomeUnknown => {
                "streaming-upstream-outcome-unknown"
            }
            Self::InterceptedStreamOutcomeUnknown => {
                "intercepted-stream-outcome-unknown"
            }
            Self::ResponseQueueFull => "response-queue-full",
            Self::ResponseWorkerUnavailable => "response-worker-unavailable",
            Self::WorkerLost => "worker-lost",
            Self::StreamingResponseNotBoundedExact => {
                "streaming-response-not-bounded-exact"
            }
            Self::ActiveResponseValidationUnavailable => {
                "active-response-validation-unavailable"
            }
            Self::UpstreamResponseNotObserved => {
                "upstream-response-not-observed"
            }
            Self::RequiredActiveResponseValidationUnavailable => {
                "required-active-response-validation-unavailable"
            }
            Self::RequiredGmailMetadataEvidenceUnavailable => {
                "required-gmail-metadata-evidence-unavailable"
            }
            Self::GenerationChangedBeforeTerminal => {
                "generation-changed-before-terminal"
            }
            Self::PreDispatchTerminalHttpStatusInvalid => {
                "pre-dispatch-terminal-http-status-invalid"
            }
            Self::PostDispatchTerminalHttpStatusInvalid => {
                "post-dispatch-terminal-http-status-invalid"
            }
            Self::TerminalOutcomeInvalid => "terminal-outcome-invalid",
            Self::DecisionTimePlanBindingMismatch => {
                "decision-time-plan-binding-mismatch"
            }
            Self::DuplicateTerminalFinalization => {
                "duplicate-terminal-finalization"
            }
            Self::TerminalStateContention => "terminal-state-contention",
            Self::CandidateEnqueueFailed => "candidate-enqueue-failed",
            Self::PostDispatchTypedCompletionRequired => {
                "post-dispatch-typed-completion-required"
            }
            Self::EarlyLocalTerminalEvidenceUnavailable => {
                "early-local-terminal-evidence-unavailable"
            }
            Self::DispatchBarrierNonAllow => "dispatch-barrier-non-allow",
            Self::DispatchBarrierEvidenceUnavailable => {
                "dispatch-barrier-evidence-unavailable"
            }
            Self::DispatchBarrierStateContention => {
                "dispatch-barrier-state-contention"
            }
            Self::DuplicateDispatchBarrier => "duplicate-dispatch-barrier",
            Self::PreDispatchResponseParseUnavailable => {
                "pre-dispatch-response-parse-unavailable"
            }
            Self::PreDispatchResponseStatusInvalid => {
                "pre-dispatch-response-status-invalid"
            }
            Self::PreDispatchFinalizationFailed => {
                "pre-dispatch-finalization-failed"
            }
            Self::PostDispatchActiveDecisionUnavailable => {
                "post-dispatch-active-decision-unavailable"
            }
            Self::PostDispatchResponseParseUnavailable => {
                "post-dispatch-response-parse-unavailable"
            }
            Self::PostDispatchFinalizationFailed => {
                "post-dispatch-finalization-failed"
            }
            Self::AccountingCustodyUnavailable => {
                "accounting-custody-unavailable"
            }
            Self::AccountingLedgerContention => {
                "accounting-ledger-contention"
            }
            Self::AccountingSerializationFailed => {
                "accounting-serialization-failed"
            }
            Self::AccountingQueueFull => "accounting-queue-full",
            Self::AccountingQueueDisconnected => {
                "accounting-queue-disconnected"
            }
            Self::AccountingOversize => "accounting-oversize",
            Self::AccountingGenerationTombstoned => {
                "accounting-generation-tombstoned"
            }
        }
    }

    fn is_evaluation_error(self) -> bool {
        matches!(
            self,
            Self::FactsCaptureError
                | Self::ActiveEvaluationError
                | Self::CandidateEvaluationError
                | Self::ResponseValidationError
                | Self::CommitmentError
                | Self::InternalError
        )
    }

    fn is_active_not_evaluated(self) -> bool {
        matches!(
            self,
            Self::ActiveEvaluationError
                | Self::CommitmentError
                | Self::InternalError
        )
    }

    pub(crate) fn response_was_released(self) -> bool {
        self == Self::RawTransportCaptureUnavailableAfterRelease
    }

    pub(crate) fn spool_phase(self) -> ShadowSpoolPhase {
        match self {
            Self::FactsCaptureError
            | Self::AccountingSerializationFailed
            | Self::AccountingOversize => ShadowSpoolPhase::Capture,
            Self::CandidateEvaluationError
            | Self::CandidateEnqueueFailed
            | Self::AccountingQueueFull
            | Self::AccountingQueueDisconnected => {
                ShadowSpoolPhase::Candidate
            }
            Self::ResponseValidationError
            | Self::ResponseQueueFull
            | Self::ResponseWorkerUnavailable
            | Self::WorkerLost
            | Self::StreamingResponseNotBoundedExact
            | Self::ActiveResponseValidationUnavailable
            | Self::UpstreamResponseNotObserved
            | Self::RequiredActiveResponseValidationUnavailable
            | Self::RequiredGmailMetadataEvidenceUnavailable => {
                ShadowSpoolPhase::Response
            }
            Self::ResponsePolicyRejected
            | Self::ResponseEvidenceInvalid
            | Self::CredentialReflectionBlocked
            | Self::RawTransportCaptureUnavailableAfterRelease
            | Self::RawTransportCaptureUnavailableAfterBlock
            | Self::BufferedLocalTerminal
            | Self::UpstreamOutcomeUnknown
            | Self::StreamingUpstreamOutcomeUnknown
            | Self::InterceptedStreamOutcomeUnknown
            | Self::PostDispatchTypedCompletionRequired
            | Self::PostDispatchTerminalHttpStatusInvalid
            | Self::PostDispatchActiveDecisionUnavailable
            | Self::PostDispatchResponseParseUnavailable
            | Self::PostDispatchFinalizationFailed => {
                ShadowSpoolPhase::PostDispatchTerminal
            }
            Self::EarlyLocalTerminalEvidenceUnavailable
            | Self::PreDispatchTerminalHttpStatusInvalid
            | Self::PreDispatchResponseParseUnavailable
            | Self::PreDispatchResponseStatusInvalid
            | Self::PreDispatchFinalizationFailed => {
                ShadowSpoolPhase::PreDispatchTerminal
            }
            Self::DispatchBarrierNonAllow
            | Self::DispatchBarrierEvidenceUnavailable
            | Self::DispatchBarrierStateContention
            | Self::DuplicateDispatchBarrier => {
                ShadowSpoolPhase::DispatchBarrier
            }
            Self::ActiveEvaluationError
            | Self::CommitmentError
            | Self::InternalError
            | Self::GenerationChangedBeforeTerminal
            | Self::TerminalOutcomeInvalid
            | Self::DecisionTimePlanBindingMismatch
            | Self::DuplicateTerminalFinalization
            | Self::TerminalStateContention
            | Self::AccountingCustodyUnavailable
            | Self::AccountingLedgerContention
            | Self::AccountingGenerationTombstoned => {
                ShadowSpoolPhase::Decision
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExclusionReason {
    DeterministicAssignmentSampling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum IngressAccountingOutcome {
    Evaluated,
    Dropped {
        reason: DropReason,
        unavailable_marker_sha256: Sha256Digest,
    },
    Error {
        terminal_reason: PolicyShadowTerminalReason,
        unavailable_marker_sha256: Sha256Digest,
    },
    Excluded {
        reason: ExclusionReason,
    },
    TransportExcluded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IngressEvidencePayload {
    evidence_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    canary_id: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    runtime_identity: RuntimeIdentity,
    ingress_sequence: u64,
    custody_ingress_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    observed_at_unix_nanos: i64,
    sampling_decision: SamplingDecision,
    facts_state: IngressFactsState,
    accounting_outcome: IngressAccountingOutcome,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for IngressEvidencePayload {
    const API_VERSION: &'static str = INGRESS_EVIDENCE_DOMAIN;
    const KIND: &'static str = "PolicyShadowIngressEvidence";
    const SIGNATURE_DOMAIN: &'static str = INGRESS_EVIDENCE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(
            self.fleet_membership_revision,
            "fleet_membership_revision",
        )?;
        validate_positive(self.ingress_sequence, "ingress_sequence")?;
        validate_positive(
            self.publication_revision,
            "publication_revision",
        )?;
        if self.issued_at_unix_nanos < self.observed_at_unix_nanos
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err(invalid("issued_at_unix_nanos", "precedes observation"));
        }
        if let IngressAccountingOutcome::Error {
            terminal_reason,
            ..
        } = &self.accounting_outcome
        {
            if !terminal_reason.is_evaluation_error() {
                return Err(ShadowError::ObservationShapeMismatch);
            }
        }
        match (&self.sampling_decision, &self.accounting_outcome) {
            (
                SamplingDecision::ExcludedByAssignment,
                IngressAccountingOutcome::Excluded {
                    reason: ExclusionReason::DeterministicAssignmentSampling,
                },
            )
            | (SamplingDecision::Included, IngressAccountingOutcome::TransportExcluded)
            | (SamplingDecision::Included, IngressAccountingOutcome::Evaluated)
            | (SamplingDecision::Included, IngressAccountingOutcome::Dropped { .. })
            | (SamplingDecision::Included, IngressAccountingOutcome::Error { .. }) => Ok(()),
            _ => Err(ShadowError::ObservationShapeMismatch),
        }
    }
}

impl IngressEvidencePayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        evidence_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        canary_id: Sha256Digest,
        fleet_id: Sha256Digest,
        fleet_membership_revision: u64,
        runtime_identity: RuntimeIdentity,
        ingress_sequence: u64,
        custody_ingress_receipt_sha256: Sha256Digest,
        publication_revision: u64,
        observed_at_unix_nanos: i64,
        sampling_decision: SamplingDecision,
        facts_state: IngressFactsState,
        accounting_outcome: IngressAccountingOutcome,
        issued_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        let payload = Self {
            evidence_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            canary_id,
            fleet_id,
            fleet_membership_revision,
            runtime_identity,
            ingress_sequence,
            custody_ingress_receipt_sha256,
            publication_revision,
            observed_at_unix_nanos,
            sampling_decision,
            facts_state,
            accounting_outcome,
            issued_at_unix_nanos,
            expires_at_unix_nanos,
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }

    pub fn ingress_sequence(&self) -> u64 {
        self.ingress_sequence
    }

    pub fn observed_at_unix_nanos(&self) -> i64 {
        self.observed_at_unix_nanos
    }
}

pub(crate) type VerifiedIngressEvidence = VerifiedSignedEnvelope<IngressEvidencePayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LatencySamples {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    facts_capture_nanos: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    active_evaluation_nanos: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    candidate_evaluation_nanos: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    response_validation_nanos: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    shadow_total_nanos: Option<u64>,
}

impl LatencySamples {
    pub fn new(
        facts_capture_nanos: Option<u64>,
        active_evaluation_nanos: Option<u64>,
        candidate_evaluation_nanos: Option<u64>,
        response_validation_nanos: Option<u64>,
        shadow_total_nanos: Option<u64>,
    ) -> Result<Self, ShadowError> {
        for value in [
            facts_capture_nanos,
            active_evaluation_nanos,
            candidate_evaluation_nanos,
            response_validation_nanos,
            shadow_total_nanos,
        ]
        .into_iter()
        .flatten()
        {
            validate_unsigned(value, "latency_sample")?;
        }
        Ok(Self {
            facts_capture_nanos,
            active_evaluation_nanos,
            candidate_evaluation_nanos,
            response_validation_nanos,
            shadow_total_nanos,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservedAuthorityBinding {
    principal_sha256: Sha256Digest,
    route_sha256: Sha256Digest,
    operation: OperationClass,
    compiled_semantic_profile_sha256: Sha256Digest,
    request_authority_class: RequestAuthorityClass,
}

impl ObservedAuthorityBinding {
    pub(crate) fn from_compiled_route(principal_sha256: Sha256Digest, route_sha256: Sha256Digest,
        operation: OperationClass, compiled_semantic_profile_sha256: Sha256Digest) -> Self {
        Self { principal_sha256, route_sha256, operation, compiled_semantic_profile_sha256,
            request_authority_class: request_authority_class(operation) }
    }

    pub(crate) fn principal_sha256(&self) -> &Sha256Digest { &self.principal_sha256 }
    pub(crate) fn route_sha256(&self) -> &Sha256Digest { &self.route_sha256 }
    pub(crate) fn operation(&self) -> OperationClass { self.operation }
    pub(crate) fn compiled_semantic_profile_sha256(&self) -> &Sha256Digest { &self.compiled_semantic_profile_sha256 }
    pub(crate) fn request_authority_class(&self) -> RequestAuthorityClass { self.request_authority_class }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DerivedExpansionSet {
    cells: Vec<SemanticExpansionCell>,
    cells_root_sha256: Sha256Digest,
}

impl DerivedExpansionSet {
    fn validate_shape(&self) -> Result<(), ShadowError> {
        if self.cells.is_empty() {
            if self.cells_root_sha256 != merkle_root(&[])? {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            return Ok(());
        }
        validate_semantic_expansion_cells(&self.cells, false)?;
        if self.cells_root_sha256 != semantic_expansion_cells_root(&self.cells)? {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum ObservationResult {
    Evaluated {
        pure_active_evaluation: EvaluationSummary,
        final_active_enforcement: ActiveEffectResolutionSummary,
        candidate_evaluation: CandidateEvaluationSummary,
        authority_binding: ObservedAuthorityBinding,
        derived_expansion: DerivedExpansionSet,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pilot_membership: Option<PilotMembershipEvidence>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        response_obligation: Option<ResponseObligationBinding>,
        response_comparison: ResponseComparison,
        latency_samples: LatencySamples,
    },
    Dropped {
        reason: DropReason,
        unavailable_marker_sha256: Sha256Digest,
        latency_samples: LatencySamples,
    },
    Error {
        terminal_reason: PolicyShadowTerminalReason,
        unavailable_marker_sha256: Sha256Digest,
        latency_samples: LatencySamples,
    },
    Excluded {
        reason: ExclusionReason,
    },
    TransportExcluded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CustodyEvidenceBinding {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    admitted_ingress_receipt_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    unavailable_ingress_receipt_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    dispatch_barrier_receipt_sha256: Option<Sha256Digest>,
    dispatch_barrier_receipt_count: u64,
    dispatch_barrier_receipts_root_sha256: Sha256Digest,
    active_effect_barrier_receipt_count: u64,
    active_effect_barrier_receipts_root_sha256: Sha256Digest,
    active_effect_commit_receipt_count: u64,
    active_effect_commit_receipts_root_sha256: Sha256Digest,
    terminal_receipt_count: u64,
    terminal_receipts_root_sha256: Sha256Digest,
    publication_receipt_count: u64,
    publication_receipts_root_sha256: Sha256Digest,
    spill_receipt_count: u64,
    spill_receipts_root_sha256: Sha256Digest,
    persistence_receipts_root_sha256: Sha256Digest,
    retrieval_proofs_root_sha256: Sha256Digest,
    compaction_receipt_count: u64,
    compaction_receipts_root_sha256: Sha256Digest,
    last_ledger_event_ordinal: u64,
    last_ledger_head_sha256: Sha256Digest,
    last_spool_root_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    custody_evidence_root_sha256: Sha256Digest,
}

impl CustodyEvidenceBinding {
    fn validate(&self) -> Result<(), ShadowError> {
        validate_unsigned(
            self.spill_receipt_count,
            "custody_evidence.spill_receipt_count",
        )?;
        validate_unsigned(
            self.dispatch_barrier_receipt_count,
            "custody_evidence.dispatch_barrier_receipt_count",
        )?;
        validate_unsigned(
            self.active_effect_barrier_receipt_count,
            "custody_evidence.active_effect_barrier_receipt_count",
        )?;
        validate_unsigned(
            self.active_effect_commit_receipt_count,
            "custody_evidence.active_effect_commit_receipt_count",
        )?;
        validate_positive(
            self.terminal_receipt_count,
            "custody_evidence.terminal_receipt_count",
        )?;
        validate_positive(
            self.publication_receipt_count,
            "custody_evidence.publication_receipt_count",
        )?;
        validate_unsigned(
            self.compaction_receipt_count,
            "custody_evidence.compaction_receipt_count",
        )?;
        validate_positive(
            self.last_ledger_event_ordinal,
            "custody_evidence.last_ledger_event_ordinal",
        )?;
        validate_positive(
            self.publication_revision,
            "custody_evidence.publication_revision",
        )?;
        if self.admitted_ingress_receipt_sha256.is_some()
            == self.unavailable_ingress_receipt_sha256.is_some()
            || self.admitted_ingress_receipt_sha256.is_some()
                && self.spill_receipt_count == 0
            || self.unavailable_ingress_receipt_sha256.is_some()
                && self.dispatch_barrier_receipt_count != 0
            || self.dispatch_barrier_receipt_sha256.is_some()
                != (self.dispatch_barrier_receipt_count > 0)
            || self.dispatch_barrier_receipt_count
                > self.spill_receipt_count
            || self.active_effect_barrier_receipt_count
                != self.active_effect_commit_receipt_count
            || self.terminal_receipt_count != 1
            || self.publication_receipt_count != 1
            || self.publication_receipts_root_sha256
                != merkle_root(&[(
                    1,
                    self.publication_reconciliation_receipt_sha256
                        .clone(),
                )])?
            || self.dispatch_barrier_receipt_count == 0
                && self.dispatch_barrier_receipts_root_sha256
                    != merkle_root(&[])?
            || self.active_effect_barrier_receipt_count == 0
                && self.active_effect_barrier_receipts_root_sha256
                    != merkle_root(&[])?
            || self.active_effect_commit_receipt_count == 0
                && self.active_effect_commit_receipts_root_sha256
                    != merkle_root(&[])?
            || self.spill_receipt_count == 0
                && self.spill_receipts_root_sha256 != merkle_root(&[])?
        {
            return Err(ShadowError::ObservationShapeMismatch);
        }
        let expected = hash_domain_frames(
            b"serverware.policyShadowCustodyEvidenceBinding/v1",
            &[&canonical_json_bytes(&serde_json::json!([
                &self.admitted_ingress_receipt_sha256,
                &self.unavailable_ingress_receipt_sha256,
                &self.dispatch_barrier_receipt_sha256,
                self.dispatch_barrier_receipt_count,
                &self.dispatch_barrier_receipts_root_sha256,
                self.active_effect_barrier_receipt_count,
                &self.active_effect_barrier_receipts_root_sha256,
                self.active_effect_commit_receipt_count,
                &self.active_effect_commit_receipts_root_sha256,
                self.terminal_receipt_count,
                &self.terminal_receipts_root_sha256,
                self.publication_receipt_count,
                &self.publication_receipts_root_sha256,
                self.spill_receipt_count,
                &self.spill_receipts_root_sha256,
                &self.persistence_receipts_root_sha256,
                &self.retrieval_proofs_root_sha256,
                self.compaction_receipt_count,
                &self.compaction_receipts_root_sha256,
                self.last_ledger_event_ordinal,
                &self.last_ledger_head_sha256,
                &self.last_spool_root_sha256,
                &self.publication_reconciliation_receipt_sha256,
                self.publication_revision,
            ]))?],
        );
        if expected != self.custody_evidence_root_sha256 {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    pub(crate) fn ingress_receipt_sha256(&self) -> &Sha256Digest {
        self.admitted_ingress_receipt_sha256
            .as_ref()
            .or(self.unavailable_ingress_receipt_sha256.as_ref())
            .expect("custody evidence validation requires one ingress receipt")
    }

    pub(crate) fn primary_dispatch_barrier_receipt_sha256(
        &self,
    ) -> Option<&Sha256Digest> {
        self.dispatch_barrier_receipt_sha256.as_ref()
    }

    pub(crate) fn dispatch_barrier_receipts(
        &self,
    ) -> (u64, &Sha256Digest) {
        (
            self.dispatch_barrier_receipt_count,
            &self.dispatch_barrier_receipts_root_sha256,
        )
    }

    pub(crate) fn spill_receipts(&self) -> (u64, &Sha256Digest) {
        (self.spill_receipt_count, &self.spill_receipts_root_sha256)
    }

    pub(crate) fn active_effect_receipts(
        &self,
    ) -> ((u64, &Sha256Digest), (u64, &Sha256Digest)) {
        (
            (
                self.active_effect_barrier_receipt_count,
                &self.active_effect_barrier_receipts_root_sha256,
            ),
            (
                self.active_effect_commit_receipt_count,
                &self.active_effect_commit_receipts_root_sha256,
            ),
        )
    }

    pub(crate) fn terminal_receipts(&self) -> (u64, &Sha256Digest) {
        (
            self.terminal_receipt_count,
            &self.terminal_receipts_root_sha256,
        )
    }

    pub(crate) fn publication_receipts(
        &self,
    ) -> (u64, &Sha256Digest) {
        (
            self.publication_receipt_count,
            &self.publication_receipts_root_sha256,
        )
    }

    pub(crate) fn durability_roots(
        &self,
    ) -> (&Sha256Digest, &Sha256Digest) {
        (
            &self.persistence_receipts_root_sha256,
            &self.retrieval_proofs_root_sha256,
        )
    }

    pub(crate) fn compaction_receipts(
        &self,
    ) -> (u64, &Sha256Digest) {
        (
            self.compaction_receipt_count,
            &self.compaction_receipts_root_sha256,
        )
    }

    pub(crate) fn publication_reconciliation(
        &self,
    ) -> (&Sha256Digest, u64) {
        (
            &self.publication_reconciliation_receipt_sha256,
            self.publication_revision,
        )
    }

    pub(crate) fn ledger_head(
        &self,
    ) -> (u64, &Sha256Digest, &Sha256Digest) {
        (
            self.last_ledger_event_ordinal,
            &self.last_ledger_head_sha256,
            &self.last_spool_root_sha256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyShadowObservationPayload {
    observation_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    generation: ShadowGenerationIdentity,
    observation_sequence: u64,
    previous_observation_sha256: Sha256Digest,
    ingress_evidence_sha256: Sha256Digest,
    ingress_evidence: SignedEnvelope<IngressEvidencePayload>,
    active_decision_sha256: Sha256Digest,
    active_decision: SignedEnvelope<ActiveDecisionReceiptPayload>,
    custody_evidence: CustodyEvidenceBinding,
    result: ObservationResult,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

/// Custody may build an unsigned payload, then pass its canonical bytes to its
/// signing subsystem. This builder never constructs an envelope or verified
/// evidence.
pub(crate) struct UnsignedObservationPayloadBuilder {
    payload: PolicyShadowObservationPayload,
}

impl UnsignedObservationPayloadBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        authority_key_independence_sha256: Sha256Digest,
        policy_authority_analysis_sha256: Sha256Digest,
        policy_authority_analysis_payload_sha256: Sha256Digest,
        custody_receipt_evidence_requirements_sha256: Sha256Digest,
        load_receipt_sha256: Sha256Digest,
        load_receipt_payload_sha256: Sha256Digest,
        canary_id: Sha256Digest,
        fleet_id: Sha256Digest,
        fleet_membership_revision: u64,
        policy_identity: PolicyIdentity,
        runtime_identity: RuntimeIdentity,
        generation: ShadowGenerationIdentity,
        observation_sequence: u64,
        previous_observation_sha256: Sha256Digest,
        ingress_evidence_sha256: Sha256Digest,
        ingress_evidence: SignedEnvelope<IngressEvidencePayload>,
        active_decision_sha256: Sha256Digest,
        active_decision: SignedEnvelope<ActiveDecisionReceiptPayload>,
        custody_evidence: CustodyEvidenceBinding,
        result: ObservationResult,
        issued_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Self {
        Self {
            payload: PolicyShadowObservationPayload {
                observation_id,
                assignment_sha256,
                assignment_payload_sha256,
                assignment_revision,
                authority_key_independence_sha256,
                policy_authority_analysis_sha256,
                policy_authority_analysis_payload_sha256,
                custody_receipt_evidence_requirements_sha256,
                load_receipt_sha256,
                load_receipt_payload_sha256,
                canary_id,
                fleet_id,
                fleet_membership_revision,
                policy_identity,
                runtime_identity,
                generation,
                observation_sequence,
                previous_observation_sha256,
                ingress_evidence_sha256,
                ingress_evidence,
                active_decision_sha256,
                active_decision,
                custody_evidence,
                result,
                issued_at_unix_nanos,
                expires_at_unix_nanos,
            },
        }
    }

    pub fn build(self) -> Result<PolicyShadowObservationPayload, ShadowError> {
        self.payload.validate_intrinsic()?;
        Ok(self.payload)
    }
}

impl PolicyShadowObservationPayload {
    pub fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    pub fn result(&self) -> &ObservationResult {
        &self.result
    }

    pub fn runtime_identity(&self) -> &RuntimeIdentity {
        &self.runtime_identity
    }
}

impl EnvelopePayload for PolicyShadowObservationPayload {
    const API_VERSION: &'static str = OBSERVATION_DOMAIN;
    const KIND: &'static str = "PolicyShadowObservation";
    const SIGNATURE_DOMAIN: &'static str = OBSERVATION_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(self.observation_sequence, "observation_sequence")?;
        validate_positive(
            self.fleet_membership_revision,
            "fleet_membership_revision",
        )?;
        self.policy_identity.validate()?;
        self.generation.validate()?;
        self.custody_evidence.validate()?;
        let bound_ingress_receipt = self
            .custody_evidence
            .admitted_ingress_receipt_sha256
            .as_ref()
            .or(
                self.custody_evidence
                    .unavailable_ingress_receipt_sha256
                    .as_ref(),
            );
        if bound_ingress_receipt
                != Some(
                    &self
                        .ingress_evidence
                        .payload
                        .custody_ingress_receipt_sha256,
                )
            || self.custody_evidence.publication_revision
                != self.ingress_evidence.payload.publication_revision
            || self.custody_evidence.dispatch_barrier_receipt_sha256
                != self
                    .active_decision
                    .payload
                    .dispatch_barrier_receipt_sha256
        {
            return Err(ShadowError::ObservationShapeMismatch);
        }
        if self.expires_at_unix_nanos <= self.issued_at_unix_nanos {
            return Err(invalid("observation.validity", "invalid validity interval"));
        }
        validate_observation_result(&self.result)
    }
}

pub(crate) type VerifiedObservation = VerifiedSignedEnvelope<PolicyShadowObservationPayload>;

fn validate_observation_result(result: &ObservationResult) -> Result<(), ShadowError> {
    let samples = match result {
        ObservationResult::Evaluated {
            pure_active_evaluation,
            final_active_enforcement,
            candidate_evaluation,
            authority_binding,
            derived_expansion,
            pilot_membership,
            response_comparison,
            latency_samples,
            ..
        } => {
            pure_active_evaluation.policy_plan.validate()?;
            validate_unsigned(
                pure_active_evaluation.evaluation_nanos,
                "active_evaluation_nanos",
            )?;
            validate_unsigned(
                candidate_evaluation.evaluation_nanos,
                "candidate_evaluation_nanos",
            )?;
            if candidate_evaluation.evaluation_purpose != "candidate-shadow"
                || candidate_evaluation.effect_capabilities_available
                || candidate_evaluation.effect_intents_executed
                || latency_samples.facts_capture_nanos.is_none()
                || latency_samples.active_evaluation_nanos.is_none()
                || latency_samples.candidate_evaluation_nanos.is_none()
                || latency_samples.shadow_total_nanos.is_none()
                || latency_samples.active_evaluation_nanos
                    != Some(pure_active_evaluation.evaluation_nanos)
                || latency_samples.candidate_evaluation_nanos
                    != Some(candidate_evaluation.evaluation_nanos)
                || final_active_enforcement.resolved_effect_intents_sha256
                    != pure_active_evaluation.effect_intents_sha256
                || pure_active_evaluation.policy_plan.semantic_commitment()?
                    != pure_active_evaluation.policy_plan_sha256
                || pure_active_evaluation
                    .policy_plan
                    .effect_intents_commitment()?
                    != pure_active_evaluation.effect_intents_sha256
                || pure_active_evaluation.effect_requirements
                    != ActiveEffectRequirements::from_plan(
                        &pure_active_evaluation.policy_plan,
                    )
            {
                return Err(ShadowError::ObservationShapeMismatch);
            }
            response_comparison.validate()?;
            let total = latency_samples
                .shadow_total_nanos
                .ok_or(ShadowError::ObservationShapeMismatch)?;
            if [
                latency_samples.facts_capture_nanos,
                latency_samples.active_evaluation_nanos,
                latency_samples.candidate_evaluation_nanos,
                latency_samples.response_validation_nanos,
            ]
            .into_iter()
            .flatten()
            .any(|sample| sample > total)
            {
                return Err(ShadowError::ObservationShapeMismatch);
            }
            let active_dispatchable = matches!(
                final_active_enforcement.final_outcome,
                FinalEnforcementOutcome::Allow
            ) && final_active_enforcement.upstream_dispatch_authorized;
            let candidate_dispatchable = matches!(
                candidate_evaluation.outcome,
                OutcomeClass::Permit | OutcomeClass::Conditional
            );
            let fixed_classification = if matches!(
                final_active_enforcement.final_outcome,
                FinalEnforcementOutcome::Deny
            )
                && candidate_evaluation.outcome == OutcomeClass::Deny
            {
                Some(ResponseComparisonClass::NotApplicableBothDeny)
            } else if !active_dispatchable {
                Some(ResponseComparisonClass::NotApplicableActiveNotDispatched)
            } else if !candidate_dispatchable {
                Some(ResponseComparisonClass::NotComparableCandidateNotDispatchable)
            } else if pure_active_evaluation.dispatch_commitment_sha256
                != candidate_evaluation.dispatch_commitment_sha256
            {
                Some(ResponseComparisonClass::NotComparableDispatchCommitmentMismatch)
            } else {
                None
            };
            if fixed_classification.is_some_and(|expected| {
                response_comparison.classification != expected
            }) || (fixed_classification.is_none()
                && matches!(
                    response_comparison.classification,
                    ResponseComparisonClass::NotApplicableBothDeny
                        | ResponseComparisonClass::NotApplicableActiveNotDispatched
                        | ResponseComparisonClass::NotComparableCandidateNotDispatchable
                        | ResponseComparisonClass::NotComparableDispatchCommitmentMismatch
                ))
            {
                return Err(ShadowError::ObservationShapeMismatch);
            }
            derived_expansion.validate_shape()?;
            let is_expansion = !derived_expansion.cells.is_empty();
            if is_expansion != pilot_membership.is_some() {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            if let Some(membership) = pilot_membership {
                validate_len(
                    "pilot_membership.principal_proof",
                    membership.principal_proof.len(),
                    0,
                    64,
                )?;
                validate_len(
                    "pilot_membership.route_proof",
                    membership.route_proof.len(),
                    0,
                    64,
                )?;
            }
            for cell in &derived_expansion.cells {
                cell.validate()?;
                if cell.active_outcome != pure_active_evaluation.outcome
                    || cell.candidate_outcome != candidate_evaluation.outcome
                    || cell.route_sha256 != authority_binding.route_sha256
                    || cell.operation != authority_binding.operation
                    || cell.compiled_semantic_profile_sha256
                        != authority_binding.compiled_semantic_profile_sha256
                    || cell.request_authority_class
                        != authority_binding.request_authority_class
                {
                    return Err(ShadowError::ExpansionCellMismatch);
                }
            }
            latency_samples
        }
        ObservationResult::Dropped {
            latency_samples, ..
        } => latency_samples,
        ObservationResult::Error {
            terminal_reason,
            latency_samples,
            ..
        } => {
            if !terminal_reason.is_evaluation_error() {
                return Err(ShadowError::ObservationShapeMismatch);
            }
            latency_samples
        }
        ObservationResult::Excluded { .. } | ObservationResult::TransportExcluded => {
            return Ok(())
        }
    };
    for value in [
        samples.facts_capture_nanos,
        samples.active_evaluation_nanos,
        samples.candidate_evaluation_nanos,
        samples.response_validation_nanos,
        samples.shadow_total_nanos,
    ]
    .into_iter()
    .flatten()
    {
        validate_unsigned(value, "latency_sample")?;
    }
    Ok(())
}

pub(crate) trait RequestCommitmentVerification {
    fn verify(
        &self,
        commitment: &RequestCommitment,
        protected_facts: &ProtectedRequestFacts,
        assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity,
        ingress_sequence: u64,
        observed_at_unix_nanos: i64,
    ) -> Result<(), ShadowError>;
}

pub(crate) struct LocalRequestCommitmentVerifier<'a> {
    key: &'a RequestCommitmentKey,
}

impl<'a> LocalRequestCommitmentVerifier<'a> {
    pub(crate) fn new(key: &'a RequestCommitmentKey) -> Self {
        Self { key }
    }
}

impl RequestCommitmentVerification for LocalRequestCommitmentVerifier<'_> {
    fn verify(
        &self,
        commitment: &RequestCommitment,
        protected_facts: &ProtectedRequestFacts,
        assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity,
        ingress_sequence: u64,
        observed_at_unix_nanos: i64,
    ) -> Result<(), ShadowError> {
        let expected = commit_protected_request_facts(
            protected_facts,
            assignment,
            runtime,
            ingress_sequence,
            observed_at_unix_nanos,
            self.key,
        )?;
        if &expected != commitment {
            return Err(ShadowError::RequestCommitmentMismatch);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_observation(
    wire: SignedEnvelope<PolicyShadowObservationPayload>,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    previous: Option<&VerifiedObservation>,
    protected_facts: Option<&ProtectedRequestFacts>,
    commitment_verifier: &dyn RequestCommitmentVerification,
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedObservation, ShadowError> {
    revalidate_verified_freshness(
        assignment,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    revalidate_verified_freshness(
        load_receipt,
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    revalidate_verified_freshness(
        policy_authority_analysis,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    if let Some(previous) = previous {
        revalidate_verified_freshness(
            previous,
            key_trust,
            trusted_time,
            assignment
                .payload()
                .observation_window
                .maximum_evidence_age_nanos
                .try_into()
                .map_err(|_| ShadowError::EvidenceTooOld)?,
        )?;
    }
    verify_load_receipt_binding(load_receipt, assignment)?;
    if policy_authority_analysis.payload().assignment_sha256
        != *assignment.envelope_sha256()
        || policy_authority_analysis
            .payload()
            .assignment_payload_sha256
            != *assignment.payload_sha256()
        || policy_authority_analysis.payload().assignment_revision
            != assignment.payload().assignment_revision
        || policy_authority_analysis.payload().canary_id
            != assignment.payload().canary_id
        || policy_authority_analysis.payload().policy_identity
            != assignment.payload().policy_identity
        || policy_authority_analysis
            .payload()
            .expected_loaded_snapshots
            != assignment.payload().expected_loaded_snapshots
        || policy_authority_analysis
            .payload()
            .response_validation_obligations_root_sha256
            != assignment
                .payload()
                .response_validation_obligations_root_sha256
    {
        return Err(ShadowError::PolicyAuthorityAnalysisMismatch);
    }
    let member = assignment
        .payload()
        .fleet
        .members
        .iter()
        .find(|member| {
            member.instance_id == load_receipt.payload().runtime_identity.instance_id
        })
        .ok_or(ShadowError::BindingDrift)?;
    let verified = verify_envelope(
        wire,
        ExpectedSigner {
            key_id: &member.shadow_signing_key_id,
            key_spki_sha256: &member.shadow_signing_key_spki_sha256,
        },
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    let ingress = verify_envelope(
        verified.payload().ingress_evidence.clone(),
        ExpectedSigner {
            key_id: &member.ingress_signing_key_id,
            key_spki_sha256: &member.ingress_signing_key_spki_sha256,
        },
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    let active_decision = verify_envelope(
        verified.payload().active_decision.clone(),
        ExpectedSigner {
            key_id: &member.active_decision_signing_key_id,
            key_spki_sha256: &member.active_decision_signing_key_spki_sha256,
        },
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    let custody_context = open_verified_custody_call(
        custody,
        trusted_time,
        PolicyShadowCustodyOperation::VerifyObservationEvidence,
        verified.envelope_sha256(),
    )?;
    let custody_result = custody.verify_observation_custody_evidence(
        &custody_context,
        &verified.payload().custody_evidence,
        ingress.payload(),
        active_decision.payload(),
    );
    finish_verified_custody_call(custody, custody_context)?;
    custody_result?;
    verify_observation_bindings(
        &verified,
        &ingress,
        &active_decision,
        assignment,
        load_receipt,
        policy_authority_analysis,
        previous,
    )?;
    verify_result_matches_ingress(&verified.payload().result, ingress.payload())?;
    match &ingress.payload().facts_state {
        IngressFactsState::Captured {
            request_commitment,
        } => {
            let facts = protected_facts.ok_or(ShadowError::RequestCommitmentMismatch)?;
            request_commitment.validate_binding(
                assignment,
                &ingress.payload().runtime_identity,
                ingress.payload().ingress_sequence,
                ingress.payload().observed_at_unix_nanos,
            )?;
            if request_commitment.sampling_decision(
                assignment
                    .payload()
                    .observation_window
                    .sampling_basis_points,
            )? != ingress.payload().sampling_decision
            {
                return Err(ShadowError::IngressEvidenceMismatch);
            }
            commitment_verifier.verify(
                request_commitment,
                facts,
                assignment,
                &ingress.payload().runtime_identity,
                ingress.payload().ingress_sequence,
                ingress.payload().observed_at_unix_nanos,
            )?;
            verify_response_obligation(
                &verified.payload().result,
                facts,
                assignment,
            )?;
            verify_semantic_expansion_binding(
                &verified.payload().result,
                facts,
                policy_authority_analysis,
            )?;
        }
        IngressFactsState::Unavailable { .. } => {
            if protected_facts.is_some()
                || matches!(
                    &verified.payload().result,
                    ObservationResult::Evaluated { .. } | ObservationResult::Excluded { .. }
                )
            {
                return Err(ShadowError::ObservationShapeMismatch);
            }
        }
    }
    Ok(verified)
}

fn verify_observation_bindings(
    observation: &VerifiedObservation,
    ingress: &VerifiedIngressEvidence,
    active_decision: &VerifiedActiveDecision,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    previous: Option<&VerifiedObservation>,
) -> Result<(), ShadowError> {
    let payload = observation.payload();
    let ingress_payload = ingress.payload();
    let active_payload = active_decision.payload();
    let assignment_payload = assignment.payload();
    let receipt_payload = load_receipt.payload();
    let expected_generation = ShadowGenerationIdentity::derive(
        assignment,
        load_receipt,
    )?;
    if payload.ingress_evidence_sha256 != *ingress.envelope_sha256()
        || payload.active_decision_sha256 != *active_decision.envelope_sha256()
        || payload.assignment_sha256 != *assignment.envelope_sha256()
        || payload.assignment_payload_sha256 != *assignment.payload_sha256()
        || payload.assignment_revision != assignment_payload.assignment_revision
        || payload.authority_key_independence_sha256
            != assignment_payload
                .authority_key_independence
                .independence_root_sha256
        || payload.policy_authority_analysis_sha256
            != *policy_authority_analysis.envelope_sha256()
        || payload.policy_authority_analysis_payload_sha256
            != *policy_authority_analysis.payload_sha256()
        || payload.custody_receipt_evidence_requirements_sha256
            != policy_authority_analysis
                .payload()
                .custody_receipt_evidence_requirements_sha256
        || payload.load_receipt_sha256 != *load_receipt.envelope_sha256()
        || payload.load_receipt_payload_sha256 != *load_receipt.payload_sha256()
        || payload.canary_id != assignment_payload.canary_id
        || payload.fleet_id != assignment_payload.fleet.fleet_id
        || payload.fleet_membership_revision != assignment_payload.fleet.membership_revision
        || payload.policy_identity != assignment_payload.policy_identity
        || payload.runtime_identity != receipt_payload.runtime_identity
        || payload.generation != expected_generation
        || ingress_payload.assignment_sha256 != payload.assignment_sha256
        || ingress_payload.assignment_payload_sha256 != payload.assignment_payload_sha256
        || ingress_payload.assignment_revision != payload.assignment_revision
        || ingress_payload.canary_id != payload.canary_id
        || ingress_payload.fleet_id != payload.fleet_id
        || ingress_payload.fleet_membership_revision != payload.fleet_membership_revision
        || ingress_payload.runtime_identity != payload.runtime_identity
        || active_payload.assignment_sha256 != payload.assignment_sha256
        || active_payload.assignment_payload_sha256 != payload.assignment_payload_sha256
        || active_payload.assignment_revision != payload.assignment_revision
        || active_payload.authority_key_independence_sha256
            != payload.authority_key_independence_sha256
        || active_payload.policy_authority_analysis_sha256
            != payload.policy_authority_analysis_sha256
        || active_payload.policy_authority_analysis_payload_sha256
            != payload.policy_authority_analysis_payload_sha256
        || active_payload.custody_receipt_evidence_requirements_sha256
            != payload.custody_receipt_evidence_requirements_sha256
        || active_payload.load_receipt_sha256 != payload.load_receipt_sha256
        || active_payload.load_receipt_payload_sha256
            != payload.load_receipt_payload_sha256
        || active_payload.canary_id != payload.canary_id
        || active_payload.policy_identity != payload.policy_identity
        || active_payload.runtime_identity != payload.runtime_identity
        || active_payload.generation_id != payload.generation.generation_id
        || active_payload.ingress_evidence_sha256 != payload.ingress_evidence_sha256
        || active_payload.ingress_sequence != ingress_payload.ingress_sequence
        || active_payload.captured_at_unix_nanos
            != ingress_payload.observed_at_unix_nanos
        || active_payload.decision_at_unix_nanos
            < active_payload.captured_at_unix_nanos
        || ingress_payload.observed_at_unix_nanos
            < assignment_payload.observation_window.starts_at_unix_nanos
        || ingress_payload.observed_at_unix_nanos
            >= assignment_payload.observation_window.ends_at_unix_nanos
        || ingress_payload
            .issued_at_unix_nanos
            .saturating_sub(ingress_payload.observed_at_unix_nanos)
            > i64::try_from(
                assignment_payload
                    .observation_window
                    .maximum_evidence_age_nanos,
            )
            .map_err(|_| ShadowError::EvidenceTooOld)?
    {
        return Err(ShadowError::BindingDrift);
    }
    let active_matches = match (&payload.result, &active_payload.result) {
        (
            ObservationResult::Evaluated {
                pure_active_evaluation,
                final_active_enforcement,
                ..
            },
            ActiveDecisionResult::Finalized {
                pure_active_evaluation: signed_plan,
                effect_resolution: signed_enforcement,
            },
        ) => {
            pure_active_evaluation == signed_plan
                && final_active_enforcement == signed_enforcement
        }
        (
            ObservationResult::Error {
                terminal_reason,
                unavailable_marker_sha256,
                ..
            },
            ActiveDecisionResult::CaptureFailed {
                terminal_reason: signed_terminal_reason,
                unavailable_marker_sha256: signed_marker,
            }
            | ActiveDecisionResult::NotEvaluated {
                terminal_reason: signed_terminal_reason,
                unavailable_marker_sha256: signed_marker,
            },
        ) => {
            terminal_reason == signed_terminal_reason
                && unavailable_marker_sha256 == signed_marker
        }
        (
            ObservationResult::Dropped {
                reason,
                unavailable_marker_sha256,
                ..
            },
            ActiveDecisionResult::CandidateDropped {
                reason: signed_reason,
                unavailable_marker_sha256: signed_marker,
                ..
            },
        ) => reason == signed_reason && unavailable_marker_sha256 == signed_marker,
        (
            ObservationResult::Excluded {
                reason: ExclusionReason::DeterministicAssignmentSampling,
            },
            ActiveDecisionResult::SampledOut {
                accounting_record_sha256,
            },
        ) => accounting_record_sha256 == ingress.envelope_sha256(),
        (
            ObservationResult::TransportExcluded,
            ActiveDecisionResult::TransportExcluded {
                accounting_record_sha256,
            },
        ) => accounting_record_sha256 == ingress.envelope_sha256(),
        _ => false,
    };
    if !active_matches {
        return Err(ShadowError::ActiveDecisionEvidenceMismatch);
    }
    match previous {
        None => {
            if payload.observation_sequence != 1
                || payload.previous_observation_sha256
                    != payload.generation.generation_id
                || ingress_payload.ingress_sequence
                    != assignment_payload.observation_window.first_ingress_sequence
            {
                return Err(ShadowError::NonContiguousObservationSequence);
            }
        }
        Some(previous) => {
            if previous.payload().assignment_sha256
                != payload.assignment_sha256
                || previous.payload().assignment_payload_sha256
                    != payload.assignment_payload_sha256
                || previous.payload().assignment_revision
                    != payload.assignment_revision
                || previous
                    .payload()
                    .authority_key_independence_sha256
                    != payload.authority_key_independence_sha256
                || previous
                    .payload()
                    .policy_authority_analysis_sha256
                    != payload.policy_authority_analysis_sha256
                || previous
                    .payload()
                    .policy_authority_analysis_payload_sha256
                    != payload.policy_authority_analysis_payload_sha256
                || previous
                    .payload()
                    .custody_receipt_evidence_requirements_sha256
                    != payload
                        .custody_receipt_evidence_requirements_sha256
                || previous.payload().load_receipt_sha256
                    != payload.load_receipt_sha256
                || previous.payload().load_receipt_payload_sha256
                    != payload.load_receipt_payload_sha256
                || previous.payload().canary_id != payload.canary_id
                || previous.payload().policy_identity
                    != payload.policy_identity
                || previous.payload().runtime_identity
                    != payload.runtime_identity
                || previous.payload().generation != payload.generation
            {
                return Err(ShadowError::BindingDrift);
            }
            let expected_observation_sequence = previous
                .payload()
                .observation_sequence
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?;
            if payload.observation_sequence != expected_observation_sequence {
                return Err(ShadowError::NonContiguousObservationSequence);
            }
            if payload.previous_observation_sha256 != *previous.envelope_sha256() {
                return Err(ShadowError::PreviousObservationHashMismatch);
            }
            let previous_ingress = previous.payload().ingress_evidence.payload.ingress_sequence;
            let expected_ingress_sequence = previous_ingress
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?;
            if ingress_payload.ingress_sequence != expected_ingress_sequence
                || ingress_payload.observed_at_unix_nanos
                    < previous
                        .payload()
                        .ingress_evidence
                        .payload
                        .observed_at_unix_nanos
            {
                return Err(ShadowError::NonContiguousIngressSequence);
            }
        }
    }
    Ok(())
}

fn verify_result_matches_ingress(
    result: &ObservationResult,
    ingress: &IngressEvidencePayload,
) -> Result<(), ShadowError> {
    let matches = match (result, &ingress.accounting_outcome) {
        (ObservationResult::Evaluated { .. }, IngressAccountingOutcome::Evaluated) => true,
        (
            ObservationResult::Dropped {
                reason,
                unavailable_marker_sha256,
                ..
            },
            IngressAccountingOutcome::Dropped {
                reason: ingress_reason,
                unavailable_marker_sha256: ingress_marker,
            },
        ) => reason == ingress_reason && unavailable_marker_sha256 == ingress_marker,
        (
            ObservationResult::Error {
                terminal_reason,
                unavailable_marker_sha256,
                ..
            },
            IngressAccountingOutcome::Error {
                terminal_reason: ingress_terminal_reason,
                unavailable_marker_sha256: ingress_marker,
            },
        ) => {
            terminal_reason == ingress_terminal_reason
                && unavailable_marker_sha256 == ingress_marker
        }
        (
            ObservationResult::Excluded { reason },
            IngressAccountingOutcome::Excluded {
                reason: ingress_reason,
            },
        ) => reason == ingress_reason,
        (
            ObservationResult::TransportExcluded,
            IngressAccountingOutcome::TransportExcluded,
        ) => true,
        _ => false,
    };
    if !matches {
        return Err(ShadowError::IngressEvidenceMismatch);
    }
    if let IngressFactsState::Unavailable {
        unavailable_marker_sha256,
        ..
    } = &ingress.facts_state
    {
        match result {
            ObservationResult::Dropped {
                unavailable_marker_sha256: result_marker,
                ..
            }
            | ObservationResult::Error {
                unavailable_marker_sha256: result_marker,
                ..
            } if result_marker == unavailable_marker_sha256 => {}
            _ => return Err(ShadowError::IngressEvidenceMismatch),
        }
    }
    Ok(())
}

fn verify_response_obligation(
    result: &ObservationResult,
    facts: &ProtectedRequestFacts,
    assignment: &VerifiedAssignment,
) -> Result<(), ShadowError> {
    let route_sha256 = facts.route_sha256().clone();
    let expected = assignment
        .payload()
        .response_validation_obligations
        .iter()
        .find(|obligation| obligation.route_sha256 == route_sha256);
    match (expected, result) {
        (
            Some(obligation),
            ObservationResult::Evaluated {
                response_obligation: Some(ResponseObligationBinding::Applied {
                    route_sha256,
                    obligation_root_sha256,
                    active_constraints_root_sha256,
                    candidate_constraints_root_sha256,
                    exact_response_commitment_sha256,
                    applied_obligations_root_sha256,
                }),
                response_comparison,
                ..
            },
        ) if route_sha256 == &obligation.route_sha256
            && obligation_root_sha256 == &obligation.obligation_root_sha256
            && response_comparison.capture_mode == ResponseCaptureMode::BoundedExact
            && response_comparison.exact_response_commitment_sha256.as_ref()
                == Some(exact_response_commitment_sha256)
            && applied_obligations_root_sha256
                == &hash_domain_frames(
                    b"serverware.policyShadowAppliedResponseObligations/v1",
                    &[
                        obligation_root_sha256.as_str().as_bytes(),
                        active_constraints_root_sha256.as_str().as_bytes(),
                        candidate_constraints_root_sha256.as_str().as_bytes(),
                        exact_response_commitment_sha256.as_str().as_bytes(),
                    ],
                )
            && response_comparison.active_validation.as_ref().is_some_and(
                |validation| {
                    validation.response_constraints_root_sha256
                        == *active_constraints_root_sha256
                        && validation.policy_snapshot_sha256
                            == assignment
                                .payload()
                                .expected_loaded_snapshots
                                .active
                                .compiled_snapshot_sha256
                },
            )
            && response_comparison.candidate_validation.as_ref().is_some_and(
                |validation| {
                    validation.response_constraints_root_sha256
                        == *candidate_constraints_root_sha256
                        && validation.policy_snapshot_sha256
                            == assignment
                                .payload()
                                .expected_loaded_snapshots
                                .candidate
                                .compiled_snapshot_sha256
                },
            )
            && matches!(
                response_comparison.classification,
                ResponseComparisonClass::ComparableIdentical
                    | ResponseComparisonClass::ComparableValidationMatch
                    | ResponseComparisonClass::ComparableValidationDivergence
            ) => Ok(()),
        (
            Some(obligation),
            ObservationResult::Evaluated {
                pure_active_evaluation,
                final_active_enforcement,
                candidate_evaluation,
                response_obligation:
                    Some(ResponseObligationBinding::NotApplicableActiveNotDispatched {
                        route_sha256,
                        obligation_root_sha256,
                        active_outcome,
                        candidate_outcome,
                        not_applicable_sha256,
                    }),
                response_comparison,
                ..
            },
        ) if route_sha256 == &obligation.route_sha256
            && obligation_root_sha256 == &obligation.obligation_root_sha256
            && active_outcome == &pure_active_evaluation.outcome
            && candidate_outcome == &candidate_evaluation.outcome
            && !final_active_enforcement.upstream_dispatch_authorized
            && !matches!(
                final_active_enforcement.final_outcome,
                FinalEnforcementOutcome::Allow
            )
            && response_comparison.capture_mode == ResponseCaptureMode::NotDispatched
            && response_comparison.classification
                == ResponseComparisonClass::NotApplicableActiveNotDispatched
            && *not_applicable_sha256
                == hash_domain_frames(
                    b"serverware.policyShadowResponseObligationNotApplicable/v1",
                    &[&canonical_json_bytes(&(
                        route_sha256,
                        obligation_root_sha256,
                        active_outcome,
                        candidate_outcome,
                    ))?],
                ) => Ok(()),
        (
            None,
            ObservationResult::Evaluated {
                response_obligation: None,
                ..
            },
        ) => Ok(()),
        (Some(_), _) => Err(ShadowError::ResponseCoverageIncomplete),
        (None, ObservationResult::Evaluated { .. }) => {
            Err(ShadowError::ResponseCoverageIncomplete)
        }
        (None, _) => Ok(()),
    }
}

fn verify_semantic_expansion_binding(
    result: &ObservationResult,
    facts: &ProtectedRequestFacts,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
) -> Result<(), ShadowError> {
    if let ObservationResult::Evaluated {
        pure_active_evaluation,
        candidate_evaluation,
        authority_binding,
        derived_expansion,
        pilot_membership,
        ..
    } = result
    {
        let route_sha256 = facts.route_sha256.clone();
        if authority_binding.principal_sha256 != facts.principal_commitment
            || authority_binding.route_sha256 != route_sha256
            || authority_binding.operation != facts.operation
            || authority_binding.compiled_semantic_profile_sha256
                != facts.compiled_semantic_profile_sha256
            || authority_binding.request_authority_class
                != request_authority_class(facts.operation)
        {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        let authorized_cells = match &policy_authority_analysis
            .payload()
            .authority_analysis
        {
            AuthorityAnalysis::NoExpansion { expansion_cells }
            | AuthorityAnalysis::ApprovedExpansion {
                expansion_cells, ..
            } => expansion_cells,
        };
        let expected_cells = authorized_cells
            .iter()
            .filter(|cell| {
                cell.route_sha256 == authority_binding.route_sha256
                    && cell.operation == authority_binding.operation
                    && cell.compiled_semantic_profile_sha256
                        == authority_binding.compiled_semantic_profile_sha256
                    && cell.request_authority_class
                        == authority_binding.request_authority_class
                    && cell.active_outcome == pure_active_evaluation.outcome
                    && cell.candidate_outcome == candidate_evaluation.outcome
            })
            .cloned()
            .collect::<Vec<_>>();
        let expected_root = semantic_expansion_cells_root(&expected_cells)?;
        if derived_expansion.cells != expected_cells
            || derived_expansion.cells_root_sha256 != expected_root
        {
            return Err(ShadowError::ExpansionCellMismatch);
        }
        match (derived_expansion.cells.as_slice(), pilot_membership) {
            (cells, Some(membership)) if !cells.is_empty() => {
                let principal_leaf = hash_domain_frames(
                    b"serverware.policyPilotPrincipalLeaf/v1",
                    &[facts.principal_commitment.as_str().as_bytes()],
                );
                let route_leaf = hash_domain_frames(
                    b"serverware.policyPilotRouteLeaf/v1",
                    &[facts.route_sha256.as_str().as_bytes()],
                );
                let principal_root =
                    verify_membership_root(&principal_leaf, &membership.principal_proof)?;
                let route_root =
                    verify_membership_root(&route_leaf, &membership.route_proof)?;
                if cells.iter().any(|cell| {
                    cell.route_sha256 != route_sha256
                        || principal_root != cell.pilot_principal_set_root_sha256
                        || route_root != cell.pilot_route_set_root_sha256
                }) || membership.principal_leaf_sha256 != principal_leaf
                    || membership.route_leaf_sha256 != route_leaf
                {
                    return Err(ShadowError::ExpansionCellMismatch);
                }
            }
            ([], None) => {}
            _ => return Err(ShadowError::ExpansionCellMismatch),
        }
    }
    Ok(())
}

fn request_authority_class(operation: OperationClass) -> RequestAuthorityClass {
    match operation {
        OperationClass::Read | OperationClass::Search => RequestAuthorityClass::Read,
        OperationClass::Write
        | OperationClass::Publish
        | OperationClass::Delete
        | OperationClass::Administrative => RequestAuthorityClass::Write,
    }
}

fn verify_membership_root(
    leaf: &Sha256Digest,
    proof: &[MerkleProofStep],
) -> Result<Sha256Digest, ShadowError> {
    validate_len("pilot_membership.proof", proof.len(), 0, 64)?;
    let mut node = leaf.clone();
    for step in proof {
        let (left, right) = match step.sibling_side {
            MerkleSiblingSide::Left => (&step.sibling_sha256, &node),
            MerkleSiblingSide::Right => (&node, &step.sibling_sha256),
        };
        let left_bytes = left.raw_bytes()?;
        let right_bytes = right.raw_bytes()?;
        node = hash_domain_frames(
            b"serverware.policyPilotMembershipNode/v1",
            &[left_bytes.as_slice(), right_bytes.as_slice()],
        );
    }
    Ok(node)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservationTotals {
    ingress_admitted: u64,
    evaluated: u64,
    dropped: u64,
    errors: u64,
    excluded: u64,
    unavailable_evidence: u64,
    active_indeterminate: u64,
    unapproved_active_indeterminate: u64,
    candidate_indeterminate: u64,
    active_deny_candidate_permit: u64,
    active_deny_candidate_conditional: u64,
    active_conditional_candidate_permit: u64,
    active_indeterminate_candidate_permit: u64,
    active_indeterminate_candidate_conditional: u64,
    authority_expansion_observations: u64,
    authority_expansion_write_observations: u64,
    response_validation_divergence: u64,
    response_validator_unavailable: u64,
    response_noncomparable: u64,
    comparable_responses: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OutcomeCounters {
    deny_deny: u64,
    deny_permit: u64,
    deny_conditional: u64,
    deny_indeterminate: u64,
    permit_deny: u64,
    permit_permit: u64,
    permit_conditional: u64,
    permit_indeterminate: u64,
    conditional_deny: u64,
    conditional_permit: u64,
    conditional_conditional: u64,
    conditional_indeterminate: u64,
    indeterminate_deny: u64,
    indeterminate_permit: u64,
    indeterminate_conditional: u64,
    indeterminate_indeterminate: u64,
    total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ComparabilityCounters {
    comparable_identical: u64,
    comparable_validation_match: u64,
    comparable_validation_divergence: u64,
    not_applicable_active_not_dispatched: u64,
    not_comparable_candidate_not_dispatchable: u64,
    not_comparable_dispatch_commitment_mismatch: u64,
    not_comparable_active_response_unavailable: u64,
    not_comparable_candidate_validator_unavailable: u64,
    not_applicable_both_deny: u64,
    total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DropCounters {
    queue_full: u64,
    worker_unavailable: u64,
    deadline_exceeded: u64,
    facts_unsupported: u64,
    shutdown: u64,
    total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ErrorCounters {
    facts_capture_error: u64,
    active_evaluation_error: u64,
    candidate_evaluation_error: u64,
    response_validation_error: u64,
    commitment_error: u64,
    internal_error: u64,
    total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LatencyHistogram {
    nanos_0_to_99_999: u64,
    nanos_100_000_to_499_999: u64,
    nanos_500_000_to_999_999: u64,
    nanos_1_000_000_to_4_999_999: u64,
    nanos_5_000_000_to_9_999_999: u64,
    nanos_10_000_000_to_49_999_999: u64,
    nanos_50_000_000_to_99_999_999: u64,
    nanos_100_000_000_to_499_999_999: u64,
    nanos_500_000_000_to_999_999_999: u64,
    nanos_1_000_000_000_to_4_999_999_999: u64,
    nanos_5_000_000_000_or_more: u64,
    total: u64,
}

impl LatencyHistogram {
    fn observe(&mut self, nanos: u64) -> Result<(), ShadowError> {
        let target = match nanos {
            0..=99_999 => &mut self.nanos_0_to_99_999,
            100_000..=499_999 => &mut self.nanos_100_000_to_499_999,
            500_000..=999_999 => &mut self.nanos_500_000_to_999_999,
            1_000_000..=4_999_999 => &mut self.nanos_1_000_000_to_4_999_999,
            5_000_000..=9_999_999 => &mut self.nanos_5_000_000_to_9_999_999,
            10_000_000..=49_999_999 => &mut self.nanos_10_000_000_to_49_999_999,
            50_000_000..=99_999_999 => &mut self.nanos_50_000_000_to_99_999_999,
            100_000_000..=499_999_999 => &mut self.nanos_100_000_000_to_499_999_999,
            500_000_000..=999_999_999 => &mut self.nanos_500_000_000_to_999_999_999,
            1_000_000_000..=4_999_999_999 => {
                &mut self.nanos_1_000_000_000_to_4_999_999_999
            }
            _ => &mut self.nanos_5_000_000_000_or_more,
        };
        increment(target)?;
        increment(&mut self.total)
    }

    fn p99_upper_bound(&self) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let rank = (self.total.saturating_mul(99).saturating_add(99)) / 100;
        let buckets = [
            (self.nanos_0_to_99_999, 99_999),
            (self.nanos_100_000_to_499_999, 499_999),
            (self.nanos_500_000_to_999_999, 999_999),
            (self.nanos_1_000_000_to_4_999_999, 4_999_999),
            (self.nanos_5_000_000_to_9_999_999, 9_999_999),
            (self.nanos_10_000_000_to_49_999_999, 49_999_999),
            (self.nanos_50_000_000_to_99_999_999, 99_999_999),
            (
                self.nanos_100_000_000_to_499_999_999,
                499_999_999,
            ),
            (
                self.nanos_500_000_000_to_999_999_999,
                999_999_999,
            ),
            (
                self.nanos_1_000_000_000_to_4_999_999_999,
                4_999_999_999,
            ),
            (self.nanos_5_000_000_000_or_more, u64::MAX),
        ];
        let mut cumulative = 0_u64;
        for (count, upper) in buckets {
            cumulative = cumulative.saturating_add(count);
            if cumulative >= rank {
                return Some(upper);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LatencyHistograms {
    facts_capture: LatencyHistogram,
    active_evaluation: LatencyHistogram,
    candidate_evaluation: LatencyHistogram,
    response_validation: LatencyHistogram,
    shadow_total: LatencyHistogram,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExpansionCellCounter {
    cell_sha256: Sha256Digest,
    authority_expansion: AuthorityExpansionCell,
    route_sha256: Sha256Digest,
    operation: OperationClass,
    compiled_semantic_profile_sha256: Sha256Digest,
    request_authority_class: RequestAuthorityClass,
    active_outcome: OutcomeClass,
    candidate_outcome: OutcomeClass,
    request_count: u64,
    write_request_count: u64,
    response_count: u64,
    write_response_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResponseRouteCoverage {
    route_sha256: Sha256Digest,
    obligation_root_sha256: Sha256Digest,
    comparable_responses: u64,
    validation_divergences: u64,
    validator_unavailable: u64,
    noncomparable: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CumulativeCounters {
    totals: ObservationTotals,
    outcomes: OutcomeCounters,
    comparability: ComparabilityCounters,
    drops: DropCounters,
    errors: ErrorCounters,
    latency_histograms: LatencyHistograms,
    expansion_cells: Vec<ExpansionCellCounter>,
    response_route_coverage: Vec<ResponseRouteCoverage>,
}

impl CumulativeCounters {
    fn from_observations(records: &[VerifiedObservation]) -> Result<Self, ShadowError> {
        let mut counters = Self::default();
        let mut expansion_cells: BTreeMap<Sha256Digest, ExpansionCellCounter> =
            BTreeMap::new();
        let mut response_routes: BTreeMap<Sha256Digest, ResponseRouteCoverage> =
            BTreeMap::new();
        for record in records {
            increment(&mut counters.totals.ingress_admitted)?;
            match &record.payload().result {
                ObservationResult::Evaluated {
                    pure_active_evaluation,
                    final_active_enforcement: _,
                    candidate_evaluation,
                    authority_binding,
                    derived_expansion,
                    pilot_membership: _,
                    response_obligation,
                    response_comparison,
                    latency_samples,
                } => {
                    let observed_expansion_cells = &derived_expansion.cells;
                    increment(&mut counters.totals.evaluated)?;
                    observe_outcome(
                        &mut counters.outcomes,
                        pure_active_evaluation.outcome,
                        candidate_evaluation.outcome,
                    )?;
                    observe_comparability(
                        &mut counters.comparability,
                        response_comparison.classification,
                    )?;
                    if candidate_evaluation.outcome == OutcomeClass::Indeterminate {
                        increment(&mut counters.totals.candidate_indeterminate)?;
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Indeterminate {
                        increment(&mut counters.totals.active_indeterminate)?;
                        if observed_expansion_cells.is_empty() {
                            increment(
                                &mut counters
                                    .totals
                                    .unapproved_active_indeterminate,
                            )?;
                        }
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Deny
                        && candidate_evaluation.outcome == OutcomeClass::Permit
                    {
                        increment(&mut counters.totals.active_deny_candidate_permit)?;
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Deny
                        && candidate_evaluation.outcome == OutcomeClass::Conditional
                    {
                        increment(
                            &mut counters
                                .totals
                                .active_deny_candidate_conditional,
                        )?;
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Conditional
                        && candidate_evaluation.outcome == OutcomeClass::Permit
                    {
                        increment(
                            &mut counters
                                .totals
                                .active_conditional_candidate_permit,
                        )?;
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Indeterminate
                        && candidate_evaluation.outcome == OutcomeClass::Permit
                    {
                        increment(
                            &mut counters
                                .totals
                                .active_indeterminate_candidate_permit,
                        )?;
                    }
                    if pure_active_evaluation.outcome == OutcomeClass::Indeterminate
                        && candidate_evaluation.outcome == OutcomeClass::Conditional
                    {
                        increment(
                            &mut counters
                                .totals
                                .active_indeterminate_candidate_conditional,
                        )?;
                    }
                    if !observed_expansion_cells.is_empty() {
                        increment(
                            &mut counters.totals.authority_expansion_observations,
                        )?;
                        if authority_binding.request_authority_class
                            == RequestAuthorityClass::Write
                            || observed_expansion_cells.iter().any(|cell| {
                                cell.request_authority_class == RequestAuthorityClass::Write
                            })
                        {
                            increment(
                                &mut counters
                                    .totals
                                    .authority_expansion_write_observations,
                            )?;
                        }
                    }
                    for cell in observed_expansion_cells {
                        let entry = expansion_cells
                            .entry(cell.cell_sha256.clone())
                            .or_insert_with(|| ExpansionCellCounter {
                                cell_sha256: cell.cell_sha256.clone(),
                                authority_expansion: cell.authority_expansion,
                                route_sha256: cell.route_sha256.clone(),
                                operation: cell.operation,
                                compiled_semantic_profile_sha256: cell
                                    .compiled_semantic_profile_sha256
                                    .clone(),
                                request_authority_class: cell.request_authority_class,
                                active_outcome: cell.active_outcome,
                                candidate_outcome: cell.candidate_outcome,
                                request_count: 0,
                                write_request_count: 0,
                                response_count: 0,
                                write_response_count: 0,
                            });
                        if entry.authority_expansion != cell.authority_expansion
                            || entry.route_sha256 != cell.route_sha256
                            || entry.operation != cell.operation
                            || entry.compiled_semantic_profile_sha256
                                != cell.compiled_semantic_profile_sha256
                            || entry.request_authority_class
                                != cell.request_authority_class
                            || entry.active_outcome != cell.active_outcome
                            || entry.candidate_outcome != cell.candidate_outcome
                        {
                            return Err(ShadowError::ExpansionCellMismatch);
                        }
                        increment(&mut entry.request_count)?;
                        if cell.request_authority_class == RequestAuthorityClass::Write {
                            increment(&mut entry.write_request_count)?;
                        }
                        if matches!(
                            response_comparison.classification,
                            ResponseComparisonClass::ComparableIdentical
                                | ResponseComparisonClass::ComparableValidationMatch
                                | ResponseComparisonClass::ComparableValidationDivergence
                        ) {
                            increment(&mut entry.response_count)?;
                            if cell.request_authority_class == RequestAuthorityClass::Write {
                                increment(&mut entry.write_response_count)?;
                            }
                        }
                        if expansion_cells.len() > MAX_EXPANSION_CELLS {
                            return Err(ShadowError::EvidenceBudgetExceeded);
                        }
                    }
                    if response_comparison.classification
                        == ResponseComparisonClass::ComparableValidationDivergence
                    {
                        increment(&mut counters.totals.response_validation_divergence)?;
                    }
                    if response_comparison.classification
                        == ResponseComparisonClass::NotComparableCandidateValidatorUnavailable
                    {
                        increment(&mut counters.totals.response_validator_unavailable)?;
                    }
                    if matches!(
                        response_comparison.classification,
                        ResponseComparisonClass::NotComparableCandidateNotDispatchable
                            | ResponseComparisonClass::NotComparableDispatchCommitmentMismatch
                            | ResponseComparisonClass::NotComparableActiveResponseUnavailable
                            | ResponseComparisonClass::NotComparableCandidateValidatorUnavailable
                    ) {
                        increment(&mut counters.totals.response_noncomparable)?;
                    }
                    if matches!(
                        response_comparison.classification,
                        ResponseComparisonClass::ComparableIdentical
                            | ResponseComparisonClass::ComparableValidationMatch
                            | ResponseComparisonClass::ComparableValidationDivergence
                    ) {
                        increment(&mut counters.totals.comparable_responses)?;
                    }
                    if let Some(binding) = response_obligation {
                        let route_sha256 = binding.route_sha256().clone();
                        let obligation_root_sha256 =
                            binding.obligation_root_sha256().clone();
                        let route = response_routes
                            .entry(route_sha256.clone())
                            .or_insert_with(|| ResponseRouteCoverage {
                                route_sha256,
                                obligation_root_sha256:
                                    obligation_root_sha256.clone(),
                                comparable_responses: 0,
                                validation_divergences: 0,
                                validator_unavailable: 0,
                                noncomparable: 0,
                            });
                        if route.obligation_root_sha256
                            != obligation_root_sha256
                        {
                            return Err(ShadowError::ResponseCoverageIncomplete);
                        }
                        match response_comparison.classification {
                            ResponseComparisonClass::ComparableIdentical
                            | ResponseComparisonClass::ComparableValidationMatch => {
                                increment(&mut route.comparable_responses)?
                            }
                            ResponseComparisonClass::ComparableValidationDivergence => {
                                increment(&mut route.comparable_responses)?;
                                increment(&mut route.validation_divergences)?;
                            }
                            ResponseComparisonClass::NotComparableCandidateValidatorUnavailable => {
                                increment(&mut route.validator_unavailable)?
                            }
                            ResponseComparisonClass::NotApplicableActiveNotDispatched
                            | ResponseComparisonClass::NotApplicableBothDeny => {}
                            _ => increment(&mut route.noncomparable)?,
                        }
                        if response_routes.len() > MAX_RESPONSE_OBLIGATIONS {
                            return Err(ShadowError::EvidenceBudgetExceeded);
                        }
                    }
                    observe_latency(&mut counters.latency_histograms, latency_samples)?;
                }
                ObservationResult::Dropped {
                    reason,
                    latency_samples,
                    ..
                } => {
                    increment(&mut counters.totals.dropped)?;
                    observe_drop(&mut counters.drops, *reason)?;
                    observe_latency(&mut counters.latency_histograms, latency_samples)?;
                }
                ObservationResult::Error {
                    terminal_reason,
                    latency_samples,
                    ..
                } => {
                    increment(&mut counters.totals.errors)?;
                    observe_error(&mut counters.errors, *terminal_reason)?;
                    observe_latency(&mut counters.latency_histograms, latency_samples)?;
                }
                ObservationResult::Excluded { .. } | ObservationResult::TransportExcluded => {
                    increment(&mut counters.totals.excluded)?;
                }
            }
            if matches!(
                &record.payload().ingress_evidence.payload.facts_state,
                IngressFactsState::Unavailable { .. }
            ) {
                increment(&mut counters.totals.unavailable_evidence)?;
            }
        }
        counters.expansion_cells = expansion_cells.into_values().collect();
        counters.response_route_coverage = response_routes.into_values().collect();
        Ok(counters)
    }
}

fn observe_outcome(
    counters: &mut OutcomeCounters,
    active: OutcomeClass,
    candidate: OutcomeClass,
) -> Result<(), ShadowError> {
    let target = match (active, candidate) {
        (OutcomeClass::Deny, OutcomeClass::Deny) => &mut counters.deny_deny,
        (OutcomeClass::Deny, OutcomeClass::Permit) => &mut counters.deny_permit,
        (OutcomeClass::Deny, OutcomeClass::Conditional) => &mut counters.deny_conditional,
        (OutcomeClass::Deny, OutcomeClass::Indeterminate) => &mut counters.deny_indeterminate,
        (OutcomeClass::Permit, OutcomeClass::Deny) => &mut counters.permit_deny,
        (OutcomeClass::Permit, OutcomeClass::Permit) => &mut counters.permit_permit,
        (OutcomeClass::Permit, OutcomeClass::Conditional) => &mut counters.permit_conditional,
        (OutcomeClass::Permit, OutcomeClass::Indeterminate) => {
            &mut counters.permit_indeterminate
        }
        (OutcomeClass::Conditional, OutcomeClass::Deny) => &mut counters.conditional_deny,
        (OutcomeClass::Conditional, OutcomeClass::Permit) => &mut counters.conditional_permit,
        (OutcomeClass::Conditional, OutcomeClass::Conditional) => {
            &mut counters.conditional_conditional
        }
        (OutcomeClass::Conditional, OutcomeClass::Indeterminate) => {
            &mut counters.conditional_indeterminate
        }
        (OutcomeClass::Indeterminate, OutcomeClass::Deny) => &mut counters.indeterminate_deny,
        (OutcomeClass::Indeterminate, OutcomeClass::Permit) => {
            &mut counters.indeterminate_permit
        }
        (OutcomeClass::Indeterminate, OutcomeClass::Conditional) => {
            &mut counters.indeterminate_conditional
        }
        (OutcomeClass::Indeterminate, OutcomeClass::Indeterminate) => {
            &mut counters.indeterminate_indeterminate
        }
    };
    increment(target)?;
    increment(&mut counters.total)
}

fn observe_comparability(
    counters: &mut ComparabilityCounters,
    class: ResponseComparisonClass,
) -> Result<(), ShadowError> {
    let target = match class {
        ResponseComparisonClass::ComparableIdentical => &mut counters.comparable_identical,
        ResponseComparisonClass::ComparableValidationMatch => {
            &mut counters.comparable_validation_match
        }
        ResponseComparisonClass::ComparableValidationDivergence => {
            &mut counters.comparable_validation_divergence
        }
        ResponseComparisonClass::NotApplicableActiveNotDispatched => {
            &mut counters.not_applicable_active_not_dispatched
        }
        ResponseComparisonClass::NotComparableCandidateNotDispatchable => {
            &mut counters.not_comparable_candidate_not_dispatchable
        }
        ResponseComparisonClass::NotComparableDispatchCommitmentMismatch => {
            &mut counters.not_comparable_dispatch_commitment_mismatch
        }
        ResponseComparisonClass::NotComparableActiveResponseUnavailable => {
            &mut counters.not_comparable_active_response_unavailable
        }
        ResponseComparisonClass::NotComparableCandidateValidatorUnavailable => {
            &mut counters.not_comparable_candidate_validator_unavailable
        }
        ResponseComparisonClass::NotApplicableBothDeny => {
            &mut counters.not_applicable_both_deny
        }
    };
    increment(target)?;
    increment(&mut counters.total)
}

fn observe_drop(counters: &mut DropCounters, reason: DropReason) -> Result<(), ShadowError> {
    let target = match reason {
        DropReason::QueueFull => &mut counters.queue_full,
        DropReason::WorkerUnavailable => &mut counters.worker_unavailable,
        DropReason::DeadlineExceeded => &mut counters.deadline_exceeded,
        DropReason::FactsUnsupported => &mut counters.facts_unsupported,
        DropReason::Shutdown => &mut counters.shutdown,
    };
    increment(target)?;
    increment(&mut counters.total)
}

fn observe_error(
    counters: &mut ErrorCounters,
    reason: PolicyShadowTerminalReason,
) -> Result<(), ShadowError> {
    let target = match reason {
        PolicyShadowTerminalReason::FactsCaptureError => &mut counters.facts_capture_error,
        PolicyShadowTerminalReason::ActiveEvaluationError => {
            &mut counters.active_evaluation_error
        }
        PolicyShadowTerminalReason::CandidateEvaluationError => {
            &mut counters.candidate_evaluation_error
        }
        PolicyShadowTerminalReason::ResponseValidationError => {
            &mut counters.response_validation_error
        }
        PolicyShadowTerminalReason::CommitmentError => &mut counters.commitment_error,
        PolicyShadowTerminalReason::InternalError => &mut counters.internal_error,
        _ => return Err(ShadowError::ObservationShapeMismatch),
    };
    increment(target)?;
    increment(&mut counters.total)
}

fn observe_latency(
    histograms: &mut LatencyHistograms,
    samples: &LatencySamples,
) -> Result<(), ShadowError> {
    if let Some(value) = samples.facts_capture_nanos {
        histograms.facts_capture.observe(value)?;
    }
    if let Some(value) = samples.active_evaluation_nanos {
        histograms.active_evaluation.observe(value)?;
    }
    if let Some(value) = samples.candidate_evaluation_nanos {
        histograms.candidate_evaluation.observe(value)?;
    }
    if let Some(value) = samples.response_validation_nanos {
        histograms.response_validation.observe(value)?;
    }
    if let Some(value) = samples.shadow_total_nanos {
        histograms.shadow_total.observe(value)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CumulativeObservationRange {
    #[serde(deserialize_with = "deserialize_required_nullable")]
    first_observation_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_observation_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    first_observation_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_observation_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    first_ingress_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_evidence_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    first_observed_at_unix_nanos: Option<i64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_observed_at_unix_nanos: Option<i64>,
    observation_count: u64,
    ingress_count: u64,
    verified_evidence_bytes: u64,
    verification_work_units: u64,
    cumulative_observation_root_sha256: Sha256Digest,
    cumulative_ingress_root_sha256: Sha256Digest,
    cumulative_active_decision_root_sha256: Sha256Digest,
    cumulative_principal_authority_root_sha256: Sha256Digest,
    cumulative_route_authority_root_sha256: Sha256Digest,
    cumulative_custody_evidence_root_sha256: Sha256Digest,
    cumulative_admitted_ingress_receipt_root_sha256: Sha256Digest,
    cumulative_unavailable_ingress_receipt_root_sha256: Sha256Digest,
    cumulative_dispatch_barrier_receipt_root_sha256: Sha256Digest,
    cumulative_active_effect_barrier_receipt_root_sha256: Sha256Digest,
    cumulative_active_effect_commit_receipt_root_sha256: Sha256Digest,
    cumulative_terminal_receipt_count: u64,
    cumulative_terminal_receipt_root_sha256: Sha256Digest,
    cumulative_publication_receipt_count: u64,
    cumulative_publication_receipt_root_sha256: Sha256Digest,
    cumulative_spill_receipt_root_sha256: Sha256Digest,
    cumulative_persistence_receipt_root_sha256: Sha256Digest,
    cumulative_retrieval_proof_root_sha256: Sha256Digest,
    cumulative_compaction_receipt_root_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ledger_event_ordinal: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ledger_head_sha256: Option<Sha256Digest>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_spool_root_sha256: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ShadowHeartbeatPayload {
    heartbeat_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    runtime_identity: RuntimeIdentity,
    generation_id: Sha256Digest,
    heartbeat_sequence: u64,
    previous_heartbeat_sha256: Sha256Digest,
    ingress_state: HeartbeatIngressState,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_evidence_sha256: Option<Sha256Digest>,
    observed_at_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HeartbeatIngressState {
    NoIngress,
    Observed,
}

impl EnvelopePayload for ShadowHeartbeatPayload {
    const API_VERSION: &'static str = HEARTBEAT_DOMAIN;
    const KIND: &'static str = "PolicyShadowHeartbeat";
    const SIGNATURE_DOMAIN: &'static str = HEARTBEAT_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "heartbeat.assignment_revision")?;
        validate_positive(self.heartbeat_sequence, "heartbeat.heartbeat_sequence")?;
        validate_positive(
            self.ingress_range_start_sequence,
            "heartbeat.ingress_range_start_sequence",
        )?;
        match (
            self.ingress_state,
            self.last_ingress_sequence,
            self.last_ingress_evidence_sha256.as_ref(),
        ) {
            (HeartbeatIngressState::NoIngress, None, None) => {}
            (HeartbeatIngressState::Observed, Some(sequence), Some(_)) => {
                validate_positive(
                    sequence,
                    "heartbeat.last_ingress_sequence",
                )?;
                if sequence < self.ingress_range_start_sequence {
                    return Err(ShadowError::SealInvalid);
                }
            }
            _ => return Err(ShadowError::SealInvalid),
        }
        if self.observed_at_unix_nanos != self.issued_at_unix_nanos
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err(ShadowError::SealInvalid);
        }
        Ok(())
    }
}

pub(crate) type VerifiedShadowHeartbeat =
    VerifiedSignedEnvelope<ShadowHeartbeatPayload>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CumulativeHeartbeatRange {
    first_heartbeat_sequence: u64,
    last_heartbeat_sequence: u64,
    heartbeat_count: u64,
    first_heartbeat_at_unix_nanos: i64,
    last_heartbeat_at_unix_nanos: i64,
    maximum_observed_gap_nanos: u64,
    cumulative_heartbeat_root_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WindowClosurePayload {
    closure_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    runtime_identity: RuntimeIdentity,
    window_ends_at_unix_nanos: i64,
    ingress_state: HeartbeatIngressState,
    ingress_range_start_sequence: u64,
    ingress_range_predecessor_head_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_sequence: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    last_ingress_evidence_sha256: Option<Sha256Digest>,
    last_heartbeat_sequence: u64,
    cumulative_heartbeat_root_sha256: Sha256Digest,
    closed_at_unix_nanos: i64,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for WindowClosurePayload {
    const API_VERSION: &'static str = WINDOW_CLOSURE_DOMAIN;
    const KIND: &'static str = "PolicyShadowWindowClosure";
    const SIGNATURE_DOMAIN: &'static str = WINDOW_CLOSURE_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(
            self.ingress_range_start_sequence,
            "ingress_range_start_sequence",
        )?;
        validate_positive(self.last_heartbeat_sequence, "last_heartbeat_sequence")?;
        match (
            self.ingress_state,
            self.last_ingress_sequence,
            self.last_ingress_evidence_sha256.as_ref(),
        ) {
            (HeartbeatIngressState::NoIngress, None, None) => {}
            (HeartbeatIngressState::Observed, Some(sequence), Some(_)) => {
                validate_positive(sequence, "last_ingress_sequence")?;
                if sequence < self.ingress_range_start_sequence {
                    return Err(ShadowError::SealInvalid);
                }
            }
            _ => return Err(ShadowError::SealInvalid),
        }
        if self.closed_at_unix_nanos < self.window_ends_at_unix_nanos
            || self.issued_at_unix_nanos != self.closed_at_unix_nanos
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err(ShadowError::SealInvalid);
        }
        Ok(())
    }
}

impl WindowClosurePayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new_unsigned(
        closure_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        runtime_identity: RuntimeIdentity,
        window_ends_at_unix_nanos: i64,
        ingress_state: HeartbeatIngressState,
        ingress_range_start_sequence: u64,
        ingress_range_predecessor_head_sha256: Sha256Digest,
        last_ingress_sequence: Option<u64>,
        last_ingress_evidence_sha256: Option<Sha256Digest>,
        last_heartbeat_sequence: u64,
        cumulative_heartbeat_root_sha256: Sha256Digest,
        closed_at_unix_nanos: i64,
        expires_at_unix_nanos: i64,
    ) -> Result<Self, ShadowError> {
        let payload = Self {
            closure_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            runtime_identity,
            window_ends_at_unix_nanos,
            ingress_state,
            ingress_range_start_sequence,
            ingress_range_predecessor_head_sha256,
            last_ingress_sequence,
            last_ingress_evidence_sha256,
            last_heartbeat_sequence,
            cumulative_heartbeat_root_sha256,
            closed_at_unix_nanos,
            issued_at_unix_nanos: closed_at_unix_nanos,
            expires_at_unix_nanos,
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CheckpointSeal {
    Open,
    Sealed {
        sealed_at_unix_nanos: i64,
        window_closure_sha256: Sha256Digest,
        window_closure: SignedEnvelope<WindowClosurePayload>,
        seal_root_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyShadowCheckpointPayload {
    checkpoint_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    generation: ShadowGenerationIdentity,
    checkpoint_sequence: u64,
    previous_checkpoint_sha256: Sha256Digest,
    previous_cumulative_observation_root_sha256: Sha256Digest,
    previous_cumulative_ingress_root_sha256: Sha256Digest,
    previous_cumulative_active_decision_root_sha256: Sha256Digest,
    previous_cumulative_custody_evidence_root_sha256: Sha256Digest,
    previous_cumulative_terminal_receipt_root_sha256: Sha256Digest,
    previous_cumulative_publication_receipt_root_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    created_at_unix_nanos: i64,
    cumulative_range: CumulativeObservationRange,
    cumulative_heartbeats: CumulativeHeartbeatRange,
    cumulative_counters: CumulativeCounters,
    seal: CheckpointSeal,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

/// Builds only unsigned checkpoint payloads. Cumulative range, roots, and all
/// counters are derived from verified observations and cannot be caller-set.
/// The heartbeat range accompanies separately signed heartbeats and is
/// independently reconstructed by `verify_checkpoint` before it can count.
pub(crate) struct UnsignedCheckpointPayloadBuilder<'a> {
    checkpoint_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    fleet_id: Sha256Digest,
    fleet_membership_revision: u64,
    policy_identity: PolicyIdentity,
    runtime_identity: RuntimeIdentity,
    generation: ShadowGenerationIdentity,
    checkpoint_sequence: u64,
    previous_checkpoint_sha256: Sha256Digest,
    previous_cumulative_observation_root_sha256: Sha256Digest,
    previous_cumulative_ingress_root_sha256: Sha256Digest,
    previous_cumulative_active_decision_root_sha256: Sha256Digest,
    previous_cumulative_custody_evidence_root_sha256: Sha256Digest,
    previous_cumulative_terminal_receipt_root_sha256: Sha256Digest,
    previous_cumulative_publication_receipt_root_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    created_at_unix_nanos: i64,
    cumulative_observations: &'a [VerifiedObservation],
    cumulative_heartbeats: CumulativeHeartbeatRange,
    seal: CheckpointSeal,
    expires_at_unix_nanos: i64,
}

impl<'a> UnsignedCheckpointPayloadBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: Sha256Digest,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        authority_key_independence_sha256: Sha256Digest,
        policy_authority_analysis_sha256: Sha256Digest,
        policy_authority_analysis_payload_sha256: Sha256Digest,
        custody_receipt_evidence_requirements_sha256: Sha256Digest,
        load_receipt_sha256: Sha256Digest,
        load_receipt_payload_sha256: Sha256Digest,
        canary_id: Sha256Digest,
        fleet_id: Sha256Digest,
        fleet_membership_revision: u64,
        policy_identity: PolicyIdentity,
        runtime_identity: RuntimeIdentity,
        generation: ShadowGenerationIdentity,
        checkpoint_sequence: u64,
        previous_checkpoint_sha256: Sha256Digest,
        previous_cumulative_observation_root_sha256: Sha256Digest,
        previous_cumulative_ingress_root_sha256: Sha256Digest,
        previous_cumulative_active_decision_root_sha256: Sha256Digest,
        previous_cumulative_custody_evidence_root_sha256: Sha256Digest,
        previous_cumulative_terminal_receipt_root_sha256: Sha256Digest,
        previous_cumulative_publication_receipt_root_sha256: Sha256Digest,
        publication_reconciliation_receipt_sha256: Sha256Digest,
        publication_revision: u64,
        created_at_unix_nanos: i64,
        cumulative_observations: &'a [VerifiedObservation],
        cumulative_heartbeats: CumulativeHeartbeatRange,
        seal: CheckpointSeal,
        expires_at_unix_nanos: i64,
    ) -> Self {
        Self {
            checkpoint_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            authority_key_independence_sha256,
            policy_authority_analysis_sha256,
            policy_authority_analysis_payload_sha256,
            custody_receipt_evidence_requirements_sha256,
            load_receipt_sha256,
            load_receipt_payload_sha256,
            canary_id,
            fleet_id,
            fleet_membership_revision,
            policy_identity,
            runtime_identity,
            generation,
            checkpoint_sequence,
            previous_checkpoint_sha256,
            previous_cumulative_observation_root_sha256,
            previous_cumulative_ingress_root_sha256,
            previous_cumulative_active_decision_root_sha256,
            previous_cumulative_custody_evidence_root_sha256,
            previous_cumulative_terminal_receipt_root_sha256,
            previous_cumulative_publication_receipt_root_sha256,
            publication_reconciliation_receipt_sha256,
            publication_revision,
            created_at_unix_nanos,
            cumulative_observations,
            cumulative_heartbeats,
            seal,
            expires_at_unix_nanos,
        }
    }

    pub fn build(self) -> Result<PolicyShadowCheckpointPayload, ShadowError> {
        let payload = PolicyShadowCheckpointPayload {
            checkpoint_id: self.checkpoint_id,
            assignment_sha256: self.assignment_sha256,
            assignment_payload_sha256: self.assignment_payload_sha256,
            assignment_revision: self.assignment_revision,
            authority_key_independence_sha256:
                self.authority_key_independence_sha256,
            policy_authority_analysis_sha256:
                self.policy_authority_analysis_sha256,
            policy_authority_analysis_payload_sha256:
                self.policy_authority_analysis_payload_sha256,
            custody_receipt_evidence_requirements_sha256:
                self.custody_receipt_evidence_requirements_sha256,
            load_receipt_sha256: self.load_receipt_sha256,
            load_receipt_payload_sha256: self.load_receipt_payload_sha256,
            canary_id: self.canary_id,
            fleet_id: self.fleet_id,
            fleet_membership_revision: self.fleet_membership_revision,
            policy_identity: self.policy_identity,
            runtime_identity: self.runtime_identity,
            generation: self.generation,
            checkpoint_sequence: self.checkpoint_sequence,
            previous_checkpoint_sha256: self.previous_checkpoint_sha256,
            previous_cumulative_observation_root_sha256: self
                .previous_cumulative_observation_root_sha256,
            previous_cumulative_ingress_root_sha256: self
                .previous_cumulative_ingress_root_sha256,
            previous_cumulative_active_decision_root_sha256: self
                .previous_cumulative_active_decision_root_sha256,
            previous_cumulative_custody_evidence_root_sha256: self
                .previous_cumulative_custody_evidence_root_sha256,
            previous_cumulative_terminal_receipt_root_sha256: self
                .previous_cumulative_terminal_receipt_root_sha256,
            previous_cumulative_publication_receipt_root_sha256: self
                .previous_cumulative_publication_receipt_root_sha256,
            publication_reconciliation_receipt_sha256: self
                .publication_reconciliation_receipt_sha256,
            publication_revision: self.publication_revision,
            created_at_unix_nanos: self.created_at_unix_nanos,
            cumulative_range: recompute_cumulative_range(self.cumulative_observations)?,
            cumulative_heartbeats: self.cumulative_heartbeats,
            cumulative_counters: CumulativeCounters::from_observations(
                self.cumulative_observations,
            )?,
            seal: self.seal,
            issued_at_unix_nanos: self.created_at_unix_nanos,
            expires_at_unix_nanos: self.expires_at_unix_nanos,
        };
        payload.validate_intrinsic()?;
        Ok(payload)
    }
}

impl PolicyShadowCheckpointPayload {
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    pub fn cumulative_range(&self) -> &CumulativeObservationRange {
        &self.cumulative_range
    }

    pub fn cumulative_counters(&self) -> &CumulativeCounters {
        &self.cumulative_counters
    }

    pub fn is_sealed(&self) -> bool {
        matches!(&self.seal, CheckpointSeal::Sealed { .. })
    }
}

impl EnvelopePayload for PolicyShadowCheckpointPayload {
    const API_VERSION: &'static str = CHECKPOINT_DOMAIN;
    const KIND: &'static str = "PolicyShadowCheckpoint";
    const SIGNATURE_DOMAIN: &'static str = CHECKPOINT_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(self.checkpoint_sequence, "checkpoint_sequence")?;
        validate_positive(
            self.publication_revision,
            "publication_revision",
        )?;
        validate_positive(
            self.fleet_membership_revision,
            "fleet_membership_revision",
        )?;
        validate_positive(
            self.cumulative_heartbeats.heartbeat_count,
            "heartbeat_count",
        )?;
        validate_positive(
            self.cumulative_heartbeats.first_heartbeat_sequence,
            "first_heartbeat_sequence",
        )?;
        validate_positive(
            self.cumulative_heartbeats.last_heartbeat_sequence,
            "last_heartbeat_sequence",
        )?;
        if self.cumulative_range.observation_count
                > MAX_CUMULATIVE_OBSERVATIONS as u64
            || self.cumulative_range.ingress_count
                != self.cumulative_range.observation_count
            || self.cumulative_range.verified_evidence_bytes
                > MAX_CUMULATIVE_EVIDENCE_BYTES
            || self.cumulative_range.verification_work_units
                > MAX_VERIFICATION_WORK_UNITS
            || self.cumulative_heartbeats.last_heartbeat_sequence
                .checked_sub(
                    self.cumulative_heartbeats.first_heartbeat_sequence,
                )
                .and_then(|delta| delta.checked_add(1))
                != Some(self.cumulative_heartbeats.heartbeat_count)
            || self.cumulative_heartbeats.first_heartbeat_at_unix_nanos
                > self.cumulative_heartbeats.last_heartbeat_at_unix_nanos
        {
            return Err(ShadowError::EvidenceBudgetExceeded);
        }
        let empty_root = merkle_root(&[])?;
        if self.cumulative_range.observation_count == 0 {
            if self.cumulative_range.first_observation_sequence.is_some()
                || self.cumulative_range.last_observation_sequence.is_some()
                || self.cumulative_range.first_observation_sha256.is_some()
                || self.cumulative_range.last_observation_sha256.is_some()
                || self.cumulative_range.first_ingress_sequence.is_some()
                || self.cumulative_range.last_ingress_sequence.is_some()
                || self
                    .cumulative_range
                    .last_ingress_evidence_sha256
                    .is_some()
                || self.cumulative_range.first_observed_at_unix_nanos.is_some()
                || self.cumulative_range.last_observed_at_unix_nanos.is_some()
                || self.cumulative_range.verified_evidence_bytes != 0
                || self.cumulative_range.verification_work_units != 0
                || self.cumulative_range.cumulative_observation_root_sha256
                    != empty_root
                || self.cumulative_range.cumulative_ingress_root_sha256
                    != empty_root
                || self
                    .cumulative_range
                    .cumulative_active_decision_root_sha256
                    != empty_root
                || self
                    .cumulative_range
                    .cumulative_principal_authority_root_sha256
                    != empty_root
                || self
                    .cumulative_range
                    .cumulative_route_authority_root_sha256
                    != empty_root
                || self
                    .cumulative_range
                    .cumulative_terminal_receipt_count
                    != 0
                || self
                    .cumulative_range
                    .cumulative_terminal_receipt_root_sha256
                    != empty_root
                || self
                    .cumulative_range
                    .cumulative_publication_receipt_count
                    != 0
                || self
                    .cumulative_range
                    .cumulative_publication_receipt_root_sha256
                    != empty_root
                || self.cumulative_counters != CumulativeCounters::default()
            {
                return Err(ShadowError::CounterMismatch);
            }
        } else if self.cumulative_range.first_observation_sequence.is_none()
            || self.cumulative_range.last_observation_sequence.is_none()
            || self.cumulative_range.first_observation_sha256.is_none()
            || self.cumulative_range.last_observation_sha256.is_none()
            || self.cumulative_range.first_ingress_sequence.is_none()
            || self.cumulative_range.last_ingress_sequence.is_none()
            || self
                .cumulative_range
                .last_ingress_evidence_sha256
                .is_none()
            || self.cumulative_range.first_observed_at_unix_nanos.is_none()
            || self.cumulative_range.last_observed_at_unix_nanos.is_none()
            || self.cumulative_range.verified_evidence_bytes == 0
            || self.cumulative_range.verification_work_units == 0
            || self.cumulative_range.cumulative_terminal_receipt_count
                < self.cumulative_range.ingress_count
            || self
                .cumulative_range
                .cumulative_publication_receipt_count
                == 0
        {
            return Err(ShadowError::CounterMismatch);
        }
        validate_len(
            "checkpoint.expansion_cells",
            self.cumulative_counters.expansion_cells.len(),
            0,
            MAX_EXPANSION_CELLS,
        )?;
        validate_len(
            "checkpoint.response_route_coverage",
            self.cumulative_counters.response_route_coverage.len(),
            0,
            MAX_RESPONSE_OBLIGATIONS,
        )?;
        if self
            .cumulative_counters
            .expansion_cells
            .windows(2)
            .any(|pair| pair[0].cell_sha256 >= pair[1].cell_sha256)
            || self
                .cumulative_counters
                .response_route_coverage
                .windows(2)
                .any(|pair| pair[0].route_sha256 >= pair[1].route_sha256)
        {
            return Err(ShadowError::CounterMismatch);
        }
        self.policy_identity.validate()?;
        self.generation.validate()?;
        if self.created_at_unix_nanos != self.issued_at_unix_nanos
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
        {
            return Err(invalid("created_at_unix_nanos", "must equal issued time"));
        }
        Ok(())
    }
}

pub(crate) type VerifiedCheckpoint = VerifiedSignedEnvelope<PolicyShadowCheckpointPayload>;

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_checkpoint(
    wire: SignedEnvelope<PolicyShadowCheckpointPayload>,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    previous: Option<&VerifiedCheckpoint>,
    cumulative_observations: &[VerifiedObservation],
    cumulative_heartbeats: &[SignedEnvelope<ShadowHeartbeatPayload>],
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedCheckpoint, ShadowError> {
    revalidate_verified_freshness(
        assignment,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    revalidate_verified_freshness(
        load_receipt,
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    revalidate_verified_freshness(
        policy_authority_analysis,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    if let Some(previous) = previous {
        revalidate_verified_freshness(
            previous,
            key_trust,
            trusted_time,
            assignment
                .payload()
                .observation_window
                .maximum_evidence_age_nanos
                .try_into()
                .map_err(|_| ShadowError::EvidenceTooOld)?,
        )?;
    }
    for observation in cumulative_observations {
        revalidate_verified_freshness(
            observation,
            key_trust,
            trusted_time,
            assignment
                .payload()
                .observation_window
                .maximum_evidence_age_nanos
                .try_into()
                .map_err(|_| ShadowError::EvidenceTooOld)?,
        )?;
    }
    verify_load_receipt_binding(load_receipt, assignment)?;
    let member = assignment
        .payload()
        .fleet
        .members
        .iter()
        .find(|member| {
            member.instance_id == load_receipt.payload().runtime_identity.instance_id
        })
        .ok_or(ShadowError::BindingDrift)?;
    let checkpoint = verify_envelope(
        wire,
        ExpectedSigner {
            key_id: &member.shadow_signing_key_id,
            key_spki_sha256: &member.shadow_signing_key_spki_sha256,
        },
        key_trust,
        trusted_time,
        assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?,
    )?;
    verify_checkpoint_bindings(
        &checkpoint,
        assignment,
        load_receipt,
        policy_authority_analysis,
        previous,
    )?;
    verify_cumulative_observations(
        &checkpoint,
        assignment,
        load_receipt,
        previous,
        cumulative_observations,
    )?;
    verify_heartbeat_continuity(
        &checkpoint,
        assignment,
        load_receipt,
        member,
        cumulative_heartbeats,
        cumulative_observations,
        key_trust,
        trusted_time,
    )?;
    verify_checkpoint_seal(
        &checkpoint,
        assignment,
        member,
        key_trust,
        trusted_time,
    )?;
    let custody_context = open_verified_custody_call(
        custody,
        trusted_time,
        PolicyShadowCustodyOperation::VerifyCheckpointSuccessor,
        checkpoint.envelope_sha256(),
    )?;
    let custody_result = custody.verify_checkpoint_successor(
        &custody_context,
        &checkpoint.payload().generation,
        checkpoint.payload().checkpoint_sequence,
        &checkpoint.payload().previous_checkpoint_sha256,
        checkpoint.payload_sha256(),
    );
    finish_verified_custody_call(custody, custody_context)?;
    custody_result?;
    Ok(checkpoint)
}

/// Reconstructs the signed checkpoint chain used by activation. Observation
/// and heartbeat bodies are intentionally not accepted at this boundary: the
/// final sealed checkpoint and the custody current-head check performed by
/// `verify_activation_readiness` are the activation evidence capabilities.
pub(crate) fn verify_activation_checkpoint_chain(
    wires: Vec<SignedEnvelope<PolicyShadowCheckpointPayload>>,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedCheckpoint, ShadowError> {
    if wires.is_empty() || wires.len() > MAX_COLLECTION_ITEMS {
        return Err(ShadowError::FleetCoverageIncomplete);
    }
    revalidate_verified_freshness(
        assignment,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    let maximum_age: i64 = assignment
        .payload()
        .observation_window
        .maximum_evidence_age_nanos
        .try_into()
        .map_err(|_| ShadowError::EvidenceTooOld)?;
    revalidate_verified_freshness(
        load_receipt,
        key_trust,
        trusted_time,
        maximum_age,
    )?;
    revalidate_verified_freshness(
        policy_authority_analysis,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    verify_load_receipt_binding(load_receipt, assignment)?;
    let member = assignment
        .payload()
        .fleet
        .members
        .iter()
        .find(|member| {
            member.instance_id
                == load_receipt.payload().runtime_identity.instance_id
        })
        .ok_or(ShadowError::BindingDrift)?;
    let mut verified = Vec::with_capacity(wires.len());
    for wire in wires {
        let checkpoint = verify_envelope(
            wire,
            ExpectedSigner {
                key_id: &member.shadow_signing_key_id,
                key_spki_sha256:
                    &member.shadow_signing_key_spki_sha256,
            },
            key_trust,
            trusted_time,
            maximum_age,
        )?;
        verify_checkpoint_bindings(
            &checkpoint,
            assignment,
            load_receipt,
            policy_authority_analysis,
            verified.last(),
        )?;
        verify_checkpoint_seal(
            &checkpoint,
            assignment,
            member,
            key_trust,
            trusted_time,
        )?;
        verified.push(checkpoint);
    }
    let final_checkpoint = verified
        .pop()
        .ok_or(ShadowError::FleetCoverageIncomplete)?;
    if !matches!(final_checkpoint.payload().seal, CheckpointSeal::Sealed { .. }) {
        return Err(ShadowError::FleetCoverageIncomplete);
    }
    Ok(final_checkpoint)
}

#[allow(clippy::too_many_arguments)]
fn verify_heartbeat_continuity(
    checkpoint: &VerifiedCheckpoint,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    member: &FleetMember,
    heartbeat_wires: &[SignedEnvelope<ShadowHeartbeatPayload>],
    cumulative_observations: &[VerifiedObservation],
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<(), ShadowError> {
    let expected = &checkpoint.payload().cumulative_heartbeats;
    let expected_count =
        usize::try_from(expected.heartbeat_count).map_err(|_| ShadowError::EvidenceBudgetExceeded)?;
    if heartbeat_wires.len() != expected_count
        || heartbeat_wires.is_empty()
        || heartbeat_wires.len() > MAX_CUMULATIVE_OBSERVATIONS
    {
        return Err(ShadowError::SealInvalid);
    }
    let generation = ShadowGenerationIdentity::derive(assignment, load_receipt)?;
    let maximum_gap = assignment
        .payload()
        .observation_window
        .maximum_heartbeat_gap_nanos;
    let maximum_age: i64 = assignment
        .payload()
        .observation_window
        .maximum_evidence_age_nanos
        .try_into()
        .map_err(|_| ShadowError::EvidenceTooOld)?;
    let coverage_start = load_receipt
        .verified_at_unix_nanos()
        .max(assignment.payload().observation_window.starts_at_unix_nanos);
    let coverage_close = match &checkpoint.payload().seal {
        CheckpointSeal::Open => checkpoint.payload().created_at_unix_nanos,
        CheckpointSeal::Sealed { window_closure, .. } => {
            window_closure.payload.window_ends_at_unix_nanos
        }
    };
    let mut previous_digest = generation.generation_id.clone();
    let mut previous_time = coverage_start;
    let mut previous_ingress_sequence: Option<u64> = None;
    let mut maximum_observed_gap = 0_u64;
    let mut leaves = Vec::with_capacity(heartbeat_wires.len());
    let mut verified = Vec::with_capacity(heartbeat_wires.len());
    for wire in heartbeat_wires {
        let heartbeat = verify_envelope(
            wire.clone(),
            ExpectedSigner {
                key_id: &member.shadow_signing_key_id,
                key_spki_sha256: &member.shadow_signing_key_spki_sha256,
            },
            key_trust,
            trusted_time,
            maximum_age,
        )?;
        let payload = heartbeat.payload();
        let expected_sequence = u64::try_from(verified.len())
            .map_err(|_| ShadowError::CounterOverflow)?
            .checked_add(1)
            .ok_or(ShadowError::CounterOverflow)?;
        let expected_ingress = cumulative_observations
            .iter()
            .take_while(|observation| {
                observation
                    .payload()
                    .ingress_evidence
                    .payload
                    .observed_at_unix_nanos
                    <= payload.observed_at_unix_nanos
            })
            .last()
            .map(|observation| {
                (
                    observation
                        .payload()
                        .ingress_evidence
                        .payload
                        .ingress_sequence,
                    observation.payload().ingress_evidence_sha256.clone(),
                )
            });
        let expected_state = if expected_ingress.is_some() {
            HeartbeatIngressState::Observed
        } else {
            HeartbeatIngressState::NoIngress
        };
        if payload.assignment_sha256 != *assignment.envelope_sha256()
            || payload.assignment_payload_sha256 != *assignment.payload_sha256()
            || payload.assignment_revision != assignment.payload().assignment_revision
            || payload.runtime_identity != load_receipt.payload().runtime_identity
            || payload.generation_id != generation.generation_id
            || payload.heartbeat_sequence != expected_sequence
            || payload.previous_heartbeat_sha256 != previous_digest
            || payload.observed_at_unix_nanos < previous_time
            || payload.ingress_range_start_sequence
                != load_receipt.payload().ingress_range_start_sequence
            || payload.ingress_range_predecessor_head_sha256
                != load_receipt
                    .payload()
                    .ingress_range_predecessor_head_sha256
            || payload.ingress_state != expected_state
            || payload.last_ingress_sequence
                != expected_ingress.as_ref().map(|(sequence, _)| *sequence)
            || payload.last_ingress_evidence_sha256
                != expected_ingress.as_ref().map(|(_, digest)| digest.clone())
            || payload.last_ingress_sequence.is_some_and(|sequence| {
                previous_ingress_sequence
                    .is_some_and(|previous| sequence < previous)
            })
        {
            return Err(ShadowError::SealInvalid);
        }
        let gap = payload
            .observed_at_unix_nanos
            .checked_sub(previous_time)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(ShadowError::SealInvalid)?;
        if gap > maximum_gap {
            return Err(ShadowError::SealInvalid);
        }
        maximum_observed_gap = maximum_observed_gap.max(gap);
        previous_time = payload.observed_at_unix_nanos;
        previous_ingress_sequence = payload.last_ingress_sequence;
        previous_digest = heartbeat.envelope_sha256().clone();
        leaves.push((payload.heartbeat_sequence, previous_digest.clone()));
        verified.push(heartbeat);
    }
    let close_gap = coverage_close
        .checked_sub(previous_time)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ShadowError::SealInvalid)?;
    maximum_observed_gap = maximum_observed_gap.max(close_gap);
    if close_gap > maximum_gap
        || expected.first_heartbeat_sequence != 1
        || expected.last_heartbeat_sequence
            != u64::try_from(verified.len()).map_err(|_| ShadowError::CounterOverflow)?
        || expected.first_heartbeat_at_unix_nanos
            != verified[0].payload().observed_at_unix_nanos
        || expected.last_heartbeat_at_unix_nanos != previous_time
        || expected.maximum_observed_gap_nanos != maximum_observed_gap
        || expected.cumulative_heartbeat_root_sha256 != merkle_root(&leaves)?
    {
        return Err(ShadowError::SealInvalid);
    }
    Ok(())
}

fn verify_checkpoint_bindings(
    checkpoint: &VerifiedCheckpoint,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    previous: Option<&VerifiedCheckpoint>,
) -> Result<(), ShadowError> {
    let payload = checkpoint.payload();
    let assignment_payload = assignment.payload();
    let expected_generation = ShadowGenerationIdentity::derive(
        assignment,
        load_receipt,
    )?;
    if payload.assignment_sha256 != *assignment.envelope_sha256()
        || payload.assignment_payload_sha256 != *assignment.payload_sha256()
        || payload.assignment_revision != assignment_payload.assignment_revision
        || payload.authority_key_independence_sha256
            != assignment_payload
                .authority_key_independence
                .independence_root_sha256
        || payload.policy_authority_analysis_sha256
            != *policy_authority_analysis.envelope_sha256()
        || payload.policy_authority_analysis_payload_sha256
            != *policy_authority_analysis.payload_sha256()
        || payload.custody_receipt_evidence_requirements_sha256
            != policy_authority_analysis
                .payload()
                .custody_receipt_evidence_requirements_sha256
        || payload.load_receipt_sha256 != *load_receipt.envelope_sha256()
        || payload.load_receipt_payload_sha256 != *load_receipt.payload_sha256()
        || payload.canary_id != assignment_payload.canary_id
        || payload.fleet_id != assignment_payload.fleet.fleet_id
        || payload.fleet_membership_revision != assignment_payload.fleet.membership_revision
        || payload.policy_identity != assignment_payload.policy_identity
        || payload.runtime_identity != load_receipt.payload().runtime_identity
        || payload.generation != expected_generation
        || payload.publication_reconciliation_receipt_sha256
            != load_receipt
                .payload()
                .publication_reconciliation_receipt_sha256
        || payload.publication_revision
            != load_receipt.payload().publication_revision
    {
        return Err(ShadowError::BindingDrift);
    }
    let empty_root = merkle_root(&[])?;
    match previous {
        None => {
            if payload.checkpoint_sequence != 1
                || payload.previous_checkpoint_sha256
                    != payload.generation.generation_id
                || payload.previous_cumulative_observation_root_sha256 != empty_root
                || payload.previous_cumulative_ingress_root_sha256 != empty_root
                || payload.previous_cumulative_active_decision_root_sha256
                    != empty_root
                || payload
                    .previous_cumulative_custody_evidence_root_sha256
                    != empty_root
                || payload
                    .previous_cumulative_terminal_receipt_root_sha256
                    != empty_root
                || payload
                    .previous_cumulative_publication_receipt_root_sha256
                    != empty_root
            {
                return Err(ShadowError::PreviousCheckpointHashMismatch);
            }
        }
        Some(previous) => {
            if previous.payload().assignment_sha256
                != payload.assignment_sha256
                || previous.payload().assignment_payload_sha256
                    != payload.assignment_payload_sha256
                || previous.payload().assignment_revision
                    != payload.assignment_revision
                || previous.payload().load_receipt_sha256
                    != payload.load_receipt_sha256
                || previous.payload().load_receipt_payload_sha256
                    != payload.load_receipt_payload_sha256
                || previous.payload().canary_id != payload.canary_id
                || previous.payload().policy_identity
                    != payload.policy_identity
                || previous.payload().runtime_identity
                    != payload.runtime_identity
                || previous.payload().generation != payload.generation
            {
                return Err(ShadowError::BindingDrift);
            }
            if matches!(&previous.payload().seal, CheckpointSeal::Sealed { .. })
                || payload.checkpoint_sequence
                    != previous
                        .payload()
                        .checkpoint_sequence
                        .checked_add(1)
                        .ok_or(ShadowError::CounterOverflow)?
                || payload.previous_checkpoint_sha256 != *previous.envelope_sha256()
                || payload.previous_cumulative_observation_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_observation_root_sha256
                || payload.previous_cumulative_ingress_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_ingress_root_sha256
                || payload.previous_cumulative_active_decision_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_active_decision_root_sha256
                || payload
                    .previous_cumulative_custody_evidence_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_custody_evidence_root_sha256
                || payload
                    .previous_cumulative_terminal_receipt_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_terminal_receipt_root_sha256
                || payload
                    .previous_cumulative_publication_receipt_root_sha256
                    != previous
                        .payload()
                        .cumulative_range
                        .cumulative_publication_receipt_root_sha256
                || payload.cumulative_range.observation_count
                    < previous.payload().cumulative_range.observation_count
                || payload.cumulative_range.ingress_count
                    < previous.payload().cumulative_range.ingress_count
                || payload.cumulative_heartbeats.heartbeat_count
                    <= previous
                        .payload()
                        .cumulative_heartbeats
                        .heartbeat_count
                || payload
                    .cumulative_heartbeats
                    .first_heartbeat_sequence
                    != previous
                        .payload()
                        .cumulative_heartbeats
                        .first_heartbeat_sequence
                || payload
                    .cumulative_heartbeats
                    .first_heartbeat_at_unix_nanos
                    != previous
                        .payload()
                        .cumulative_heartbeats
                        .first_heartbeat_at_unix_nanos
                || previous.payload().cumulative_counters.totals.dropped
                    > payload.cumulative_counters.totals.dropped
                || previous.payload().cumulative_counters.totals.errors
                    > payload.cumulative_counters.totals.errors
                || previous
                    .payload()
                    .cumulative_counters
                    .totals
                    .candidate_indeterminate
                    > payload
                        .cumulative_counters
                        .totals
                        .candidate_indeterminate
                || previous
                    .payload()
                    .cumulative_counters
                    .totals
                    .unavailable_evidence
                    > payload.cumulative_counters.totals.unavailable_evidence
            {
                return Err(ShadowError::CumulativeCheckpointRegression);
            }
        }
    }
    Ok(())
}

fn verify_cumulative_observations(
    checkpoint: &VerifiedCheckpoint,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    previous: Option<&VerifiedCheckpoint>,
    records: &[VerifiedObservation],
) -> Result<(), ShadowError> {
    if records.len() > MAX_CUMULATIVE_OBSERVATIONS {
        return Err(ShadowError::EvidenceBudgetExceeded);
    }
    let record_work = u64::try_from(records.len())
        .map_err(|_| ShadowError::EvidenceBudgetExceeded)?
        .checked_mul(12)
        .ok_or(ShadowError::EvidenceBudgetExceeded)?;
    let predecessor_work = previous
        .map(|checkpoint| checkpoint.payload().cumulative_range.observation_count)
        .unwrap_or(0)
        .checked_mul(12)
        .ok_or(ShadowError::EvidenceBudgetExceeded)?;
    if record_work
        .checked_add(predecessor_work)
        .filter(|work| *work <= MAX_VERIFICATION_WORK_UNITS)
        .is_none()
    {
        return Err(ShadowError::EvidenceBudgetExceeded);
    }
    for (index, record) in records.iter().enumerate() {
        let expected_observation = u64::try_from(index + 1)
            .map_err(|_| ShadowError::CounterOverflow)?;
        let expected_ingress = assignment
            .payload()
            .observation_window
            .first_ingress_sequence
            .checked_add(
                u64::try_from(index)
                    .map_err(|_| ShadowError::CounterOverflow)?,
            )
            .ok_or(ShadowError::CounterOverflow)?;
        if record.payload().observation_sequence != expected_observation
            || record
                .payload()
                .ingress_evidence
                .payload
                .ingress_sequence
                != expected_ingress
            || record.payload().runtime_identity != checkpoint.payload().runtime_identity
            || record.payload().generation != checkpoint.payload().generation
            || record.payload().assignment_sha256 != *assignment.envelope_sha256()
            || record.payload().assignment_payload_sha256
                != *assignment.payload_sha256()
            || record.payload().assignment_revision
                != assignment.payload().assignment_revision
            || record.payload().load_receipt_sha256
                != *load_receipt.envelope_sha256()
            || record.payload().load_receipt_payload_sha256
                != *load_receipt.payload_sha256()
            || record.payload().canary_id != assignment.payload().canary_id
            || record.payload().policy_identity
                != assignment.payload().policy_identity
            || record.payload().runtime_identity
                != load_receipt.payload().runtime_identity
        {
            return Err(ShadowError::BindingDrift);
        }
        if index > 0
            && record.payload().previous_observation_sha256
                != *records[index - 1].envelope_sha256()
        {
            return Err(ShadowError::PreviousObservationHashMismatch);
        }
    }
    let expected_range = recompute_cumulative_range(records)?;
    if checkpoint.payload().cumulative_range != expected_range {
        return Err(ShadowError::MerkleRootMismatch);
    }
    let expected_counters = CumulativeCounters::from_observations(records)?;
    if checkpoint.payload().cumulative_counters != expected_counters {
        return Err(ShadowError::CounterMismatch);
    }
    if let Some(previous) = previous {
        let prefix_count = usize::try_from(
            previous.payload().cumulative_range.observation_count,
        )
        .map_err(|_| ShadowError::EvidenceBudgetExceeded)?;
        if prefix_count > records.len() {
            return Err(ShadowError::CumulativeCheckpointRegression);
        }
        let predecessor_range = recompute_cumulative_range(&records[..prefix_count])?;
        let predecessor_counters =
            CumulativeCounters::from_observations(&records[..prefix_count])?;
        let appended_is_contiguous = if prefix_count == 0
            || prefix_count == records.len()
        {
            true
        } else {
            previous
                .payload()
                .cumulative_range
                .last_observation_sequence
                .and_then(|sequence| sequence.checked_add(1))
                == Some(
                    records[prefix_count]
                        .payload()
                        .observation_sequence,
                )
                && previous
                    .payload()
                    .cumulative_range
                    .last_ingress_sequence
                    .and_then(|sequence| sequence.checked_add(1))
                    == Some(
                        records[prefix_count]
                            .payload()
                            .ingress_evidence
                            .payload
                            .ingress_sequence,
                    )
        };
        if predecessor_range != previous.payload().cumulative_range
            || predecessor_counters != previous.payload().cumulative_counters
            || previous.payload().assignment_sha256
                != checkpoint.payload().assignment_sha256
            || previous.payload().assignment_payload_sha256
                != checkpoint.payload().assignment_payload_sha256
            || previous.payload().assignment_revision
                != checkpoint.payload().assignment_revision
            || previous.payload().load_receipt_sha256
                != checkpoint.payload().load_receipt_sha256
            || previous.payload().load_receipt_payload_sha256
                != checkpoint.payload().load_receipt_payload_sha256
            || previous.payload().canary_id != checkpoint.payload().canary_id
            || previous.payload().policy_identity
                != checkpoint.payload().policy_identity
            || previous.payload().runtime_identity
                != checkpoint.payload().runtime_identity
            || !appended_is_contiguous
        {
            return Err(ShadowError::CumulativeCheckpointRegression);
        }
    }
    Ok(())
}

fn recompute_cumulative_range(
    records: &[VerifiedObservation],
) -> Result<CumulativeObservationRange, ShadowError> {
    if records.len() > MAX_CUMULATIVE_OBSERVATIONS {
        return Err(ShadowError::EvidenceBudgetExceeded);
    }
    if records.is_empty() {
        let empty_root = merkle_root(&[])?;
        return Ok(CumulativeObservationRange {
            first_observation_sequence: None,
            last_observation_sequence: None,
            first_observation_sha256: None,
            last_observation_sha256: None,
            first_ingress_sequence: None,
            last_ingress_sequence: None,
            last_ingress_evidence_sha256: None,
            first_observed_at_unix_nanos: None,
            last_observed_at_unix_nanos: None,
            observation_count: 0,
            ingress_count: 0,
            verified_evidence_bytes: 0,
            verification_work_units: 0,
            cumulative_observation_root_sha256: empty_root.clone(),
            cumulative_ingress_root_sha256: empty_root.clone(),
            cumulative_active_decision_root_sha256: empty_root.clone(),
            cumulative_principal_authority_root_sha256: empty_root.clone(),
            cumulative_route_authority_root_sha256: empty_root.clone(),
            cumulative_custody_evidence_root_sha256: empty_root.clone(),
            cumulative_admitted_ingress_receipt_root_sha256:
                empty_root.clone(),
            cumulative_unavailable_ingress_receipt_root_sha256:
                empty_root.clone(),
            cumulative_dispatch_barrier_receipt_root_sha256:
                empty_root.clone(),
            cumulative_active_effect_barrier_receipt_root_sha256:
                empty_root.clone(),
            cumulative_active_effect_commit_receipt_root_sha256:
                empty_root.clone(),
            cumulative_terminal_receipt_count: 0,
            cumulative_terminal_receipt_root_sha256:
                empty_root.clone(),
            cumulative_publication_receipt_count: 0,
            cumulative_publication_receipt_root_sha256:
                empty_root.clone(),
            cumulative_spill_receipt_root_sha256: empty_root.clone(),
            cumulative_persistence_receipt_root_sha256:
                empty_root.clone(),
            cumulative_retrieval_proof_root_sha256: empty_root.clone(),
            cumulative_compaction_receipt_root_sha256: empty_root,
            last_ledger_event_ordinal: None,
            last_ledger_head_sha256: None,
            last_spool_root_sha256: None,
        });
    }
    let first = records.first().ok_or(ShadowError::CounterMismatch)?;
    let last = records.last().ok_or(ShadowError::CounterMismatch)?;
    let mut observation_root = StreamingMerkleAccumulator::new();
    let mut ingress_root = StreamingMerkleAccumulator::new();
    let mut active_decision_root = StreamingMerkleAccumulator::new();
    let mut principal_authority_root = StreamingMerkleAccumulator::new();
    let mut route_authority_root = StreamingMerkleAccumulator::new();
    let mut custody_evidence_root = StreamingMerkleAccumulator::new();
    let mut admitted_ingress_root = StreamingMerkleAccumulator::new();
    let mut unavailable_ingress_root = StreamingMerkleAccumulator::new();
    let mut dispatch_barrier_root = StreamingMerkleAccumulator::new();
    let mut active_effect_barrier_root =
        StreamingMerkleAccumulator::new();
    let mut active_effect_commit_root =
        StreamingMerkleAccumulator::new();
    let mut terminal_receipt_root = StreamingMerkleAccumulator::new();
    let mut publication_receipt_root =
        StreamingMerkleAccumulator::new();
    let mut terminal_receipt_count = 0_u64;
    let mut publication_receipt_count = 0_u64;
    let mut spill_receipt_root = StreamingMerkleAccumulator::new();
    let mut persistence_receipt_root = StreamingMerkleAccumulator::new();
    let mut retrieval_proof_root = StreamingMerkleAccumulator::new();
    let mut compaction_receipt_root = StreamingMerkleAccumulator::new();
    let mut evidence_bytes = 0_u64;
    let mut work_units = 0_u64;
    for record in records {
        let observation_sequence = record.payload().observation_sequence;
        let ingress_sequence = record
            .payload()
            .ingress_evidence
            .payload
            .ingress_sequence;
        observation_root.push(observation_sequence, record.envelope_sha256())?;
        ingress_root.push(
            ingress_sequence,
            &Sha256Digest::compute(&canonical_json_bytes(
                &record.payload().ingress_evidence,
            )?),
        )?;
        active_decision_root.push(
            observation_sequence,
            &record.payload().active_decision_sha256,
        )?;
        let custody = &record.payload().custody_evidence;
        custody_evidence_root.push(
            observation_sequence,
            &custody.custody_evidence_root_sha256,
        )?;
        if let Some(receipt) =
            custody.admitted_ingress_receipt_sha256.as_ref()
        {
            admitted_ingress_root.push(observation_sequence, receipt)?;
        }
        if let Some(receipt) =
            custody.unavailable_ingress_receipt_sha256.as_ref()
        {
            unavailable_ingress_root.push(observation_sequence, receipt)?;
        }
        if custody.dispatch_barrier_receipt_count > 0 {
            dispatch_barrier_root.push(
                observation_sequence,
                &custody.dispatch_barrier_receipts_root_sha256,
            )?;
        }
        if custody.active_effect_barrier_receipt_count > 0 {
            active_effect_barrier_root.push(
                observation_sequence,
                &custody.active_effect_barrier_receipts_root_sha256,
            )?;
            active_effect_commit_root.push(
                observation_sequence,
                &custody.active_effect_commit_receipts_root_sha256,
            )?;
        }
        terminal_receipt_count = terminal_receipt_count
            .checked_add(custody.terminal_receipt_count)
            .ok_or(ShadowError::CounterOverflow)?;
        publication_receipt_count = publication_receipt_count
            .checked_add(custody.publication_receipt_count)
            .ok_or(ShadowError::CounterOverflow)?;
        terminal_receipt_root.push(
            observation_sequence,
            &custody.terminal_receipts_root_sha256,
        )?;
        publication_receipt_root.push(
            observation_sequence,
            &custody.publication_receipts_root_sha256,
        )?;
        spill_receipt_root.push(
            observation_sequence,
            &custody.spill_receipts_root_sha256,
        )?;
        persistence_receipt_root.push(
            observation_sequence,
            &custody.persistence_receipts_root_sha256,
        )?;
        retrieval_proof_root.push(
            observation_sequence,
            &custody.retrieval_proofs_root_sha256,
        )?;
        compaction_receipt_root.push(
            observation_sequence,
            &custody.compaction_receipts_root_sha256,
        )?;
        if let ObservationResult::Evaluated {
            authority_binding, ..
        } = &record.payload().result
        {
            principal_authority_root.push(
                observation_sequence,
                &authority_binding.principal_sha256,
            )?;
            route_authority_root.push(
                observation_sequence,
                &authority_binding.route_sha256,
            )?;
        }
        let record_bytes = u64::try_from(canonical_json_bytes(&record.envelope)?.len())
            .map_err(|_| ShadowError::EvidenceBudgetExceeded)?;
        evidence_bytes = evidence_bytes
            .checked_add(record_bytes)
            .filter(|value| *value <= MAX_CUMULATIVE_EVIDENCE_BYTES)
            .ok_or(ShadowError::EvidenceBudgetExceeded)?;
        work_units = work_units
            .checked_add(20)
            .filter(|value| *value <= MAX_VERIFICATION_WORK_UNITS)
            .ok_or(ShadowError::EvidenceBudgetExceeded)?;
    }
    Ok(CumulativeObservationRange {
        first_observation_sequence: Some(first.payload().observation_sequence),
        last_observation_sequence: Some(last.payload().observation_sequence),
        first_observation_sha256: Some(first.envelope_sha256().clone()),
        last_observation_sha256: Some(last.envelope_sha256().clone()),
        first_ingress_sequence: Some(
            first
                .payload()
                .ingress_evidence
                .payload
                .ingress_sequence,
        ),
        last_ingress_sequence: Some(
            last
                .payload()
                .ingress_evidence
                .payload
                .ingress_sequence,
        ),
        last_ingress_evidence_sha256: Some(
            last.payload().ingress_evidence_sha256.clone(),
        ),
        first_observed_at_unix_nanos: Some(
            first
                .payload()
                .ingress_evidence
                .payload
                .observed_at_unix_nanos,
        ),
        last_observed_at_unix_nanos: Some(
            last
                .payload()
                .ingress_evidence
                .payload
                .observed_at_unix_nanos,
        ),
        observation_count: u64::try_from(records.len())
            .map_err(|_| ShadowError::CounterOverflow)?,
        ingress_count: u64::try_from(records.len())
            .map_err(|_| ShadowError::CounterOverflow)?,
        verified_evidence_bytes: evidence_bytes,
        verification_work_units: work_units,
        cumulative_observation_root_sha256: observation_root.finish()?,
        cumulative_ingress_root_sha256: ingress_root.finish()?,
        cumulative_active_decision_root_sha256: active_decision_root.finish()?,
        cumulative_principal_authority_root_sha256:
            principal_authority_root.finish()?,
        cumulative_route_authority_root_sha256: route_authority_root.finish()?,
        cumulative_custody_evidence_root_sha256:
            custody_evidence_root.finish()?,
        cumulative_admitted_ingress_receipt_root_sha256:
            admitted_ingress_root.finish()?,
        cumulative_unavailable_ingress_receipt_root_sha256:
            unavailable_ingress_root.finish()?,
        cumulative_dispatch_barrier_receipt_root_sha256:
            dispatch_barrier_root.finish()?,
        cumulative_active_effect_barrier_receipt_root_sha256:
            active_effect_barrier_root.finish()?,
        cumulative_active_effect_commit_receipt_root_sha256:
            active_effect_commit_root.finish()?,
        cumulative_terminal_receipt_count: terminal_receipt_count,
        cumulative_terminal_receipt_root_sha256:
            terminal_receipt_root.finish()?,
        cumulative_publication_receipt_count:
            publication_receipt_count,
        cumulative_publication_receipt_root_sha256:
            publication_receipt_root.finish()?,
        cumulative_spill_receipt_root_sha256:
            spill_receipt_root.finish()?,
        cumulative_persistence_receipt_root_sha256:
            persistence_receipt_root.finish()?,
        cumulative_retrieval_proof_root_sha256:
            retrieval_proof_root.finish()?,
        cumulative_compaction_receipt_root_sha256:
            compaction_receipt_root.finish()?,
        last_ledger_event_ordinal: Some(
            last.payload()
                .custody_evidence
                .last_ledger_event_ordinal,
        ),
        last_ledger_head_sha256: Some(
            last.payload()
                .custody_evidence
                .last_ledger_head_sha256
                .clone(),
        ),
        last_spool_root_sha256: Some(
            last.payload()
                .custody_evidence
                .last_spool_root_sha256
                .clone(),
        ),
    })
}

struct StreamingMerkleAccumulator {
    frontier: Vec<Option<Sha256Digest>>,
    previous_sequence: Option<u64>,
}

impl StreamingMerkleAccumulator {
    fn new() -> Self {
        Self {
            frontier: vec![None; 64],
            previous_sequence: None,
        }
    }

    fn push(
        &mut self,
        sequence: u64,
        digest: &Sha256Digest,
    ) -> Result<(), ShadowError> {
        if self
            .previous_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(ShadowError::NonContiguousObservationSequence);
        }
        self.previous_sequence = Some(sequence);
        let mut input = Vec::with_capacity(MERKLE_LEAF_DOMAIN.len() + 42);
        input.extend_from_slice(MERKLE_LEAF_DOMAIN);
        input.push(0);
        input.extend_from_slice(&sequence.to_be_bytes());
        input.extend_from_slice(&digest.raw_bytes()?);
        let mut node = Sha256Digest::compute(&input);
        for slot in &mut self.frontier {
            if let Some(left) = slot.take() {
                node = merkle_parent(&left, &node)?;
            } else {
                *slot = Some(node);
                return Ok(());
            }
        }
        Err(ShadowError::EvidenceBudgetExceeded)
    }

    fn finish(self) -> Result<Sha256Digest, ShadowError> {
        let mut root: Option<Sha256Digest> = None;
        for node in self.frontier.into_iter().flatten() {
            root = Some(match root {
                Some(right) => merkle_parent(&node, &right)?,
                None => node,
            });
        }
        match root {
            Some(root) => Ok(root),
            None => merkle_root(&[]),
        }
    }
}

fn merkle_parent(
    left: &Sha256Digest,
    right: &Sha256Digest,
) -> Result<Sha256Digest, ShadowError> {
    let mut input = Vec::with_capacity(MERKLE_NODE_DOMAIN.len() + 66);
    input.extend_from_slice(MERKLE_NODE_DOMAIN);
    input.push(1);
    input.extend_from_slice(&left.raw_bytes()?);
    input.extend_from_slice(&right.raw_bytes()?);
    Ok(Sha256Digest::compute(&input))
}

fn verify_checkpoint_seal(
    checkpoint: &VerifiedCheckpoint,
    assignment: &VerifiedAssignment,
    member: &FleetMember,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<(), ShadowError> {
    let payload = checkpoint.payload();
    let window = &assignment.payload().observation_window;
    match &payload.seal {
        CheckpointSeal::Open => {
            if payload.created_at_unix_nanos >= window.seal_deadline_unix_nanos {
                return Err(ShadowError::SealDeadlineExceeded);
            }
        }
        CheckpointSeal::Sealed {
            sealed_at_unix_nanos,
            window_closure_sha256,
            window_closure,
            seal_root_sha256,
        } => {
            let trusted_now = trusted_time.now_unix_nanos()?;
            if *sealed_at_unix_nanos < window.ends_at_unix_nanos
                || *sealed_at_unix_nanos >= window.seal_deadline_unix_nanos
                || *sealed_at_unix_nanos > trusted_now
            {
                return Err(ShadowError::SealInvalid);
            }
            let closure = verify_envelope(
                window_closure.clone(),
                ExpectedSigner {
                    key_id: &member.ingress_signing_key_id,
                    key_spki_sha256: &member.ingress_signing_key_spki_sha256,
                },
                key_trust,
                trusted_time,
                assignment
                    .payload()
                    .observation_window
                    .maximum_evidence_age_nanos
                    .try_into()
                    .map_err(|_| ShadowError::EvidenceTooOld)?,
            )?;
            let expected_ingress_state =
                if payload.cumulative_range.ingress_count == 0 {
                    HeartbeatIngressState::NoIngress
                } else {
                    HeartbeatIngressState::Observed
                };
            if *window_closure_sha256 != *closure.envelope_sha256()
                || closure.payload().assignment_sha256 != *assignment.envelope_sha256()
                || closure.payload().assignment_payload_sha256 != *assignment.payload_sha256()
                || closure.payload().assignment_revision
                    != assignment.payload().assignment_revision
                || closure.payload().runtime_identity != payload.runtime_identity
                || closure.payload().window_ends_at_unix_nanos != window.ends_at_unix_nanos
                || closure.payload().ingress_state
                    != expected_ingress_state
                || closure.payload().ingress_range_start_sequence
                    != window.first_ingress_sequence
                || closure
                    .payload()
                    .ingress_range_predecessor_head_sha256
                    != payload
                        .generation
                        .ingress_range_predecessor_head_sha256
                || closure.payload().last_ingress_sequence
                    != payload.cumulative_range.last_ingress_sequence
                || closure.payload().last_ingress_evidence_sha256
                    != payload
                        .cumulative_range
                        .last_ingress_evidence_sha256
                || closure.payload().last_heartbeat_sequence
                    != payload.cumulative_heartbeats.last_heartbeat_sequence
                || closure.payload().cumulative_heartbeat_root_sha256
                    != payload
                        .cumulative_heartbeats
                        .cumulative_heartbeat_root_sha256
                || closure.payload().closed_at_unix_nanos != *sealed_at_unix_nanos
            {
                return Err(ShadowError::SealInvalid);
            }
            let observation_root =
                payload.cumulative_range.cumulative_observation_root_sha256.raw_bytes()?;
            let ingress_root =
                payload.cumulative_range.cumulative_ingress_root_sha256.raw_bytes()?;
            let active_decision_root = payload
                .cumulative_range
                .cumulative_active_decision_root_sha256
                .raw_bytes()?;
            let principal_authority_root = payload
                .cumulative_range
                .cumulative_principal_authority_root_sha256
                .raw_bytes()?;
            let route_authority_root = payload
                .cumulative_range
                .cumulative_route_authority_root_sha256
                .raw_bytes()?;
            let terminal_receipt_root = payload
                .cumulative_range
                .cumulative_terminal_receipt_root_sha256
                .raw_bytes()?;
            let publication_receipt_root = payload
                .cumulative_range
                .cumulative_publication_receipt_root_sha256
                .raw_bytes()?;
            let authority_key_independence = payload
                .authority_key_independence_sha256
                .raw_bytes()?;
            let policy_authority_analysis = payload
                .policy_authority_analysis_sha256
                .raw_bytes()?;
            let custody_requirements = payload
                .custody_receipt_evidence_requirements_sha256
                .raw_bytes()?;
            let closure_digest = closure.envelope_sha256().raw_bytes()?;
            let heartbeat_root = payload
                .cumulative_heartbeats
                .cumulative_heartbeat_root_sha256
                .raw_bytes()?;
            let sealed_at = sealed_at_unix_nanos.to_be_bytes();
            let expected_seal = hash_domain_frames(
                b"serverware.policyShadowCheckpointSeal/v1",
                &[
                    observation_root.as_slice(),
                    ingress_root.as_slice(),
                    active_decision_root.as_slice(),
                    principal_authority_root.as_slice(),
                    route_authority_root.as_slice(),
                    terminal_receipt_root.as_slice(),
                    publication_receipt_root.as_slice(),
                    authority_key_independence.as_slice(),
                    policy_authority_analysis.as_slice(),
                    custody_requirements.as_slice(),
                    heartbeat_root.as_slice(),
                    closure_digest.as_slice(),
                    sealed_at.as_slice(),
                ],
            );
            if *seal_root_sha256 != expected_seal {
                return Err(ShadowError::SealInvalid);
            }
        }
    }
    Ok(())
}

/// Merkle construction is normative: each leaf is
/// SHA-256(LEAF_DOMAIN || 0x00 || sequence_be_u64 || digest_32). Each parent is
/// SHA-256(NODE_DOMAIN || 0x01 || left_32 || right_32). An unpaired node is
/// promoted unchanged. The empty root is SHA-256(EMPTY_DOMAIN || 0x00).
pub(crate) fn merkle_root(leaves: &[(u64, Sha256Digest)]) -> Result<Sha256Digest, ShadowError> {
    if leaves.is_empty() {
        let mut empty = Vec::with_capacity(MERKLE_EMPTY_DOMAIN.len() + 1);
        empty.extend_from_slice(MERKLE_EMPTY_DOMAIN);
        empty.push(0);
        return Ok(Sha256Digest::compute(&empty));
    }
    let mut previous_sequence = None;
    let mut level = Vec::with_capacity(leaves.len());
    for (sequence, digest) in leaves {
        if previous_sequence.is_some_and(|previous| *sequence <= previous) {
            return Err(ShadowError::NonContiguousObservationSequence);
        }
        previous_sequence = Some(*sequence);
        let mut input = Vec::new();
        input.extend_from_slice(MERKLE_LEAF_DOMAIN);
        input.push(0);
        input.extend_from_slice(&sequence.to_be_bytes());
        input.extend_from_slice(&digest.raw_bytes()?);
        level.push(Sha256Digest::compute(&input));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0].clone());
            } else {
                let mut input = Vec::new();
                input.extend_from_slice(MERKLE_NODE_DOMAIN);
                input.push(1);
                input.extend_from_slice(&pair[0].raw_bytes()?);
                input.extend_from_slice(&pair[1].raw_bytes()?);
                next.push(Sha256Digest::compute(&input));
            }
        }
        level = next;
    }
    level.pop().ok_or(ShadowError::MerkleRootMismatch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthorityExpansionCell {
    EndpointAdded,
    CredentialScopeAdded,
    WriteMethodEnabled,
    QuotaIncreased,
    BudgetIncreased,
    ResponseFieldExposureAdded,
    ResponseValidationRelaxed,
    ResponseFilterReduced,
    OtherCompilerDeclared,
    ActiveDenyToConditional,
    ActiveDenyToPermit,
    ActiveConditionalToPermit,
    ActiveIndeterminateToConditional,
    ActiveIndeterminateToPermit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum PilotRestrictions {
    NotApplicable,
    Constrained {
        principal_set_root_sha256: Sha256Digest,
        route_set_root_sha256: Sha256Digest,
        maximum_requests: u64,
        maximum_duration_nanos: u64,
        maximum_write_requests: u64,
        cells: Vec<SemanticExpansionCell>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ApprovalMode {
    SinglePersonHardwareWebauthn,
    TwoPersonHardwareWebauthn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum AuthorityAnalysis {
    NoExpansion {
        expansion_cells: Vec<SemanticExpansionCell>,
    },
    ApprovedExpansion {
        expansion_cells: Vec<SemanticExpansionCell>,
        approval_mode: ApprovalMode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReceiptEvidenceClass {
    Terminal,
    Publication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReceiptCountUnit {
    CoveredIngress,
    CoveredMember,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReceiptEvidenceRequirement {
    receipt_class: ReceiptEvidenceClass,
    signer_role: PolicyShadowCustodySignerRole,
    expected_signing_key_id: Sha256Digest,
    expected_signing_key_spki_sha256: Sha256Digest,
    expected_signing_key_material_sha256: Sha256Digest,
    count_unit: ReceiptCountUnit,
    minimum_count_per_unit: u64,
    leaf_domain: CanonicalAscii,
    root_domain: CanonicalAscii,
    requirement_root_sha256: Sha256Digest,
}

impl ReceiptEvidenceRequirement {
    fn validate(
        &self,
        expected_class: ReceiptEvidenceClass,
        expected_role: PolicyShadowCustodySignerRole,
        expected_unit: ReceiptCountUnit,
        expected_leaf_domain: &str,
        expected_root_domain: &str,
    ) -> Result<(), ShadowError> {
        if self.receipt_class != expected_class
            || self.signer_role != expected_role
            || self.count_unit != expected_unit
            || self.minimum_count_per_unit != 1
            || self.leaf_domain.as_str() != expected_leaf_domain
            || self.root_domain.as_str() != expected_root_domain
        {
            return Err(ShadowError::PolicyAuthorityAnalysisMismatch);
        }
        let expected = hash_domain_frames(
            b"serverware.policyShadowReceiptEvidenceRequirement/v1",
            &[&canonical_json_bytes(&(
                self.receipt_class,
                self.signer_role,
                &self.expected_signing_key_id,
                &self.expected_signing_key_spki_sha256,
                &self.expected_signing_key_material_sha256,
                self.count_unit,
                self.minimum_count_per_unit,
                &self.leaf_domain,
                &self.root_domain,
            ))?],
        );
        if expected != self.requirement_root_sha256 {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CustodyReceiptEvidenceRequirements {
    terminal: ReceiptEvidenceRequirement,
    publication: ReceiptEvidenceRequirement,
    requirements_root_sha256: Sha256Digest,
}

impl CustodyReceiptEvidenceRequirements {
    fn validate(&self) -> Result<(), ShadowError> {
        self.terminal.validate(
            ReceiptEvidenceClass::Terminal,
            PolicyShadowCustodySignerRole::TerminalAppend,
            ReceiptCountUnit::CoveredIngress,
            "serverware.policyShadowTerminalReceiptLeaf/v1",
            "serverware.policyShadowTerminalReceiptRoot/v1",
        )?;
        self.publication.validate(
            ReceiptEvidenceClass::Publication,
            PolicyShadowCustodySignerRole::PublicationReconciliation,
            ReceiptCountUnit::CoveredMember,
            "serverware.policyShadowPublicationReceiptLeaf/v1",
            "serverware.policyShadowPublicationReceiptRoot/v1",
        )?;
        let expected = hash_domain_frames(
            b"serverware.policyShadowCustodyReceiptEvidenceRequirements/v1",
            &[
                self.terminal
                    .requirement_root_sha256
                    .as_str()
                    .as_bytes(),
                self.publication
                    .requirement_root_sha256
                    .as_str()
                    .as_bytes(),
            ],
        );
        if expected != self.requirements_root_sha256 {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyAuthorityAnalysisPayload {
    analysis_id: Sha256Digest,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    expected_analysis_key_id: Sha256Digest,
    expected_analysis_key_spki_sha256: Sha256Digest,
    expected_analysis_key_material_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    policy_identity: PolicyIdentity,
    expected_loaded_snapshots: AssignedSnapshotIdentities,
    custody_authority_sha256: Sha256Digest,
    authority_key_independence_sha256: Sha256Digest,
    custody_receipt_evidence_requirements:
        CustodyReceiptEvidenceRequirements,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    response_validation_obligations_root_sha256: Sha256Digest,
    route_authority_root_sha256: Sha256Digest,
    operation_authority_root_sha256: Sha256Digest,
    authority_analysis: AuthorityAnalysis,
    pilot_restrictions: PilotRestrictions,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for PolicyAuthorityAnalysisPayload {
    const API_VERSION: &'static str = POLICY_AUTHORITY_ANALYSIS_DOMAIN;
    const KIND: &'static str = "PolicyAuthorityAnalysis";
    const SIGNATURE_DOMAIN: &'static str = POLICY_AUTHORITY_ANALYSIS_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.assignment_revision, "analysis.assignment_revision")?;
        self.policy_identity.validate()?;
        self.expected_loaded_snapshots
            .validate_against_policy(&self.policy_identity)?;
        self.custody_receipt_evidence_requirements.validate()?;
        let requirements_sha256 = hash_domain_frames(
            b"serverware.policyShadowCustodyReceiptEvidenceRequirementsPayload/v1",
            &[&canonical_json_bytes(
                &self.custody_receipt_evidence_requirements,
            )?],
        );
        if requirements_sha256
            != self.custody_receipt_evidence_requirements_sha256
        {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        if self.expires_at_unix_nanos <= self.issued_at_unix_nanos {
            return Err(ShadowError::PolicyAuthorityAnalysisMismatch);
        }
        match (&self.authority_analysis, &self.pilot_restrictions) {
            (
                AuthorityAnalysis::NoExpansion { expansion_cells },
                PilotRestrictions::NotApplicable,
            ) => validate_semantic_expansion_cells(expansion_cells, true),
            (
                AuthorityAnalysis::ApprovedExpansion {
                    expansion_cells, ..
                },
                PilotRestrictions::Constrained {
                    principal_set_root_sha256,
                    route_set_root_sha256,
                    maximum_requests,
                    maximum_duration_nanos,
                    maximum_write_requests,
                    cells,
                    ..
                },
            ) => {
                validate_positive(*maximum_requests, "pilot.maximum_requests")?;
                validate_positive(*maximum_duration_nanos, "pilot.maximum_duration_nanos")?;
                validate_unsigned(*maximum_write_requests, "pilot.maximum_write_requests")?;
                if maximum_write_requests > maximum_requests {
                    return Err(ShadowError::ExpansionLimitExceeded);
                }
                validate_semantic_expansion_cells(expansion_cells, false)?;
                validate_semantic_expansion_cells(cells, false)?;
                if expansion_cells != cells
                    || expansion_cells.iter().any(|cell| {
                        cell.route_authority_root_sha256
                            != self.route_authority_root_sha256
                            || cell.operation_authority_root_sha256
                                != self.operation_authority_root_sha256
                            || cell.pilot_principal_set_root_sha256
                                != *principal_set_root_sha256
                            || cell.pilot_route_set_root_sha256
                                != *route_set_root_sha256
                    })
                {
                    return Err(ShadowError::ExpansionCellMismatch);
                }
                Ok(())
            }
            _ => Err(ShadowError::ExpansionCellMismatch),
        }
    }
}

pub(crate) type VerifiedPolicyAuthorityAnalysis =
    VerifiedSignedEnvelope<PolicyAuthorityAnalysisPayload>;

pub(crate) struct ActivationAuthoritySigners<'a> {
    pub(crate) analysis: ExpectedSigner<'a>,
    pub(crate) readiness: ExpectedSigner<'a>,
    pub(crate) approval: ExpectedSigner<'a>,
}

pub(crate) fn activation_authority_signers(
    assignment: &VerifiedAssignment,
) -> Result<ActivationAuthoritySigners<'_>, ShadowError> {
    let scope = &assignment.payload().assignment_id;
    let independence =
        &assignment.payload().authority_key_independence;
    let analysis = independence.binding(
        AuthorityRole::CompilerAnalysis,
        scope,
    )?;
    let readiness = independence.binding(
        AuthorityRole::ActivationReadiness,
        scope,
    )?;
    let approval = independence.binding(
        AuthorityRole::ActivationApproval,
        scope,
    )?;
    Ok(ActivationAuthoritySigners {
        analysis: ExpectedSigner {
            key_id: &analysis.key_id,
            key_spki_sha256: &analysis.key_spki_sha256,
        },
        readiness: ExpectedSigner {
            key_id: &readiness.key_id,
            key_spki_sha256: &readiness.key_spki_sha256,
        },
        approval: ExpectedSigner {
            key_id: &approval.key_id,
            key_spki_sha256: &approval.key_spki_sha256,
        },
    })
}

pub(crate) fn verify_policy_authority_analysis(
    wire: SignedEnvelope<PolicyAuthorityAnalysisPayload>,
    assignment: &VerifiedAssignment,
    analysis_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedPolicyAuthorityAnalysis, ShadowError> {
    revalidate_verified_freshness(
        assignment,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    verify_assignment_authority_key_material(assignment, key_trust)?;
    let pinned_analysis = assignment
        .payload()
        .authority_key_independence
        .binding(
            AuthorityRole::CompilerAnalysis,
            &assignment.payload().assignment_id,
        )?;
    if analysis_signer.key_id != &pinned_analysis.key_id
        || analysis_signer.key_spki_sha256
            != &pinned_analysis.key_spki_sha256
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    if analysis_signer.key_id == &assignment.envelope.signing_key_id
        || analysis_signer.key_spki_sha256
            == &assignment.envelope.signing_key_spki_sha256
        || assignment.payload().fleet.members.iter().any(|member| {
            analysis_signer.key_id == &member.ingress_signing_key_id
                || analysis_signer.key_id
                    == &member.active_decision_signing_key_id
                || analysis_signer.key_id == &member.shadow_signing_key_id
                || analysis_signer.key_spki_sha256
                    == &member.ingress_signing_key_spki_sha256
                || analysis_signer.key_spki_sha256
                    == &member.active_decision_signing_key_spki_sha256
                || analysis_signer.key_spki_sha256
                    == &member.shadow_signing_key_spki_sha256
        })
        || assignment
            .payload()
            .custody_authority
            .role_signers()
            .iter()
            .any(|(key_id, key_spki_sha256)| {
                analysis_signer.key_id == *key_id
                    || analysis_signer.key_spki_sha256
                        == *key_spki_sha256
            })
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let analysis = verify_envelope(
        wire,
        analysis_signer,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    let payload = analysis.payload();
    let independence =
        &assignment.payload().authority_key_independence;
    let terminal_signer = independence.binding(
        AuthorityRole::CustodyTerminalAppend,
        &assignment.payload().assignment_id,
    )?;
    let publication_signer = independence.binding(
        AuthorityRole::CustodyPublicationReconciliation,
        &assignment.payload().assignment_id,
    )?;
    if payload.expected_analysis_key_id != pinned_analysis.key_id
        || payload.expected_analysis_key_spki_sha256
            != pinned_analysis.key_spki_sha256
        || payload.expected_analysis_key_material_sha256
            != pinned_analysis.key_material_sha256
        || payload.authority_key_independence_sha256
            != independence.independence_root_sha256
        || payload
            .custody_receipt_evidence_requirements
            .terminal
            .expected_signing_key_id
            != terminal_signer.key_id
        || payload
            .custody_receipt_evidence_requirements
            .terminal
            .expected_signing_key_spki_sha256
            != terminal_signer.key_spki_sha256
        || payload
            .custody_receipt_evidence_requirements
            .terminal
            .expected_signing_key_material_sha256
            != terminal_signer.key_material_sha256
        || payload
            .custody_receipt_evidence_requirements
            .publication
            .expected_signing_key_id
            != publication_signer.key_id
        || payload
            .custody_receipt_evidence_requirements
            .publication
            .expected_signing_key_spki_sha256
            != publication_signer.key_spki_sha256
        || payload
            .custody_receipt_evidence_requirements
            .publication
            .expected_signing_key_material_sha256
            != publication_signer.key_material_sha256
        || payload.assignment_sha256 != *assignment.envelope_sha256()
        || payload.assignment_payload_sha256 != *assignment.payload_sha256()
        || payload.assignment_revision != assignment.payload().assignment_revision
        || payload.canary_id != assignment.payload().canary_id
        || payload.policy_identity != assignment.payload().policy_identity
        || payload.expected_loaded_snapshots
            != assignment.payload().expected_loaded_snapshots
        || payload.custody_authority_sha256
            != Sha256Digest::compute(&canonical_json_bytes(
                &assignment.payload().custody_authority,
            )?)
        || payload.response_validation_obligations_root_sha256
            != assignment
                .payload()
                .response_validation_obligations_root_sha256
        || payload.issued_at_unix_nanos
            < assignment.payload().issued_at_unix_nanos
        || payload.expires_at_unix_nanos
            > assignment.payload().expires_at_unix_nanos
    {
        return Err(ShadowError::PolicyAuthorityAnalysisMismatch);
    }
    Ok(analysis)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivationPrecondition {
    expected_predecessor_publication_revision: u64,
    expected_predecessor_policy_sha256: Sha256Digest,
    expected_predecessor_policy_sequence: u64,
    expected_predecessor_rollback_epoch: u64,
    candidate_policy_sha256: Sha256Digest,
    candidate_policy_sequence: u64,
    candidate_rollback_epoch: u64,
    expected_publication_key_id: Sha256Digest,
    expected_publication_key_spki_sha256: Sha256Digest,
    expected_publication_key_material_sha256: Sha256Digest,
    activation_deadline_unix_nanos: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemberReadinessEvidence {
    instance_id: Identifier,
    spiffe_id: SpiffeId,
    boot_id_sha256: Sha256Digest,
    generation_id: Sha256Digest,
    generation_epoch: u64,
    generation_tombstone_epoch: u64,
    load_receipt_sha256: Sha256Digest,
    load_receipt_payload_sha256: Sha256Digest,
    final_checkpoint_sha256: Sha256Digest,
    final_checkpoint_payload_sha256: Sha256Digest,
    final_checkpoint_sequence: u64,
    last_observation_sequence: u64,
    last_ingress_sequence: u64,
    observation_count: u64,
    ingress_count: u64,
    evaluated_observation_count: u64,
    comparable_response_count: u64,
    heartbeat_count: u64,
    last_heartbeat_sequence: u64,
    last_heartbeat_at_unix_nanos: i64,
    maximum_observed_heartbeat_gap_nanos: u64,
    cumulative_observation_root_sha256: Sha256Digest,
    cumulative_ingress_root_sha256: Sha256Digest,
    cumulative_active_decision_root_sha256: Sha256Digest,
    cumulative_principal_authority_root_sha256: Sha256Digest,
    cumulative_route_authority_root_sha256: Sha256Digest,
    cumulative_custody_evidence_root_sha256: Sha256Digest,
    cumulative_admitted_ingress_receipt_root_sha256: Sha256Digest,
    cumulative_unavailable_ingress_receipt_root_sha256: Sha256Digest,
    cumulative_dispatch_barrier_receipt_root_sha256: Sha256Digest,
    cumulative_active_effect_barrier_receipt_root_sha256: Sha256Digest,
    cumulative_active_effect_commit_receipt_root_sha256: Sha256Digest,
    cumulative_terminal_receipt_count: u64,
    cumulative_terminal_receipt_root_sha256: Sha256Digest,
    cumulative_publication_receipt_count: u64,
    cumulative_publication_receipt_root_sha256: Sha256Digest,
    cumulative_spill_receipt_root_sha256: Sha256Digest,
    cumulative_persistence_receipt_root_sha256: Sha256Digest,
    cumulative_retrieval_proof_root_sha256: Sha256Digest,
    cumulative_compaction_receipt_root_sha256: Sha256Digest,
    last_ledger_event_ordinal: u64,
    last_ledger_head_sha256: Sha256Digest,
    last_spool_root_sha256: Sha256Digest,
    publication_reconciliation_receipt_sha256: Sha256Digest,
    publication_revision: u64,
    cumulative_heartbeat_root_sha256: Sha256Digest,
    seal_root_sha256: Sha256Digest,
    sealed_at_unix_nanos: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FleetReadiness {
    fleet_id: Sha256Digest,
    membership_revision: u64,
    membership_root_sha256: Sha256Digest,
    expected_member_count: u64,
    covered_member_count: u64,
    member_evidence: Vec<MemberReadinessEvidence>,
    member_evidence_root_sha256: Sha256Digest,
    custody_authority_sha256: Sha256Digest,
    fleet_custody_evidence_root_sha256: Sha256Digest,
    terminal_receipt_count: u64,
    terminal_receipt_root_sha256: Sha256Digest,
    publication_receipt_count: u64,
    publication_receipt_root_sha256: Sha256Digest,
    publication_revision_root_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadinessRates {
    candidate_evaluation_p99_nanos: u64,
    shadow_total_p99_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TrustCheckpointBinding {
    checkpoint_id: Sha256Digest,
    as_of_unix_nanos: i64,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
}

impl From<&AtomicTrustCheckpoint> for TrustCheckpointBinding {
    fn from(checkpoint: &AtomicTrustCheckpoint) -> Self {
        Self {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            as_of_unix_nanos: checkpoint.as_of_unix_nanos,
            revocation_generation: checkpoint.revocation_generation,
            revocation_root_sha256: checkpoint.revocation_root_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadinessCore {
    core_version: String,
    readiness_revision: u64,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    expected_readiness_key_id: Sha256Digest,
    expected_readiness_key_spki_sha256: Sha256Digest,
    expected_readiness_key_material_sha256: Sha256Digest,
    canary_id: Sha256Digest,
    policy_identity: PolicyIdentity,
    trust_checkpoint: TrustCheckpointBinding,
    fleet_readiness: FleetReadiness,
    aggregate_counters: CumulativeCounters,
    readiness_thresholds: ReadinessThresholds,
    calculated_rates: ReadinessRates,
    policy_authority_analysis_sha256: Sha256Digest,
    policy_authority_analysis_payload_sha256: Sha256Digest,
    authority_analysis: AuthorityAnalysis,
    pilot_restrictions: PilotRestrictions,
    custody_receipt_evidence_requirements_sha256: Sha256Digest,
    terminal_receipt_count: u64,
    terminal_receipt_root_sha256: Sha256Digest,
    publication_receipt_count: u64,
    publication_receipt_root_sha256: Sha256Digest,
    response_validation_obligations_root_sha256: Sha256Digest,
    activation_precondition: ActivationPrecondition,
    evidence_root_sha256: Sha256Digest,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl ReadinessCore {
    fn digest(&self) -> Result<Sha256Digest, ShadowError> {
        let canonical = canonical_json_bytes(self)?;
        Ok(hash_domain_frames(READINESS_CORE_DOMAIN, &[&canonical]))
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.core_version != "serverware.policyReadinessCore/v2" {
            return Err(ShadowError::ReadinessUnsafe);
        }
        validate_positive(self.readiness_revision, "readiness_revision")?;
        validate_positive(self.assignment_revision, "assignment_revision")?;
        validate_positive(
            self.trust_checkpoint.revocation_generation,
            "trust_checkpoint.revocation_generation",
        )?;
        validate_positive(
            self.fleet_readiness.membership_revision,
            "membership_revision",
        )?;
        validate_positive(
            self.fleet_readiness.expected_member_count,
            "expected_member_count",
        )?;
        validate_positive(
            self.fleet_readiness.covered_member_count,
            "covered_member_count",
        )?;
        validate_positive(
            self.fleet_readiness.terminal_receipt_count,
            "fleet.terminal_receipt_count",
        )?;
        validate_positive(
            self.fleet_readiness.publication_receipt_count,
            "fleet.publication_receipt_count",
        )?;
        validate_positive(
            self.terminal_receipt_count,
            "readiness.terminal_receipt_count",
        )?;
        validate_positive(
            self.publication_receipt_count,
            "readiness.publication_receipt_count",
        )?;
        validate_len(
            "member_evidence",
            self.fleet_readiness.member_evidence.len(),
            1,
            MAX_COLLECTION_ITEMS,
        )?;
        for evidence in &self.fleet_readiness.member_evidence {
            validate_positive(
                evidence.publication_revision,
                "member_evidence.publication_revision",
            )?;
            validate_positive(
                evidence.last_ledger_event_ordinal,
                "member_evidence.last_ledger_event_ordinal",
            )?;
            validate_positive(
                evidence.cumulative_terminal_receipt_count,
                "member_evidence.cumulative_terminal_receipt_count",
            )?;
            validate_positive(
                evidence.cumulative_publication_receipt_count,
                "member_evidence.cumulative_publication_receipt_count",
            )?;
        }
        if self.terminal_receipt_count
                != self.fleet_readiness.terminal_receipt_count
            || self.terminal_receipt_root_sha256
                != self.fleet_readiness.terminal_receipt_root_sha256
            || self.publication_receipt_count
                != self.fleet_readiness.publication_receipt_count
            || self.publication_receipt_root_sha256
                != self.fleet_readiness.publication_receipt_root_sha256
            || self.publication_receipt_count
                < self.fleet_readiness.covered_member_count
        {
            return Err(ShadowError::ReadinessUnsafe);
        }
        validate_len(
            "readiness.aggregate.expansion_cells",
            self.aggregate_counters.expansion_cells.len(),
            0,
            MAX_EXPANSION_CELLS,
        )?;
        validate_len(
            "readiness.aggregate.response_route_coverage",
            self.aggregate_counters.response_route_coverage.len(),
            0,
            MAX_RESPONSE_OBLIGATIONS,
        )?;
        if self
            .aggregate_counters
            .expansion_cells
            .windows(2)
            .any(|pair| pair[0].cell_sha256 >= pair[1].cell_sha256)
            || self
                .aggregate_counters
                .response_route_coverage
                .windows(2)
                .any(|pair| pair[0].route_sha256 >= pair[1].route_sha256)
        {
            return Err(ShadowError::CounterMismatch);
        }
        validate_positive(
            self.activation_precondition
                .expected_predecessor_publication_revision,
            "expected_predecessor_publication_revision",
        )?;
        validate_positive(
            self.activation_precondition.expected_predecessor_policy_sequence,
            "expected_predecessor_policy_sequence",
        )?;
        validate_positive(
            self.activation_precondition.expected_predecessor_rollback_epoch,
            "expected_predecessor_rollback_epoch",
        )?;
        validate_positive(
            self.activation_precondition.candidate_policy_sequence,
            "candidate_policy_sequence",
        )?;
        validate_positive(
            self.activation_precondition.candidate_rollback_epoch,
            "candidate_rollback_epoch",
        )?;
        if self.activation_precondition.candidate_policy_sha256
                == self
                    .activation_precondition
                    .expected_predecessor_policy_sha256
            || self.activation_precondition.candidate_policy_sequence
                <= self
                    .activation_precondition
                    .expected_predecessor_policy_sequence
            || self.expires_at_unix_nanos <= self.issued_at_unix_nanos
            || self.activation_precondition.activation_deadline_unix_nanos
                <= self.issued_at_unix_nanos
            || self.activation_precondition.activation_deadline_unix_nanos
                > self.expires_at_unix_nanos
        {
            return Err(ShadowError::ReadinessUnsafe);
        }
        match (&self.authority_analysis, &self.pilot_restrictions) {
            (
                AuthorityAnalysis::NoExpansion {
                    expansion_cells,
                },
                PilotRestrictions::NotApplicable,
            ) => validate_semantic_expansion_cells(expansion_cells, true),
            (
                AuthorityAnalysis::ApprovedExpansion {
                    expansion_cells, ..
                },
                PilotRestrictions::Constrained {
                    maximum_requests,
                    maximum_duration_nanos,
                    maximum_write_requests,
                    cells,
                    ..
                },
            ) => {
                validate_positive(*maximum_requests, "pilot.maximum_requests")?;
                validate_positive(*maximum_duration_nanos, "pilot.maximum_duration_nanos")?;
                validate_unsigned(*maximum_write_requests, "pilot.maximum_write_requests")?;
                if maximum_write_requests > maximum_requests {
                    return Err(ShadowError::ExpansionLimitExceeded);
                }
                validate_semantic_expansion_cells(expansion_cells, false)?;
                validate_semantic_expansion_cells(cells, false)?;
                if expansion_cells != cells {
                    return Err(ShadowError::ExpansionCellMismatch);
                }
                Ok(())
            }
            _ => Err(ShadowError::ExpansionCellMismatch),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WebAuthnAssertionEvidence {
    pub(crate) assertion_evidence_sha256: Sha256Digest,
    pub(crate) principal_id: Identifier,
    pub(crate) credential_id: Sha256Digest,
    pub(crate) readiness_core_challenge_sha256: Sha256Digest,
    pub(crate) assertion_object_sha256: Sha256Digest,
    pub(crate) authenticator_data_sha256: Sha256Digest,
    pub(crate) client_data_json_sha256: Sha256Digest,
    pub(crate) assertion_signature_sha256: Sha256Digest,
    pub(crate) cose_public_key_sha256: Sha256Digest,
    pub(crate) rp_id: Identifier,
    pub(crate) origin: CanonicalAscii,
    pub(crate) credential_state_revision: u64,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) expected_previous_signature_counter: Option<u64>,
    pub(crate) signature_counter: u64,
    pub(crate) replay_state_sha256: Sha256Digest,
    pub(crate) approved_at_unix_nanos: i64,
}

impl WebAuthnAssertionEvidence {
    fn recompute_evidence_sha256(&self) -> Result<Sha256Digest, ShadowError> {
        Ok(hash_domain_frames(
            b"serverware.policyActivationWebAuthnAssertion/v1",
            &[&canonical_json_bytes(&(
                &self.principal_id,
                &self.credential_id,
                &self.readiness_core_challenge_sha256,
                &self.assertion_object_sha256,
                &self.authenticator_data_sha256,
                &self.client_data_json_sha256,
                &self.assertion_signature_sha256,
                &self.cose_public_key_sha256,
                &self.rp_id,
                &self.origin,
                self.credential_state_revision,
                self.expected_previous_signature_counter,
                self.signature_counter,
                &self.replay_state_sha256,
                self.approved_at_unix_nanos,
            ))?],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivationApprovalPayload {
    approval_id: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    authority_key_independence_sha256: Sha256Digest,
    expected_approval_key_id: Sha256Digest,
    expected_approval_key_spki_sha256: Sha256Digest,
    expected_approval_key_material_sha256: Sha256Digest,
    readiness_core_sha256: Sha256Digest,
    activation_context_sha256: Sha256Digest,
    approval_mode: ApprovalMode,
    expansion_cells: Vec<Sha256Digest>,
    assertions: Vec<WebAuthnAssertionEvidence>,
    use_limit: u8,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for ActivationApprovalPayload {
    const API_VERSION: &'static str = ACTIVATION_APPROVAL_DOMAIN;
    const KIND: &'static str = "PolicyActivationApproval";
    const SIGNATURE_DOMAIN: &'static str = ACTIVATION_APPROVAL_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        if self.use_limit != 1
            || self.readiness_core_sha256 != self.activation_context_sha256
        {
            return Err(ShadowError::ApprovalBindingMismatch);
        }
        validate_digest_set(&self.expansion_cells, 1, MAX_EXPANSION_CELLS)?;
        let required = match self.approval_mode {
            ApprovalMode::SinglePersonHardwareWebauthn => 1,
            ApprovalMode::TwoPersonHardwareWebauthn => 2,
        };
        if self.assertions.len() != required {
            return Err(ShadowError::ApprovalBindingMismatch);
        }
        let mut assertion_digests = BTreeSet::new();
        for assertion in &self.assertions {
            validate_positive(
                assertion.credential_state_revision,
                "credential_state_revision",
            )?;
            validate_unsigned(assertion.signature_counter, "signature_counter")?;
            if assertion.recompute_evidence_sha256()?
                    != assertion.assertion_evidence_sha256
                || assertion
                    .expected_previous_signature_counter
                    .is_some_and(|previous| {
                        assertion.signature_counter != 0
                            && previous >= assertion.signature_counter
                    })
                || !assertion_digests
                    .insert(assertion.assertion_evidence_sha256.clone())
                || assertion.approved_at_unix_nanos < self.issued_at_unix_nanos
                || assertion.approved_at_unix_nanos >= self.expires_at_unix_nanos
            {
                return Err(ShadowError::ApprovalBindingMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyActivationReadinessPayload {
    readiness_id: Sha256Digest,
    readiness_revision: u64,
    readiness_core: ReadinessCore,
    readiness_core_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    activation_approval: Option<SignedEnvelope<ActivationApprovalPayload>>,
    decision: String,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
}

impl EnvelopePayload for PolicyActivationReadinessPayload {
    const API_VERSION: &'static str = READINESS_DOMAIN;
    const KIND: &'static str = "PolicyActivationReadiness";
    const SIGNATURE_DOMAIN: &'static str = READINESS_DOMAIN;

    fn issued_at_unix_nanos(&self) -> i64 {
        self.issued_at_unix_nanos
    }

    fn expires_at_unix_nanos(&self) -> i64 {
        self.expires_at_unix_nanos
    }

    fn validate_intrinsic(&self) -> Result<(), ShadowError> {
        validate_positive(self.readiness_revision, "readiness_revision")?;
        if self.decision != "ready-for-atomic-activation"
            || self.readiness_revision != self.readiness_core.readiness_revision
            || self.issued_at_unix_nanos != self.readiness_core.issued_at_unix_nanos
            || self.expires_at_unix_nanos != self.readiness_core.expires_at_unix_nanos
            || self.readiness_core.core_version != "serverware.policyReadinessCore/v2"
        {
            return Err(ShadowError::ReadinessUnsafe);
        }
        self.readiness_core.policy_identity.validate()?;
        self.readiness_core.validate_intrinsic()
    }
}

pub(crate) struct VerifiedWebAuthnAssertion {
    assertion_evidence_sha256: Sha256Digest,
    principal_id: Identifier,
    credential_id: Sha256Digest,
    assertion_object_sha256: Sha256Digest,
    authenticator_data_sha256: Sha256Digest,
    client_data_json_sha256: Sha256Digest,
    assertion_signature_sha256: Sha256Digest,
    cose_public_key_sha256: Sha256Digest,
    rp_id: Identifier,
    origin: CanonicalAscii,
    credential_state_revision: u64,
    previous_signature_counter: Option<u64>,
    signature_counter: u64,
    replay_state_sha256: Sha256Digest,
    hardware_backed: bool,
    user_present: bool,
    user_verified: bool,
}

impl VerifiedWebAuthnAssertion {
    pub(crate) fn from_authenticator_verification(
        assertion_evidence_sha256: Sha256Digest,
        principal_id: Identifier,
        credential_id: Sha256Digest,
        assertion_object_sha256: Sha256Digest,
        authenticator_data_sha256: Sha256Digest,
        client_data_json_sha256: Sha256Digest,
        assertion_signature_sha256: Sha256Digest,
        cose_public_key_sha256: Sha256Digest,
        rp_id: Identifier,
        origin: CanonicalAscii,
        credential_state_revision: u64,
        previous_signature_counter: Option<u64>,
        signature_counter: u64,
        replay_state_sha256: Sha256Digest,
        hardware_backed: bool,
        user_present: bool,
        user_verified: bool,
    ) -> Self {
        Self {
            assertion_evidence_sha256,
            principal_id,
            credential_id,
            assertion_object_sha256,
            authenticator_data_sha256,
            client_data_json_sha256,
            assertion_signature_sha256,
            cose_public_key_sha256,
            rp_id,
            origin,
            credential_state_revision,
            previous_signature_counter,
            signature_counter,
            replay_state_sha256,
            hardware_backed,
            user_present,
            user_verified,
        }
    }
}

/// Implementations resolve the exact assertion bytes by the signed digests,
/// validate origin/RP policy, verify the authenticator signature and challenge,
/// and return authenticator-derived properties. Caller booleans are never used.
pub(crate) trait WebAuthnVerification {
    fn verify_assertion(
        &self,
        evidence: &WebAuthnAssertionEvidence,
        expected_readiness_core_sha256: &Sha256Digest,
        trusted_now_unix_nanos: i64,
    ) -> Result<VerifiedWebAuthnAssertion, ShadowError>;
}

pub(crate) struct VerifiedActivationReadiness {
    envelope: VerifiedSignedEnvelope<PolicyActivationReadinessPayload>,
    activation_consumption: ActivationConsumptionBinding,
    assignment: VerifiedAssignment,
    policy_authority_analysis: VerifiedPolicyAuthorityAnalysis,
    load_receipts: Vec<VerifiedLoadReceipt>,
    final_checkpoints: Vec<VerifiedCheckpoint>,
    approval_signer_key_id: Sha256Digest,
    approval_signer_key_spki_sha256: Sha256Digest,
    _no_activation_capability: PhantomData<fn() -> ()>,
}

impl VerifiedActivationReadiness {
    pub(crate) fn payload(&self) -> &PolicyActivationReadinessPayload {
        self.envelope.payload()
    }

    fn into_revalidated_consumption(
        self,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
        attestation: &dyn RuntimeAttestationVerification,
        custody: &dyn PolicyShadowCustodyRpcSupervisor,
        webauthn: &dyn WebAuthnVerification,
    ) -> Result<ActivationConsumptionBinding, ShadowError> {
        let current_checkpoint = key_trust.current_checkpoint()?;
        let trusted_now = verify_activation_time_binding(
            trusted_time,
            &current_checkpoint,
            self.envelope
                .payload()
                .readiness_core
                .activation_precondition
                .activation_deadline_unix_nanos,
        )?;
        if self.envelope.trust_checkpoint != current_checkpoint
            || !self
                .activation_consumption
                .matches_trust_checkpoint(&current_checkpoint)
        {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        verify_assignment_authority_key_material(
            &self.assignment,
            key_trust,
        )?;
        let mut authority_roles = vec![
            (
                &self.assignment.envelope.signing_key_id,
                &self.assignment.envelope.signing_key_spki_sha256,
            ),
            (
                &self
                    .policy_authority_analysis
                    .envelope
                    .signing_key_id,
                &self
                    .policy_authority_analysis
                    .envelope
                    .signing_key_spki_sha256,
            ),
            (
                &self.envelope.envelope.signing_key_id,
                &self.envelope.envelope.signing_key_spki_sha256,
            ),
            (
                &self.approval_signer_key_id,
                &self.approval_signer_key_spki_sha256,
            ),
        ];
        for member in &self.assignment.payload().fleet.members {
            authority_roles.extend([
                (
                    &member.tee_attestation_key_id,
                    &member.tee_attestation_key_spki_sha256,
                ),
                (
                    &member.ingress_signing_key_id,
                    &member.ingress_signing_key_spki_sha256,
                ),
                (
                    &member.active_decision_signing_key_id,
                    &member.active_decision_signing_key_spki_sha256,
                ),
                (
                    &member.shadow_signing_key_id,
                    &member.shadow_signing_key_spki_sha256,
                ),
            ]);
        }
        authority_roles.extend(
            self.assignment
                .payload()
                .custody_authority
                .role_signers(),
        );
        enforce_cross_document_role_key_independence(authority_roles)?;
        revalidate_verified_at_checkpoint(
            &self.envelope,
            &current_checkpoint,
            key_trust,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        revalidate_verified_at_checkpoint(
            &self.assignment,
            &current_checkpoint,
            key_trust,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        revalidate_verified_at_checkpoint(
            &self.policy_authority_analysis,
            &current_checkpoint,
            key_trust,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        let evidence_max_age: i64 = self
            .assignment
            .payload()
            .observation_window
            .maximum_evidence_age_nanos
            .try_into()
            .map_err(|_| ShadowError::EvidenceTooOld)?;
        for receipt in &self.load_receipts {
            revalidate_verified_at_checkpoint(
                receipt,
                &current_checkpoint,
                key_trust,
                evidence_max_age,
            )?;
        }
        for checkpoint in &self.final_checkpoints {
            revalidate_verified_at_checkpoint(
                checkpoint,
                &current_checkpoint,
                key_trust,
                evidence_max_age,
            )?;
        }
        for member in &self.assignment.payload().fleet.members {
            for (domain, key_id, key_spki_sha256) in [
                (
                    INGRESS_EVIDENCE_DOMAIN,
                    &member.ingress_signing_key_id,
                    &member.ingress_signing_key_spki_sha256,
                ),
                (
                    ACTIVE_DECISION_DOMAIN,
                    &member.active_decision_signing_key_id,
                    &member.active_decision_signing_key_spki_sha256,
                ),
                (
                    OBSERVATION_DOMAIN,
                    &member.shadow_signing_key_id,
                    &member.shadow_signing_key_spki_sha256,
                ),
                (
                    HEARTBEAT_DOMAIN,
                    &member.shadow_signing_key_id,
                    &member.shadow_signing_key_spki_sha256,
                ),
                (
                    CHECKPOINT_DOMAIN,
                    &member.shadow_signing_key_id,
                    &member.shadow_signing_key_spki_sha256,
                ),
            ] {
                key_trust.resolve_ed25519_key(
                    &current_checkpoint,
                    domain,
                    key_id,
                    key_spki_sha256,
                )?;
            }
            let receipt = self
                .load_receipts
                .iter()
                .find(|receipt| {
                    receipt.payload().runtime_identity.instance_id
                        == member.instance_id
                })
                .ok_or(ShadowError::FleetCoverageIncomplete)?;
            attestation.verify_runtime_identity(
                &current_checkpoint,
                &receipt.payload().runtime_identity,
                member,
                self.assignment.payload_sha256(),
                trusted_now,
            )?;
            let checkpoint = self
                .final_checkpoints
                .iter()
                .find(|checkpoint| {
                    checkpoint.payload().runtime_identity.instance_id
                        == member.instance_id
                })
                .ok_or(ShadowError::FleetCoverageIncomplete)?;
            let CheckpointSeal::Sealed { window_closure, .. } =
                &checkpoint.payload().seal
            else {
                return Err(ShadowError::FleetCoverageIncomplete);
            };
            verify_wire_at_checkpoint(
                window_closure,
                ExpectedSigner {
                    key_id: &member.ingress_signing_key_id,
                    key_spki_sha256:
                        &member.ingress_signing_key_spki_sha256,
                },
                &current_checkpoint,
                key_trust,
                evidence_max_age,
            )?;
        }
        verify_complete_fleet(
            &self.envelope.payload().readiness_core,
            &self.assignment,
            &self.load_receipts,
            &self.final_checkpoints,
            custody,
            trusted_time,
        )?;
        verify_readiness_counters(
            &self.envelope.payload().readiness_core,
            &self.assignment,
            &self.final_checkpoints,
        )?;
        verify_readiness_evidence_root(&self.envelope.payload().readiness_core)?;
        validate_freshness(
            self.envelope.payload().issued_at_unix_nanos(),
            self.envelope.payload().expires_at_unix_nanos(),
            trusted_now,
            MAX_ENVELOPE_AGE_NANOS,
        )?;
        let recomputed_consumption = verify_authority_and_approval(
            self.envelope.payload().activation_approval.as_ref(),
            &self.envelope.payload().readiness_core,
            &self.envelope.payload().readiness_core_sha256,
            &self.policy_authority_analysis,
            &self.assignment,
            ExpectedSigner {
                key_id: &self.approval_signer_key_id,
                key_spki_sha256:
                    &self.approval_signer_key_spki_sha256,
            },
            key_trust,
            webauthn,
            trusted_time,
            trusted_now,
            &current_checkpoint,
        )?;
        if recomputed_consumption != self.activation_consumption {
            return Err(ShadowError::ActivationConsumptionBindingMismatch);
        }
        if key_trust.current_checkpoint()? != current_checkpoint {
            return Err(ShadowError::TrustCheckpointMismatch);
        }
        Ok(self.activation_consumption)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_and_publish(
        self,
        activation_request_sha256: Sha256Digest,
        activation_request_id: Identifier,
        activation_replay_id: Identifier,
        key_trust: &dyn EnvelopeKeyTrust,
        trusted_time: &dyn TrustedTime,
        attestation: &dyn RuntimeAttestationVerification,
        webauthn: &dyn WebAuthnVerification,
        custody: &dyn PolicyShadowCustodyRpcSupervisor,
    ) -> Result<VerifiedActivationPublicationReceipt, ShadowError> {
        let assignment_sha256 =
            self.assignment.envelope_sha256().clone();
        let assignment_payload_sha256 =
            self.assignment.payload_sha256().clone();
        let assignment_revision =
            self.assignment.payload().assignment_revision;
        let authority_key_independence_sha256 = self
            .assignment
            .payload()
            .authority_key_independence
            .independence_root_sha256
            .clone();
        let readiness_envelope_sha256 = self.envelope.envelope_sha256().clone();
        let assignment_publication_signer = self
            .assignment
            .payload()
            .authority_key_independence
            .binding(
                AuthorityRole::CustodyActivationPublication,
                &self.assignment.payload().assignment_id,
            )?;
        let expected_publication_key_id =
            assignment_publication_signer.key_id.clone();
        let expected_publication_key_spki_sha256 =
            assignment_publication_signer.key_spki_sha256.clone();
        let readiness_publication_key_id = self
            .envelope
            .payload()
            .readiness_core
            .activation_precondition
            .expected_publication_key_id
            .clone();
        let readiness_publication_key_spki_sha256 = self
            .envelope
            .payload()
            .readiness_core
            .activation_precondition
            .expected_publication_key_spki_sha256
            .clone();
        if readiness_publication_key_id != expected_publication_key_id
            || readiness_publication_key_spki_sha256
                != expected_publication_key_spki_sha256
        {
            return Err(ShadowError::SignerBindingMismatch);
        }
        let readiness_payload_sha256 = self.envelope.payload_sha256().clone();
        let readiness_core_sha256 = self.envelope.payload().readiness_core_sha256.clone();
        let binding = self.into_revalidated_consumption(
            key_trust,
            trusted_time,
            attestation,
            custody,
            webauthn,
        )?;
        let transaction = ActivationPublicationTransaction::new(
            activation_request_sha256,
            activation_request_id,
            activation_replay_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            authority_key_independence_sha256,
            readiness_envelope_sha256.clone(),
            readiness_payload_sha256,
            readiness_core_sha256,
            binding,
        )?;
        let expected_transaction_sha256 = transaction.transaction_sha256.clone();
        let (
            expected_publication_revision,
            expected_predecessor_policy_sha256,
            expected_predecessor_policy_sequence,
            expected_predecessor_rollback_epoch,
            candidate_policy_sha256,
            candidate_policy_sequence,
            candidate_rollback_epoch,
        ) = transaction.consumption.expected_publication();
        // Revalidation may use ordinary custody reads. Open the globally
        // exclusive mutation only after those reads are complete so activation
        // never re-enters the custody supervisor while publication is live.
        let operation_id_sha256 = hash_domain_frames(
            b"serverware.policyActivationPublicationRpc/v2",
            &[expected_transaction_sha256.as_str().as_bytes()],
        );
        let context = custody.open_bound_call(
            operation_id_sha256.clone(),
            PolicyShadowCustodyOperation::ConsumeAndPublishActivation,
            expected_transaction_sha256.clone(),
        )?;
        if !context.authorizes(
            PolicyShadowCustodyOperation::ConsumeAndPublishActivation,
        ) || !context.operation_deadline().authorizes_operation_at(
            production_now_boottime_nanos()?,
        )
        {
            return Err(ShadowError::CustodyUnavailable);
        }
        let operation_deadline = context.operation_deadline().clone();
        let receipt_result =
            custody.consume_recheck_and_publish(&context, transaction);
        let completion = custody.finish_call(context)?;
        if !completion.validates(
            &operation_id_sha256,
            &operation_deadline,
        ) {
            return Err(ShadowError::CustodyUnavailable);
        }
        let receipt = receipt_result?;
        if receipt.wire.transaction_sha256 != expected_transaction_sha256
            || receipt.wire.replaced_publication_revision
                != expected_publication_revision
            || receipt.wire.published_publication_revision
                != expected_publication_revision
                    .checked_add(1)
                    .ok_or(ShadowError::CounterOverflow)?
            || receipt.wire.replaced_policy_sha256
                != expected_predecessor_policy_sha256
            || receipt.wire.replaced_policy_sequence
                != expected_predecessor_policy_sequence
            || receipt.wire.replaced_rollback_epoch
                != expected_predecessor_rollback_epoch
            || receipt.wire.published_policy_sha256
                != candidate_policy_sha256
            || receipt.wire.published_policy_sequence
                != candidate_policy_sequence
            || receipt.wire.published_rollback_epoch
                != candidate_rollback_epoch
            || receipt.wire.replaced_policy_sha256
                == receipt.wire.published_policy_sha256
            || receipt.wire.replaced_policy_sequence
                >= receipt.wire.published_policy_sequence
        {
            return Err(ShadowError::ActivationConsumptionBindingMismatch);
        }
        Ok(receipt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AssertionConsumption {
    pub(crate) assertion_evidence_sha256: Sha256Digest,
    pub(crate) principal_id: Identifier,
    pub(crate) credential_id: Sha256Digest,
    pub(crate) assertion_object_sha256: Sha256Digest,
    pub(crate) authenticator_data_sha256: Sha256Digest,
    pub(crate) client_data_json_sha256: Sha256Digest,
    pub(crate) assertion_signature_sha256: Sha256Digest,
    pub(crate) cose_public_key_sha256: Sha256Digest,
    pub(crate) rp_id: Identifier,
    pub(crate) origin: CanonicalAscii,
    pub(crate) credential_state_revision: u64,
    pub(crate) previous_signature_counter: Option<u64>,
    pub(crate) signature_counter: u64,
    pub(crate) replay_state_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", rename_all_fields = "camelCase")]
pub(crate) enum ActivationConsumptionBinding {
    NoExpansion {
        readiness_core_sha256: Sha256Digest,
        trust_checkpoint_id: Sha256Digest,
        trust_checkpoint_as_of_unix_nanos: i64,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        trusted_now_unix_nanos: i64,
        maximum_checkpoint_age_nanos: u64,
        expected_publication_revision: u64,
        expected_predecessor_policy_sha256: Sha256Digest,
        expected_predecessor_policy_sequence: u64,
        expected_predecessor_rollback_epoch: u64,
        candidate_policy_sha256: Sha256Digest,
        candidate_policy_sequence: u64,
        candidate_rollback_epoch: u64,
        activation_deadline_unix_nanos: i64,
    },
    ApprovedExpansion {
        approval_id: Sha256Digest,
        approval_envelope_sha256: Sha256Digest,
        approval_payload_sha256: Sha256Digest,
        readiness_core_sha256: Sha256Digest,
        trust_checkpoint_id: Sha256Digest,
        trust_checkpoint_as_of_unix_nanos: i64,
        trust_revocation_generation: u64,
        trust_revocation_root_sha256: Sha256Digest,
        trusted_now_unix_nanos: i64,
        maximum_checkpoint_age_nanos: u64,
        assertions: Vec<AssertionConsumption>,
        expected_publication_revision: u64,
        expected_predecessor_policy_sha256: Sha256Digest,
        expected_predecessor_policy_sequence: u64,
        expected_predecessor_rollback_epoch: u64,
        candidate_policy_sha256: Sha256Digest,
        candidate_policy_sequence: u64,
        candidate_rollback_epoch: u64,
        activation_deadline_unix_nanos: i64,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ActivationPublicationTransaction {
    transaction_sha256: Sha256Digest,
    activation_request_sha256: Sha256Digest,
    activation_request_id: Identifier,
    activation_replay_id: Identifier,
    assignment_sha256: Sha256Digest,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    authority_key_independence_sha256: Sha256Digest,
    readiness_envelope_sha256: Sha256Digest,
    readiness_payload_sha256: Sha256Digest,
    readiness_core_sha256: Sha256Digest,
    consumption: ActivationConsumptionBinding,
}

impl ActivationPublicationTransaction {
    fn new(
        activation_request_sha256: Sha256Digest,
        activation_request_id: Identifier,
        activation_replay_id: Identifier,
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        authority_key_independence_sha256: Sha256Digest,
        readiness_envelope_sha256: Sha256Digest,
        readiness_payload_sha256: Sha256Digest,
        readiness_core_sha256: Sha256Digest,
        consumption: ActivationConsumptionBinding,
    ) -> Result<Self, ShadowError> {
        if activation_request_id == activation_replay_id {
            return Err(ShadowError::ActivationConsumptionBindingMismatch);
        }
        let transaction_sha256 = hash_domain_frames(
            b"serverware.policyActivationAtomicConsumption/v1",
            &[&canonical_json_bytes(&(
                &activation_request_sha256,
                &activation_request_id,
                &activation_replay_id,
                &readiness_envelope_sha256,
                &readiness_payload_sha256,
                &readiness_core_sha256,
                &assignment_sha256,
                &assignment_payload_sha256,
                assignment_revision,
                &authority_key_independence_sha256,
                &consumption,
            ))?],
        );
        Ok(Self {
            transaction_sha256,
            activation_request_sha256,
            activation_request_id,
            activation_replay_id,
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            authority_key_independence_sha256,
            readiness_envelope_sha256,
            readiness_payload_sha256,
            readiness_core_sha256,
            consumption,
        })
    }

    pub(crate) fn transaction_sha256(&self) -> &Sha256Digest {
        &self.transaction_sha256
    }

    pub(crate) fn readiness_envelope_sha256(&self) -> &Sha256Digest {
        &self.readiness_envelope_sha256
    }

    pub(crate) fn readiness_payload_sha256(&self) -> &Sha256Digest {
        &self.readiness_payload_sha256
    }

    pub(crate) fn readiness_core_sha256(&self) -> &Sha256Digest {
        &self.readiness_core_sha256
    }

    pub(crate) fn consumption(&self) -> &ActivationConsumptionBinding {
        &self.consumption
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ActivationPublicationReceiptWire {
    pub(crate) assignment_sha256: Sha256Digest,
    pub(crate) assignment_payload_sha256: Sha256Digest,
    pub(crate) assignment_revision: u64,
    pub(crate) readiness_core_sha256: Sha256Digest,
    pub(crate) authority_key_independence_sha256: Sha256Digest,
    pub(crate) transaction_sha256: Sha256Digest,
    pub(crate) replaced_policy_sha256: Sha256Digest,
    pub(crate) replaced_policy_sequence: u64,
    pub(crate) replaced_rollback_epoch: u64,
    pub(crate) published_policy_sha256: Sha256Digest,
    pub(crate) published_policy_sequence: u64,
    pub(crate) published_rollback_epoch: u64,
    pub(crate) replaced_publication_revision: u64,
    pub(crate) published_publication_revision: u64,
    pub(crate) trusted_observed_at_unix_nanos: i64,
    pub(crate) trusted_time_checkpoint_sha256: Sha256Digest,
    pub(crate) persistence_receipt_sha256: Sha256Digest,
    pub(crate) retrieval_id_sha256: Sha256Digest,
    pub(crate) retrieval_proof_sha256: Sha256Digest,
    pub(crate) signing_key_id: Sha256Digest,
    pub(crate) signing_key_spki_sha256: Sha256Digest,
    pub(crate) signature: CanonicalEd25519Signature,
    pub(crate) signed_receipt_sha256: Sha256Digest,
}

impl ActivationPublicationReceiptWire {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_custody(
        assignment_sha256: Sha256Digest,
        assignment_payload_sha256: Sha256Digest,
        assignment_revision: u64,
        readiness_core_sha256: Sha256Digest,
        authority_key_independence_sha256: Sha256Digest,
        transaction_sha256: Sha256Digest,
        replaced_policy_sha256: Sha256Digest,
        replaced_policy_sequence: u64,
        replaced_rollback_epoch: u64,
        published_policy_sha256: Sha256Digest,
        published_policy_sequence: u64,
        published_rollback_epoch: u64,
        replaced_publication_revision: u64,
        published_publication_revision: u64,
        trusted_observed_at_unix_nanos: i64,
        trusted_time_checkpoint_sha256: Sha256Digest,
        persistence_receipt_sha256: Sha256Digest,
        retrieval_id_sha256: Sha256Digest,
        retrieval_proof_sha256: Sha256Digest,
        signing_key_id: Sha256Digest,
        signing_key_spki_sha256: Sha256Digest,
        signature: String,
        signed_receipt_sha256: Sha256Digest,
    ) -> Result<Self, ShadowError> {
        validate_positive(
            assignment_revision,
            "activation.assignment_revision",
        )?;
        validate_positive(replaced_policy_sequence, "activation.replaced_policy_sequence")?;
        validate_positive(replaced_rollback_epoch, "activation.replaced_rollback_epoch")?;
        validate_positive(published_policy_sequence, "activation.policy_sequence")?;
        validate_positive(published_rollback_epoch, "activation.rollback_epoch")?;
        validate_positive(
            replaced_publication_revision,
            "activation.replaced_publication_revision",
        )?;
        validate_positive(
            published_publication_revision,
            "activation.published_publication_revision",
        )?;
        if replaced_policy_sha256 == published_policy_sha256
            || published_policy_sequence <= replaced_policy_sequence
            || replaced_publication_revision
                .checked_add(1)
                != Some(published_publication_revision)
            || trusted_observed_at_unix_nanos <= 0
        {
            return Err(ShadowError::ActivationConsumptionBindingMismatch);
        }
        let signature = CanonicalEd25519Signature(signature);
        signature.decode()?;
        let wire = Self {
            assignment_sha256,
            assignment_payload_sha256,
            assignment_revision,
            readiness_core_sha256,
            authority_key_independence_sha256,
            transaction_sha256,
            replaced_policy_sha256,
            replaced_policy_sequence,
            replaced_rollback_epoch,
            published_policy_sha256,
            published_policy_sequence,
            published_rollback_epoch,
            replaced_publication_revision,
            published_publication_revision,
            trusted_observed_at_unix_nanos,
            trusted_time_checkpoint_sha256,
            persistence_receipt_sha256,
            retrieval_id_sha256,
            retrieval_proof_sha256,
            signing_key_id,
            signing_key_spki_sha256,
            signature,
            signed_receipt_sha256,
        };
        let canonical_payload = wire.canonical_payload()?;
        let expected = hash_domain_frames(
            b"serverware.policyActivationPublicationReceipt/v1",
            &[
                canonical_payload.as_slice(),
                wire.signature.0.as_bytes(),
            ],
        );
        if wire.signed_receipt_sha256 != expected {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(wire)
    }

    fn validate_deserialized_invariants(&self) -> Result<(), ShadowError> {
        let reconstructed = Self::from_custody(
            self.assignment_sha256.clone(),
            self.assignment_payload_sha256.clone(),
            self.assignment_revision,
            self.readiness_core_sha256.clone(),
            self.authority_key_independence_sha256.clone(),
            self.transaction_sha256.clone(),
            self.replaced_policy_sha256.clone(),
            self.replaced_policy_sequence,
            self.replaced_rollback_epoch,
            self.published_policy_sha256.clone(),
            self.published_policy_sequence,
            self.published_rollback_epoch,
            self.replaced_publication_revision,
            self.published_publication_revision,
            self.trusted_observed_at_unix_nanos,
            self.trusted_time_checkpoint_sha256.clone(),
            self.persistence_receipt_sha256.clone(),
            self.retrieval_id_sha256.clone(),
            self.retrieval_proof_sha256.clone(),
            self.signing_key_id.clone(),
            self.signing_key_spki_sha256.clone(),
            self.signature.0.clone(),
            self.signed_receipt_sha256.clone(),
        )?;
        if reconstructed != *self {
            return Err(ShadowError::PayloadDigestMismatch);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, ShadowError> {
        canonical_json_bytes(&serde_json::json!([
            &self.assignment_sha256,
            &self.assignment_payload_sha256,
            self.assignment_revision,
            &self.readiness_core_sha256,
            &self.authority_key_independence_sha256,
            &self.transaction_sha256,
            &self.replaced_policy_sha256,
            self.replaced_policy_sequence,
            self.replaced_rollback_epoch,
            &self.published_policy_sha256,
            self.published_policy_sequence,
            self.published_rollback_epoch,
            self.replaced_publication_revision,
            self.published_publication_revision,
            self.trusted_observed_at_unix_nanos,
            &self.trusted_time_checkpoint_sha256,
            &self.persistence_receipt_sha256,
            &self.retrieval_id_sha256,
            &self.retrieval_proof_sha256,
            PolicyShadowCustodySignerRole::ActivationPublication,
            &self.signing_key_id,
            &self.signing_key_spki_sha256,
        ]))
    }
}

#[derive(Clone)]
pub(crate) struct VerifiedActivationPublicationReceipt {
    wire: ActivationPublicationReceiptWire,
    canonical_payload_sha256: Sha256Digest,
    verified_trust_checkpoint: AtomicTrustCheckpoint,
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_activation_publication_receipt(
    wire: ActivationPublicationReceiptWire,
    expected_transaction: &ActivationPublicationTransaction,
    expected_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
    maximum_age_nanos: i64,
) -> Result<VerifiedActivationPublicationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.assignment_sha256
            != expected_transaction.assignment_sha256
        || wire.assignment_payload_sha256
            != expected_transaction.assignment_payload_sha256
        || wire.assignment_revision
            != expected_transaction.assignment_revision
        || wire.readiness_core_sha256
            != expected_transaction.readiness_core_sha256
        || wire.authority_key_independence_sha256
            != expected_transaction.authority_key_independence_sha256
        || wire.transaction_sha256
            != *expected_transaction.transaction_sha256()
    {
        return Err(ShadowError::ActivationConsumptionBindingMismatch);
    }
    let (
        expected_revision,
        expected_predecessor_sha256,
        expected_predecessor_sequence,
        expected_predecessor_epoch,
        candidate_sha256,
        candidate_sequence,
        candidate_epoch,
    ) = expected_transaction.consumption().expected_publication();
    if wire.replaced_publication_revision != expected_revision
        || wire.published_publication_revision
            != expected_revision
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?
        || wire.replaced_policy_sha256 != expected_predecessor_sha256
        || wire.replaced_policy_sequence != expected_predecessor_sequence
        || wire.replaced_rollback_epoch != expected_predecessor_epoch
        || wire.published_policy_sha256 != candidate_sha256
        || wire.published_policy_sequence != candidate_sequence
        || wire.published_rollback_epoch != candidate_epoch
    {
        return Err(ShadowError::ActivationConsumptionBindingMismatch);
    }
    let canonical_payload = wire.canonical_payload()?;
    let verified_trust_checkpoint = verify_custody_receipt_authority(
        PolicyShadowCustodySignerRole::ActivationPublication,
        &wire.signing_key_id,
        &wire.signing_key_spki_sha256,
        &wire.signature,
        wire.trusted_observed_at_unix_nanos,
        &wire.trusted_time_checkpoint_sha256,
        &wire.persistence_receipt_sha256,
        &wire.retrieval_id_sha256,
        &wire.retrieval_proof_sha256,
        &canonical_payload,
        expected_signer,
        key_trust,
        trusted_time,
        proof_verifier,
        maximum_age_nanos,
    )?;
    Ok(VerifiedActivationPublicationReceipt {
        wire,
        canonical_payload_sha256: Sha256Digest::compute(&canonical_payload),
        verified_trust_checkpoint,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in crate::policy_shadow) fn verify_production_activation_publication_receipt(
    wire: ActivationPublicationReceiptWire,
    expected_transaction: &ActivationPublicationTransaction,
    configuration: &ProductionCustodyConfiguration,
    key_trust: &dyn EnvelopeKeyTrust,
    trusted_time: &dyn TrustedTime,
    proof_verifier: &dyn PolicyShadowPersistenceProofVerifier,
) -> Result<VerifiedActivationPublicationReceipt, ShadowError> {
    wire.validate_deserialized_invariants()?;
    if wire.assignment_sha256
            != expected_transaction.assignment_sha256
        || wire.assignment_payload_sha256
            != expected_transaction.assignment_payload_sha256
        || wire.assignment_revision
            != expected_transaction.assignment_revision
        || wire.readiness_core_sha256
            != expected_transaction.readiness_core_sha256
        || wire.authority_key_independence_sha256
            != expected_transaction.authority_key_independence_sha256
        || wire.transaction_sha256
            != *expected_transaction.transaction_sha256()
    {
        return Err(ShadowError::ActivationConsumptionBindingMismatch);
    }
    let (
        expected_revision,
        expected_predecessor_sha256,
        expected_predecessor_sequence,
        expected_predecessor_epoch,
        candidate_sha256,
        candidate_sequence,
        candidate_epoch,
    ) = expected_transaction.consumption().expected_publication();
    if wire.replaced_publication_revision != expected_revision
        || wire.published_publication_revision
            != expected_revision
                .checked_add(1)
                .ok_or(ShadowError::CounterOverflow)?
        || wire.replaced_policy_sha256 != expected_predecessor_sha256
        || wire.replaced_policy_sequence != expected_predecessor_sequence
        || wire.replaced_rollback_epoch != expected_predecessor_epoch
        || wire.published_policy_sha256 != candidate_sha256
        || wire.published_policy_sequence != candidate_sequence
        || wire.published_rollback_epoch != candidate_epoch
    {
        return Err(ShadowError::ActivationConsumptionBindingMismatch);
    }
    let canonical_payload = wire.canonical_payload()?;
    let canonical_payload_sha256 =
        Sha256Digest::compute(&canonical_payload);
    let verified_trust_checkpoint =
        verify_production_custody_receipt_authority(
            configuration,
            PolicyShadowCustodySignerRole::ActivationPublication,
            &wire.signing_key_id,
            &wire.signing_key_spki_sha256,
            &wire.signature,
            wire.trusted_observed_at_unix_nanos,
            &wire.trusted_time_checkpoint_sha256,
            &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256,
            &wire.retrieval_proof_sha256,
            &canonical_payload,
            key_trust,
            trusted_time,
            proof_verifier,
    )?;
    Ok(VerifiedActivationPublicationReceipt {
        wire,
        canonical_payload_sha256,
        verified_trust_checkpoint,
    })
}

impl VerifiedActivationPublicationReceipt {
    pub(crate) fn wire(&self) -> &ActivationPublicationReceiptWire {
        &self.wire
    }

    pub(crate) fn canonical_payload_sha256(&self) -> &Sha256Digest {
        &self.canonical_payload_sha256
    }

    pub(crate) fn signed_receipt_sha256(&self) -> &Sha256Digest {
        &self.wire.signed_receipt_sha256
    }

    pub(crate) fn verified_trust_checkpoint(
        &self,
    ) -> &AtomicTrustCheckpoint {
        &self.verified_trust_checkpoint
    }
}

impl ActivationConsumptionBinding {
    #[allow(clippy::type_complexity)]
    fn expected_publication(
        &self,
    ) -> (
        u64,
        Sha256Digest,
        u64,
        u64,
        Sha256Digest,
        u64,
        u64,
    ) {
        match self {
            Self::NoExpansion {
                expected_publication_revision,
                expected_predecessor_policy_sha256,
                expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch,
                candidate_policy_sha256,
                candidate_policy_sequence,
                candidate_rollback_epoch,
                ..
            }
            | Self::ApprovedExpansion {
                expected_publication_revision,
                expected_predecessor_policy_sha256,
                expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch,
                candidate_policy_sha256,
                candidate_policy_sequence,
                candidate_rollback_epoch,
                ..
            } => (
                *expected_publication_revision,
                expected_predecessor_policy_sha256.clone(),
                *expected_predecessor_policy_sequence,
                *expected_predecessor_rollback_epoch,
                candidate_policy_sha256.clone(),
                *candidate_policy_sequence,
                *candidate_rollback_epoch,
            ),
        }
    }

    fn matches_trust_checkpoint(&self, checkpoint: &AtomicTrustCheckpoint) -> bool {
        let (
            checkpoint_id,
            checkpoint_as_of,
            revocation_generation,
            revocation_root_sha256,
        ) = match self {
            Self::NoExpansion {
                trust_checkpoint_id,
                trust_checkpoint_as_of_unix_nanos,
                trust_revocation_generation,
                trust_revocation_root_sha256,
                ..
            }
            | Self::ApprovedExpansion {
                trust_checkpoint_id,
                trust_checkpoint_as_of_unix_nanos,
                trust_revocation_generation,
                trust_revocation_root_sha256,
                ..
            } => (
                trust_checkpoint_id,
                *trust_checkpoint_as_of_unix_nanos,
                *trust_revocation_generation,
                trust_revocation_root_sha256,
            ),
        };
        checkpoint_id == &checkpoint.checkpoint_id
            && checkpoint_as_of == checkpoint.as_of_unix_nanos
            && revocation_generation == checkpoint.revocation_generation
            && revocation_root_sha256 == &checkpoint.revocation_root_sha256
    }
}

fn verify_activation_time_binding(
    trusted_time: &dyn TrustedTime,
    checkpoint: &AtomicTrustCheckpoint,
    activation_deadline_unix_nanos: i64,
) -> Result<i64, ShadowError> {
    let trusted_now = trusted_time.now_unix_nanos()?;
    let checkpoint_age = trusted_now
        .checked_sub(checkpoint.as_of_unix_nanos)
        .ok_or(ShadowError::TrustCheckpointMismatch)?;
    if checkpoint.as_of_unix_nanos > trusted_now
        || checkpoint_age > MAX_ACTIVATION_CHECKPOINT_AGE_NANOS
        || trusted_now >= activation_deadline_unix_nanos
    {
        return Err(ShadowError::EvidenceExpired);
    }
    Ok(trusted_now)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_activation_readiness(
    wire: SignedEnvelope<PolicyActivationReadinessPayload>,
    assignment: &VerifiedAssignment,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    load_receipts: &[VerifiedLoadReceipt],
    final_checkpoints: &[VerifiedCheckpoint],
    readiness_signer: ExpectedSigner<'_>,
    approval_signer: ExpectedSigner<'_>,
    attestation: &dyn RuntimeAttestationVerification,
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    key_trust: &dyn EnvelopeKeyTrust,
    webauthn: &dyn WebAuthnVerification,
    trusted_time: &dyn TrustedTime,
) -> Result<VerifiedActivationReadiness, ShadowError> {
    let trust_checkpoint = key_trust.current_checkpoint()?;
    verify_assignment_authority_key_material(assignment, key_trust)?;
    if key_trust.current_checkpoint()? != trust_checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let key_independence =
        &assignment.payload().authority_key_independence;
    let pinned_readiness = key_independence.binding(
        AuthorityRole::ActivationReadiness,
        &assignment.payload().assignment_id,
    )?;
    let pinned_approval = key_independence.binding(
        AuthorityRole::ActivationApproval,
        &assignment.payload().assignment_id,
    )?;
    let pinned_activation_publication = key_independence.binding(
        AuthorityRole::CustodyActivationPublication,
        &assignment.payload().assignment_id,
    )?;
    if readiness_signer.key_id != &pinned_readiness.key_id
        || readiness_signer.key_spki_sha256
            != &pinned_readiness.key_spki_sha256
        || approval_signer.key_id != &pinned_approval.key_id
        || approval_signer.key_spki_sha256
            != &pinned_approval.key_spki_sha256
    {
        return Err(ShadowError::SignerBindingMismatch);
    }
    let readiness = verify_envelope(
        wire,
        readiness_signer,
        key_trust,
        trusted_time,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    if readiness.trust_checkpoint != trust_checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    let core = &readiness.payload().readiness_core;
    let mut authority_roles = vec![(
        &assignment.envelope.signing_key_id,
        &assignment.envelope.signing_key_spki_sha256,
    )];
    authority_roles.extend(
        key_independence.bindings.iter().map(|binding| {
            (&binding.key_id, &binding.key_spki_sha256)
        }),
    );
    enforce_cross_document_role_key_independence(authority_roles)?;
    let core_digest = core.digest()?;
    if core_digest != readiness.payload().readiness_core_sha256
        || core.assignment_sha256 != *assignment.envelope_sha256()
        || core.assignment_payload_sha256 != *assignment.payload_sha256()
        || core.assignment_revision != assignment.payload().assignment_revision
        || core.authority_key_independence_sha256
            != assignment
                .payload()
                .authority_key_independence
                .independence_root_sha256
        || core.expected_readiness_key_id != pinned_readiness.key_id
        || core.expected_readiness_key_spki_sha256
            != pinned_readiness.key_spki_sha256
        || core.expected_readiness_key_material_sha256
            != pinned_readiness.key_material_sha256
        || core.canary_id != assignment.payload().canary_id
        || core.policy_identity != assignment.payload().policy_identity
        || core.trust_checkpoint
            != TrustCheckpointBinding::from(&trust_checkpoint)
        || core.readiness_thresholds != assignment.payload().readiness_thresholds
        || core.response_validation_obligations_root_sha256
            != assignment
                .payload()
                .response_validation_obligations_root_sha256
        || core.policy_authority_analysis_sha256
            != *policy_authority_analysis.envelope_sha256()
        || core.policy_authority_analysis_payload_sha256
            != *policy_authority_analysis.payload_sha256()
        || core.authority_analysis
            != policy_authority_analysis.payload().authority_analysis
        || core.pilot_restrictions
            != policy_authority_analysis.payload().pilot_restrictions
        || core.custody_receipt_evidence_requirements_sha256
            != policy_authority_analysis
                .payload()
                .custody_receipt_evidence_requirements_sha256
        || policy_authority_analysis.payload().assignment_sha256
            != *assignment.envelope_sha256()
        || policy_authority_analysis
            .payload()
            .assignment_payload_sha256
            != *assignment.payload_sha256()
        || core
            .activation_precondition
            .expected_predecessor_policy_sha256
            != assignment.payload().policy_identity.predecessor_policy_sha256
        || core
            .activation_precondition
            .expected_publication_key_id
            != pinned_activation_publication.key_id
        || core
            .activation_precondition
            .expected_publication_key_spki_sha256
            != pinned_activation_publication.key_spki_sha256
        || core
            .activation_precondition
            .expected_publication_key_material_sha256
            != pinned_activation_publication.key_material_sha256
        || core
            .activation_precondition
            .expected_predecessor_policy_sequence
            != assignment.payload().policy_identity.predecessor_policy_sequence
        || core
            .activation_precondition
            .expected_predecessor_rollback_epoch
            != assignment.payload().policy_identity.rollback_epoch
        || core.activation_precondition.candidate_policy_sha256
            != assignment.payload().policy_identity.candidate_policy_sha256
        || core.activation_precondition.candidate_policy_sequence
            != assignment.payload().policy_identity.candidate_policy_sequence
        || core.activation_precondition.candidate_rollback_epoch
            != assignment.payload().policy_identity.rollback_epoch
    {
        return Err(ShadowError::BindingDrift);
    }
    let trusted_now = verify_activation_time_binding(
        trusted_time,
        &trust_checkpoint,
        core.activation_precondition.activation_deadline_unix_nanos,
    )?;
    revalidate_verified_at_checkpoint(
        &readiness,
        &trust_checkpoint,
        key_trust,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    revalidate_verified_at_checkpoint(
        assignment,
        &trust_checkpoint,
        key_trust,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    revalidate_verified_at_checkpoint(
        policy_authority_analysis,
        &trust_checkpoint,
        key_trust,
        MAX_ENVELOPE_AGE_NANOS,
    )?;
    let evidence_max_age: i64 = assignment
        .payload()
        .observation_window
        .maximum_evidence_age_nanos
        .try_into()
        .map_err(|_| ShadowError::EvidenceTooOld)?;
    for receipt in load_receipts {
        revalidate_verified_at_checkpoint(
            receipt,
            &trust_checkpoint,
            key_trust,
            evidence_max_age,
        )?;
    }
    for checkpoint in final_checkpoints {
        revalidate_verified_at_checkpoint(
            checkpoint,
            &trust_checkpoint,
            key_trust,
            evidence_max_age,
        )?;
    }
    for member in &assignment.payload().fleet.members {
        for (domain, key_id, key_spki_sha256) in [
            (
                INGRESS_EVIDENCE_DOMAIN,
                &member.ingress_signing_key_id,
                &member.ingress_signing_key_spki_sha256,
            ),
            (
                ACTIVE_DECISION_DOMAIN,
                &member.active_decision_signing_key_id,
                &member.active_decision_signing_key_spki_sha256,
            ),
            (
                OBSERVATION_DOMAIN,
                &member.shadow_signing_key_id,
                &member.shadow_signing_key_spki_sha256,
            ),
            (
                HEARTBEAT_DOMAIN,
                &member.shadow_signing_key_id,
                &member.shadow_signing_key_spki_sha256,
            ),
            (
                CHECKPOINT_DOMAIN,
                &member.shadow_signing_key_id,
                &member.shadow_signing_key_spki_sha256,
            ),
        ] {
            key_trust.resolve_ed25519_key(
                &trust_checkpoint,
                domain,
                key_id,
                key_spki_sha256,
            )?;
        }
        let receipt = load_receipts
            .iter()
            .find(|receipt| {
                receipt.payload().runtime_identity.instance_id
                    == member.instance_id
            })
            .ok_or(ShadowError::FleetCoverageIncomplete)?;
        attestation.verify_runtime_identity(
            &trust_checkpoint,
            &receipt.payload().runtime_identity,
            member,
            assignment.payload_sha256(),
            trusted_now,
        )?;
        let checkpoint = final_checkpoints
            .iter()
            .find(|checkpoint| {
                checkpoint.payload().runtime_identity.instance_id
                    == member.instance_id
            })
            .ok_or(ShadowError::FleetCoverageIncomplete)?;
        let CheckpointSeal::Sealed { window_closure, .. } =
            &checkpoint.payload().seal
        else {
            return Err(ShadowError::FleetCoverageIncomplete);
        };
        verify_wire_at_checkpoint(
            window_closure,
            ExpectedSigner {
                key_id: &member.ingress_signing_key_id,
                key_spki_sha256:
                    &member.ingress_signing_key_spki_sha256,
            },
            &trust_checkpoint,
            key_trust,
            evidence_max_age,
        )?;
    }
    if trusted_now
            < assignment.payload().observation_window.ends_at_unix_nanos
        || trusted_now
            >= core.activation_precondition.activation_deadline_unix_nanos
    {
        return Err(ShadowError::EvidenceExpired);
    }
    verify_complete_fleet(
        core,
        assignment,
        load_receipts,
        final_checkpoints,
        custody,
        trusted_time,
    )?;
    verify_readiness_counters(core, assignment, final_checkpoints)?;
    verify_readiness_evidence_root(core)?;
    let approval_signer_key_id = approval_signer.key_id.clone();
    let approval_signer_key_spki_sha256 =
        approval_signer.key_spki_sha256.clone();
    let activation_consumption = verify_authority_and_approval(
        readiness.payload().activation_approval.as_ref(),
        core,
        &core_digest,
        policy_authority_analysis,
        assignment,
        approval_signer,
        key_trust,
        webauthn,
        trusted_time,
        trusted_now,
        &trust_checkpoint,
    )?;
    if key_trust.current_checkpoint()? != trust_checkpoint {
        return Err(ShadowError::TrustCheckpointMismatch);
    }
    Ok(VerifiedActivationReadiness {
        envelope: readiness,
        activation_consumption,
        assignment: assignment.clone(),
        policy_authority_analysis: policy_authority_analysis.clone(),
        load_receipts: load_receipts.to_vec(),
        final_checkpoints: final_checkpoints.to_vec(),
        approval_signer_key_id,
        approval_signer_key_spki_sha256,
        _no_activation_capability: PhantomData,
    })
}

fn verify_readiness_evidence_root(core: &ReadinessCore) -> Result<(), ShadowError> {
    let assignment_payload_digest = core.assignment_payload_sha256.raw_bytes()?;
    let authority_key_independence = core
        .authority_key_independence_sha256
        .raw_bytes()?;
    let member_evidence_root = core
        .fleet_readiness
        .member_evidence_root_sha256
        .raw_bytes()?;
    let terminal_receipt_root = core
        .terminal_receipt_root_sha256
        .raw_bytes()?;
    let publication_receipt_root = core
        .publication_receipt_root_sha256
        .raw_bytes()?;
    let aggregate_counters = canonical_json_bytes(&core.aggregate_counters)?;
    let thresholds = canonical_json_bytes(&core.readiness_thresholds)?;
    let analysis = core.policy_authority_analysis_sha256.raw_bytes()?;
    let custody_requirements = core
        .custody_receipt_evidence_requirements_sha256
        .raw_bytes()?;
    let response_obligations = core
        .response_validation_obligations_root_sha256
        .raw_bytes()?;
    let trust_checkpoint = canonical_json_bytes(&core.trust_checkpoint)?;
    let expected = hash_domain_frames(
        b"serverware.policyReadinessEvidenceRoot/v2",
        &[
            assignment_payload_digest.as_slice(),
            authority_key_independence.as_slice(),
            member_evidence_root.as_slice(),
            &core.terminal_receipt_count.to_be_bytes(),
            terminal_receipt_root.as_slice(),
            &core.publication_receipt_count.to_be_bytes(),
            publication_receipt_root.as_slice(),
            aggregate_counters.as_slice(),
            thresholds.as_slice(),
            analysis.as_slice(),
            custody_requirements.as_slice(),
            response_obligations.as_slice(),
            trust_checkpoint.as_slice(),
        ],
    );
    if expected != core.evidence_root_sha256 {
        return Err(ShadowError::MerkleRootMismatch);
    }
    Ok(())
}

fn verify_complete_fleet(
    core: &ReadinessCore,
    assignment: &VerifiedAssignment,
    load_receipts: &[VerifiedLoadReceipt],
    checkpoints: &[VerifiedCheckpoint],
    custody: &dyn PolicyShadowCustodyRpcSupervisor,
    trusted_time: &dyn TrustedTime,
) -> Result<(), ShadowError> {
    let members = &assignment.payload().fleet.members;
    if load_receipts.len() != members.len()
        || checkpoints.len() != members.len()
        || core.fleet_readiness.expected_member_count != members.len() as u64
        || core.fleet_readiness.covered_member_count != members.len() as u64
        || core.fleet_readiness.member_evidence.len() != members.len()
        || core.fleet_readiness.fleet_id != assignment.payload().fleet.fleet_id
        || core.fleet_readiness.membership_revision
            != assignment.payload().fleet.membership_revision
        || core.fleet_readiness.membership_root_sha256
            != assignment.payload().fleet.membership_root_sha256
        || core.fleet_readiness.custody_authority_sha256
            != Sha256Digest::compute(&canonical_json_bytes(
                &assignment.payload().custody_authority,
            )?)
    {
        return Err(ShadowError::FleetCoverageIncomplete);
    }
    let mut expected_instances = BTreeSet::new();
    let mut evidence_leaves = Vec::new();
    let mut custody_leaves = Vec::new();
    let mut terminal_receipt_leaves = Vec::new();
    let mut publication_receipt_leaves = Vec::new();
    let mut publication_revision_leaves = Vec::new();
    let mut terminal_receipt_count = 0_u64;
    let mut publication_receipt_count = 0_u64;
    for (member_index, member) in members.iter().enumerate() {
        expected_instances.insert(member.instance_id.clone());
        let receipt = load_receipts
            .iter()
            .find(|receipt| receipt.payload().runtime_identity.instance_id == member.instance_id)
            .ok_or(ShadowError::FleetCoverageIncomplete)?;
        let checkpoint = checkpoints
            .iter()
            .find(|checkpoint| checkpoint.payload().runtime_identity.instance_id == member.instance_id)
            .ok_or(ShadowError::FleetCoverageIncomplete)?;
        verify_load_receipt_binding(receipt, assignment)?;
        let generation = ShadowGenerationIdentity::derive(
            assignment,
            receipt,
        )?;
        if checkpoint.payload().assignment_sha256
            != *assignment.envelope_sha256()
            || checkpoint.payload().assignment_payload_sha256
                != *assignment.payload_sha256()
            || checkpoint.payload().assignment_revision
                != assignment.payload().assignment_revision
            || checkpoint.payload().load_receipt_sha256
                != *receipt.envelope_sha256()
            || checkpoint.payload().load_receipt_payload_sha256
                != *receipt.payload_sha256()
            || checkpoint.payload().canary_id
                != assignment.payload().canary_id
            || checkpoint.payload().policy_identity
                != assignment.payload().policy_identity
            || checkpoint.payload().runtime_identity
                != receipt.payload().runtime_identity
            || checkpoint.payload().generation != generation
            || !checkpoint
                .payload()
                .runtime_identity
                .matches_member(member)
        {
            return Err(ShadowError::BindingDrift);
        }
        let custody_context = open_verified_custody_call(
            custody,
            trusted_time,
            PolicyShadowCustodyOperation::VerifyCurrentCheckpointHead,
            checkpoint.envelope_sha256(),
        )?;
        let custody_result = custody.verify_current_sealed_checkpoint_head(
            &custody_context,
            &generation,
            checkpoint.payload().checkpoint_sequence,
            checkpoint.envelope_sha256(),
        );
        finish_verified_custody_call(custody, custody_context)?;
        custody_result?;
        verify_member_readiness(checkpoint, assignment, receipt, core)?;
        let (sealed_at, seal_root) = match &checkpoint.payload().seal {
            CheckpointSeal::Sealed {
                sealed_at_unix_nanos,
                seal_root_sha256,
                ..
            } => (*sealed_at_unix_nanos, seal_root_sha256),
            CheckpointSeal::Open => return Err(ShadowError::FleetCoverageIncomplete),
        };
        let evidence = core
            .fleet_readiness
            .member_evidence
            .iter()
            .find(|evidence| evidence.instance_id == member.instance_id)
            .ok_or(ShadowError::FleetCoverageIncomplete)?;
        if evidence.spiffe_id != member.spiffe_id
            || evidence.boot_id_sha256 != member.boot_id_sha256
            || evidence.generation_id != generation.generation_id
            || evidence.generation_epoch != generation.generation_epoch
            || evidence.generation_tombstone_epoch
                != generation.generation_tombstone_epoch
            || evidence.load_receipt_sha256 != *receipt.envelope_sha256()
            || evidence.load_receipt_payload_sha256 != *receipt.payload_sha256()
            || evidence.final_checkpoint_sha256 != *checkpoint.envelope_sha256()
            || evidence.final_checkpoint_payload_sha256 != *checkpoint.payload_sha256()
            || evidence.final_checkpoint_sequence != checkpoint.payload().checkpoint_sequence
            || Some(evidence.last_observation_sequence)
                != checkpoint.payload().cumulative_range.last_observation_sequence
            || Some(evidence.last_ingress_sequence)
                != checkpoint.payload().cumulative_range.last_ingress_sequence
            || evidence.observation_count
                != checkpoint.payload().cumulative_range.observation_count
            || evidence.ingress_count
                != checkpoint.payload().cumulative_range.ingress_count
            || evidence.evaluated_observation_count
                != checkpoint.payload().cumulative_counters.totals.evaluated
            || evidence.comparable_response_count
                != checkpoint
                    .payload()
                    .cumulative_counters
                    .totals
                    .comparable_responses
            || evidence.heartbeat_count
                != checkpoint.payload().cumulative_heartbeats.heartbeat_count
            || evidence.last_heartbeat_sequence
                != checkpoint
                    .payload()
                    .cumulative_heartbeats
                    .last_heartbeat_sequence
            || evidence.last_heartbeat_at_unix_nanos
                != checkpoint
                    .payload()
                    .cumulative_heartbeats
                    .last_heartbeat_at_unix_nanos
            || evidence.maximum_observed_heartbeat_gap_nanos
                != checkpoint
                    .payload()
                    .cumulative_heartbeats
                    .maximum_observed_gap_nanos
            || evidence.cumulative_observation_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_observation_root_sha256
            || evidence.cumulative_ingress_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_ingress_root_sha256
            || evidence.cumulative_active_decision_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_active_decision_root_sha256
            || evidence.cumulative_principal_authority_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_principal_authority_root_sha256
            || evidence.cumulative_route_authority_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_route_authority_root_sha256
            || evidence.cumulative_custody_evidence_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_custody_evidence_root_sha256
            || evidence.cumulative_admitted_ingress_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_admitted_ingress_receipt_root_sha256
            || evidence.cumulative_unavailable_ingress_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_unavailable_ingress_receipt_root_sha256
            || evidence.cumulative_dispatch_barrier_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_dispatch_barrier_receipt_root_sha256
            || evidence
                .cumulative_active_effect_barrier_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_active_effect_barrier_receipt_root_sha256
            || evidence
                .cumulative_active_effect_commit_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_active_effect_commit_receipt_root_sha256
            || evidence.cumulative_terminal_receipt_count
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_terminal_receipt_count
            || evidence.cumulative_terminal_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_terminal_receipt_root_sha256
            || evidence.cumulative_publication_receipt_count
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_publication_receipt_count
            || evidence.cumulative_publication_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_publication_receipt_root_sha256
            || evidence.cumulative_spill_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_spill_receipt_root_sha256
            || evidence.cumulative_persistence_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_persistence_receipt_root_sha256
            || evidence.cumulative_retrieval_proof_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_retrieval_proof_root_sha256
            || evidence.cumulative_compaction_receipt_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_range
                    .cumulative_compaction_receipt_root_sha256
            || Some(evidence.last_ledger_event_ordinal)
                != checkpoint
                    .payload()
                    .cumulative_range
                    .last_ledger_event_ordinal
            || Some(&evidence.last_ledger_head_sha256)
                != checkpoint
                    .payload()
                    .cumulative_range
                    .last_ledger_head_sha256
                    .as_ref()
            || Some(&evidence.last_spool_root_sha256)
                != checkpoint
                    .payload()
                    .cumulative_range
                    .last_spool_root_sha256
                    .as_ref()
            || evidence.publication_reconciliation_receipt_sha256
                != checkpoint
                    .payload()
                    .publication_reconciliation_receipt_sha256
            || evidence.publication_revision
                != checkpoint.payload().publication_revision
            || evidence.cumulative_heartbeat_root_sha256
                != checkpoint
                    .payload()
                    .cumulative_heartbeats
                    .cumulative_heartbeat_root_sha256
            || &evidence.seal_root_sha256 != seal_root
            || evidence.sealed_at_unix_nanos != sealed_at
        {
            return Err(ShadowError::FleetCoverageIncomplete);
        }
        evidence_leaves.push((
            u64::try_from(member_index + 1).map_err(|_| ShadowError::CounterOverflow)?,
            Sha256Digest::compute(&canonical_json_bytes(evidence)?),
        ));
        custody_leaves.push((
            u64::try_from(member_index + 1)
                .map_err(|_| ShadowError::CounterOverflow)?,
            evidence.cumulative_custody_evidence_root_sha256.clone(),
        ));
        terminal_receipt_count = terminal_receipt_count
            .checked_add(evidence.cumulative_terminal_receipt_count)
            .ok_or(ShadowError::CounterOverflow)?;
        publication_receipt_count = publication_receipt_count
            .checked_add(evidence.cumulative_publication_receipt_count)
            .ok_or(ShadowError::CounterOverflow)?;
        terminal_receipt_leaves.push((
            u64::try_from(member_index + 1)
                .map_err(|_| ShadowError::CounterOverflow)?,
            evidence.cumulative_terminal_receipt_root_sha256.clone(),
        ));
        publication_receipt_leaves.push((
            u64::try_from(member_index + 1)
                .map_err(|_| ShadowError::CounterOverflow)?,
            evidence
                .cumulative_publication_receipt_root_sha256
                .clone(),
        ));
        publication_revision_leaves.push((
            u64::try_from(member_index + 1)
                .map_err(|_| ShadowError::CounterOverflow)?,
            Sha256Digest::compute(&canonical_json_bytes(&(
                &evidence.publication_reconciliation_receipt_sha256,
                evidence.publication_revision,
            ))?),
        ));
    }
    let actual_instances: BTreeSet<Identifier> = core
        .fleet_readiness
        .member_evidence
        .iter()
        .map(|evidence| evidence.instance_id.clone())
        .collect();
    if actual_instances != expected_instances
        || merkle_root(&evidence_leaves)?
            != core.fleet_readiness.member_evidence_root_sha256
        || merkle_root(&custody_leaves)?
            != core.fleet_readiness.fleet_custody_evidence_root_sha256
        || terminal_receipt_count
            != core.fleet_readiness.terminal_receipt_count
        || merkle_root(&terminal_receipt_leaves)?
            != core.fleet_readiness.terminal_receipt_root_sha256
        || publication_receipt_count
            != core.fleet_readiness.publication_receipt_count
        || merkle_root(&publication_receipt_leaves)?
            != core.fleet_readiness.publication_receipt_root_sha256
        || publication_receipt_count
            < core.fleet_readiness.covered_member_count
        || merkle_root(&publication_revision_leaves)?
            != core.fleet_readiness.publication_revision_root_sha256
    {
        return Err(ShadowError::FleetCoverageIncomplete);
    }
    Ok(())
}

fn verify_member_readiness(
    checkpoint: &VerifiedCheckpoint,
    assignment: &VerifiedAssignment,
    load_receipt: &VerifiedLoadReceipt,
    core: &ReadinessCore,
) -> Result<(), ShadowError> {
    let payload = checkpoint.payload();
    let counters = &payload.cumulative_counters;
    let totals = &counters.totals;
    let window = &assignment.payload().observation_window;
    let coverage_started_at = load_receipt
        .verified_at_unix_nanos()
        .max(window.starts_at_unix_nanos);
    let coverage_closed_at = match &payload.seal {
        CheckpointSeal::Sealed { window_closure, .. } => {
            window_closure.payload.window_ends_at_unix_nanos
        }
        CheckpointSeal::Open => return Err(ShadowError::ReadinessUnsafe),
    };
    let covered_duration = coverage_closed_at
        .checked_sub(coverage_started_at)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ShadowError::ReadinessUnsafe)?;
    if load_receipt.payload().loaded_at_unix_nanos > coverage_started_at
        || coverage_started_at < window.starts_at_unix_nanos
        || coverage_started_at >= window.ends_at_unix_nanos
        || coverage_closed_at != window.ends_at_unix_nanos
        || payload.cumulative_range.observation_count == 0
        || payload.cumulative_range.ingress_count == 0
        || payload
            .cumulative_range
            .cumulative_terminal_receipt_count
            < payload.cumulative_range.ingress_count
        || payload
            .cumulative_range
            .cumulative_publication_receipt_count
            == 0
        || payload.cumulative_range.first_ingress_sequence
            != Some(window.first_ingress_sequence)
        || covered_duration < window.minimum_duration_nanos
        || payload.cumulative_heartbeats.first_heartbeat_at_unix_nanos
            < coverage_started_at
        || payload.cumulative_heartbeats.last_heartbeat_at_unix_nanos
            > coverage_closed_at
        || payload.cumulative_heartbeats.maximum_observed_gap_nanos
            > window.maximum_heartbeat_gap_nanos
        || totals.dropped != 0
        || totals.errors != 0
        || totals.unavailable_evidence != 0
        || totals.unapproved_active_indeterminate != 0
        || totals.candidate_indeterminate != 0
        || totals.response_validation_divergence != 0
        || totals.response_validator_unavailable != 0
        || totals.response_noncomparable != 0
        || totals.ingress_admitted
            < core
                .readiness_thresholds
                .minimum_ingress_requests_per_member
        || totals.evaluated
            < core
                .readiness_thresholds
                .minimum_evaluated_observations_per_member
        || totals.comparable_responses
            < core
                .readiness_thresholds
                .minimum_comparable_responses_per_member
        || payload
            .cumulative_range
            .cumulative_unavailable_ingress_receipt_root_sha256
            != merkle_root(&[])?
    {
        return Err(ShadowError::ReadinessUnsafe);
    }
    for obligation in &assignment.payload().response_validation_obligations {
        let coverage = counters
            .response_route_coverage
            .iter()
            .find(|coverage| coverage.route_sha256 == obligation.route_sha256)
            .ok_or(ShadowError::ResponseCoverageIncomplete)?;
        let requires_comparable = response_route_requires_comparable(
            &core.authority_analysis,
            &obligation.route_sha256,
        );
        if coverage.obligation_root_sha256 != obligation.obligation_root_sha256
            || (requires_comparable && coverage.comparable_responses == 0)
            || coverage.validation_divergences != 0
            || coverage.validator_unavailable != 0
            || coverage.noncomparable != 0
        {
            return Err(ShadowError::ResponseCoverageIncomplete);
        }
    }
    match (&core.authority_analysis, &core.pilot_restrictions) {
        (
            AuthorityAnalysis::NoExpansion { expansion_cells },
            PilotRestrictions::NotApplicable,
        ) if expansion_cells.is_empty() && counters.expansion_cells.is_empty() => {}
        (
            AuthorityAnalysis::ApprovedExpansion {
                expansion_cells, ..
            },
            PilotRestrictions::Constrained {
                maximum_duration_nanos,
                cells,
                ..
            },
        ) => {
            if expansion_cells != cells
                || covered_duration > *maximum_duration_nanos
                || counters.expansion_cells.len() != expansion_cells.len()
                || expansion_cells.iter().any(|cell| {
                    counters
                        .expansion_cells
                        .iter()
                        .find(|counter| counter.cell_sha256 == cell.cell_sha256)
                        .is_none_or(|counter| {
                            counter.request_count == 0
                                || counter.request_count
                                    > cell.maximum_requests
                                || counter.write_request_count
                                    > cell.maximum_write_requests
                                || counter.response_count > counter.request_count
                                || (expansion_cell_requires_response_coverage(cell)
                                    && counter.response_count == 0)
                                || counter.write_response_count
                                    > counter.write_request_count
                                || counter.authority_expansion
                                    != cell.authority_expansion
                                || counter.route_sha256 != cell.route_sha256
                                || counter.operation != cell.operation
                                || counter.compiled_semantic_profile_sha256
                                    != cell.compiled_semantic_profile_sha256
                                || counter.request_authority_class
                                    != cell.request_authority_class
                                || counter.active_outcome != cell.active_outcome
                                || counter.candidate_outcome
                                    != cell.candidate_outcome
                        })
                })
            {
                return Err(ShadowError::ExpansionCellMismatch);
            }
        }
        _ => return Err(ShadowError::ExpansionCellMismatch),
    }
    Ok(())
}

fn verify_readiness_counters(
    core: &ReadinessCore,
    assignment: &VerifiedAssignment,
    checkpoints: &[VerifiedCheckpoint],
) -> Result<(), ShadowError> {
    let aggregate = sum_checkpoint_counters(checkpoints)?;
    if aggregate != core.aggregate_counters {
        return Err(ShadowError::CounterMismatch);
    }
    let totals = &aggregate.totals;
    if totals.dropped != 0
        || totals.errors != 0
        || totals.unapproved_active_indeterminate != 0
        || totals.candidate_indeterminate != 0
        || totals.unavailable_evidence != 0
        || totals.response_validation_divergence != 0
        || totals.ingress_admitted < core.readiness_thresholds.minimum_ingress_requests
        || totals.evaluated < core.readiness_thresholds.minimum_evaluated_observations
        || totals.comparable_responses < core.readiness_thresholds.minimum_comparable_responses
    {
        return Err(ShadowError::ReadinessUnsafe);
    }
    verify_expansion_counters(core, assignment, &aggregate)?;
    verify_response_route_coverage(core, assignment, &aggregate)?;
    let candidate_p99 = aggregate
        .latency_histograms
        .candidate_evaluation
        .p99_upper_bound()
        .ok_or(ShadowError::ReadinessUnsafe)?;
    let total_p99 = aggregate
        .latency_histograms
        .shadow_total
        .p99_upper_bound()
        .ok_or(ShadowError::ReadinessUnsafe)?;
    if core.calculated_rates.candidate_evaluation_p99_nanos != candidate_p99
        || core.calculated_rates.shadow_total_p99_nanos != total_p99
        || candidate_p99
            > core
                .readiness_thresholds
                .maximum_candidate_evaluation_p99_nanos
        || total_p99 > core.readiness_thresholds.maximum_shadow_total_p99_nanos
    {
        return Err(ShadowError::ReadinessUnsafe);
    }
    Ok(())
}

fn verify_expansion_counters(
    core: &ReadinessCore,
    assignment: &VerifiedAssignment,
    aggregate: &CumulativeCounters,
) -> Result<(), ShadowError> {
    match (&core.authority_analysis, &core.pilot_restrictions) {
        (
            AuthorityAnalysis::NoExpansion { expansion_cells },
            PilotRestrictions::NotApplicable,
        ) => {
            if !expansion_cells.is_empty()
                || !aggregate.expansion_cells.is_empty()
                || aggregate.totals.authority_expansion_observations != 0
                || aggregate
                    .totals
                    .authority_expansion_write_observations
                    != 0
                || aggregate.totals.active_deny_candidate_permit != 0
                || aggregate.totals.active_deny_candidate_conditional != 0
                || aggregate.totals.active_conditional_candidate_permit != 0
                || aggregate.totals.active_indeterminate_candidate_permit != 0
                || aggregate.totals.active_indeterminate_candidate_conditional != 0
            {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            Ok(())
        }
        (
            AuthorityAnalysis::ApprovedExpansion {
                expansion_cells, ..
            },
            PilotRestrictions::Constrained {
                principal_set_root_sha256,
                route_set_root_sha256,
                maximum_requests,
                maximum_duration_nanos,
                maximum_write_requests,
                cells,
            },
        ) => {
            if expansion_cells != cells
                || aggregate.expansion_cells.len() != expansion_cells.len()
            {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            let authorized: BTreeMap<&Sha256Digest, &SemanticExpansionCell> =
                expansion_cells
                    .iter()
                    .map(|cell| (&cell.cell_sha256, cell))
                    .collect();
            for counter in &aggregate.expansion_cells {
                let cell = authorized
                    .get(&counter.cell_sha256)
                    .ok_or(ShadowError::ExpansionCellMismatch)?;
                if counter.request_count == 0
                    || counter.request_count > cell.maximum_requests
                    || counter.write_request_count
                        > cell.maximum_write_requests
                    || counter.response_count > counter.request_count
                    || (expansion_cell_requires_response_coverage(cell)
                        && counter.response_count == 0)
                    || counter.write_response_count > counter.write_request_count
                    || counter.authority_expansion != cell.authority_expansion
                    || counter.route_sha256 != cell.route_sha256
                    || counter.operation != cell.operation
                    || counter.compiled_semantic_profile_sha256
                        != cell.compiled_semantic_profile_sha256
                    || counter.request_authority_class
                        != cell.request_authority_class
                    || counter.active_outcome != cell.active_outcome
                    || counter.candidate_outcome != cell.candidate_outcome
                    || cell.pilot_principal_set_root_sha256
                        != *principal_set_root_sha256
                    || cell.pilot_route_set_root_sha256 != *route_set_root_sha256
                    || (counter.request_authority_class == RequestAuthorityClass::Read
                        && (counter.write_request_count != 0
                            || counter.write_response_count != 0))
                    || (counter.request_authority_class == RequestAuthorityClass::Write
                        && (counter.write_request_count != counter.request_count
                            || counter.write_response_count != counter.response_count))
                {
                    return Err(ShadowError::ExpansionCellMismatch);
                }
            }
            if aggregate.totals.authority_expansion_observations
                    > *maximum_requests
                || aggregate
                    .totals
                    .authority_expansion_write_observations
                    > *maximum_write_requests
                || aggregate.totals.authority_expansion_observations == 0
            {
                return Err(ShadowError::ExpansionLimitExceeded);
            }
            let duration = assignment
                .payload()
                .observation_window
                .ends_at_unix_nanos
                .checked_sub(
                    assignment
                        .payload()
                        .observation_window
                        .starts_at_unix_nanos,
                )
                .ok_or(ShadowError::ExpansionLimitExceeded)?;
            if duration < 0
                || u64::try_from(duration)
                    .map_err(|_| ShadowError::ExpansionLimitExceeded)?
                    > *maximum_duration_nanos
            {
                return Err(ShadowError::ExpansionLimitExceeded);
            }
            Ok(())
        }
        _ => Err(ShadowError::ExpansionCellMismatch),
    }
}

fn expansion_cell_requires_response_coverage(cell: &SemanticExpansionCell) -> bool {
    matches!(
        cell.authority_expansion,
        AuthorityExpansionCell::ResponseFieldExposureAdded
            | AuthorityExpansionCell::ResponseValidationRelaxed
            | AuthorityExpansionCell::ResponseFilterReduced
    )
}

fn response_route_requires_comparable(
    analysis: &AuthorityAnalysis,
    route_sha256: &Sha256Digest,
) -> bool {
    let cells = match analysis {
        AuthorityAnalysis::NoExpansion { expansion_cells }
        | AuthorityAnalysis::ApprovedExpansion {
            expansion_cells, ..
        } => expansion_cells,
    };
    let route_cells = cells
        .iter()
        .filter(|cell| &cell.route_sha256 == route_sha256)
        .collect::<Vec<_>>();
    route_cells.is_empty()
        || route_cells
            .iter()
            .any(|cell| expansion_cell_requires_response_coverage(cell))
}

fn verify_response_route_coverage(
    core: &ReadinessCore,
    assignment: &VerifiedAssignment,
    aggregate: &CumulativeCounters,
) -> Result<(), ShadowError> {
    if assignment
        .payload()
        .response_validation_obligations
        .is_empty()
    {
        return if aggregate.response_route_coverage.is_empty() {
            Ok(())
        } else {
            Err(ShadowError::ResponseCoverageIncomplete)
        };
    }
    for obligation in &assignment.payload().response_validation_obligations {
        let coverage = aggregate
            .response_route_coverage
            .iter()
            .find(|coverage| coverage.route_sha256 == obligation.route_sha256)
            .ok_or(ShadowError::ResponseCoverageIncomplete)?;
        let requires_comparable = response_route_requires_comparable(
            &core.authority_analysis,
            &obligation.route_sha256,
        );
        if coverage.obligation_root_sha256
            != obligation.obligation_root_sha256
            || (requires_comparable
                && coverage.comparable_responses
                    < obligation.minimum_comparable_responses)
            || coverage.validation_divergences != 0
            || coverage.validator_unavailable != 0
            || coverage.noncomparable != 0
        {
            return Err(ShadowError::ResponseCoverageIncomplete);
        }
    }
    if aggregate.response_route_coverage.len()
        != assignment
            .payload()
            .response_validation_obligations
            .len()
    {
        return Err(ShadowError::ResponseCoverageIncomplete);
    }
    Ok(())
}

fn sum_checkpoint_counters(
    checkpoints: &[VerifiedCheckpoint],
) -> Result<CumulativeCounters, ShadowError> {
    let mut aggregate = CumulativeCounters::default();
    for checkpoint in checkpoints {
        add_counters(&mut aggregate, &checkpoint.payload().cumulative_counters)?;
    }
    Ok(aggregate)
}

fn add_counters(
    target: &mut CumulativeCounters,
    source: &CumulativeCounters,
) -> Result<(), ShadowError> {
    macro_rules! add {
        ($($field:expr => $value:expr),+ $(,)?) => {
            $(checked_add($field, $value)?;)+
        };
    }
    add!(
        &mut target.totals.ingress_admitted => source.totals.ingress_admitted,
        &mut target.totals.evaluated => source.totals.evaluated,
        &mut target.totals.dropped => source.totals.dropped,
        &mut target.totals.errors => source.totals.errors,
        &mut target.totals.excluded => source.totals.excluded,
        &mut target.totals.unavailable_evidence => source.totals.unavailable_evidence,
        &mut target.totals.active_indeterminate => source.totals.active_indeterminate,
        &mut target.totals.unapproved_active_indeterminate => source.totals.unapproved_active_indeterminate,
        &mut target.totals.candidate_indeterminate => source.totals.candidate_indeterminate,
        &mut target.totals.active_deny_candidate_permit => source.totals.active_deny_candidate_permit,
        &mut target.totals.active_deny_candidate_conditional => source.totals.active_deny_candidate_conditional,
        &mut target.totals.active_conditional_candidate_permit => source.totals.active_conditional_candidate_permit,
        &mut target.totals.active_indeterminate_candidate_permit => source.totals.active_indeterminate_candidate_permit,
        &mut target.totals.active_indeterminate_candidate_conditional => source.totals.active_indeterminate_candidate_conditional,
        &mut target.totals.authority_expansion_observations => source.totals.authority_expansion_observations,
        &mut target.totals.authority_expansion_write_observations => source.totals.authority_expansion_write_observations,
        &mut target.totals.response_validation_divergence => source.totals.response_validation_divergence,
        &mut target.totals.response_validator_unavailable => source.totals.response_validator_unavailable,
        &mut target.totals.response_noncomparable => source.totals.response_noncomparable,
        &mut target.totals.comparable_responses => source.totals.comparable_responses,
    );
    add_outcomes(&mut target.outcomes, &source.outcomes)?;
    add_comparability(&mut target.comparability, &source.comparability)?;
    add_drops(&mut target.drops, &source.drops)?;
    add_errors(&mut target.errors, &source.errors)?;
    add_histograms(&mut target.latency_histograms, &source.latency_histograms)?;
    add_expansion_cell_counters(
        &mut target.expansion_cells,
        &source.expansion_cells,
    )?;
    add_response_route_coverage(
        &mut target.response_route_coverage,
        &source.response_route_coverage,
    )
}

fn add_expansion_cell_counters(
    target: &mut Vec<ExpansionCellCounter>,
    source: &[ExpansionCellCounter],
) -> Result<(), ShadowError> {
    for source_counter in source {
        if let Some(target_counter) = target
            .iter_mut()
            .find(|counter| counter.cell_sha256 == source_counter.cell_sha256)
        {
            if target_counter.authority_expansion
                != source_counter.authority_expansion
                || target_counter.route_sha256 != source_counter.route_sha256
                || target_counter.operation != source_counter.operation
                || target_counter.compiled_semantic_profile_sha256
                    != source_counter.compiled_semantic_profile_sha256
                || target_counter.request_authority_class
                    != source_counter.request_authority_class
                || target_counter.active_outcome != source_counter.active_outcome
                || target_counter.candidate_outcome != source_counter.candidate_outcome
            {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            checked_add(
                &mut target_counter.request_count,
                source_counter.request_count,
            )?;
            checked_add(
                &mut target_counter.write_request_count,
                source_counter.write_request_count,
            )?;
            checked_add(
                &mut target_counter.response_count,
                source_counter.response_count,
            )?;
            checked_add(
                &mut target_counter.write_response_count,
                source_counter.write_response_count,
            )?;
        } else {
            target.push(source_counter.clone());
        }
    }
    target.sort_by(|left, right| left.cell_sha256.cmp(&right.cell_sha256));
    validate_len(
        "aggregate.expansion_cells",
        target.len(),
        0,
        MAX_EXPANSION_CELLS,
    )
}

fn add_response_route_coverage(
    target: &mut Vec<ResponseRouteCoverage>,
    source: &[ResponseRouteCoverage],
) -> Result<(), ShadowError> {
    for source_coverage in source {
        if let Some(target_coverage) = target
            .iter_mut()
            .find(|coverage| coverage.route_sha256 == source_coverage.route_sha256)
        {
            if target_coverage.obligation_root_sha256
                != source_coverage.obligation_root_sha256
            {
                return Err(ShadowError::ResponseCoverageIncomplete);
            }
            checked_add(
                &mut target_coverage.comparable_responses,
                source_coverage.comparable_responses,
            )?;
            checked_add(
                &mut target_coverage.validation_divergences,
                source_coverage.validation_divergences,
            )?;
            checked_add(
                &mut target_coverage.validator_unavailable,
                source_coverage.validator_unavailable,
            )?;
            checked_add(
                &mut target_coverage.noncomparable,
                source_coverage.noncomparable,
            )?;
        } else {
            target.push(source_coverage.clone());
        }
    }
    target.sort_by(|left, right| left.route_sha256.cmp(&right.route_sha256));
    validate_len(
        "aggregate.response_route_coverage",
        target.len(),
        0,
        MAX_RESPONSE_OBLIGATIONS,
    )
}

fn add_outcomes(target: &mut OutcomeCounters, source: &OutcomeCounters) -> Result<(), ShadowError> {
    let target_fields = [
        &mut target.deny_deny,
        &mut target.deny_permit,
        &mut target.deny_conditional,
        &mut target.deny_indeterminate,
        &mut target.permit_deny,
        &mut target.permit_permit,
        &mut target.permit_conditional,
        &mut target.permit_indeterminate,
        &mut target.conditional_deny,
        &mut target.conditional_permit,
        &mut target.conditional_conditional,
        &mut target.conditional_indeterminate,
        &mut target.indeterminate_deny,
        &mut target.indeterminate_permit,
        &mut target.indeterminate_conditional,
        &mut target.indeterminate_indeterminate,
        &mut target.total,
    ];
    let source_fields = [
        source.deny_deny,
        source.deny_permit,
        source.deny_conditional,
        source.deny_indeterminate,
        source.permit_deny,
        source.permit_permit,
        source.permit_conditional,
        source.permit_indeterminate,
        source.conditional_deny,
        source.conditional_permit,
        source.conditional_conditional,
        source.conditional_indeterminate,
        source.indeterminate_deny,
        source.indeterminate_permit,
        source.indeterminate_conditional,
        source.indeterminate_indeterminate,
        source.total,
    ];
    for (target, source) in target_fields.into_iter().zip(source_fields) {
        checked_add(target, source)?;
    }
    Ok(())
}

fn add_comparability(
    target: &mut ComparabilityCounters,
    source: &ComparabilityCounters,
) -> Result<(), ShadowError> {
    let target_fields = [
        &mut target.comparable_identical,
        &mut target.comparable_validation_match,
        &mut target.comparable_validation_divergence,
        &mut target.not_applicable_active_not_dispatched,
        &mut target.not_comparable_candidate_not_dispatchable,
        &mut target.not_comparable_dispatch_commitment_mismatch,
        &mut target.not_comparable_active_response_unavailable,
        &mut target.not_comparable_candidate_validator_unavailable,
        &mut target.not_applicable_both_deny,
        &mut target.total,
    ];
    let source_fields = [
        source.comparable_identical,
        source.comparable_validation_match,
        source.comparable_validation_divergence,
        source.not_applicable_active_not_dispatched,
        source.not_comparable_candidate_not_dispatchable,
        source.not_comparable_dispatch_commitment_mismatch,
        source.not_comparable_active_response_unavailable,
        source.not_comparable_candidate_validator_unavailable,
        source.not_applicable_both_deny,
        source.total,
    ];
    for (target, source) in target_fields.into_iter().zip(source_fields) {
        checked_add(target, source)?;
    }
    Ok(())
}

fn add_drops(target: &mut DropCounters, source: &DropCounters) -> Result<(), ShadowError> {
    let target_fields = [
        &mut target.queue_full,
        &mut target.worker_unavailable,
        &mut target.deadline_exceeded,
        &mut target.facts_unsupported,
        &mut target.shutdown,
        &mut target.total,
    ];
    let source_fields = [
        source.queue_full,
        source.worker_unavailable,
        source.deadline_exceeded,
        source.facts_unsupported,
        source.shutdown,
        source.total,
    ];
    for (target, source) in target_fields.into_iter().zip(source_fields) {
        checked_add(target, source)?;
    }
    Ok(())
}

fn add_errors(target: &mut ErrorCounters, source: &ErrorCounters) -> Result<(), ShadowError> {
    let target_fields = [
        &mut target.facts_capture_error,
        &mut target.active_evaluation_error,
        &mut target.candidate_evaluation_error,
        &mut target.response_validation_error,
        &mut target.commitment_error,
        &mut target.internal_error,
        &mut target.total,
    ];
    let source_fields = [
        source.facts_capture_error,
        source.active_evaluation_error,
        source.candidate_evaluation_error,
        source.response_validation_error,
        source.commitment_error,
        source.internal_error,
        source.total,
    ];
    for (target, source) in target_fields.into_iter().zip(source_fields) {
        checked_add(target, source)?;
    }
    Ok(())
}

fn add_histograms(
    target: &mut LatencyHistograms,
    source: &LatencyHistograms,
) -> Result<(), ShadowError> {
    add_histogram(&mut target.facts_capture, &source.facts_capture)?;
    add_histogram(&mut target.active_evaluation, &source.active_evaluation)?;
    add_histogram(&mut target.candidate_evaluation, &source.candidate_evaluation)?;
    add_histogram(&mut target.response_validation, &source.response_validation)?;
    add_histogram(&mut target.shadow_total, &source.shadow_total)
}

fn add_histogram(
    target: &mut LatencyHistogram,
    source: &LatencyHistogram,
) -> Result<(), ShadowError> {
    let target_fields = [
        &mut target.nanos_0_to_99_999,
        &mut target.nanos_100_000_to_499_999,
        &mut target.nanos_500_000_to_999_999,
        &mut target.nanos_1_000_000_to_4_999_999,
        &mut target.nanos_5_000_000_to_9_999_999,
        &mut target.nanos_10_000_000_to_49_999_999,
        &mut target.nanos_50_000_000_to_99_999_999,
        &mut target.nanos_100_000_000_to_499_999_999,
        &mut target.nanos_500_000_000_to_999_999_999,
        &mut target.nanos_1_000_000_000_to_4_999_999_999,
        &mut target.nanos_5_000_000_000_or_more,
        &mut target.total,
    ];
    let source_fields = [
        source.nanos_0_to_99_999,
        source.nanos_100_000_to_499_999,
        source.nanos_500_000_to_999_999,
        source.nanos_1_000_000_to_4_999_999,
        source.nanos_5_000_000_to_9_999_999,
        source.nanos_10_000_000_to_49_999_999,
        source.nanos_50_000_000_to_99_999_999,
        source.nanos_100_000_000_to_499_999_999,
        source.nanos_500_000_000_to_999_999_999,
        source.nanos_1_000_000_000_to_4_999_999_999,
        source.nanos_5_000_000_000_or_more,
        source.total,
    ];
    for (target, source) in target_fields.into_iter().zip(source_fields) {
        checked_add(target, source)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_authority_and_approval(
    approval_wire: Option<&SignedEnvelope<ActivationApprovalPayload>>,
    core: &ReadinessCore,
    core_digest: &Sha256Digest,
    policy_authority_analysis: &VerifiedPolicyAuthorityAnalysis,
    assignment: &VerifiedAssignment,
    approval_signer: ExpectedSigner<'_>,
    key_trust: &dyn EnvelopeKeyTrust,
    webauthn: &dyn WebAuthnVerification,
    trusted_time: &dyn TrustedTime,
    trusted_now: i64,
    trust_checkpoint: &AtomicTrustCheckpoint,
) -> Result<ActivationConsumptionBinding, ShadowError> {
    let expected_approval_binding = assignment
        .payload()
        .authority_key_independence
        .binding(
            AuthorityRole::ActivationApproval,
            &assignment.payload().assignment_id,
        )?;
    if core.policy_authority_analysis_sha256
        != *policy_authority_analysis.envelope_sha256()
        || core.policy_authority_analysis_payload_sha256
            != *policy_authority_analysis.payload_sha256()
    {
        return Err(ShadowError::PolicyAuthorityAnalysisMismatch);
    }
    match (&core.authority_analysis, &core.pilot_restrictions) {
        (
            AuthorityAnalysis::NoExpansion {
                expansion_cells,
            },
            PilotRestrictions::NotApplicable,
        ) => {
            if !expansion_cells.is_empty() {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            if approval_wire.is_some() {
                return Err(ShadowError::ApprovalUnexpected);
            }
            Ok(ActivationConsumptionBinding::NoExpansion {
                readiness_core_sha256: core_digest.clone(),
                trust_checkpoint_id: trust_checkpoint.checkpoint_id.clone(),
                trust_checkpoint_as_of_unix_nanos:
                    trust_checkpoint.as_of_unix_nanos,
                trust_revocation_generation:
                    trust_checkpoint.revocation_generation,
                trust_revocation_root_sha256: trust_checkpoint
                    .revocation_root_sha256
                    .clone(),
                trusted_now_unix_nanos: trusted_now,
                maximum_checkpoint_age_nanos:
                    u64::try_from(MAX_ACTIVATION_CHECKPOINT_AGE_NANOS)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                expected_publication_revision: core
                    .activation_precondition
                    .expected_predecessor_publication_revision,
                expected_predecessor_policy_sha256: core
                    .activation_precondition
                    .expected_predecessor_policy_sha256
                    .clone(),
                expected_predecessor_policy_sequence: core
                    .activation_precondition
                    .expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch: core
                    .activation_precondition
                    .expected_predecessor_rollback_epoch,
                candidate_policy_sha256: core
                    .activation_precondition
                    .candidate_policy_sha256
                    .clone(),
                candidate_policy_sequence: core
                    .activation_precondition
                    .candidate_policy_sequence,
                candidate_rollback_epoch: core
                    .activation_precondition
                    .candidate_rollback_epoch,
                activation_deadline_unix_nanos: core
                    .activation_precondition
                    .activation_deadline_unix_nanos,
            })
        }
        (
            AuthorityAnalysis::ApprovedExpansion {
                expansion_cells,
                approval_mode,
                ..
            },
            PilotRestrictions::Constrained {
                maximum_requests,
                maximum_duration_nanos,
                cells,
                ..
            },
        ) => {
            validate_positive(*maximum_requests, "pilot.maximum_requests")?;
            validate_positive(*maximum_duration_nanos, "pilot.maximum_duration_nanos")?;
            if expansion_cells.is_empty() || expansion_cells != cells {
                return Err(ShadowError::ExpansionCellMismatch);
            }
            let approval_wire = approval_wire.ok_or(ShadowError::ApprovalMissing)?;
            let approval = verify_envelope(
                approval_wire.clone(),
                approval_signer,
                key_trust,
                trusted_time,
                MAX_ENVELOPE_AGE_NANOS,
            )?;
            if approval.trust_checkpoint != *trust_checkpoint {
                return Err(ShadowError::TrustCheckpointMismatch);
            }
            revalidate_verified_at_checkpoint(
                &approval,
                trust_checkpoint,
                key_trust,
                MAX_ENVELOPE_AGE_NANOS,
            )?;
            let payload = approval.payload();
            let expected_cell_digests: Vec<Sha256Digest> = expansion_cells
                .iter()
                .map(|cell| cell.cell_sha256.clone())
                .collect();
            if payload.assignment_payload_sha256
                    != *assignment.payload_sha256()
                || payload.authority_key_independence_sha256
                    != assignment
                        .payload()
                        .authority_key_independence
                        .independence_root_sha256
                || payload.expected_approval_key_id
                    != expected_approval_binding.key_id
                || payload.expected_approval_key_spki_sha256
                    != expected_approval_binding.key_spki_sha256
                || payload.expected_approval_key_material_sha256
                    != expected_approval_binding.key_material_sha256
                || payload.readiness_core_sha256 != *core_digest
                || payload.activation_context_sha256 != *core_digest
                || payload.approval_mode != *approval_mode
                || payload.expansion_cells != expected_cell_digests
            {
                return Err(ShadowError::ApprovalBindingMismatch);
            }
            let required = match approval_mode {
                ApprovalMode::SinglePersonHardwareWebauthn => 1,
                ApprovalMode::TwoPersonHardwareWebauthn => 2,
            };
            if payload.assertions.len() != required {
                return Err(ShadowError::ApprovalBindingMismatch);
            }
            let mut principals = BTreeSet::new();
            let mut credentials = BTreeSet::new();
            let mut assertion_consumption = Vec::with_capacity(required);
            for assertion in &payload.assertions {
                if assertion.readiness_core_challenge_sha256 != *core_digest
                    || assertion.approved_at_unix_nanos < payload.issued_at_unix_nanos
                    || assertion.approved_at_unix_nanos >= payload.expires_at_unix_nanos
                {
                    return Err(ShadowError::ApprovalBindingMismatch);
                }
                let verified =
                    webauthn.verify_assertion(assertion, core_digest, trusted_now)?;
                if !verified.hardware_backed {
                    return Err(ShadowError::ApproverNotHardwareBacked);
                }
                if !verified.user_present {
                    return Err(ShadowError::ApproverUserPresenceMissing);
                }
                if !verified.user_verified {
                    return Err(ShadowError::ApproverUserVerificationMissing);
                }
                if verified.assertion_evidence_sha256
                        != assertion.assertion_evidence_sha256
                    || assertion.recompute_evidence_sha256()?
                        != assertion.assertion_evidence_sha256
                    || verified.principal_id != assertion.principal_id
                    || verified.credential_id != assertion.credential_id
                    || verified.assertion_object_sha256
                        != assertion.assertion_object_sha256
                    || verified.authenticator_data_sha256
                        != assertion.authenticator_data_sha256
                    || verified.client_data_json_sha256
                        != assertion.client_data_json_sha256
                    || verified.assertion_signature_sha256
                        != assertion.assertion_signature_sha256
                    || verified.cose_public_key_sha256
                        != assertion.cose_public_key_sha256
                    || verified.rp_id != assertion.rp_id
                    || verified.origin != assertion.origin
                    || verified.credential_state_revision
                        != assertion.credential_state_revision
                    || verified.previous_signature_counter
                        != assertion.expected_previous_signature_counter
                    || verified.signature_counter != assertion.signature_counter
                    || verified.replay_state_sha256
                        != assertion.replay_state_sha256
                {
                    return Err(ShadowError::ApprovalBindingMismatch);
                }
                if !principals.insert(verified.principal_id.clone()) {
                    return Err(ShadowError::ApproverPrincipalReused);
                }
                if !credentials.insert(verified.credential_id.clone()) {
                    return Err(ShadowError::ApproverCredentialReused);
                }
                assertion_consumption.push(AssertionConsumption {
                    assertion_evidence_sha256: assertion
                        .assertion_evidence_sha256
                        .clone(),
                    principal_id: assertion.principal_id.clone(),
                    credential_id: assertion.credential_id.clone(),
                    assertion_object_sha256: assertion
                        .assertion_object_sha256
                        .clone(),
                    authenticator_data_sha256: assertion
                        .authenticator_data_sha256
                        .clone(),
                    client_data_json_sha256: assertion
                        .client_data_json_sha256
                        .clone(),
                    assertion_signature_sha256: assertion
                        .assertion_signature_sha256
                        .clone(),
                    cose_public_key_sha256: assertion
                        .cose_public_key_sha256
                        .clone(),
                    rp_id: assertion.rp_id.clone(),
                    origin: assertion.origin.clone(),
                    credential_state_revision: assertion
                        .credential_state_revision,
                    previous_signature_counter: assertion
                        .expected_previous_signature_counter,
                    signature_counter: assertion.signature_counter,
                    replay_state_sha256: assertion.replay_state_sha256.clone(),
                });
            }
            Ok(ActivationConsumptionBinding::ApprovedExpansion {
                approval_id: payload.approval_id.clone(),
                approval_envelope_sha256: approval.envelope_sha256().clone(),
                approval_payload_sha256: approval.payload_sha256().clone(),
                readiness_core_sha256: core_digest.clone(),
                trust_checkpoint_id: trust_checkpoint.checkpoint_id.clone(),
                trust_checkpoint_as_of_unix_nanos:
                    trust_checkpoint.as_of_unix_nanos,
                trust_revocation_generation:
                    trust_checkpoint.revocation_generation,
                trust_revocation_root_sha256: trust_checkpoint
                    .revocation_root_sha256
                    .clone(),
                trusted_now_unix_nanos: trusted_now,
                maximum_checkpoint_age_nanos:
                    u64::try_from(MAX_ACTIVATION_CHECKPOINT_AGE_NANOS)
                        .map_err(|_| ShadowError::CounterOverflow)?,
                assertions: assertion_consumption,
                expected_publication_revision: core
                    .activation_precondition
                    .expected_predecessor_publication_revision,
                expected_predecessor_policy_sha256: core
                    .activation_precondition
                    .expected_predecessor_policy_sha256
                    .clone(),
                expected_predecessor_policy_sequence: core
                    .activation_precondition
                    .expected_predecessor_policy_sequence,
                expected_predecessor_rollback_epoch: core
                    .activation_precondition
                    .expected_predecessor_rollback_epoch,
                candidate_policy_sha256: core
                    .activation_precondition
                    .candidate_policy_sha256
                    .clone(),
                candidate_policy_sequence: core
                    .activation_precondition
                    .candidate_policy_sequence,
                candidate_rollback_epoch: core
                    .activation_precondition
                    .candidate_rollback_epoch,
                activation_deadline_unix_nanos: core
                    .activation_precondition
                    .activation_deadline_unix_nanos,
            })
        }
        _ => Err(ShadowError::ExpansionCellMismatch),
    }
}

fn hash_domain_frames(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(*part);
    }
    Sha256Digest(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_semantic_expansion_cells(
    cells: &[SemanticExpansionCell],
    must_be_empty: bool,
) -> Result<(), ShadowError> {
    if must_be_empty {
        return if cells.is_empty() {
            Ok(())
        } else {
            Err(ShadowError::ExpansionCellMismatch)
        };
    }
    if cells.is_empty()
        || cells.len() > MAX_EXPANSION_CELLS
        || cells
            .windows(2)
            .any(|pair| pair[0].cell_sha256 >= pair[1].cell_sha256)
    {
        return Err(ShadowError::ExpansionCellMismatch);
    }
    for cell in cells {
        cell.validate()?;
    }
    Ok(())
}

fn semantic_expansion_cells_root(
    cells: &[SemanticExpansionCell],
) -> Result<Sha256Digest, ShadowError> {
    let leaves = cells
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            Ok((
                u64::try_from(index + 1).map_err(|_| ShadowError::CounterOverflow)?,
                cell.cell_sha256.clone(),
            ))
        })
        .collect::<Result<Vec<_>, ShadowError>>()?;
    merkle_root(&leaves)
}

fn validate_digest_set(
    values: &[Sha256Digest],
    minimum: usize,
    maximum: usize,
) -> Result<(), ShadowError> {
    validate_len("digest_set", values.len(), minimum, maximum)?;
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ShadowError::ExpansionCellMismatch);
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ShadowError> {
    if value == 0 || value > MAX_SIGNED_INTEGER {
        return Err(invalid(field, "must be a positive signed-schema integer"));
    }
    Ok(())
}

fn validate_unsigned(value: u64, field: &'static str) -> Result<(), ShadowError> {
    if value > MAX_SIGNED_INTEGER {
        return Err(invalid(field, "exceeds signed-schema integer range"));
    }
    Ok(())
}

fn validate_len(
    field: &'static str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), ShadowError> {
    if actual < minimum || actual > maximum {
        return Err(invalid(field, "collection length outside permitted range"));
    }
    Ok(())
}

fn reject_duplicate_by<'a, T, F>(
    values: &'a [T],
    key: F,
    field: &'static str,
) -> Result<(), ShadowError>
where
    F: Fn(&'a T) -> &'a str,
{
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(key(value))) {
        return Err(invalid(field, "duplicates are forbidden"));
    }
    Ok(())
}

fn increment(value: &mut u64) -> Result<(), ShadowError> {
    checked_add(value, 1)
}

fn checked_add(value: &mut u64, increment: u64) -> Result<(), ShadowError> {
    *value = value
        .checked_add(increment)
        .filter(|value| *value <= MAX_SIGNED_INTEGER)
        .ok_or(ShadowError::CounterOverflow)?;
    Ok(())
}

// Component-only local trust/storage fixture. It exercises the actual legacy
// receipt verifier, not production assignment/attestation/RPC or durable I/O.
// No Verified* value is constructed here: signatures, pins, time, exact stored
// payload and retrieval bindings must all pass verify_shadow_spill_receipt.
#[cfg(test)]
pub(crate) mod terminal_receipt_fixture {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Fault {
        None,
        Signature,
        PinnedKey,
        VerificationKey,
        StaleTime,
        FutureTime,
        Checkpoint,
        PersistenceBytes,
        RetrievalBytes,
    }

    struct FixedTrust {
        checkpoint: AtomicTrustCheckpoint,
        role: PolicyShadowCustodySignerRole,
        key_id: Sha256Digest,
        key_spki: Sha256Digest,
        key: VerifyingKey,
    }

    impl EnvelopeKeyTrust for FixedTrust {
        fn current_checkpoint(&self) -> Result<AtomicTrustCheckpoint, ShadowError> {
            Ok(self.checkpoint.clone())
        }

        fn resolve_ed25519_key(
            &self,
            checkpoint: &AtomicTrustCheckpoint,
            signature_domain: &str,
            key_id: &Sha256Digest,
            key_spki_sha256: &Sha256Digest,
        ) -> Result<VerifyingKey, ShadowError> {
            if checkpoint != &self.checkpoint
                || signature_domain != self.role.signature_domain()
                || key_id != &self.key_id
                || key_spki_sha256 != &self.key_spki
            {
                return Err(ShadowError::TrustResolutionFailed);
            }
            Ok(self.key)
        }
    }

    struct FixedTime(i64);

    impl TrustedTime for FixedTime {
        fn now_unix_nanos(&self) -> Result<i64, ShadowError> {
            Ok(self.0)
        }
    }

    struct ExactLocalStore {
        role: PolicyShadowCustodySignerRole,
        persistence_id: Sha256Digest,
        retrieval_id: Sha256Digest,
        retrieval_proof: Sha256Digest,
        persisted: Vec<u8>,
        retrieved: Vec<u8>,
    }

    impl PolicyShadowPersistenceProofVerifier for ExactLocalStore {
        fn verify_persistence_receipt(
            &self,
            role: PolicyShadowCustodySignerRole,
            persistence_receipt_sha256: &Sha256Digest,
            canonical_payload: &[u8],
        ) -> Result<(), ShadowError> {
            if role != self.role || persistence_receipt_sha256 != &self.persistence_id
                || canonical_payload != self.persisted.as_slice()
            {
                return Err(ShadowError::PayloadDigestMismatch);
            }
            Ok(())
        }

        fn verify_immutable_retrieval(
            &self,
            role: PolicyShadowCustodySignerRole,
            retrieval_id_sha256: &Sha256Digest,
            retrieval_proof_sha256: &Sha256Digest,
            canonical_payload: &[u8],
        ) -> Result<(), ShadowError> {
            if role != self.role || retrieval_id_sha256 != &self.retrieval_id
                || retrieval_proof_sha256 != &self.retrieval_proof
                || canonical_payload != self.retrieved.as_slice()
            {
                return Err(ShadowError::BindingDrift);
            }
            Ok(())
        }
    }

    pub(crate) fn verify(
        event: &ShadowSpoolEvent,
        disposition: ShadowSpoolDisposition,
        fault: Fault,
    ) -> Result<VerifiedShadowSpillReceipt, ShadowError> {
        with_wire(event, disposition, fault, |wire, signer, trust, time, store| {
            verify_shadow_spill_receipt(wire, event, signer, trust, time, store, 100)
        })
    }

    // Exercises the shared response joins against a real signed wire before
    // verification. The callback cannot obtain a manufactured Verified value.
    pub(super) fn with_wire<T>(
        event: &ShadowSpoolEvent,
        disposition: ShadowSpoolDisposition,
        fault: Fault,
        verify: impl FnOnce(
            SignedShadowSpillReceipt, ExpectedSigner<'_>, &dyn EnvelopeKeyTrust,
            &dyn TrustedTime, &dyn PolicyShadowPersistenceProofVerifier,
        ) -> Result<T, ShadowError>,
    ) -> Result<T, ShadowError> {
        let key = SigningKey::from_bytes(&[73; 32]);
        let role = custody_signer_role_for_spool_phase(event.phase());
        let key_id = Sha256Digest::compute(b"local terminal component key");
        let key_spki = ed25519_public_key_material_sha256(&key.verifying_key());
        let checkpoint = AtomicTrustCheckpoint::new(
            Sha256Digest::compute(b"local terminal component checkpoint"),
            1_000_000,
            1,
            Sha256Digest::compute(b"local terminal component revocations"),
        )?;
        let persistence_id = Sha256Digest::compute(b"local terminal component stored slot");
        let retrieval_id = Sha256Digest::compute(b"local terminal component retrieval slot");
        let retrieval_proof = Sha256Digest::compute(b"local terminal component retrieval proof");
        let predecessor = Sha256Digest::compute(b"local terminal component predecessor");
        let observed_at = 1_000_000_i64;
        let record_digest = hash_domain_frames(
            b"serverware.policyShadowSpoolRecord/v1",
            &[&canonical_json_bytes(&(
                &event.generation_id,
                event.ingress_sequence,
                &event.request_binding_sha256,
                &event.request_commitment_sha256,
                event.phase,
                disposition,
                &event.event_sha256,
                &event.canonical_event_bytes,
                1_u64,
                0_u64,
                &predecessor,
                observed_at,
                &checkpoint.checkpoint_id,
                &persistence_id,
                &retrieval_id,
                &retrieval_proof,
            ))?],
        );
        let resulting_head = hash_domain_frames(
            b"serverware.policyShadowSpoolHead/v1",
            &[&canonical_json_bytes(&(0_u64, &predecessor, 1_u64, &record_digest))?],
        );
        let mut wire = SignedShadowSpillReceipt {
            generation_id: event.generation_id.clone(),
            ingress_sequence: event.ingress_sequence,
            request_binding_sha256: event.request_binding_sha256.clone(),
            request_commitment_sha256: event.request_commitment_sha256.clone(),
            event_ordinal: 1,
            event_phase: event.phase,
            disposition,
            event_sha256: event.event_sha256.clone(),
            canonical_event_bytes: event.canonical_event_bytes.clone(),
            predecessor_event_ordinal: 0,
            predecessor_head_sha256: predecessor,
            resulting_head_sha256: resulting_head,
            trusted_observed_at_unix_nanos: observed_at,
            trusted_time_checkpoint_sha256: checkpoint.checkpoint_id.clone(),
            persistence_receipt_sha256: persistence_id.clone(),
            retrieval_id_sha256: retrieval_id.clone(),
            retrieval_proof_sha256: retrieval_proof.clone(),
            signing_key_id: key_id.clone(),
            signing_key_spki_sha256: key_spki.clone(),
            signature: CanonicalEd25519Signature(String::new()),
            signed_receipt_sha256: Sha256Digest::compute(b"not yet signed"),
        };
        let payload = wire.canonical_signature_payload()?;
        let mut signature = key.sign(&signature_preimage(role.signature_domain(), &payload)).to_bytes();
        if fault == Fault::Signature {
            signature[0] ^= 1;
        }
        wire.signature = CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(signature));
        // Refresh the outer receipt digest even for the bad-signature case:
        // its oracle must be actual Ed25519 verification, not digest parsing.
        wire.signed_receipt_sha256 = hash_domain_frames(
            b"serverware.policyShadowSpillReceipt/v1",
            &[&canonical_json_bytes(&(
                &record_digest,
                &wire.resulting_head_sha256,
                &key_id,
                &key_spki,
                &wire.signature,
            ))?],
        );
        let mut store = ExactLocalStore {
            role,
            persistence_id,
            retrieval_id,
            retrieval_proof,
            persisted: payload.clone(),
            retrieved: payload,
        };
        if fault == Fault::PersistenceBytes {
            store.persisted.push(b' ');
        }
        if fault == Fault::RetrievalBytes {
            store.retrieved.push(b' ');
        }
        let mut trust = FixedTrust {
            checkpoint,
            role,
            key_id: key_id.clone(),
            key_spki: key_spki.clone(),
            key: key.verifying_key(),
        };
        if fault == Fault::Checkpoint {
            trust.checkpoint.checkpoint_id = Sha256Digest::compute(b"another checkpoint");
        }
        if fault == Fault::VerificationKey {
            trust.key = SigningKey::from_bytes(&[74; 32]).verifying_key();
        }
        let expected_key = if fault == Fault::PinnedKey {
            Sha256Digest::compute(b"another pinned key")
        } else {
            key_id
        };
        let now = match fault {
            Fault::StaleTime => observed_at + 101,
            Fault::FutureTime => observed_at - 1,
            _ => observed_at + 1,
        };
        verify(
            wire,
            ExpectedSigner { key_id: &expected_key, key_spki_sha256: &key_spki },
            &trust,
            &FixedTime(now),
            &store,
        )
    }
}

// Test data and real cryptographic verification only. These helpers do not
// establish assignment/load admission, production RPC or durable storage.
#[cfg(test)]
pub(crate) mod custody_response_fixture {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(crate) fn generation() -> ShadowGenerationIdentity {
        let digest = |name: &str| Sha256Digest::compute(name.as_bytes());
        let mut value = ShadowGenerationIdentity {
            generation_id: digest("unset"), generation_epoch: 1,
            minimum_generation_tombstone_epoch: 1, generation_tombstone_epoch: 1,
            assignment_revision: 1, assignment_sha256: digest("assignment"),
            assignment_payload_sha256: digest("assignment payload"),
            load_receipt_sha256: digest("load"), load_receipt_payload_sha256: digest("load payload"),
            active_policy_sha256: digest("active"), active_policy_sequence: 1, active_rollback_epoch: 1,
            active_compiled_snapshot_sha256: digest("compiled active"),
            candidate_policy_sha256: digest("candidate"), candidate_policy_sequence: 2, candidate_rollback_epoch: 1,
            candidate_compiled_snapshot_sha256: digest("compiled candidate"), runtime_boot_id_sha256: digest("boot"),
            assignment_starts_at_unix_nanos: 0, assignment_ends_at_unix_nanos: 2_000_000,
            sampling_basis_points: 5000, request_commitment_key_id: digest("commitment key"),
            request_commitment_key_epoch: 1, request_facts_schema_sha256: digest("facts"),
            ingress_range_start_sequence: 1, ingress_range_predecessor_head_sha256: digest("range predecessor"),
            observation_interval_sha256: digest("interval"), response_validation_obligations_root_sha256: digest("obligations"),
            publication_reconciliation_receipt_sha256: digest("reconciliation"), publication_revision: 1,
            authoritative_ledger_event_ordinal: 0, authoritative_ledger_head_sha256: digest("ledger"),
            authoritative_spool_root_sha256: digest("spool"),
        };
        value.generation_id = value.recompute_id().unwrap();
        value.validate().unwrap();
        value
    }

    pub(crate) fn preparation(generation: &ShadowGenerationIdentity) -> PreparedGenerationPublication {
        PreparedGenerationPublication::from_custody(
            None, generation, 1, 4, 0, Sha256Digest::compute(b"ledger"),
            hash_domain_frames(b"serverware.policyShadowPersistedSequenceRange/v1", &[&canonical_json_bytes(&(
                generation.generation_id(), 1_u64, 4_u64, &generation.ingress_range_predecessor_head_sha256,
            )).unwrap()]),
            Sha256Digest::compute(b"spool"), Sha256Digest::compute(b"prepared"),
        ).unwrap()
    }

    struct Authority {
        key: SigningKey,
        role: PolicyShadowCustodySignerRole,
        checkpoint: AtomicTrustCheckpoint,
        key_id: Sha256Digest,
        key_spki: Sha256Digest,
        persisted: Vec<u8>,
        retrieved: Vec<u8>,
    }

    impl Authority {
        fn new(role: PolicyShadowCustodySignerRole) -> Self {
            let key = SigningKey::from_bytes(&[91; 32]);
            Self {
                key_spki: ed25519_public_key_material_sha256(&key.verifying_key()), key,
                role, key_id: Sha256Digest::compute(role.signature_domain().as_bytes()),
                checkpoint: AtomicTrustCheckpoint::new(Sha256Digest::compute(b"response fixture checkpoint"),
                    1_000_000, 1, Sha256Digest::compute(b"response fixture revocations")).unwrap(),
                persisted: Vec::new(), retrieved: Vec::new(),
            }
        }
        fn sign(&mut self, payload: &[u8]) -> CanonicalEd25519Signature {
            self.persisted = payload.to_vec();
            self.retrieved = payload.to_vec();
            CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(self.key.sign(
                &signature_preimage(self.role.signature_domain(), payload)).to_bytes()))
        }
        fn expected(&self) -> ExpectedSigner<'_> {
            ExpectedSigner { key_id: &self.key_id, key_spki_sha256: &self.key_spki }
        }
    }

    impl TrustedTime for Authority {
        fn now_unix_nanos(&self) -> Result<i64, ShadowError> { Ok(1_000_001) }
    }
    impl EnvelopeKeyTrust for Authority {
        fn current_checkpoint(&self) -> Result<AtomicTrustCheckpoint, ShadowError> { Ok(self.checkpoint.clone()) }
        fn resolve_ed25519_key(&self, checkpoint: &AtomicTrustCheckpoint, domain: &str,
            key_id: &Sha256Digest, key_spki: &Sha256Digest) -> Result<VerifyingKey, ShadowError> {
            if checkpoint != &self.checkpoint || domain != self.role.signature_domain()
                || key_id != &self.key_id || key_spki != &self.key_spki {
                return Err(ShadowError::TrustResolutionFailed);
            }
            Ok(self.key.verifying_key())
        }
    }
    impl PolicyShadowPersistenceProofVerifier for Authority {
        fn verify_persistence_receipt(&self, role: PolicyShadowCustodySignerRole,
            receipt: &Sha256Digest, payload: &[u8]) -> Result<(), ShadowError> {
            if role != self.role || receipt != &Sha256Digest::compute(b"response fixture persistence")
                || payload != self.persisted.as_slice() { return Err(ShadowError::PayloadDigestMismatch); }
            Ok(())
        }
        fn verify_immutable_retrieval(&self, role: PolicyShadowCustodySignerRole,
            id: &Sha256Digest, proof: &Sha256Digest, payload: &[u8]) -> Result<(), ShadowError> {
            if role != self.role || id != &Sha256Digest::compute(b"response fixture retrieval")
                || proof != &Sha256Digest::compute(b"response fixture retrieval proof")
                || payload != self.retrieved.as_slice() { return Err(ShadowError::BindingDrift); }
            Ok(())
        }
    }

    pub(crate) fn publication(generation: &ShadowGenerationIdentity, prepared: &PreparedGenerationPublication,
        revision: u64) -> VerifiedPublicationReconciliationReceipt {
        let mut authority = Authority::new(PolicyShadowCustodySignerRole::PublicationReconciliation);
        let mut wire = PublicationReconciliationReceiptWire {
            state: PublicationReconciliationState::Published, publication_revision: revision,
            predecessor_generation_sha256: None,
            committed_generation_sha256: Some(generation.generation_id().clone()),
            published_generation_sha256: Some(generation.generation_id().clone()),
            first_ingress_sequence: Some(prepared.first_ingress_sequence), last_ingress_sequence: Some(prepared.last_ingress_sequence),
            ledger_event_ordinal: 0, ledger_head_sha256: Sha256Digest::compute(b"ledger"), spool_root_sha256: Sha256Digest::compute(b"spool"),
            prepared_publication_sha256: Some(prepared.preparation_receipt_sha256().clone()),
            trusted_observed_at_unix_nanos: 1_000_000, trusted_time_checkpoint_sha256: authority.checkpoint.checkpoint_id.clone(),
            persistence_receipt_sha256: Sha256Digest::compute(b"response fixture persistence"),
            retrieval_id_sha256: Sha256Digest::compute(b"response fixture retrieval"),
            retrieval_proof_sha256: Sha256Digest::compute(b"response fixture retrieval proof"),
            signer_role: authority.role, signing_key_id: authority.key_id.clone(), signing_key_spki_sha256: authority.key_spki.clone(),
            signature: CanonicalEd25519Signature(String::new()), signed_receipt_sha256: Sha256Digest::compute(b"unsigned"),
        };
        let payload = wire.canonical_payload().unwrap();
        wire.signature = authority.sign(&payload);
        wire.signed_receipt_sha256 = hash_domain_frames(b"serverware.policyShadowPublicationReconciliationReceipt/v1",
            &[&payload, wire.signature.0.as_bytes()]);
        verify_publication_reconciliation_receipt(wire, authority.expected(), &authority, &authority, &authority, 100).unwrap()
    }

    fn unavailable<T>(binding: &Sha256Digest, generation: Option<&ShadowGenerationIdentity>,
        verify: impl FnOnce(SignedUnavailableGenerationReceipt, &Authority) -> Result<T, ShadowError>) -> Result<T, ShadowError> {
        let mut authority = Authority::new(PolicyShadowCustodySignerRole::UnavailableIngress);
        let mut wire = SignedUnavailableGenerationReceipt {
            request_binding_sha256: binding.clone(), request_commitment_sha256: Sha256Digest::compute(b"unavailable commitment"),
            generation_id: generation.map(|value| value.generation_id().clone()),
            generation_install_state: if generation.is_some() { UnavailableGenerationInstallState::Installed } else { UnavailableGenerationInstallState::Uninstalled },
            reason: if generation.is_some() { CustodyUnavailableReason::DurableSpoolBackpressure } else { CustodyUnavailableReason::NoInstalledGeneration },
            event_ordinal: 1, predecessor_event_ordinal: 0, predecessor_head_sha256: Sha256Digest::compute(b"unavailable predecessor"),
            resulting_head_sha256: Sha256Digest::compute(b"unset"), trusted_observed_at_unix_nanos: 1_000_000,
            trusted_time_checkpoint_sha256: authority.checkpoint.checkpoint_id.clone(),
            persistence_receipt_sha256: Sha256Digest::compute(b"response fixture persistence"),
            retrieval_id_sha256: Sha256Digest::compute(b"response fixture retrieval"), retrieval_proof_sha256: Sha256Digest::compute(b"response fixture retrieval proof"),
            signing_key_id: authority.key_id.clone(), signing_key_spki_sha256: authority.key_spki.clone(),
            signature: CanonicalEd25519Signature(String::new()), signed_receipt_sha256: Sha256Digest::compute(b"unsigned"),
        };
        let record = hash_domain_frames(b"serverware.policyShadowUnavailableGenerationRecord/v1", &[&canonical_json_bytes(&(
            &wire.request_binding_sha256, &wire.request_commitment_sha256, &wire.generation_id, wire.generation_install_state,
            wire.reason, wire.event_ordinal, wire.predecessor_event_ordinal, &wire.predecessor_head_sha256,
            wire.trusted_observed_at_unix_nanos, &wire.trusted_time_checkpoint_sha256, &wire.persistence_receipt_sha256,
            &wire.retrieval_id_sha256, &wire.retrieval_proof_sha256,
        ))?]);
        wire.resulting_head_sha256 = hash_domain_frames(b"serverware.policyShadowUnavailableGenerationHead/v1",
            &[&canonical_json_bytes(&(wire.predecessor_event_ordinal, &wire.predecessor_head_sha256, wire.event_ordinal, &record))?]);
        wire.signature = authority.sign(&wire.canonical_signature_payload()?);
        wire.signed_receipt_sha256 = hash_domain_frames(b"serverware.policyShadowUnavailableGenerationReceipt/v1", &[&canonical_json_bytes(&(
            &record, &wire.resulting_head_sha256, &wire.signing_key_id, &wire.signing_key_spki_sha256, &wire.signature,
        ))?]);
        verify(wire, &authority)
    }

    fn terminal_event(payload: &[u8]) -> ShadowSpoolEvent {
        ShadowSpoolEvent::new(Sha256Digest::compute(b"terminal generation"), 1,
            Sha256Digest::compute(b"terminal request"), Sha256Digest::compute(b"terminal commitment"),
            ShadowSpoolPhase::PreDispatchTerminal, Sha256Digest::compute(payload), payload.to_vec()).unwrap()
    }

    fn terminal(request: &TerminalSlotAppendRequest, event: &ShadowSpoolEvent, outcome: u8,
        disposition: ShadowSpoolDisposition, fault: terminal_receipt_fixture::Fault) -> Result<TerminalSlotAppendOutcome, ShadowError> {
        terminal_receipt_fixture::with_wire(event, disposition, fault, |receipt, signer, trust, time, store| {
            let wire = match outcome {
                0 => TerminalSlotAppendOutcomeWire::Committed(receipt),
                1 => TerminalSlotAppendOutcomeWire::Existing(receipt),
                _ => TerminalSlotAppendOutcomeWire::Fork(receipt),
            };
            // The production consumer uses this same binding check followed
            // by the assignment-bound verifier. Here the real local verifier
            // proves cryptography/bytes only, not production assignment/RPC.
            let (wire, expected) = wire.receipt_and_expected_event(request)?;
            match wire {
                TerminalSlotAppendOutcomeWire::Committed(receipt) => Ok(TerminalSlotAppendOutcome::Committed(
                    verify_shadow_spill_receipt(receipt, &expected, signer, trust, time, store, 100)?)),
                TerminalSlotAppendOutcomeWire::Existing(receipt) => Ok(TerminalSlotAppendOutcome::Existing(
                    verify_shadow_spill_receipt(receipt, &expected, signer, trust, time, store, 100)?)),
                TerminalSlotAppendOutcomeWire::Fork(receipt) => Ok(TerminalSlotAppendOutcome::Fork(
                    verify_shadow_spill_receipt(receipt, &expected, signer, trust, time, store, 100)?)),
            }
        })
    }

    #[test]
    fn custody_terminal_wire_preserves_committed_existing_and_authenticated_fork() {
        let event = terminal_event(b"requested terminal");
        let request = TerminalSlotAppendRequest::new(event.clone()).unwrap();
        assert!(matches!(terminal(&request, &event, 0, ShadowSpoolDisposition::Appended, terminal_receipt_fixture::Fault::None),
            Ok(TerminalSlotAppendOutcome::Committed(_))));
        assert!(matches!(terminal(&request, &event, 1, ShadowSpoolDisposition::Appended, terminal_receipt_fixture::Fault::None),
            Ok(TerminalSlotAppendOutcome::Existing(_))));
        let conflicting = terminal_event(b"previously stored conflicting terminal");
        assert!(matches!(terminal(&request, &conflicting, 2, ShadowSpoolDisposition::Appended, terminal_receipt_fixture::Fault::None),
            Ok(TerminalSlotAppendOutcome::Fork(receipt)) if receipt.matches_event(&conflicting)));
        for outcome in [0, 1] {
            assert_eq!(terminal(&request, &conflicting, outcome, ShadowSpoolDisposition::Appended,
                terminal_receipt_fixture::Fault::None).err(), Some(ShadowError::BindingDrift));
        }
        assert_eq!(terminal(&request, &event, 2, ShadowSpoolDisposition::Appended,
            terminal_receipt_fixture::Fault::None).err(), Some(ShadowError::BindingDrift));
    }

    #[test]
    fn custody_terminal_wire_rejects_cross_request_tuple_phase_and_unavailable() {
        let event = terminal_event(b"requested terminal");
        let request = TerminalSlotAppendRequest::new(event.clone()).unwrap();
        for field in 0..5 {
            let mut conflicting = terminal_event(b"conflict");
            match field {
                0 => conflicting.generation_id = Sha256Digest::compute(b"other generation"),
                1 => conflicting.ingress_sequence = 2,
                2 => conflicting.request_binding_sha256 = Sha256Digest::compute(b"other request"),
                3 => conflicting.request_commitment_sha256 = Sha256Digest::compute(b"other commitment"),
                _ => conflicting.phase = ShadowSpoolPhase::Capture,
            }
            assert_eq!(terminal(&request, &conflicting, 2, ShadowSpoolDisposition::Appended,
                terminal_receipt_fixture::Fault::None).err(), Some(ShadowError::BindingDrift), "field {field}");
        }
        assert_eq!(terminal(&request, &event, 0, ShadowSpoolDisposition::Unavailable,
            terminal_receipt_fixture::Fault::None).err(), Some(ShadowError::BindingDrift));
    }

    #[test]
    fn custody_terminal_wire_requires_real_crypto_time_and_exact_byte_proofs() {
        use terminal_receipt_fixture::Fault;
        let event = terminal_event(b"requested terminal");
        let request = TerminalSlotAppendRequest::new(event.clone()).unwrap();
        for (fault, expected) in [
            (Fault::Signature, ShadowError::SignatureInvalid), (Fault::PinnedKey, ShadowError::SignerBindingMismatch),
            (Fault::VerificationKey, ShadowError::SignatureInvalid), (Fault::StaleTime, ShadowError::EvidenceTooOld),
            (Fault::FutureTime, ShadowError::EvidenceTooOld), (Fault::Checkpoint, ShadowError::TrustCheckpointMismatch),
            (Fault::PersistenceBytes, ShadowError::PayloadDigestMismatch), (Fault::RetrievalBytes, ShadowError::BindingDrift),
        ] {
            assert_eq!(terminal(&request, &event, 0, ShadowSpoolDisposition::Appended, fault).err(), Some(expected), "{fault:?}");
        }
    }

    fn assigned(expected_generation: Option<&ShadowGenerationIdentity>, expected_bounds: Option<(u64, u64)>,
        expected_binding: &Sha256Digest, issued: &ShadowGenerationIdentity, sequence: u64,
        decision: SamplingDecision, fault: terminal_receipt_fixture::Fault) -> Result<PersistedIngressAdmission, ShadowError> {
        let sampling = CustodySamplingAuthorizationWire::new(issued.generation_id().clone(),
            Sha256Digest::compute(b"ingress request"), sequence, issued.sampling_basis_points,
            Sha256Digest::compute(b"ingress commitment"), decision)?;
        let bytes = canonical_ingress_admission_event_bytes(issued, 1_000_000, &sampling)?;
        let event = ShadowSpoolEvent::new(issued.generation_id().clone(), sequence,
            sampling.request_binding_sha256.clone(), sampling.request_commitment_sha256.clone(),
            ShadowSpoolPhase::IngressOpen, Sha256Digest::compute(&bytes), bytes)?;
        terminal_receipt_fixture::with_wire(&event, ShadowSpoolDisposition::Appended, fault,
            |receipt, signer, trust, time, store| {
                let wire = IngressCustodyAdmissionWire::Assigned(PersistedIngressAdmissionWire {
                    observed_at_unix_nanos: 1_000_000, sampling, opening_spill_receipt: receipt,
                });
                wire.validate_expected_binding(expected_generation, expected_bounds, expected_binding)?;
                let IngressCustodyAdmissionWire::Assigned(wire) = wire else { unreachable!() };
                verify_persisted_ingress_admission(expected_generation.ok_or(ShadowError::GenerationIdentityMismatch)?,
                    wire.observed_at_unix_nanos, wire.sampling, wire.opening_spill_receipt, signer, trust, time, store, 100)
            })
    }

    #[test]
    fn custody_ingress_wire_binds_captured_generation_request_range_and_sampling() {
        use terminal_receipt_fixture::Fault;
        let generation = generation();
        let binding = Sha256Digest::compute(b"ingress request");
        for decision in [SamplingDecision::Included, SamplingDecision::ExcludedByAssignment] {
            let receipt = assigned(Some(&generation), Some((1, 4)), &binding, &generation, 1, decision, Fault::None).unwrap();
            assert_eq!(receipt.sampling.decision, decision);
            assert_eq!(receipt.generation_id(), generation.generation_id());
        }
        assert_eq!(assigned(None, None, &binding, &generation, 1, SamplingDecision::Included, Fault::None).err(),
            Some(ShadowError::GenerationIdentityMismatch));
        assert_eq!(assigned(Some(&generation), Some((1, 4)), &Sha256Digest::compute(b"other request"), &generation,
            1, SamplingDecision::Included, Fault::None).err(), Some(ShadowError::BindingDrift));
        assert_eq!(assigned(Some(&generation), Some((1, 4)), &binding, &generation,
            5, SamplingDecision::Included, Fault::None).err(), Some(ShadowError::NonContiguousIngressSequence));
        let mut changed = generation.clone();
        changed.runtime_boot_id_sha256 = Sha256Digest::compute(b"other boot");
        changed.generation_id = changed.recompute_id().unwrap();
        assert_eq!(assigned(Some(&generation), Some((1, 4)), &binding, &changed,
            1, SamplingDecision::Included, Fault::None).err(), Some(ShadowError::BindingDrift));
        assert_eq!(assigned(Some(&generation), Some((1, 4)), &binding, &generation,
            1, SamplingDecision::Included, Fault::Signature).err(), Some(ShadowError::SignatureInvalid));
        assert_eq!(assigned(Some(&generation), Some((1, 4)), &binding, &generation,
            1, SamplingDecision::Included, Fault::RetrievalBytes).err(), Some(ShadowError::BindingDrift));
    }

    #[test]
    fn custody_unavailable_wire_is_authenticated_and_revalidates_parsed_invariants() {
        let binding = Sha256Digest::compute(b"unavailable request");
        for generation in [None, Some(generation())] {
            unavailable(&binding, generation.as_ref(), |wire, authority| {
                let encoded = canonical_json_bytes(&IngressCustodyAdmissionWire::Unavailable(wire.clone()))?;
                let parsed: IngressCustodyAdmissionWire = serde_json::from_slice(&encoded).unwrap();
                parsed.validate_expected_binding(generation.as_ref(), None, &binding)?;
                let IngressCustodyAdmissionWire::Unavailable(parsed) = parsed else { unreachable!() };
                let verified = verify_unavailable_generation_receipt(parsed, authority.expected(), authority, authority, authority, 100)?;
                assert_eq!(verified.request_binding_sha256(), &binding);
                assert_eq!(IngressCustodyAdmissionWire::Unavailable(wire.clone())
                    .validate_expected_binding(generation.as_ref(), None, &Sha256Digest::compute(b"other request")).err(), Some(ShadowError::BindingDrift));
                let mut malformed = wire;
                malformed.event_ordinal = 0;
                assert_eq!(malformed.validate_deserialized_invariants().err(), Some(ShadowError::InvalidField {
                    field: "custody_unavailable.event_ordinal", reason: "must be a positive signed-schema integer",
                }));
                Ok(())
            }).unwrap();
        }
    }

    #[test]
    fn custody_response_wire_rejects_unknown_tags_fields_and_forged_authority_shape() {
        let event = terminal_event(b"terminal");
        terminal_receipt_fixture::with_wire(&event, ShadowSpoolDisposition::Appended, terminal_receipt_fixture::Fault::None,
            |receipt, _, _, _, _| {
                let baseline = serde_json::to_value(TerminalSlotAppendOutcomeWire::Committed(receipt)).unwrap();
                assert!(serde_json::from_value::<TerminalSlotAppendOutcomeWire>(baseline.clone()).is_ok());
                let mut unknown = baseline.clone(); unknown["outcome"] = serde_json::json!("verified");
                assert!(serde_json::from_value::<TerminalSlotAppendOutcomeWire>(unknown).is_err());
                let mut unknown = baseline; unknown["authority"] = serde_json::json!(true);
                assert!(serde_json::from_value::<TerminalSlotAppendOutcomeWire>(unknown).is_err());
                assert!(serde_json::from_value::<IngressCustodyAdmissionWire>(serde_json::json!({
                    "outcome":"assigned", "receipt":{"verified":true}})).is_err());
                Ok(())
            }).unwrap();
    }
}

// Local component fixture only: the real legacy barrier/commit verifiers must
// authenticate each signature, role/key pin, time checkpoint and exact stored
// payload. This is not production assignment/attestation, RPC or durable I/O
// evidence, and it never constructs a Verified* value directly.
#[cfg(test)]
pub(crate) mod credential_effect_receipt_fixture {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Fault {
        None,
        Signature,
        PinnedKey,
        VerificationKey,
        StaleTime,
        FutureTime,
        Checkpoint,
        PersistenceBytes,
        RetrievalBytes,
    }

    const OBSERVED_AT: i64 = 2_000_000;
    const MAXIMUM_AGE: i64 = 100;

    struct FixtureAuthority {
        key: SigningKey,
        role: PolicyShadowCustodySignerRole,
        key_id: Sha256Digest,
        key_spki: Sha256Digest,
        checkpoint: AtomicTrustCheckpoint,
        persistence_id: Sha256Digest,
        retrieval_id: Sha256Digest,
        retrieval_proof: Sha256Digest,
        persisted: Vec<u8>,
        retrieved: Vec<u8>,
        fault: Fault,
    }

    impl FixtureAuthority {
        fn new(role: PolicyShadowCustodySignerRole, fault: Fault) -> Result<Self, ShadowError> {
            let key = SigningKey::from_bytes(&[81; 32]);
            Ok(Self {
                key_spki: ed25519_public_key_material_sha256(&key.verifying_key()),
                key,
                role,
                key_id: Sha256Digest::compute(b"local credential effect component key"),
                checkpoint: AtomicTrustCheckpoint::new(
                    Sha256Digest::compute(b"local credential effect checkpoint"),
                    OBSERVED_AT,
                    1,
                    Sha256Digest::compute(b"local credential effect revocations"),
                )?,
                persistence_id: Sha256Digest::compute(b"local credential effect stored slot"),
                retrieval_id: Sha256Digest::compute(b"local credential effect retrieval slot"),
                retrieval_proof: Sha256Digest::compute(b"local credential effect retrieval proof"),
                persisted: Vec::new(),
                retrieved: Vec::new(),
                fault,
            })
        }

        fn sign_and_store(&mut self, payload: &[u8]) -> CanonicalEd25519Signature {
            // Keep independent copies of the originally issued payload, not
            // the bytes subsequently presented to either proof verifier.
            self.persisted = payload.to_vec();
            self.retrieved = payload.to_vec();
            if self.fault == Fault::PersistenceBytes {
                self.persisted.push(b' ');
            }
            if self.fault == Fault::RetrievalBytes {
                self.retrieved.push(b' ');
            }
            let mut signature = self.key
                .sign(&signature_preimage(self.role.signature_domain(), payload))
                .to_bytes();
            if self.fault == Fault::Signature {
                signature[0] ^= 1;
            }
            CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(signature))
        }

        fn expected_key_id(&self) -> Sha256Digest {
            if self.fault == Fault::PinnedKey {
                Sha256Digest::compute(b"different independently pinned credential effect key")
            } else {
                self.key_id.clone()
            }
        }
    }

    impl EnvelopeKeyTrust for FixtureAuthority {
        fn current_checkpoint(&self) -> Result<AtomicTrustCheckpoint, ShadowError> {
            let mut checkpoint = self.checkpoint.clone();
            if self.fault == Fault::Checkpoint {
                checkpoint.checkpoint_id = Sha256Digest::compute(b"different credential effect checkpoint");
            }
            Ok(checkpoint)
        }

        fn resolve_ed25519_key(
            &self,
            checkpoint: &AtomicTrustCheckpoint,
            signature_domain: &str,
            key_id: &Sha256Digest,
            key_spki_sha256: &Sha256Digest,
        ) -> Result<VerifyingKey, ShadowError> {
            if checkpoint != &self.checkpoint
                || signature_domain != self.role.signature_domain()
                || key_id != &self.key_id
                || key_spki_sha256 != &self.key_spki
            {
                return Err(ShadowError::TrustResolutionFailed);
            }
            Ok(if self.fault == Fault::VerificationKey {
                SigningKey::from_bytes(&[82; 32]).verifying_key()
            } else {
                self.key.verifying_key()
            })
        }
    }

    impl TrustedTime for FixtureAuthority {
        fn now_unix_nanos(&self) -> Result<i64, ShadowError> {
            Ok(match self.fault {
                Fault::StaleTime => OBSERVED_AT + MAXIMUM_AGE + 1,
                Fault::FutureTime => OBSERVED_AT - 1,
                _ => OBSERVED_AT + 1,
            })
        }
    }

    impl PolicyShadowPersistenceProofVerifier for FixtureAuthority {
        fn verify_persistence_receipt(
            &self,
            role: PolicyShadowCustodySignerRole,
            persistence_receipt_sha256: &Sha256Digest,
            canonical_payload: &[u8],
        ) -> Result<(), ShadowError> {
            if role != self.role || persistence_receipt_sha256 != &self.persistence_id
                || canonical_payload != self.persisted.as_slice()
            {
                return Err(ShadowError::PayloadDigestMismatch);
            }
            Ok(())
        }

        fn verify_immutable_retrieval(
            &self,
            role: PolicyShadowCustodySignerRole,
            retrieval_id_sha256: &Sha256Digest,
            retrieval_proof_sha256: &Sha256Digest,
            canonical_payload: &[u8],
        ) -> Result<(), ShadowError> {
            if role != self.role || retrieval_id_sha256 != &self.retrieval_id
                || retrieval_proof_sha256 != &self.retrieval_proof
                || canonical_payload != self.retrieved.as_slice()
            {
                return Err(ShadowError::BindingDrift);
            }
            Ok(())
        }
    }

    fn permit_against(
        issued: &ActiveEffectPreparation,
        expected: &ActiveEffectPreparation,
        barrier_ordinal: u64,
        fault: Fault,
    ) -> Result<VerifiedActiveEffectPermit, ShadowError> {
        let mut authority = FixtureAuthority::new(PolicyShadowCustodySignerRole::ActiveEffectBarrier, fault)?;
        let mut wire = ActiveEffectBarrierReceiptWire {
            preparation: issued.clone(),
            barrier_ordinal,
            predecessor_head_sha256: Sha256Digest::compute(b"local credential barrier predecessor"),
            resulting_head_sha256: Sha256Digest::compute(b"local credential barrier head"),
            trusted_observed_at_unix_nanos: OBSERVED_AT,
            trusted_time_checkpoint_sha256: authority.checkpoint.checkpoint_id.clone(),
            persistence_receipt_sha256: authority.persistence_id.clone(),
            retrieval_id_sha256: authority.retrieval_id.clone(),
            retrieval_proof_sha256: authority.retrieval_proof.clone(),
            signing_key_id: authority.key_id.clone(),
            signing_key_spki_sha256: authority.key_spki.clone(),
            signature: CanonicalEd25519Signature(String::new()),
            signed_receipt_sha256: Sha256Digest::compute(b"not yet signed"),
        };
        let payload = wire.canonical_payload()?;
        wire.signature = authority.sign_and_store(&payload);
        // Even signature-negative controls refresh the outer digest so they
        // must reach actual signature verification, not a stale-hash guard.
        wire.signed_receipt_sha256 = hash_domain_frames(
            b"serverware.policyShadowActiveEffectBarrierReceipt/v1",
            &[payload.as_slice(), wire.signature.0.as_bytes()],
        );
        let expected_key = authority.expected_key_id();
        verify_active_effect_barrier(
            wire,
            expected,
            ExpectedSigner { key_id: &expected_key, key_spki_sha256: &authority.key_spki },
            &authority,
            &authority,
            &authority,
            MAXIMUM_AGE,
        )
    }

    pub(crate) fn permit(
        preparation: &ActiveEffectPreparation,
        fault: Fault,
    ) -> Result<VerifiedActiveEffectPermit, ShadowError> {
        permit_against(preparation, preparation, 1, fault)
    }

    pub(crate) fn alternate_permit(
        preparation: &ActiveEffectPreparation,
    ) -> Result<VerifiedActiveEffectPermit, ShadowError> {
        permit_against(preparation, preparation, 2, Fault::None)
    }

    fn commit_against(
        issued_permit: &VerifiedActiveEffectPermit,
        expected_permit: &VerifiedActiveEffectPermit,
        issued_state: ActiveEffectCommitState,
        expected_state: ActiveEffectCommitState,
        issued_result: &Sha256Digest,
        expected_result: &Sha256Digest,
        fault: Fault,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
        let mut authority = FixtureAuthority::new(PolicyShadowCustodySignerRole::ActiveEffectCommit, fault)?;
        let mut wire = ActiveEffectCommitReceiptWire {
            effect_id_sha256: issued_permit.preparation().effect_id_sha256().clone(),
            barrier_receipt_sha256: issued_permit.signed_receipt_sha256().clone(),
            terminal_state: issued_state,
            result_sha256: issued_result.clone(),
            reconcile_required: matches!(issued_state, ActiveEffectCommitState::OutcomeUnknown | ActiveEffectCommitState::ReconcileRequired),
            trusted_observed_at_unix_nanos: OBSERVED_AT,
            trusted_time_checkpoint_sha256: authority.checkpoint.checkpoint_id.clone(),
            persistence_receipt_sha256: authority.persistence_id.clone(),
            retrieval_id_sha256: authority.retrieval_id.clone(),
            retrieval_proof_sha256: authority.retrieval_proof.clone(),
            signing_key_id: authority.key_id.clone(),
            signing_key_spki_sha256: authority.key_spki.clone(),
            signature: CanonicalEd25519Signature(String::new()),
            signed_receipt_sha256: Sha256Digest::compute(b"not yet signed"),
        };
        let payload = wire.canonical_payload()?;
        wire.signature = authority.sign_and_store(&payload);
        wire.signed_receipt_sha256 = hash_domain_frames(
            b"serverware.policyShadowActiveEffectCommitReceipt/v1",
            &[payload.as_slice(), wire.signature.0.as_bytes()],
        );
        let expected_key = authority.expected_key_id();
        verify_active_effect_commit(
            wire,
            expected_permit,
            expected_state,
            expected_result,
            ExpectedSigner { key_id: &expected_key, key_spki_sha256: &authority.key_spki },
            &authority,
            &authority,
            &authority,
            MAXIMUM_AGE,
        )
    }

    pub(crate) fn commit(
        permit: &VerifiedActiveEffectPermit,
        state: ActiveEffectCommitState,
        result: &Sha256Digest,
        fault: Fault,
    ) -> Result<VerifiedActiveEffectCommitReceipt, ShadowError> {
        commit_against(permit, permit, state, state, result, result, fault)
    }

    fn preparation() -> ActiveEffectPreparation {
        ActiveEffectPreparation::new(
            Sha256Digest::compute(b"local credential generation"),
            7,
            ActiveMutableEffectKind::CredentialGeneration,
            Sha256Digest::compute(b"local credential parent-bound intent"),
            Sha256Digest::compute(b"local credential parent-bound prepared state"),
        ).expect("valid local preparation")
    }

    #[test]
    fn credential_effect_receipts_authenticate_exact_barrier_and_all_terminal_states() {
        let preparation = preparation();
        let permit = permit(&preparation, Fault::None).expect("authentic barrier");
        assert_eq!(permit.preparation(), &preparation);
        let result = Sha256Digest::compute(b"local credential result");
        // Independent verifier cases, not repeated commits to a real custody
        // supervisor. This fixture does not prove one-use/replay/CAS behavior.
        for state in [ActiveEffectCommitState::Committed, ActiveEffectCommitState::Aborted,
            ActiveEffectCommitState::OutcomeUnknown, ActiveEffectCommitState::ReconcileRequired]
        {
            let receipt = commit(&permit, state, &result, Fault::None).expect("authentic commit");
            assert_eq!(receipt.effect_id_sha256(), preparation.effect_id_sha256());
            assert_eq!(receipt.terminal_state(), state);
            assert_eq!(receipt.result_sha256(), &result);
        }
    }

    #[test]
    fn credential_effect_barrier_rejects_crossed_preparation_components() {
        let expected = preparation();
        for component in 0..5 {
            let issued = ActiveEffectPreparation::new(
                if component == 0 { Sha256Digest::compute(b"another generation") } else { expected.generation_id.clone() },
                if component == 1 { 8 } else { expected.ingress_sequence },
                if component == 2 { ActiveMutableEffectKind::CredentialLease } else { expected.effect_kind },
                if component == 3 { Sha256Digest::compute(b"another intent") } else { expected.effect_intent_sha256.clone() },
                if component == 4 { Sha256Digest::compute(b"another prepared state") } else { expected.prepared_state_sha256.clone() },
            ).expect("coherent different preparation");
            assert_eq!(permit_against(&issued, &expected, 1, Fault::None).err(), Some(ShadowError::BindingDrift));
        }
    }

    #[test]
    fn credential_effect_commit_rejects_crossed_effect_barrier_state_and_result() {
        let preparation = preparation();
        let expected = permit(&preparation, Fault::None).expect("authentic expected barrier");
        let other_barrier = permit_against(&preparation, &preparation, 2, Fault::None).expect("authentic different barrier");
        let other_preparation = ActiveEffectPreparation::new(
            preparation.generation_id.clone(), 8, preparation.effect_kind,
            preparation.effect_intent_sha256.clone(), preparation.prepared_state_sha256.clone(),
        ).expect("different effect preparation");
        let other_effect = permit(&other_preparation, Fault::None).expect("authentic different effect");
        let result = Sha256Digest::compute(b"local credential result");
        let other_result = Sha256Digest::compute(b"other local credential result");
        for issued in [&other_barrier, &other_effect] {
            assert_eq!(commit_against(issued, &expected, ActiveEffectCommitState::Committed,
                ActiveEffectCommitState::Committed, &result, &result, Fault::None).err(), Some(ShadowError::BindingDrift));
        }
        assert_eq!(commit_against(&expected, &expected, ActiveEffectCommitState::Aborted,
            ActiveEffectCommitState::Committed, &result, &result, Fault::None).err(), Some(ShadowError::BindingDrift));
        assert_eq!(commit_against(&expected, &expected, ActiveEffectCommitState::Committed,
            ActiveEffectCommitState::Committed, &other_result, &result, Fault::None).err(), Some(ShadowError::BindingDrift));
    }

    #[test]
    fn credential_effect_receipts_reject_crypto_time_and_independent_storage_faults() {
        let preparation = preparation();
        let authentic_permit = permit(&preparation, Fault::None).expect("authentic barrier baseline");
        let result = Sha256Digest::compute(b"local credential result");
        for (fault, expected) in [
            (Fault::Signature, ShadowError::SignatureInvalid),
            (Fault::PinnedKey, ShadowError::SignerBindingMismatch),
            (Fault::VerificationKey, ShadowError::SignatureInvalid),
            (Fault::StaleTime, ShadowError::EvidenceTooOld),
            (Fault::FutureTime, ShadowError::EvidenceTooOld),
            (Fault::Checkpoint, ShadowError::TrustCheckpointMismatch),
            (Fault::PersistenceBytes, ShadowError::PayloadDigestMismatch),
            (Fault::RetrievalBytes, ShadowError::BindingDrift),
        ] {
            assert_eq!(permit(&preparation, fault).err(), Some(expected.clone()), "barrier {fault:?}");
            assert_eq!(commit(&authentic_permit, ActiveEffectCommitState::Committed, &result, fault).err(),
                Some(expected), "commit {fault:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::parse(format!("sha256:{}", hex::encode([byte; 32])))
            .expect("test digest")
    }

    #[test]
    fn canonical_json_sorts_ascii_keys_and_rejects_floats() {
        let value = serde_json::json!({"z": 2, "a": "x"});
        assert_eq!(
            canonical_json_bytes(&value).expect("canonical JSON"),
            br#"{"a":"x","z":2}"#
        );
        assert!(canonical_json_bytes(&serde_json::json!({"x": 1.5})).is_err());
    }

    #[test]
    fn validated_analysis_produces_separate_plan_types() {
        let analysis = ValidatedPolicyAnalysis::new(
            PolicyOutcome::Conditional {
                reason: Identifier::parse("quota").expect("reason"),
            },
            vec![digest(1)],
            vec![digest(2)],
            vec![ActiveEffectIntent::ReserveQuota {
                counter_sha256: digest(3),
                claim_sha256: digest(4),
                weighted_units: 1,
            }],
            PolicyOutcome::Conditional {
                reason: Identifier::parse("quota").expect("reason"),
            },
            vec![digest(1)],
            vec![digest(2)],
            vec![CandidateEffectIntent::WouldReserveQuota {
                counter_sha256: digest(3),
                claim_sha256: digest(4),
                weighted_units: 1,
            }],
        )
        .expect("validated analysis");
        let (active, candidate) = analysis.into_separate_plans();
        assert_eq!(active.outcome().class(), OutcomeClass::Conditional);
        assert_eq!(candidate.outcome().class(), OutcomeClass::Conditional);
        assert_ne!(
            active.semantic_commitment().expect("active commitment"),
            candidate
                .semantic_commitment()
                .expect("candidate commitment")
        );
    }

    #[test]
    fn candidate_constructor_forces_shadow_only_capabilities() {
        let candidate =
            CandidatePolicyPlan::new_shadow_only(PolicyOutcome::Permit, vec![], vec![], vec![])
                .expect("candidate plan");
        assert!(candidate.validate().is_ok());
    }

    #[test]
    fn request_commitment_key_constructor_remains_crate_scoped() {
        let key = RequestCommitmentKey::from_secret(digest(9), 1, &[7_u8; 32])
            .expect("crate-local key");
        assert_eq!(key.key_epoch, 1);
    }
}
